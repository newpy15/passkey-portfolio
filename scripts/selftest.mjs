// 자체 검증: 서버를 임시 데이터로 띄우고, "가짜 인증기"로 등록·로그인을 수행하며 차단 동작을 확인한다.
// 결과는 evidence/selftest-result.md 에 요청/응답 표로 남는다. (카드 5의 "확인 네 가지의 요청과 응답" 초안)
//
// ⚠ 이것은 소프트웨어 인증기로 한 테스트다. 과제의 "실제 패스키 등록/로그인" 증빙(화면 캡처 등)을 대신하지 않는다.
import { spawn } from 'node:child_process';
import crypto from 'node:crypto';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const PORT = 3100 + Math.floor(Math.random() * 500);
const ORIGIN = `http://localhost:${PORT}`;
const SETUP = 'selftest-code';
const dataFile = path.join(os.tmpdir(), `passkey-selftest-${Date.now()}.json`);

// ── 최소 CBOR 인코더 (attestationObject, COSE 키에 필요한 만큼만) ──
function cbor(v) {
  const head = (major, n) => {
    if (n < 24) return Buffer.from([(major << 5) | n]);
    if (n < 256) return Buffer.from([(major << 5) | 24, n]);
    return Buffer.from([(major << 5) | 25, n >> 8, n & 255]);
  };
  if (Buffer.isBuffer(v)) return Buffer.concat([head(2, v.length), v]);
  if (typeof v === 'string') { const b = Buffer.from(v); return Buffer.concat([head(3, b.length), b]); }
  if (typeof v === 'number') return v >= 0 ? head(0, v) : head(1, -1 - v);
  const entries = v instanceof Map ? [...v] : Object.entries(v);
  return Buffer.concat([head(5, entries.length), ...entries.flatMap(([k, x]) => [cbor(k), cbor(x)])]);
}
const sha256 = (b) => crypto.createHash('sha256').update(b).digest();
const b64u = (b) => Buffer.from(b).toString('base64url');

class SoftAuthenticator {
  constructor(name) {
    this.name = name;
    const { publicKey, privateKey } = crypto.generateKeyPairSync('ec', { namedCurve: 'P-256' });
    this.priv = privateKey;
    this.jwk = publicKey.export({ format: 'jwk' });
    this.credId = crypto.randomBytes(32);
    this.counter = 0;
    this.userHandle = null;
  }
  clientData(type, challenge, origin = ORIGIN) {
    return Buffer.from(JSON.stringify({ type, challenge, origin, crossOrigin: false }));
  }
  create(options, origin) {
    if ((options.excludeCredentials ?? []).some((c) => c.id === b64u(this.credId))) {
      const e = new Error('이미 이 인증기에 등록된 패스키'); e.name = 'InvalidStateError'; throw e; // 브라우저가 실제로 던지는 오류
    }
    this.userHandle = options.user.id;
    const rpIdHash = sha256(Buffer.from(options.rp.id));
    const cose = cbor(new Map([[1, 2], [3, -7], [-1, 1], [-2, Buffer.from(this.jwk.x, 'base64url')], [-3, Buffer.from(this.jwk.y, 'base64url')]]));
    const idLen = Buffer.alloc(2); idLen.writeUInt16BE(this.credId.length);
    const counter = Buffer.alloc(4);
    const authData = Buffer.concat([rpIdHash, Buffer.from([0x45]), counter, Buffer.alloc(16), idLen, this.credId, cose]); // UP|UV|AT
    const cd = this.clientData('webauthn.create', options.challenge, origin);
    return {
      id: b64u(this.credId), rawId: b64u(this.credId), type: 'public-key', clientExtensionResults: {},
      response: { clientDataJSON: b64u(cd), attestationObject: b64u(cbor({ fmt: 'none', attStmt: {}, authData })), transports: ['internal'] },
    };
  }
  get(options, { origin, badSignature } = {}) {
    this.counter += 1;
    const rpIdHash = sha256(Buffer.from(options.rpId));
    const counter = Buffer.alloc(4); counter.writeUInt32BE(this.counter);
    const authData = Buffer.concat([rpIdHash, Buffer.from([0x05]), counter]); // UP|UV
    const cd = this.clientData('webauthn.get', options.challenge, origin);
    const signed = Buffer.concat([authData, sha256(cd)]);
    let sig = crypto.sign('sha256', signed, this.priv);
    if (badSignature) { sig = Buffer.from(sig); sig[sig.length - 1] ^= 0xff; }
    return {
      id: b64u(this.credId), rawId: b64u(this.credId), type: 'public-key', clientExtensionResults: {},
      response: { clientDataJSON: b64u(cd), authenticatorData: b64u(authData), signature: b64u(sig), userHandle: this.userHandle },
    };
  }
}

// ── HTTP 도우미 + 기록 ──
const rows = [];
let cookieJar = {}; // 이름 -> 쿠키값 (기록에는 가려서 적는다. T08-C34)
const mask = (c) => (c ? '<세션값 가림>' : '없음');

async function call(who, method, url, body, { cookie, headers } = {}) {
  const res = await fetch(ORIGIN + url, {
    method,
    headers: { 'Content-Type': 'application/json', Origin: ORIGIN, ...(cookie ? { Cookie: cookie } : {}), ...headers },
    body: body ? JSON.stringify(body) : undefined,
    redirect: 'manual',
  });
  const text = await res.text();
  let json; try { json = JSON.parse(text); } catch { json = null; }
  const setCookie = res.headers.get('set-cookie');
  return { status: res.status, json, text, cookie: setCookie ? setCookie.split(';')[0] : null };
}

function record(item, who, req, cookie, res, expect, note = '') {
  const pass = Array.isArray(expect) ? expect.includes(res.status) : res.status === expect;
  rows.push({ item, who, req, cookie: mask(cookie), status: res.status, brief: res.json ? JSON.stringify(res.json).slice(0, 90) : res.text.slice(0, 60), pass, note });
  if (!pass) console.error(`  ✗ ${item}: 기대 ${expect}, 실제 ${res.status}`);
  else console.log(`  ✓ ${item} → ${res.status}`);
  return pass;
}

async function registerAccount(username, auth, label = '테스트 패스키') {
  const o = await call(username, 'POST', '/api/register/options', { username, label, setupCode: SETUP });
  const cred = auth.create(o.json);
  const v = await call(username, 'POST', '/api/register/verify', cred);
  return { options: o, verify: v, cookie: v.cookie };
}

async function loginWith(auth, opts) {
  const o = await call('-', 'POST', '/api/login/options', {});
  const cred = auth.get(o.json, opts);
  const v = await call('-', 'POST', '/api/login/verify', cred);
  return { options: o, cred, verify: v, cookie: v.cookie };
}

// ── 서버 기동 ──
const server = spawn(process.execPath, ['server.mjs'], { cwd: root, env: { ...process.env, PORT: String(PORT), ORIGIN, DATA_FILE: dataFile, SETUP_CODE: SETUP } });
let started = false;
server.stdout.on('data', (d) => { if (String(d).includes('listening')) started = true; });
server.stderr.on('data', (d) => process.stderr.write(d));
for (let i = 0; i < 50 && !started; i++) await new Promise((r) => setTimeout(r, 100));
if (!started) { console.error('서버가 뜨지 않았습니다'); server.kill(); process.exit(1); }

try {
  console.log(`테스트 서버 ${ORIGIN}`);

  // 1. 로그인 없이 비공개 자료 요청 → 거절 (T08-C16, C17)
  let r = await call('(없음)', 'GET', '/api/private/items');
  record('1. 로그인 없이 비공개 자료 요청', '로그인 안 함', 'GET /api/private/items', null, r, [401, 403]);

  // 1-1. 방문자(설정 코드 없음)는 계정을 만들 수 없다
  r = await call('방문자', 'POST', '/api/register/options', { username: 'intruder', label: 'x' });
  record('A. 설정 코드 없이 계정 만들기 요청(방문자)', '방문자', 'POST /api/register/options', null, r, 403);
  r = await call('방문자', 'POST', '/api/register/options', { username: 'intruder', label: 'x', setupCode: 'wrong' });
  record('A. 틀린 설정 코드로 계정 만들기 요청(방문자)', '방문자', 'POST /api/register/options', null, r, 403);

  // 2. 공개 페이지 소스에 비공개 내용이 없는가 (T08-C18) — 계정 만든 뒤 다시 확인
  // 3. 계정 A, B 등록 (각자 다른 인증기)
  const A = new SoftAuthenticator('A-기기1'); const B = new SoftAuthenticator('B-기기');
  const a = await registerAccount('alice-test', A, 'A의 첫 패스키');
  record('2. 계정 A 패스키 등록', 'alice-test', 'POST /api/register/options → verify', null, a.verify, 200, `챌린지 ${a.options.json.challenge.slice(0, 8)}…`);
  const b = await registerAccount('bob-test', B, 'B의 패스키');
  record('2. 계정 B 패스키 등록', 'bob-test', 'POST /api/register/options → verify', null, b.verify, 200, `챌린지 ${b.options.json.challenge.slice(0, 8)}…`);
  record('2. 등록 챌린지는 요청마다 다름', '-', 'A와 B 등록 챌린지 비교', null, { status: a.options.json.challenge !== b.options.json.challenge ? 200 : 500, json: null, text: '' }, 200);

  // 4. 각 계정의 비공개 자료: 3개 이상, 서로 다름 (T08-C14, C36)
  const itemsA = await call('alice-test', 'GET', '/api/private/items', null, { cookie: a.cookie });
  const itemsB = await call('bob-test', 'GET', '/api/private/items', null, { cookie: b.cookie });
  record('3. A의 비공개 자료 (3개 이상)', 'alice-test', 'GET /api/private/items', a.cookie, itemsA, 200, `${itemsA.json.items.length}건`);
  record('3. B의 비공개 자료 (A와 다름)', 'bob-test', 'GET /api/private/items', b.cookie, itemsB, 200, `${itemsB.json.items.length}건, 제목 상이: ${itemsA.json.items[0].title !== itemsB.json.items[0].title}`);

  // 5. 공개 페이지(소스)에 비공개 문구가 없다 (T08-C18)
  const page = await call('(없음)', 'GET', '/');
  const leaked = [...itemsA.json.items, ...itemsB.json.items].some((i) => page.text.includes(i.title) || page.text.includes(i.body));
  record('4. 로그인 없이 받은 페이지 소스에 비공개 내용 없음', '로그인 안 함', 'GET /', null, { status: leaked ? 500 : 200, json: null, text: '' }, 200, `소스 길이 ${page.text.length}자`);

  // 6. 남의 자료 접근 (T08-C37~C41)
  const bobItemId = itemsB.json.items[0].id;
  r = await call('alice-test', 'GET', `/api/private/items/${bobItemId}`, null, { cookie: a.cookie });
  record('5. A가 B의 항목 id로 직접 요청', 'alice-test', `GET /api/private/items/<B의 항목>`, a.cookie, r, 403);
  const aliceItemId = itemsA.json.items[0].id;
  r = await call('bob-test', 'GET', `/api/private/items/${aliceItemId}`, null, { cookie: b.cookie });
  record('5. B가 A의 항목 id로 직접 요청 (반대 방향)', 'bob-test', `GET /api/private/items/<A의 항목>`, b.cookie, r, 403);
  r = await call('alice-test', 'GET', '/api/private/items?owner=bob-test&user=bob-test', null, { cookie: a.cookie });
  record('5. 주소에 다른 계정을 적어도 내 자료만 옴', 'alice-test', 'GET /api/private/items?owner=bob-test', a.cookie, { ...r, status: r.json?.owner === 'alice-test' ? 200 : 500 }, 200, `응답 owner=${r.json?.owner}`);
  r = await call('alice-test', 'POST', '/api/private/items', { title: '메모', body: 'x', owner: 'bob-test' }, { cookie: a.cookie });
  const bAfter = await call('bob-test', 'GET', '/api/private/items', null, { cookie: b.cookie });
  record('5. 본문에 다른 계정을 적어 보낸 저장 요청', 'alice-test', 'POST /api/private/items {owner:"bob-test"}', a.cookie, { ...r, status: bAfter.json.items.length === itemsB.json.items.length ? 201 : 500 }, 201, `B 항목 수 변화 없음: ${bAfter.json.items.length === itemsB.json.items.length}`);

  // 7. 챌린지: 요청마다 다름 + 재사용 거절 (T08-C27, C28, C31)
  const l1 = await loginWith(A);
  record('6. A 로그인 (서명 검증 통과)', 'alice-test', 'POST /api/login/options → verify', null, l1.verify, 200, `챌린지 ${l1.options.json.challenge.slice(0, 8)}…`);
  const l2 = await loginWith(A);
  record('6. 로그인 챌린지는 매번 다름', '-', '직전 로그인과 챌린지 비교', null, { status: l1.options.json.challenge !== l2.options.json.challenge ? 200 : 500, json: null, text: '' }, 200, `${l1.options.json.challenge.slice(0, 8)}… ≠ ${l2.options.json.challenge.slice(0, 8)}…`);
  r = await call('-', 'POST', '/api/login/verify', l1.cred); // 이미 쓴 응답을 그대로 재전송
  record('6. 이미 사용한 챌린지/응답 재사용', '-', 'POST /api/login/verify (재전송)', null, r, 400);

  // 8. 서명 검증이 실제로 통과 여부를 가른다 (카드 3 막히는 지점)
  const bad = await loginWith(A, { badSignature: true });
  record('7. 일부러 틀린 서명 전송', '-', 'POST /api/login/verify (서명 변조)', null, bad.verify, 401);
  const wrongOrigin = await loginWith(A, { origin: 'https://evil.example' });
  record('7. 다른 사이트(origin)에서 만든 응답 전송', '-', 'POST /api/login/verify (origin 변조)', null, wrongOrigin.verify, 401);
  const fake = await call('-', 'POST', '/api/login/verify', { id: 'AAAA', response: { clientDataJSON: b64u(JSON.stringify({ challenge: 'nope' })) } });
  record('7. 서버가 발급하지 않은 챌린지', '-', 'POST /api/login/verify (임의 챌린지)', null, fake, 400);

  // 9. 두 번째 패스키: excludeCredentials (카드 4)
  const sessA = l2.cookie;
  const addOpt = await call('alice-test', 'POST', '/api/passkeys/options', { label: 'A의 두번째' }, { cookie: sessA });
  record('8. 패스키 추가 옵션에 기존 패스키가 제외 목록으로 포함', 'alice-test', 'POST /api/passkeys/options', sessA, { ...addOpt, status: addOpt.json.excludeCredentials?.length === 1 ? 200 : 500 }, 200, `excludeCredentials ${addOpt.json.excludeCredentials?.length}개`);
  let sameDeviceError = '';
  try { A.create(addOpt.json); } catch (e) { sameDeviceError = e.name; }
  record('8. 같은 인증기로 두 번째 등록 시도 → 브라우저가 거절(InvalidStateError)', 'alice-test', '(인증기 단계에서 거절)', null, { status: sameDeviceError === 'InvalidStateError' ? 200 : 500, json: null, text: '' }, 200, sameDeviceError);
  const A2 = new SoftAuthenticator('A-기기2');
  const addVerify = await call('alice-test', 'POST', '/api/passkeys/verify', A2.create(addOpt.json), { cookie: sessA });
  record('8. 다른 인증기로 두 번째 패스키 등록', 'alice-test', 'POST /api/passkeys/verify', sessA, addVerify, 200);
  const list = await call('alice-test', 'GET', '/api/passkeys', null, { cookie: sessA });
  record('8. 패스키 목록에 두 개', 'alice-test', 'GET /api/passkeys', sessA, { ...list, status: list.json.passkeys.length === 2 ? 200 : 500 }, 200, list.json.passkeys.map((p) => p.label).join(', '));

  // 10. 다른 계정이 내 패스키를 삭제할 수 없다
  const bobTriesDelete = await call('bob-test', 'DELETE', `/api/passkeys/${b64u(A.credId)}`, null, { cookie: b.cookie });
  record('9. B가 A의 패스키 삭제 시도', 'bob-test', 'DELETE /api/passkeys/<A의 패스키>', b.cookie, bobTriesDelete, 404);

  // 11. 삭제 → 삭제한 패스키로 로그인 불가, 남은 패스키로 가능 (T08-C44, C45)
  const del = await call('alice-test', 'DELETE', `/api/passkeys/${b64u(A.credId)}`, null, { cookie: sessA });
  record('10. A가 첫 패스키 삭제', 'alice-test', 'DELETE /api/passkeys/<첫 패스키>', sessA, del, 200);
  const afterDel = await loginWith(A);
  record('10. 삭제한 패스키로 로그인 → 거절', '-', 'POST /api/login/verify (삭제된 패스키)', null, afterDel.verify, 401);
  const stillOk = await loginWith(A2);
  record('10. 남은 패스키로 로그인 → 성공', 'alice-test', 'POST /api/login/verify (남은 패스키)', null, stillOk.verify, 200);

  // 12. 마지막 패스키는 지울 수 없다 (T08-C46)
  const last = await call('alice-test', 'DELETE', `/api/passkeys/${b64u(A2.credId)}`, null, { cookie: stillOk.cookie });
  record('11. 마지막 패스키 삭제 시도 → 거절(정책)', 'alice-test', 'DELETE /api/passkeys/<마지막>', stillOk.cookie, last, 409);

  // 13. 로그아웃 후 같은 세션값 재사용 (T08-C33)
  const before = await call('alice-test', 'GET', '/api/private/items', null, { cookie: stillOk.cookie });
  record('12. 로그아웃 전: 같은 세션값으로 조회', 'alice-test', 'GET /api/private/items', stillOk.cookie, before, 200);
  await call('alice-test', 'POST', '/api/logout', {}, { cookie: stillOk.cookie });
  const after = await call('alice-test', 'GET', '/api/private/items', null, { cookie: stillOk.cookie });
  record('12. 로그아웃 후: 같은 세션값으로 다시 요청 → 거절', 'alice-test', 'POST /api/logout 뒤 GET /api/private/items', stillOk.cookie, after, [401, 403]);

  // 14. 다른 Origin의 변경 요청 (CSRF 보조 방어)
  const csrf = await call('-', 'POST', '/api/logout', {}, { headers: { Origin: 'https://evil.example' } });
  record('13. 다른 사이트에서 온 변경 요청', '-', 'POST /api/logout (Origin: evil)', null, csrf, 403);

  // 15. 저장소에 개인키/비밀번호 흔적이 없다 (T08-C23, C35)
  const dbText = fs.readFileSync(dataFile, 'utf8');
  const hasSecret = /privateKey|password|BEGIN PRIVATE|"sid"|__Host-sid/i.test(dbText);
  record('14. 서버 저장소에 개인키·비밀번호·세션값 없음', '-', 'data 파일 검사', null, { status: hasSecret ? 500 : 200, json: null, text: '' }, 200, '저장된 것: 공개키·자격 증명 ID·메타데이터');
} finally {
  server.kill();
}

// ── 결과 저장 ──
const failed = rows.filter((x) => !x.pass).length;
const md = [
  '# 자체 검증 결과 (소프트웨어 인증기 사용)',
  '',
  `- 실행 시각: ${new Date().toISOString()}`,
  `- 대상: 임시 서버 ${ORIGIN} (임시 데이터 파일, 종료 후 폐기)`,
  `- 결과: ${rows.length - failed}/${rows.length} 통과`,
  '- ⚠ 가짜 인증기로 한 테스트입니다. 실제 기기·브라우저로 한 등록/로그인 증빙은 별도로 남겨야 합니다.',
  '',
  '| 확인 | 누가 | 요청 | 세션값 | 응답 | 응답 요약 | 판정 | 메모 |',
  '|---|---|---|---|---|---|---|---|',
  ...rows.map((x) => `| ${x.item} | ${x.who} | \`${x.req}\` | ${x.cookie} | ${x.status} | \`${x.brief.replace(/\|/g, '/')}\` | ${x.pass ? '통과' : '**실패**'} | ${x.note} |`),
  '',
].join('\n');
fs.mkdirSync(path.join(root, 'evidence'), { recursive: true });
fs.writeFileSync(path.join(root, 'evidence', 'selftest-result.md'), md);
fs.rmSync(dataFile, { force: true });
console.log(`\n${rows.length - failed}/${rows.length} 통과 → evidence/selftest-result.md`);
process.exit(failed ? 1 : 0);
