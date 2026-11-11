// 배포된 서버에 "로그인 없이" 보낼 수 있는 요청만 보내고, 요청/응답을 evidence/live-check.md 에 기록한다.
// 계정·세션·설정 코드가 필요한 요청은 하지 않는다. 쿠키/토큰은 다루지 않는다.
//   사용법: node scripts/live-check.mjs https://주소
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const base = (process.argv[2] ?? '').replace(/\/$/, '');
if (!/^https:\/\//.test(base)) { console.error('https 주소를 인자로 주세요'); process.exit(1); }
const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const out = [];
const log = (s = '') => out.push(s);

async function call(method, url, { body, headers } = {}) {
  const res = await fetch(base + url, { method, headers: { ...(body ? { 'Content-Type': 'application/json' } : {}), ...headers }, body, redirect: 'manual' });
  const text = await res.text();
  return { status: res.status, cache: res.headers.get('cache-control'), text };
}
const show = (title, req, r, note = '') => {
  log(`### ${title}`);
  log('');
  log('- 요청: `' + req + '`');
  log(`- 응답 상태: **${r.status}**`);
  if (r.cache) log(`- Cache-Control: \`${r.cache}\``);
  log('- 응답 본문: `' + r.text.replace(/\s+/g, ' ').slice(0, 200) + '`');
  if (note) log('- 확인: ' + note);
  log('');
};

log('# 배포 서버 직접 확인 기록 (로그인 없이 보낸 요청)');
log('');
log(`- 대상: ${base}`);
log(`- 실행 시각: ${new Date().toISOString()}`);
log('- 이 파일에는 쿠키·세션값·설정 코드가 들어 있지 않습니다.');
log('');

let r = await call('GET', '/api/private/items');
show('1. 로그인 없이 비공개 자료 요청 (T08-C16, C17)', 'GET /api/private/items (쿠키 없음)', r, r.status === 401 ? '401로 거절됨' : '**기대와 다름**');

r = await call('GET', '/api/private/items', { headers: { Cookie: 'sid=garbage; __Host-sid=garbage' } });
show('2. 임의의 값을 세션처럼 보낸 요청', 'GET /api/private/items (가짜 쿠키값)', r, r.status === 401 ? '서버가 모르는 세션값은 거절됨' : '**기대와 다름**');

r = await call('GET', '/api/private/items/00000000-0000-0000-0000-000000000000');
show('3. 로그인 없이 항목 id 직접 요청', 'GET /api/private/items/<임의 id>', r, r.status === 401 ? '로그인 확인이 id 조회보다 먼저 이뤄짐' : '**기대와 다름**');

r = await call('GET', '/api/session');
show('4. 로그인 상태 확인', 'GET /api/session', r);

const chs = [];
for (let i = 1; i <= 3; i++) {
  r = await call('POST', '/api/login/options', { body: '{}', headers: { Origin: base } });
  const ch = JSON.parse(r.text).challenge;
  chs.push(ch);
  log(`- 로그인 요청 ${i}회차: 상태 ${r.status}, challenge = \`${ch}\``);
}
log('');
log(`### 5. 로그인 챌린지는 요청마다 다름 (T08-C27, C28)`);
log('');
log(`- 세 값이 모두 다른가: **${new Set(chs).size === chs.length ? '예' : '아니오'}**`);
log(`- 길이: ${chs.map((c) => Buffer.from(c, 'base64url').length).join(', ')} 바이트 (서버가 만든 무작위 값)`);
log('');

r = await call('POST', '/api/register/options', { body: JSON.stringify({ username: 'visitor-probe' }), headers: { Origin: base } });
show('6. 방문자가 설정 코드 없이 계정 만들기 요청', 'POST /api/register/options {username}', r, r.status === 403 ? '403으로 거절됨. 방문자는 계정을 만들 수 없음' : '**기대와 다름**');

r = await call('POST', '/api/logout', { body: '{}', headers: { Origin: 'https://evil.example' } });
show('7. 다른 사이트에서 온 변경 요청', 'POST /api/logout (Origin: https://evil.example)', r, r.status === 403 ? '403으로 거절됨' : '**기대와 다름**');

const file = path.join(root, 'evidence', 'live-check.md');
fs.writeFileSync(file, out.join('\n'));
console.log(out.join('\n'));
