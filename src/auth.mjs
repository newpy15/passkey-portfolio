// 패스키 등록 · 로그인 · 로그아웃 · 패스키 관리.  (설명서 ③ "네 흐름이 소스 어디를 지나가나"의 근거)
//
//   [등록]    POST /api/register/options  →  브라우저가 인증기 호출  →  POST /api/register/verify
//   [로그인]  POST /api/login/options     →  브라우저가 인증기 호출  →  POST /api/login/verify
//   [로그아웃] POST /api/logout
//   [패스키 추가/삭제] /api/passkeys/*  (로그인 필요)
import crypto from 'node:crypto';
import { Router } from 'express';
import {
  generateRegistrationOptions,
  verifyRegistrationResponse,
  generateAuthenticationOptions,
  verifyAuthenticationResponse,
} from '@simplewebauthn/server';
import { config } from './config.mjs';
import { users, seedItems, save } from './store.mjs';
import {
  putChallenge, takeChallenge, createSession, destroySession, readSession,
  parseCookies, setSessionCookie, clearSessionCookie, COOKIE_NAME,
} from './sessions.mjs';
import { audit } from './audit.mjs';

const b64u = (buf) => Buffer.from(buf).toString('base64url');
const fromB64u = (s) => new Uint8Array(Buffer.from(s, 'base64url'));

const USERNAME_RE = /^[a-z0-9_-]{3,20}$/;
const normUsername = (v) => (typeof v === 'string' ? v.trim().toLowerCase() : '');
const normLabel = (v) => (typeof v === 'string' && v.trim() ? v.trim().slice(0, 30) : '내 패스키');

// 간단한 요청 횟수 제한 (IP당 1분 30회). 인증 엔드포인트 남용 방지.
const hits = new Map();
function rateLimit(req, res, next) {
  const key = req.ip;
  const now = Date.now();
  const arr = (hits.get(key) ?? []).filter((t) => now - t < 60_000);
  arr.push(now);
  hits.set(key, arr);
  if (arr.length > 30) return res.status(429).json({ error: 'too_many_requests' });
  next();
}

// ── 로그인 상태 확인 미들웨어 (비공개 라우트도 이걸 쓴다) ─────────────────────
export function requireAuth(req, res, next) {
  const token = parseCookies(req.headers.cookie)[COOKIE_NAME];
  const session = readSession(token);
  const user = session && users.byId(session.userId);
  if (!user) {
    audit({ event: 'private_denied', ok: false, detail: `${req.method} ${req.path} 로그인 없음` });
    return res.status(401).json({ error: 'unauthenticated', message: '패스키로 로그인해야 볼 수 있습니다.' });
  }
  req.user = user; // 이후 모든 데이터 조회는 "요청에 적힌 계정"이 아니라 이 값만 기준으로 한다. (T08-C40)
  req.sessionToken = token;
  next();
}

const publicCred = (c) => ({
  id: c.id,
  label: c.label,
  createdAt: c.createdAt,
  lastUsedAt: c.lastUsedAt ?? null,
  deviceType: c.deviceType, // singleDevice: 기기에 묶임 / multiDevice: 동기화 가능(비밀번호 관리자 등)
  backedUp: c.backedUp,
  transports: c.transports ?? [],
  aaguid: c.aaguid,
});

export const authRouter = Router();

authRouter.get('/session', (req, res) => {
  const session = readSession(parseCookies(req.headers.cookie)[COOKIE_NAME]);
  const user = session && users.byId(session.userId);
  res.set('Cache-Control', 'no-store');
  res.json(user ? { authenticated: true, username: user.username } : { authenticated: false });
});

// ── 등록 ───────────────────────────────────────────────────────────
// 계정은 "검증이 끝난 뒤"에야 만든다. 중간에 취소하면 서버에 아무것도 남지 않는다. (T08-C25)
authRouter.post('/register/options', rateLimit, async (req, res) => {
  // 소유자만 계정을 만들 수 있다. SETUP_CODE가 없으면 닫힘, 있으면 일치해야 한다.
  const sha = (s) => crypto.createHash('sha256').update(String(s)).digest();
  if (!config.setupCode) {
    audit({ event: 'register_options', ok: false, detail: '계정 생성 닫힘(SETUP_CODE 없음)' });
    return res.status(403).json({ error: 'registration_closed', message: '새 계정 만들기는 닫혀 있습니다.' });
  }
  if (!crypto.timingSafeEqual(sha(req.body?.setupCode ?? ''), sha(config.setupCode))) {
    audit({ event: 'register_options', ok: false, detail: '설정 코드 불일치' });
    return res.status(403).json({ error: 'bad_setup_code', message: '설정 코드가 맞지 않습니다.' });
  }
  const username = normUsername(req.body?.username);
  if (!USERNAME_RE.test(username)) {
    return res.status(400).json({ error: 'bad_username', message: '이름은 영문 소문자·숫자·_·- 3~20자입니다.' });
  }
  if (users.byName(username)) {
    // 이미 있는 계정에 패스키를 붙이려면 로그인한 뒤 "패스키 추가"를 써야 한다.
    // (그렇지 않으면 남의 계정에 내 패스키를 붙일 수 있다.)
    return res.status(409).json({ error: 'username_taken', message: '이미 있는 이름입니다. 내 계정이면 로그인 후 패스키를 추가하세요.' });
  }
  if (users.count() >= config.maxAccounts) {
    return res.status(403).json({ error: 'account_limit', message: '이 데모 서버의 계정 수 한도에 도달했습니다.' });
  }
  const label = normLabel(req.body?.label);
  const handle = crypto.randomBytes(32); // userHandle: 사용자 이름이 아닌 무작위 값
  const options = await generateRegistrationOptions({
    rpName: config.rpName,
    rpID: config.rpID,
    userName: username,
    userDisplayName: username,
    userID: handle,
    attestationType: 'none', // 인증기 증명서는 요구하지 않음(개인정보 최소화)
    authenticatorSelection: { residentKey: 'required', userVerification: 'required' },
    timeout: 120_000,
  });
  putChallenge(options.challenge, { type: 'register', username, handle: b64u(handle), label });
  audit({ event: 'register_options', ok: true, challenge: options.challenge, detail: username });
  res.json(options);
});

authRouter.post('/register/verify', rateLimit, async (req, res) => {
  const entry = takeChallenge(req.body, 'register');
  if (!entry) {
    audit({ event: 'register_verify', ok: false, detail: '챌린지 없음/만료/재사용' });
    return res.status(400).json({ error: 'challenge_invalid', message: '챌린지가 없거나 이미 사용·만료되었습니다.' });
  }
  try {
    const v = await verifyRegistrationResponse({
      response: req.body,
      expectedChallenge: entry.challenge,
      expectedOrigin: config.origin,
      expectedRPID: config.rpID,
      requireUserVerification: true,
    });
    if (!v.verified) throw new Error('not verified');
    const { credential, credentialDeviceType, credentialBackedUp, aaguid } = v.registrationInfo;
    if (users.byName(entry.username) || users.byCredentialId(credential.id)) throw new Error('이미 존재');

    const user = users.create({
      id: crypto.randomUUID(),
      username: entry.username,
      handle: entry.handle,
      createdAt: new Date().toISOString(),
      credentials: [{
        id: credential.id,
        publicKey: b64u(credential.publicKey), // 공개키만 저장
        counter: credential.counter,
        transports: credential.transports ?? [],
        label: entry.label,
        createdAt: new Date().toISOString(),
        deviceType: credentialDeviceType,
        backedUp: credentialBackedUp,
        aaguid,
      }],
      items: seedItems(users.count()),
    });
    const token = createSession(user.id);
    setSessionCookie(res, token);
    audit({ event: 'register_verify', ok: true, userId: user.id, challenge: entry.challenge, detail: `${entry.label} / ${credentialDeviceType}${credentialBackedUp ? ' / 백업됨' : ''}` });
    res.json({ verified: true, username: user.username });
  } catch (e) {
    audit({ event: 'register_verify', ok: false, challenge: entry.challenge, detail: String(e.message).slice(0, 120) });
    res.status(400).json({ error: 'verification_failed', message: '등록 검증에 실패했습니다.' });
  }
});

// ── 로그인 ─────────────────────────────────────────────────────────
// allowCredentials를 비워 두는 "사용자 이름 없는 로그인": 인증기가 이 사이트의 패스키를 골라 준다.
authRouter.post('/login/options', rateLimit, async (_req, res) => {
  const options = await generateAuthenticationOptions({
    rpID: config.rpID,
    userVerification: 'required',
    timeout: 120_000,
  });
  putChallenge(options.challenge, { type: 'login' });
  audit({ event: 'login_options', ok: true, challenge: options.challenge });
  res.json(options);
});

authRouter.post('/login/verify', rateLimit, async (req, res) => {
  const entry = takeChallenge(req.body, 'login');
  if (!entry) {
    audit({ event: 'login_verify', ok: false, detail: '챌린지 없음/만료/재사용' });
    return res.status(400).json({ error: 'challenge_invalid', message: '챌린지가 없거나 이미 사용·만료되었습니다.' });
  }
  const credId = typeof req.body?.id === 'string' ? req.body.id : '';
  const user = users.byCredentialId(credId);
  if (!user) {
    // 삭제된 패스키로 들어오려는 경우도 여기서 막힌다. (T08-C45)
    audit({ event: 'login_verify', ok: false, challenge: entry.challenge, detail: '서버에 없는 패스키(삭제됨/미등록)' });
    return res.status(401).json({ error: 'unknown_credential', message: '이 패스키로는 로그인할 수 없습니다.' });
  }
  const cred = user.credentials.find((c) => c.id === credId);
  try {
    const handleFromAuthenticator = req.body.response?.userHandle;
    if (handleFromAuthenticator && handleFromAuthenticator !== user.handle) throw new Error('userHandle 불일치');

    const v = await verifyAuthenticationResponse({
      response: req.body,
      expectedChallenge: entry.challenge,
      expectedOrigin: config.origin,
      expectedRPID: config.rpID,
      credential: { id: cred.id, publicKey: fromB64u(cred.publicKey), counter: cred.counter, transports: cred.transports },
      requireUserVerification: true,
    });
    if (!v.verified) throw new Error('not verified');

    cred.counter = v.authenticationInfo.newCounter;
    cred.lastUsedAt = new Date().toISOString();
    save();
    const token = createSession(user.id); // 항상 새 세션
    setSessionCookie(res, token);
    audit({ event: 'login_verify', ok: true, userId: user.id, challenge: entry.challenge, detail: `서명 검증 통과 (${cred.label})` });
    res.json({ verified: true, username: user.username });
  } catch (e) {
    audit({ event: 'login_verify', ok: false, userId: user.id, challenge: entry.challenge, detail: `서명 검증 실패: ${String(e.message).slice(0, 100)}` });
    res.status(401).json({ error: 'verification_failed', message: '서명 검증에 실패했습니다.' });
  }
});

authRouter.post('/logout', (req, res) => {
  const token = parseCookies(req.headers.cookie)[COOKIE_NAME];
  const session = readSession(token);
  destroySession(token); // 서버 쪽 세션을 지운다. 쿠키만 지우는 게 아니다. (T08-C33)
  clearSessionCookie(res);
  audit({ event: 'logout', ok: true, userId: session?.userId ?? null });
  res.json({ ok: true });
});

// ── 패스키 관리 (로그인 필요) ───────────────────────────────────────────
authRouter.get('/passkeys', requireAuth, (req, res) => {
  res.set('Cache-Control', 'no-store');
  res.json({ passkeys: req.user.credentials.map(publicCred) });
});

authRouter.post('/passkeys/options', requireAuth, async (req, res) => {
  const user = req.user;
  const label = normLabel(req.body?.label);
  const options = await generateRegistrationOptions({
    rpName: config.rpName,
    rpID: config.rpID,
    userName: user.username,
    userDisplayName: user.username,
    userID: fromB64u(user.handle),
    attestationType: 'none',
    // 이미 등록된 패스키를 제외 목록에 넣는다. 같은 인증기에 같은 계정의 패스키가 중복 생기지 않는다.
    // → 두 번째 패스키는 "다른" 인증기(다른 기기·보안 키·다른 비밀번호 관리자)에 만들어야 한다. (카드 4)
    excludeCredentials: user.credentials.map((c) => ({ id: c.id, transports: c.transports })),
    authenticatorSelection: { residentKey: 'required', userVerification: 'required' },
    timeout: 120_000,
  });
  putChallenge(options.challenge, { type: 'add', userId: user.id, label });
  audit({ event: 'passkey_add_options', ok: true, userId: user.id, challenge: options.challenge, detail: `excludeCredentials ${user.credentials.length}개` });
  res.json(options);
});

authRouter.post('/passkeys/verify', requireAuth, async (req, res) => {
  const user = req.user;
  const entry = takeChallenge(req.body, 'add');
  if (!entry || entry.userId !== user.id) { // 다른 계정이 받은 챌린지는 쓸 수 없다
    audit({ event: 'passkey_add_verify', ok: false, userId: user.id, detail: '챌린지 없음/만료/재사용/남의 것' });
    return res.status(400).json({ error: 'challenge_invalid', message: '챌린지가 유효하지 않습니다.' });
  }
  try {
    const v = await verifyRegistrationResponse({
      response: req.body,
      expectedChallenge: entry.challenge,
      expectedOrigin: config.origin,
      expectedRPID: config.rpID,
      requireUserVerification: true,
    });
    if (!v.verified) throw new Error('not verified');
    const { credential, credentialDeviceType, credentialBackedUp, aaguid } = v.registrationInfo;
    if (users.byCredentialId(credential.id)) throw new Error('이미 등록된 패스키');
    user.credentials.push({
      id: credential.id,
      publicKey: b64u(credential.publicKey),
      counter: credential.counter,
      transports: credential.transports ?? [],
      label: entry.label,
      createdAt: new Date().toISOString(),
      deviceType: credentialDeviceType,
      backedUp: credentialBackedUp,
      aaguid,
    });
    save();
    audit({ event: 'passkey_add_verify', ok: true, userId: user.id, challenge: entry.challenge, detail: `${entry.label} / ${credentialDeviceType}${credentialBackedUp ? ' / 백업됨' : ''}` });
    res.json({ verified: true });
  } catch (e) {
    audit({ event: 'passkey_add_verify', ok: false, userId: user.id, challenge: entry.challenge, detail: String(e.message).slice(0, 120) });
    res.status(400).json({ error: 'verification_failed', message: '등록 검증에 실패했습니다.' });
  }
});

authRouter.delete('/passkeys/:id', requireAuth, (req, res) => {
  const user = req.user;
  const idx = user.credentials.findIndex((c) => c.id === req.params.id); // 내 계정 안에서만 찾는다
  if (idx < 0) {
    audit({ event: 'passkey_delete', ok: false, userId: user.id, detail: '내 계정에 없는 패스키 id (남의 것 포함)' });
    return res.status(404).json({ error: 'not_found' });
  }
  if (user.credentials.length <= 1) {
    // 정책: 마지막 패스키는 지울 수 없다. 지우면 비밀번호도 복구 수단도 없어 계정에 영영 못 들어온다. (T08-C46)
    audit({ event: 'passkey_delete', ok: false, userId: user.id, detail: '마지막 패스키 삭제 거절' });
    return res.status(409).json({ error: 'last_passkey', message: '마지막 패스키는 삭제할 수 없습니다. 먼저 다른 패스키를 추가하세요.' });
  }
  const [removed] = user.credentials.splice(idx, 1);
  save();
  audit({ event: 'passkey_delete', ok: true, userId: user.id, detail: `${removed.label} 삭제` });
  res.json({ ok: true });
});
