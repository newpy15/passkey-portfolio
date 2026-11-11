// 세션과 챌린지. 둘 다 "서버가 만들고, 서버가 보관하고, 서버가 검증한다."
import crypto from 'node:crypto';
import { config } from './config.mjs';

const sha256 = (s) => crypto.createHash('sha256').update(s).digest('hex');

// ── 세션 ───────────────────────────────────────────────────────────
// 쿠키에는 무작위 토큰만 담고, 서버에는 그 해시만 보관한다.
// 로그인할 때마다 새 토큰을 발급(세션 고정 공격 방지), 로그아웃하면 서버에서 지운다. (T08-C33)
const sessions = new Map(); // tokenHash -> { userId, exp }

export const COOKIE_NAME = config.secureCookie ? '__Host-sid' : 'sid';

export function createSession(userId) {
  const token = crypto.randomBytes(32).toString('base64url');
  sessions.set(sha256(token), { userId, exp: Date.now() + config.sessionTtlMs });
  return token;
}

export function readSession(token) {
  if (!token) return null;
  const key = sha256(token);
  const s = sessions.get(key);
  if (!s) return null;
  if (s.exp < Date.now()) {
    sessions.delete(key);
    return null;
  }
  return s;
}

export function destroySession(token) {
  if (token) sessions.delete(sha256(token));
}

export function parseCookies(header = '') {
  const out = {};
  for (const part of header.split(';')) {
    const i = part.indexOf('=');
    if (i > 0) out[part.slice(0, i).trim()] = decodeURIComponent(part.slice(i + 1).trim());
  }
  return out;
}

export function setSessionCookie(res, token) {
  res.cookie(COOKIE_NAME, token, {
    httpOnly: true, // 스크립트가 읽을 수 없음
    sameSite: 'lax',
    secure: config.secureCookie, // https에서만 전송
    path: '/',
    maxAge: config.sessionTtlMs,
  });
}

export function clearSessionCookie(res) {
  res.clearCookie(COOKIE_NAME, {
    httpOnly: true,
    sameSite: 'lax',
    secure: config.secureCookie,
    path: '/',
  });
}

// ── 챌린지 ─────────────────────────────────────────────────────────
// 서버가 매번 새로 만들고(T08-C19, C27), 검증이 끝날 때까지 서버에 보관한다.
// "한 번 쓰면 끝": 검증 성공·실패와 관계없이 꺼내는 순간 지운다. (T08-C31)
const challenges = new Map(); // challenge -> { type, exp, ...context }

export function putChallenge(challenge, context) {
  challenges.set(challenge, { ...context, exp: Date.now() + config.challengeTtlMs });
}

// 클라이언트가 보낸 응답 안의 clientDataJSON에서 챌린지를 꺼내, 서버가 발급한 것인지 확인한다.
export function takeChallenge(webauthnResponse, expectedType) {
  let challenge;
  try {
    const json = Buffer.from(webauthnResponse.response.clientDataJSON, 'base64url').toString('utf8');
    challenge = JSON.parse(json).challenge;
  } catch {
    return null;
  }
  if (typeof challenge !== 'string') return null;
  const entry = challenges.get(challenge);
  challenges.delete(challenge); // 성공이든 실패든 소각
  if (!entry || entry.exp < Date.now() || entry.type !== expectedType) return null;
  return { challenge, ...entry };
}

setInterval(() => {
  const now = Date.now();
  for (const [k, v] of challenges) if (v.exp < now) challenges.delete(k);
  for (const [k, v] of sessions) if (v.exp < now) sessions.delete(k);
}, 60_000).unref();
