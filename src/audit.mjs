// 감사 기록: 성공과 실패를 나란히 남긴다. (T08-C30, C45, C47~)
// 지켜야 할 것: 세션 토큰·쿠키·서명·공개키 전체값은 절대 적지 않는다. (T08-C34)
// 챌린지도 앞 8글자만 적는다. "요청마다 값이 다르다"는 것만 보이면 충분하다.
import { db, save } from './store.mjs';

export function audit({ event, ok, userId = null, challenge = null, detail = '' }) {
  const entry = {
    t: new Date().toISOString(),
    event,
    ok,
    userId,
    challenge: challenge ? challenge.slice(0, 8) + '…' : null,
    detail,
  };
  db.audit.push(entry);
  if (db.audit.length > 1000) db.audit.splice(0, db.audit.length - 1000);
  save();
  console.log(`[audit] ${entry.ok ? 'OK ' : 'DENY'} ${entry.event}${entry.detail ? ' - ' + entry.detail : ''}`);
}

export const auditFor = (userId) => db.audit.filter((e) => e.userId === userId).slice(-50).reverse();
