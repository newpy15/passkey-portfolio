// 설정 한 곳에 모음. 배포할 때는 환경변수만 바꾸면 된다.
//   ORIGIN  : 브라우저 주소창에 보이는 주소 (예: https://my-portfolio.onrender.com)
//   RP_ID   : 패스키가 묶이는 도메인. 보통 ORIGIN의 호스트명과 같다 (포트·https 제외)
// 주의: 한 번 등록한 패스키는 RP_ID가 바뀌면 쓸 수 없다. 주소를 확정한 뒤에 등록할 것.
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const port = Number(process.env.PORT ?? 3000);
const origin = process.env.ORIGIN ?? `http://localhost:${port}`;

export const config = {
  root,
  port,
  origin,
  rpID: process.env.RP_ID ?? new URL(origin).hostname,
  rpName: '김도연 포트폴리오',
  dataFile: process.env.DATA_FILE ?? path.join(root, 'data', 'db.json'),
  // 계정 생성에 필요한 소유자 전용 코드. 비어 있으면 계정 생성이 완전히 닫힌다(기본값).
  // 방문자가 계정을 만들 수 없게 하는 장치다. 값은 코드에 쓰지 말고 환경변수로만 넣을 것.
  setupCode: process.env.SETUP_CODE ?? '',
  maxAccounts: Number(process.env.MAX_ACCOUNTS ?? 10), // 공개 서버에 계정이 무한정 쌓이지 않게
  secureCookie: origin.startsWith('https://'),
  sessionTtlMs: 8 * 60 * 60 * 1000,
  challengeTtlMs: 3 * 60 * 1000,
};
