// 로그아웃 전/후에 "같은 세션값"으로 비공개 자료를 다시 요청해 결과를 보여 준다. (T08-C33, C34)
// 세션값은 붙여 넣지 않는다. 크롬에서 값을 복사(Ctrl+C)만 해 두면 이 스크립트가 클립보드에서 직접 읽는다.
// 값은 화면에도, 출력에도 나오지 않는다.
//
//   [로그인한 상태]  1) 크롬 F12 → Application → Cookies → __Host-sid 의 Value 를 복사(Ctrl+C)
//                    2) node scripts/replay.mjs https://주소            → 200 이 나옴 (값은 임시 파일에 저장됨)
//   [로그아웃]       3) 사이트에서 로그아웃
//                    4) node scripts/replay.mjs https://주소 --again    → 같은 값으로 다시 요청 → 401 이 나옴 (임시 파일 삭제)
import { execFileSync } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';

const base = (process.argv[2] ?? '').replace(/\/$/, '');
const again = process.argv.includes('--again');
if (!/^https:\/\/|^http:\/\/localhost/.test(base)) { console.error('주소를 인자로 주세요'); process.exit(1); }

const tmp = path.join(os.tmpdir(), 'pk-replay.tmp');
let value;
if (again) {
  if (!fs.existsSync(tmp)) { console.error('저장된 값이 없습니다. 먼저 --again 없이 실행하세요.'); process.exit(1); }
  value = fs.readFileSync(tmp, 'utf8').trim();
  fs.rmSync(tmp, { force: true }); // 한 번 쓰고 지운다
} else {
  // 값만 복사했거나, 크롬 Network 탭의 "Copy as cURL" 텍스트 어느 쪽이든 된다.
  const clip = execFileSync('powershell', ['-NoProfile', '-Command', 'Get-Clipboard -Raw'], { encoding: 'utf8' });
  const found = clip.match(/(?:__Host-sid|(?<![\w-])sid)=([A-Za-z0-9_-]{20,150})/);
  value = found ? found[1] : /^[A-Za-z0-9_-]{20,100}$/.test(clip.trim()) ? clip.trim() : '';
  if (!value) {
    console.error('클립보드에서 세션값을 찾지 못했습니다. 크롬 Network 탭에서 요청을 우클릭 → Copy → Copy as cURL 로 복사한 뒤 다시 실행하세요.');
    process.exit(1);
  }
  fs.writeFileSync(tmp, value);
  execFileSync('powershell', ['-NoProfile', '-Command', 'Set-Clipboard -Value " "']); // 클립보드에서 지움
}

const name = base.startsWith('https://') ? '__Host-sid' : 'sid';
const res = await fetch(`${base}/api/private/items`, { headers: { Cookie: `${name}=${encodeURIComponent(value)}` } });
const text = await res.text();
let summary = text.slice(0, 120);
try {
  const j = JSON.parse(text);
  if (j.items) summary = `owner=${j.owner}, 항목 ${j.items.length}건`;
} catch { /* 그대로 */ }

console.log('');
console.log(`시각      : ${new Date().toLocaleString('ko-KR')}`);
console.log(`요청      : GET ${base}/api/private/items  (Cookie: ${name}=<가림>)`);
console.log(`응답 상태 : ${res.status}`);
console.log(`응답 요약 : ${summary}`);
console.log(again ? '(같은 세션값으로 로그아웃 후 다시 요청한 결과)' : '(로그인 상태에서 요청한 결과)');
