// 교차 접근 확인: "내 세션으로 남의 자료를 요청하면 거절되는가" (T08-C37 ~ C40)
// 계정마다 한 번씩, 그 계정으로 로그인한 상태에서 실행한다. 세션값은 크롬에서 복사(Ctrl+C)만 해 두면
// 이 스크립트가 클립보드에서 읽는다. 세션값은 저장하지도, 출력하지도 않는다. 저장하는 것은 항목 id뿐이다.
//
//   1) 계정 X로 로그인 → 쿠키 복사 → node scripts/cross-check.mjs https://주소      (X의 항목 id 저장)
//   2) 계정 Y로 로그인 → 쿠키 복사 → node scripts/cross-check.mjs https://주소      (Y가 X의 자료를 요청 → 403)
//   3) 계정 X로 다시 로그인 → 쿠키 복사 → 같은 명령                                  (X가 Y의 자료를 요청 → 403, 반대 방향)
import { execFileSync } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';

const base = (process.argv[2] ?? '').replace(/\/$/, '');
if (!/^https:\/\/|^http:\/\/localhost/.test(base)) { console.error('주소를 인자로 주세요'); process.exit(1); }
const name = base.startsWith('https://') ? '__Host-sid' : 'sid';

// 클립보드에서 세션값 추출: 값만 복사했거나, 크롬 Network 탭의 "Copy as cURL" 텍스트 어느 쪽이든 된다.
const clip = execFileSync('powershell', ['-NoProfile', '-Command', 'Get-Clipboard -Raw'], { encoding: 'utf8' });
const found = clip.match(/(?:__Host-sid|(?<![\w-])sid)=([A-Za-z0-9_-]{20,150})/);
const value = found ? found[1] : /^[A-Za-z0-9_-]{20,100}$/.test(clip.trim()) ? clip.trim() : '';
if (!value) {
  console.error('클립보드에서 세션값을 찾지 못했습니다. 크롬 Network 탭에서 요청을 우클릭 → Copy → Copy as cURL 로 복사한 뒤 다시 실행하세요.');
  process.exit(1);
}
execFileSync('powershell', ['-NoProfile', '-Command', 'Set-Clipboard -Value " "']); // 클립보드에서 지움

const get = (url) => fetch(base + url, { headers: { Cookie: `${name}=${encodeURIComponent(value)}` } });
const stateFile = path.join(os.tmpdir(), 'pk-cross.json');
const state = fs.existsSync(stateFile) ? JSON.parse(fs.readFileSync(stateFile, 'utf8')) : {};

const me = await get('/api/private/items');
if (me.status !== 200) { console.error(`내 자료를 가져오지 못했습니다 (상태 ${me.status}). 로그인 상태에서 복사한 값인지 확인하세요.`); process.exit(1); }
const mine = await me.json();
state[mine.owner] = mine.items.map((i) => i.id); // 항목 id만 저장 (세션값은 저장 안 함)
fs.writeFileSync(stateFile, JSON.stringify(state));

console.log('');
console.log(`시각          : ${new Date().toLocaleString('ko-KR')}`);
console.log(`로그인한 계정 : ${mine.owner}  (자료 ${mine.items.length}건)`);

const others = Object.keys(state).filter((o) => o !== mine.owner);
if (others.length === 0) {
  console.log('');
  console.log('저장했습니다. 이제 사이트에서 다른 계정으로 로그인한 뒤, 그 계정의 쿠키를 복사하고 같은 명령을 다시 실행하세요.');
  process.exit(0);
}

for (const other of others) {
  const victimId = state[other][0];
  const before = mine.items.length;
  const r = await get(`/api/private/items/${victimId}`);
  const body = (await r.text()).replace(/\s+/g, ' ');
  const after = (await (await get('/api/private/items')).json()).items.length;
  const q = await (await get(`/api/private/items?owner=${encodeURIComponent(other)}`)).json();

  console.log('');
  console.log(`── ${mine.owner} 가 ${other} 의 자료를 요청 ──`);
  console.log(`요청          : GET /api/private/items/${victimId.slice(0, 8)}…  (${other} 의 항목 id, Cookie: ${name}=<가림>)`);
  console.log(`응답 상태     : ${r.status}`);
  console.log(`응답 본문     : ${body.slice(0, 120)}`);
  console.log(`내 자료 건수  : 요청 전 ${before}건 → 요청 후 ${after}건 ${before === after ? '(변화 없음)' : '(**변함**)'}`);
  console.log(`주소에 상대 계정 적기 : GET /api/private/items?owner=${other}`);
  console.log(`  → 응답의 owner = ${q.owner} ${q.owner === mine.owner ? '(내 자료만 옴)' : '(**남의 자료가 옴**)'}`);
  console.log(`판정          : ${r.status === 403 && before === after && q.owner === mine.owner ? '통과' : '**실패**'}`);
}
