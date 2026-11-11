// 저장소: JSON 파일 하나. 서버에 남는 것은 "공개키와 공개 메타데이터"뿐이다.
// 개인키는 인증기(기기·보안 키·비밀번호 관리자) 밖으로 나오지 않으므로 여기에 있을 수 없다. (T08-C23)
// 비밀번호 필드도 없다. (T08-C35)
//
// 무료 호스팅은 재시작하면 디스크가 지워지는 경우가 많다. 영구 디스크가 있는 곳을 쓰거나
// DATA_FILE을 그 디스크 경로로 지정할 것.
import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import { config } from './config.mjs';

let db = { users: [], audit: [] };

export function load() {
  try {
    db = JSON.parse(fs.readFileSync(config.dataFile, 'utf8'));
  } catch {
    db = { users: [], audit: [] };
  }
}

export function save() {
  fs.mkdirSync(path.dirname(config.dataFile), { recursive: true });
  const tmp = config.dataFile + '.tmp';
  fs.writeFileSync(tmp, JSON.stringify(db, null, 2));
  fs.renameSync(tmp, config.dataFile); // 쓰다 죽어도 파일이 반쯤 깨지지 않게
}

export const users = {
  count: () => db.users.length,
  byName: (name) => db.users.find((u) => u.username === name),
  byId: (id) => db.users.find((u) => u.id === id),
  byCredentialId: (credId) => db.users.find((u) => u.credentials.some((c) => c.id === credId)),
  create(user) {
    db.users.push(user);
    save();
    return user;
  },
};

// ── 가상 비공개 데이터 ──────────────────────────────────────────────
// 실제 개인정보를 넣지 않는다. 전부 직접 만든 가상의 내용이다. (T08-C12)
// 계정마다 주제가 달라서 "남의 자료가 섞이지 않았다"는 것을 눈으로 확인할 수 있다. (T08-C36)
const SEED_THEMES = [
  [
    ['준비 중인 프로젝트 메모', '가상: 패스키 로그인 데모. 챌린지는 서버가 만들고 한 번만 쓴다.'],
    ['지원하려는 곳 목록', '가상: A사 보안 엔지니어, B사 인프라 인턴, C사 보안관제 신입.'],
    ['개인 회고', '가상: 이번 주는 인증 흐름을 그려 보며 서명 검증이 핵심임을 이해했다.'],
  ],
  [
    ['스터디 계획', '가상: 평일 저녁 1시간 네트워크 패킷 읽기, 주말 2시간 취약점 실습.'],
    ['읽을 문서 목록', '가상: WebAuthn 명세, OWASP 인증 치트시트, 세션 관리 가이드.'],
    ['이번 달 목표', '가상: 포트폴리오 비공개 영역 완성, 접근 차단 검증표 작성.'],
  ],
  [
    ['면접 질문 연습', '가상: 비밀번호 없이 로그인하는 원리를 한 문장으로 설명해 보기.'],
    ['도구 정리', '가상: Wireshark 필터 모음, 크롬 개발자 도구 WebAuthn 가상 인증기.'],
    ['메모', '가상: 패스키는 두 개 이상 등록해 두기. 하나를 잃어도 들어올 수 있어야 한다.'],
  ],
];

export function seedItems(nthAccount) {
  const theme = SEED_THEMES[nthAccount % SEED_THEMES.length];
  return theme.map(([title, body]) => ({
    id: crypto.randomUUID(),
    title,
    body,
    createdAt: new Date().toISOString(),
  }));
}

export { db };
