# 패스키(WebAuthn) 비공개 영역이 붙은 자기소개 페이지

공개 소개 페이지는 누구나 볼 수 있고, 비공개 영역은 패스키(비밀번호 없음)로만 열립니다.
비공개 영역의 내용은 모두 직접 만든 가상의 내용이며 실제 개인정보는 없습니다.

## 실행

```bash
npm install
npm start          # http://localhost:3000
npm run selftest   # 가짜 인증기로 차단 동작 검증
```

## 환경변수

| 이름 | 설명 |
|---|---|
| `ORIGIN` | 브라우저 주소창의 주소 (예: `https://example.onrender.com`) |
| `RP_ID` | 패스키가 묶이는 도메인 (ORIGIN의 호스트명) |
| `SETUP_CODE` | 계정 생성용 소유자 코드. 비어 있으면 계정 생성이 닫힘 |
| `DATA_FILE` | 데이터 파일 경로 (기본 `data/db.json`) |
| `MAX_ACCOUNTS` | 계정 수 한도 (기본 10) |

## 구조

- `src/auth.mjs` 등록·로그인·로그아웃·패스키 관리
- `src/private.mjs` 비공개 자료 API (로그인 필수)
- `src/sessions.mjs` 세션, 1회용 챌린지
- `public/` 소개 페이지와 비공개 영역 화면
