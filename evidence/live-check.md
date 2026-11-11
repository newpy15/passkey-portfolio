# 배포 서버 직접 확인 기록 (로그인 없이 보낸 요청)

- 대상: https://passkey-portfolio-6o03.onrender.com
- 실행 시각: 2026-11-11T05:31:18.563Z
- 이 파일에는 쿠키·세션값·설정 코드가 들어 있지 않습니다.

### 1. 로그인 없이 비공개 자료 요청 (T08-C16, C17)

- 요청: `GET /api/private/items (쿠키 없음)`
- 응답 상태: **401**
- Cache-Control: `no-store`
- 응답 본문: `{"error":"unauthenticated","message":"패스키로 로그인해야 볼 수 있습니다."}`
- 확인: 401로 거절됨

### 2. 임의의 값을 세션처럼 보낸 요청

- 요청: `GET /api/private/items (가짜 쿠키값)`
- 응답 상태: **401**
- Cache-Control: `no-store`
- 응답 본문: `{"error":"unauthenticated","message":"패스키로 로그인해야 볼 수 있습니다."}`
- 확인: 서버가 모르는 세션값은 거절됨

### 3. 로그인 없이 항목 id 직접 요청

- 요청: `GET /api/private/items/<임의 id>`
- 응답 상태: **401**
- Cache-Control: `no-store`
- 응답 본문: `{"error":"unauthenticated","message":"패스키로 로그인해야 볼 수 있습니다."}`
- 확인: 로그인 확인이 id 조회보다 먼저 이뤄짐

### 4. 로그인 상태 확인

- 요청: `GET /api/session`
- 응답 상태: **200**
- Cache-Control: `no-store`
- 응답 본문: `{"authenticated":false}`

- 로그인 요청 1회차: 상태 200, challenge = `79Yi-5UfzNp9vUzCdR11Aou73mcPTJ4N70PIk1tVFSI`
- 로그인 요청 2회차: 상태 200, challenge = `pZpdhIIW-YKz0j2JkO3W-6F9qvXu9GkOXczZlh0bxVo`
- 로그인 요청 3회차: 상태 200, challenge = `CetnL58R5dGIMiRln6dRAyi7JPA_BEPkS3tjheEoR8k`

### 5. 로그인 챌린지는 요청마다 다름 (T08-C27, C28)

- 세 값이 모두 다른가: **예**
- 길이: 32, 32, 32 바이트 (서버가 만든 무작위 값)

### 6. 방문자가 설정 코드 없이 계정 만들기 요청

- 요청: `POST /api/register/options {username}`
- 응답 상태: **403**
- 응답 본문: `{"error":"bad_setup_code","message":"설정 코드가 맞지 않습니다."}`
- 확인: 403으로 거절됨. 방문자는 계정을 만들 수 없음

### 7. 다른 사이트에서 온 변경 요청

- 요청: `POST /api/logout (Origin: https://evil.example)`
- 응답 상태: **403**
- 응답 본문: `{"error":"bad_origin"}`
- 확인: 403으로 거절됨
