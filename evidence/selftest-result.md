# 자체 검증 결과 (소프트웨어 인증기 사용)

- 실행 시각: 2026-11-11T06:14:16.206Z
- 대상: 임시 서버 http://localhost:3397 (임시 데이터 파일, 종료 후 폐기)
- 결과: 32/32 통과
- ⚠ 가짜 인증기로 한 테스트입니다. 실제 기기·브라우저로 한 등록/로그인 증빙은 별도로 남겨야 합니다.

| 확인 | 누가 | 요청 | 세션값 | 응답 | 응답 요약 | 판정 | 메모 |
|---|---|---|---|---|---|---|---|
| 1. 로그인 없이 비공개 자료 요청 | 로그인 안 함 | `GET /api/private/items` | 없음 | 401 | `{"error":"unauthenticated","message":"패스키로 로그인해야 볼 수 있습니다."}` | 통과 |  |
| A. 설정 코드 없이 계정 만들기 요청(방문자) | 방문자 | `POST /api/register/options` | 없음 | 403 | `{"error":"bad_setup_code","message":"설정 코드가 맞지 않습니다."}` | 통과 |  |
| A. 틀린 설정 코드로 계정 만들기 요청(방문자) | 방문자 | `POST /api/register/options` | 없음 | 403 | `{"error":"bad_setup_code","message":"설정 코드가 맞지 않습니다."}` | 통과 |  |
| 2. 계정 A 패스키 등록 | alice-test | `POST /api/register/options → verify` | 없음 | 200 | `{"verified":true,"username":"alice-test"}` | 통과 | 챌린지 VJq1kdPn… |
| 2. 계정 B 패스키 등록 | bob-test | `POST /api/register/options → verify` | 없음 | 200 | `{"verified":true,"username":"bob-test"}` | 통과 | 챌린지 C2kPLgQd… |
| 2. 등록 챌린지는 요청마다 다름 | - | `A와 B 등록 챌린지 비교` | 없음 | 200 | `` | 통과 |  |
| 3. A의 비공개 자료 (3개 이상) | alice-test | `GET /api/private/items` | <세션값 가림> | 200 | `{"owner":"alice-test","items":[{"id":"1a69d11c-0acb-48f5-8edb-95179a6672c2","title":"준비 중인` | 통과 | 3건 |
| 3. B의 비공개 자료 (A와 다름) | bob-test | `GET /api/private/items` | <세션값 가림> | 200 | `{"owner":"bob-test","items":[{"id":"99252346-6f26-4da2-b731-ae11c3ebf3bc","title":"스터디 계획"` | 통과 | 3건, 제목 상이: true |
| 4. 로그인 없이 받은 페이지 소스에 비공개 내용 없음 | 로그인 안 함 | `GET /` | 없음 | 200 | `` | 통과 | 소스 길이 33052자 |
| 5. A가 B의 항목 id로 직접 요청 | alice-test | `GET /api/private/items/<B의 항목>` | <세션값 가림> | 403 | `{"error":"forbidden","message":"다른 계정의 자료입니다."}` | 통과 |  |
| 5. B가 A의 항목 id로 직접 요청 (반대 방향) | bob-test | `GET /api/private/items/<A의 항목>` | <세션값 가림> | 403 | `{"error":"forbidden","message":"다른 계정의 자료입니다."}` | 통과 |  |
| 5. 주소에 다른 계정을 적어도 내 자료만 옴 | alice-test | `GET /api/private/items?owner=bob-test` | <세션값 가림> | 200 | `{"owner":"alice-test","items":[{"id":"1a69d11c-0acb-48f5-8edb-95179a6672c2","title":"준비 중인` | 통과 | 응답 owner=alice-test |
| 5. 본문에 다른 계정을 적어 보낸 저장 요청 | alice-test | `POST /api/private/items {owner:"bob-test"}` | <세션값 가림> | 201 | `{"id":"bce22e50-ce8f-4a37-a911-1cea30370cf2","title":"메모","body":"x","createdAt":"2026-11-` | 통과 | B 항목 수 변화 없음: true |
| 6. A 로그인 (서명 검증 통과) | alice-test | `POST /api/login/options → verify` | 없음 | 200 | `{"verified":true,"username":"alice-test"}` | 통과 | 챌린지 wr4hJXY-… |
| 6. 로그인 챌린지는 매번 다름 | - | `직전 로그인과 챌린지 비교` | 없음 | 200 | `` | 통과 | wr4hJXY-… ≠ heb8wUui… |
| 6. 이미 사용한 챌린지/응답 재사용 | - | `POST /api/login/verify (재전송)` | 없음 | 400 | `{"error":"challenge_invalid","message":"챌린지가 없거나 이미 사용·만료되었습니다."}` | 통과 |  |
| 7. 일부러 틀린 서명 전송 | - | `POST /api/login/verify (서명 변조)` | 없음 | 401 | `{"error":"verification_failed","message":"서명 검증에 실패했습니다."}` | 통과 |  |
| 7. 다른 사이트(origin)에서 만든 응답 전송 | - | `POST /api/login/verify (origin 변조)` | 없음 | 401 | `{"error":"verification_failed","message":"서명 검증에 실패했습니다."}` | 통과 |  |
| 7. 서버가 발급하지 않은 챌린지 | - | `POST /api/login/verify (임의 챌린지)` | 없음 | 400 | `{"error":"challenge_invalid","message":"챌린지가 없거나 이미 사용·만료되었습니다."}` | 통과 |  |
| 8. 패스키 추가 옵션에 기존 패스키가 제외 목록으로 포함 | alice-test | `POST /api/passkeys/options` | <세션값 가림> | 200 | `{"challenge":"gqLzFNVodCO9UEuwc_UtOUbBsjhdnGRlZVHrhUzQSlo","rp":{"name":"김도연 포트폴리오","id":"` | 통과 | excludeCredentials 1개 |
| 8. 같은 인증기로 두 번째 등록 시도 → 브라우저가 거절(InvalidStateError) | alice-test | `(인증기 단계에서 거절)` | 없음 | 200 | `` | 통과 | InvalidStateError |
| 8. 다른 인증기로 두 번째 패스키 등록 | alice-test | `POST /api/passkeys/verify` | <세션값 가림> | 200 | `{"verified":true}` | 통과 |  |
| 8. 패스키 목록에 두 개 | alice-test | `GET /api/passkeys` | <세션값 가림> | 200 | `{"passkeys":[{"id":"5u-Q6HxEykmREpFKHIO3wllrTDI1YaDFMbYEjyeT62s","label":"A의 첫 패스키","creat` | 통과 | A의 첫 패스키, A의 두번째 |
| 9. B가 A의 패스키 삭제 시도 | bob-test | `DELETE /api/passkeys/<A의 패스키>` | <세션값 가림> | 404 | `{"error":"not_found"}` | 통과 |  |
| 10. A가 첫 패스키 삭제 | alice-test | `DELETE /api/passkeys/<첫 패스키>` | <세션값 가림> | 200 | `{"ok":true}` | 통과 |  |
| 10. 삭제한 패스키로 로그인 → 거절 | - | `POST /api/login/verify (삭제된 패스키)` | 없음 | 401 | `{"error":"unknown_credential","message":"이 패스키로는 로그인할 수 없습니다."}` | 통과 |  |
| 10. 남은 패스키로 로그인 → 성공 | alice-test | `POST /api/login/verify (남은 패스키)` | 없음 | 200 | `{"verified":true,"username":"alice-test"}` | 통과 |  |
| 11. 마지막 패스키 삭제 시도 → 거절(정책) | alice-test | `DELETE /api/passkeys/<마지막>` | <세션값 가림> | 409 | `{"error":"last_passkey","message":"마지막 패스키는 삭제할 수 없습니다. 먼저 다른 패스키를 추가하세요."}` | 통과 |  |
| 12. 로그아웃 전: 같은 세션값으로 조회 | alice-test | `GET /api/private/items` | <세션값 가림> | 200 | `{"owner":"alice-test","items":[{"id":"1a69d11c-0acb-48f5-8edb-95179a6672c2","title":"준비 중인` | 통과 |  |
| 12. 로그아웃 후: 같은 세션값으로 다시 요청 → 거절 | alice-test | `POST /api/logout 뒤 GET /api/private/items` | <세션값 가림> | 401 | `{"error":"unauthenticated","message":"패스키로 로그인해야 볼 수 있습니다."}` | 통과 |  |
| 13. 다른 사이트에서 온 변경 요청 | - | `POST /api/logout (Origin: evil)` | 없음 | 403 | `{"error":"bad_origin"}` | 통과 |  |
| 14. 서버 저장소에 개인키·비밀번호·세션값 없음 | - | `data 파일 검사` | 없음 | 200 | `` | 통과 | 저장된 것: 공개키·자격 증명 ID·메타데이터 |
