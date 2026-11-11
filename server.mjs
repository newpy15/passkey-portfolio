import path from 'node:path';
import express from 'express';
import { config } from './src/config.mjs';
import { load } from './src/store.mjs';
import { authRouter } from './src/auth.mjs';
import { privateRouter } from './src/private.mjs';

load();
const app = express();
app.disable('x-powered-by');
app.set('trust proxy', 1); // Render·Fly 같은 호스팅은 프록시 뒤에 있다(req.ip, https 판단용)

// 보안 헤더. CSP는 기존 소개 페이지가 쓰는 CDN(Pretendard, Lucide)만 허용한다.
// 개선 여지: 인라인 스크립트·스타일을 파일로 빼면 'unsafe-inline'을 없앨 수 있다.
app.use((_req, res, next) => {
  res.set({
    'X-Content-Type-Options': 'nosniff',
    'X-Frame-Options': 'DENY',
    'Referrer-Policy': 'strict-origin-when-cross-origin',
    'Content-Security-Policy': [
      "default-src 'self'",
      "script-src 'self' 'unsafe-inline' https://unpkg.com",
      "style-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net",
      'font-src https://cdn.jsdelivr.net',
      "img-src 'self' data:",
      "connect-src 'self' https://cdn.jsdelivr.net https://unpkg.com", // 개발자 도구가 받는 소스맵(.map) 요청 허용
      "frame-ancestors 'none'",
      "base-uri 'none'",
      "form-action 'self'",
    ].join('; '),
  });
  next();
});

app.use(express.json({ limit: '100kb' }));

// CSRF 방어(쿠키 SameSite=Lax에 더해): 브라우저가 보낸 변경 요청의 Origin이 우리 주소가 아니면 거절.
app.use('/api', (req, res, next) => {
  if (req.method !== 'GET' && req.headers.origin && req.headers.origin !== config.origin) {
    return res.status(403).json({ error: 'bad_origin' });
  }
  next();
});

app.use('/api/private', privateRouter);
app.use('/api', authRouter);
app.use('/api', (_req, res) => res.status(404).json({ error: 'not_found' }));

// 공개 영역: 소개 페이지. 로그인 없이 누구나. 비공개 내용은 이 폴더 어디에도 없다.
app.use(express.static(path.join(config.root, 'public')));

app.listen(config.port, () => {
  console.log(`listening on ${config.origin}  (rpID=${config.rpID})`);
});
