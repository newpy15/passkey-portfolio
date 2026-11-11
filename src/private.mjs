// 비공개 영역 API. 이 파일의 모든 라우트는 requireAuth(로그인 확인)를 통과해야만 실행된다.
// 비공개 내용은 HTML 소스에 들어 있지 않고, 인증된 요청의 JSON 응답으로만 내려간다. (T08-C15, C18)
import crypto from 'node:crypto';
import { Router } from 'express';
import { db, save } from './store.mjs';
import { requireAuth } from './auth.mjs';
import { audit, auditFor } from './audit.mjs';

export const privateRouter = Router();

// 로그아웃 뒤 "뒤로 가기"로 캐시된 비공개 응답이 다시 보이지 않게 한다.
privateRouter.use((_req, res, next) => {
  res.set('Cache-Control', 'no-store');
  next();
});
privateRouter.use(requireAuth);

privateRouter.get('/items', (req, res) => {
  // 쿼리(?owner=...)나 본문에 다른 계정을 적어도 무시한다. 소유자는 오직 세션에서 나온 req.user. (T08-C40)
  res.json({ owner: req.user.username, items: req.user.items });
});

// 항목 id로 직접 접근하는 경로. 남의 항목 id를 알아내 요청해도 막혀야 한다. (T08-C37, C38)
privateRouter.get('/items/:id', (req, res) => {
  const mine = req.user.items.find((i) => i.id === req.params.id);
  if (mine) return res.json(mine);
  const existsElsewhere = db.users.some((u) => u.items.some((i) => i.id === req.params.id));
  audit({ event: 'private_item_read', ok: false, userId: req.user.id, detail: existsElsewhere ? '다른 계정의 항목 요청 → 403' : '없는 항목 → 404' });
  if (existsElsewhere) return res.status(403).json({ error: 'forbidden', message: '다른 계정의 자료입니다.' });
  res.status(404).json({ error: 'not_found' });
});

privateRouter.post('/items', (req, res) => {
  const title = typeof req.body?.title === 'string' ? req.body.title.trim() : '';
  const body = typeof req.body?.body === 'string' ? req.body.body.trim() : '';
  if (!title || title.length > 80 || body.length > 500) {
    return res.status(400).json({ error: 'bad_input', message: '제목은 1~80자, 내용은 500자 이하입니다.' });
  }
  if (req.user.items.length >= 30) return res.status(400).json({ error: 'limit', message: '항목은 최대 30개입니다.' });
  const item = { id: crypto.randomUUID(), title, body, createdAt: new Date().toISOString() };
  req.user.items.push(item); // 저장 대상은 항상 req.user
  save();
  res.status(201).json(item);
});

privateRouter.delete('/items/:id', (req, res) => {
  const idx = req.user.items.findIndex((i) => i.id === req.params.id);
  if (idx < 0) return res.status(404).json({ error: 'not_found' });
  req.user.items.splice(idx, 1);
  save();
  res.json({ ok: true });
});

privateRouter.get('/activity', (req, res) => {
  res.json({ events: auditFor(req.user.id) });
});
