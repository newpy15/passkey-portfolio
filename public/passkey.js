// 비공개 영역 UI + WebAuthn 호출. 외부 라이브러리 없이 브라우저 표준 API(navigator.credentials)만 쓴다.
// 사용자·서버 데이터는 전부 textContent로만 넣는다(innerHTML 금지) → XSS 방지.
(() => {
  const dialog = document.getElementById('pk-dialog');
  const body = document.getElementById('pk-body');
  const titleText = document.getElementById('pk-title-text');
  const openBtn = document.getElementById('pk-open');
  const openLabel = document.getElementById('pk-open-label');
  let state = { authenticated: false, username: null };

  // ── 작은 도우미 ──────────────────────────────────────────────────
  const el = (tag, props = {}, ...kids) => {
    const n = document.createElement(tag);
    for (const [k, v] of Object.entries(props)) {
      if (v == null) continue; // null/undefined 속성은 달지 않는다
      if (k === 'class') n.className = v;
      else if (k.startsWith('on')) n.addEventListener(k.slice(2), v);
      else n.setAttribute(k, v);
    }
    for (const k of kids.flat()) if (k != null) n.append(k.nodeType ? k : document.createTextNode(String(k)));
    return n;
  };
  const toBuf = (s) => {
    const b = atob(s.replace(/-/g, '+').replace(/_/g, '/').padEnd(Math.ceil(s.length / 4) * 4, '='));
    return Uint8Array.from(b, (c) => c.charCodeAt(0)).buffer;
  };
  const toB64u = (buf) => btoa(String.fromCharCode(...new Uint8Array(buf))).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');

  async function api(method, url, data) {
    const res = await fetch(url, {
      method,
      credentials: 'same-origin',
      headers: data ? { 'Content-Type': 'application/json' } : {},
      body: data ? JSON.stringify(data) : undefined,
    });
    let json = null;
    try { json = await res.json(); } catch { /* 본문 없음 */ }
    return { ok: res.ok, status: res.status, json };
  }

  // ── 브라우저 ↔ 서버 JSON 변환 ─────────────────────────────────────
  const creationOptions = (o) => ({
    ...o,
    challenge: toBuf(o.challenge),
    user: { ...o.user, id: toBuf(o.user.id) },
    excludeCredentials: (o.excludeCredentials ?? []).map((c) => ({ ...c, id: toBuf(c.id) })),
  });
  const requestOptions = (o) => ({
    ...o,
    challenge: toBuf(o.challenge),
    allowCredentials: (o.allowCredentials ?? []).map((c) => ({ ...c, id: toBuf(c.id) })),
  });
  const attestationJSON = (c) => ({
    id: c.id, rawId: toB64u(c.rawId), type: c.type,
    clientExtensionResults: c.getClientExtensionResults(),
    authenticatorAttachment: c.authenticatorAttachment ?? undefined,
    response: {
      clientDataJSON: toB64u(c.response.clientDataJSON),
      attestationObject: toB64u(c.response.attestationObject),
      transports: c.response.getTransports?.() ?? [],
    },
  });
  const assertionJSON = (c) => ({
    id: c.id, rawId: toB64u(c.rawId), type: c.type,
    clientExtensionResults: c.getClientExtensionResults(),
    authenticatorAttachment: c.authenticatorAttachment ?? undefined,
    response: {
      clientDataJSON: toB64u(c.response.clientDataJSON),
      authenticatorData: toB64u(c.response.authenticatorData),
      signature: toB64u(c.response.signature),
      userHandle: c.response.userHandle ? toB64u(c.response.userHandle) : undefined,
    },
  });

  // 사람이 알아볼 수 있는 오류 문구. (T08-C25: 취소하면 안내가 나오고 서버에는 아무것도 저장되지 않는다)
  function explain(e) {
    switch (e?.name) {
      case 'NotAllowedError': return '취소했거나 시간이 지났습니다. 서버에는 아무것도 저장되지 않았습니다.';
      case 'InvalidStateError': return '이 인증기(기기·보안 키·비밀번호 관리자)에는 이 계정의 패스키가 이미 있습니다. 다른 인증기로 등록해 보세요.';
      case 'NotSupportedError': return '이 브라우저나 기기는 패스키를 지원하지 않습니다.';
      case 'SecurityError': return '이 주소에서는 패스키를 쓸 수 없습니다. https 주소(개발 중에는 localhost)에서 열어야 합니다.';
      case 'AbortError': return '요청이 중단되었습니다.';
      default: return e?.message ? `오류: ${e.message}` : '알 수 없는 오류가 발생했습니다.';
    }
  }

  function supported() {
    return window.isSecureContext && !!window.PublicKeyCredential && !!navigator.credentials;
  }

  // ── 화면 ────────────────────────────────────────────────────────
  function statusBox() {
    const box = el('div', { class: 'pk-status', role: 'status', 'aria-live': 'polite' });
    box.show = (kind, text) => {
      box.className = `pk-status ${kind}`;
      box.textContent = text;
      box.scrollIntoView({ block: 'nearest' }); // 아래로 스크롤한 상태에서도 안내가 눈에 보이게
    };
    return box;
  }

  function renderLoggedOut() {
    titleText.textContent = '비공개 영역 — 패스키 필요';
    openLabel.textContent = '패스키로 열기';
    const status = statusBox();
    const nameInput = el('input', { class: 'pk-input', id: 'pk-username', type: 'text', autocomplete: 'username webauthn', placeholder: '예: my-name (영문 소문자·숫자 3~20자)', 'aria-label': '새 계정 이름' });
    const labelInput = el('input', { class: 'pk-input', id: 'pk-label', type: 'text', maxlength: '30', placeholder: '이 패스키의 이름 (예: 노트북 Windows Hello)', 'aria-label': '패스키 이름' });

    const loginBtn = el('button', { class: 'pk-btn', type: 'button', onclick: () => run(loginBtn, status, doLogin) }, '패스키로 로그인');
    const codeInput = el('input', { class: 'pk-input', id: 'pk-code', type: 'password', autocomplete: 'off', 'aria-label': '설정 코드' });
    const regBtn = el('button', { class: 'pk-btn', type: 'button', onclick: () => run(regBtn, status, () => doRegister(nameInput.value, labelInput.value, codeInput.value)) }, '새 계정 만들고 패스키 등록');

    // 계정 만들기는 소유자 전용. 주소 끝에 #setup 이 있을 때만 폼을 그린다(서버도 설정 코드 없이는 거절).
    const ownerSetup = location.hash === '#setup'
      ? el('section', {}, el('h3', {}, '소유자 설정'),
          // 입력칸을 form 안에 두어 "비밀번호 칸이 form 밖에 있다"는 브라우저 경고를 없앤다. 전송은 하지 않는다.
          el('form', { autocomplete: 'off', onsubmit: (e) => e.preventDefault() },
            el('div', { class: 'pk-row' }, el('label', { for: 'pk-username', class: 'pk-note' }, '계정 이름'), nameInput),
            el('div', { class: 'pk-row', style: 'margin-top:8px' }, el('label', { for: 'pk-label', class: 'pk-note' }, '패스키 이름'), labelInput),
            el('div', { class: 'pk-row', style: 'margin-top:8px' }, el('label', { for: 'pk-code', class: 'pk-note' }, '설정 코드(계정 생성용, 로그인 비밀번호 아님)'), codeInput),
            el('div', { class: 'pk-row', style: 'margin-top:8px' }, regBtn)))
      : null;

    body.replaceChildren(
      el('p', { class: 'pk-note' }, '비밀번호를 쓰지 않습니다. 이 기기(또는 휴대폰·보안 키·비밀번호 관리자)가 만든 패스키로 본인임을 확인합니다. 패스키가 없으면 이 영역의 내용은 화면에도, 페이지 소스에도 나타나지 않습니다.'),
      ...(supported() ? [] : [el('div', { class: 'pk-status err' }, '이 환경에서는 패스키를 쓸 수 없습니다. https 주소(개발 중에는 localhost)에서 패스키를 지원하는 브라우저로 열어 주세요.')]),
      status,
      el('section', {}, el('h3', {}, '패스키로 로그인'), el('p', { class: 'pk-note' }, '이 사이트에 등록한 패스키를 선택해 로그인합니다. 이 영역은 소유자 전용이며, 방문자는 계정을 만들 수 없습니다.'), el('div', { class: 'pk-row', style: 'margin-top:8px' }, loginBtn)),
      ...(ownerSetup ? [ownerSetup] : []),
    );
  }

  async function renderLoggedIn(flash) {
    titleText.textContent = `${state.username}의 비공개 영역`;
    openLabel.textContent = '비공개 영역 보기';
    const status = statusBox();
    if (flash) status.show(flash.kind, flash.text);

    const [items, keys, act] = await Promise.all([
      api('GET', '/api/private/items'), api('GET', '/api/passkeys'), api('GET', '/api/private/activity'),
    ]);
    if (items.status === 401) return refresh(); // 세션이 끝났으면 로그인 화면으로

    const itemList = el('ul', { class: 'pk-list' }, items.json.items.map((i) =>
      el('li', {}, el('div', {}, el('div', { class: 'pk-title' }, i.title), el('div', { class: 'pk-meta' }, i.body)),
        el('button', { class: 'pk-btn danger', type: 'button', 'aria-label': `${i.title} 삭제`, onclick: async () => { await api('DELETE', `/api/private/items/${i.id}`); renderLoggedIn(); } }, '삭제'))));

    const titleIn = el('input', { class: 'pk-input', type: 'text', maxlength: '80', placeholder: '제목', 'aria-label': '새 항목 제목' });
    const bodyIn = el('input', { class: 'pk-input', type: 'text', maxlength: '500', placeholder: '내용 (가상의 내용만)', 'aria-label': '새 항목 내용' });
    const addItemBtn = el('button', { class: 'pk-btn', type: 'button', onclick: async () => {
      const r = await api('POST', '/api/private/items', { title: titleIn.value, body: bodyIn.value });
      if (!r.ok) return status.show('err', r.json?.message ?? '저장하지 못했습니다.');
      renderLoggedIn();
    } }, '항목 추가');

    const only = keys.json.passkeys.length <= 1;
    const keyList = el('ul', { class: 'pk-list' }, keys.json.passkeys.map((k) =>
      el('li', {}, el('div', {},
        el('div', { class: 'pk-title' }, k.label),
        el('div', { class: 'pk-meta' }, `등록 ${new Date(k.createdAt).toLocaleString('ko-KR')} · ${k.deviceType === 'multiDevice' ? '동기화 가능(여러 기기)' : '이 인증기에만 저장'}${k.backedUp ? ' · 백업됨' : ''} · 마지막 사용 ${k.lastUsedAt ? new Date(k.lastUsedAt).toLocaleString('ko-KR') : '없음'}`)),
        el('button', { class: 'pk-btn danger', type: 'button', disabled: only ? '' : null, title: only ? '마지막 패스키는 삭제할 수 없습니다' : '', 'aria-label': `${k.label} 패스키 삭제`, onclick: async () => {
          if (!confirm(`"${k.label}" 패스키를 삭제할까요? 삭제한 패스키로는 더 이상 로그인할 수 없습니다.`)) return;
          const r = await api('DELETE', `/api/passkeys/${encodeURIComponent(k.id)}`);
          renderLoggedIn(r.ok ? { kind: 'ok', text: '패스키를 삭제했습니다.' } : { kind: 'err', text: r.json?.message ?? '삭제하지 못했습니다.' });
        } }, '삭제'))));

    const newLabel = el('input', { class: 'pk-input', type: 'text', maxlength: '30', placeholder: '새 패스키 이름 (예: 휴대폰)', 'aria-label': '추가할 패스키 이름' });
    const addKeyBtn = el('button', { class: 'pk-btn', type: 'button', onclick: () => run(addKeyBtn, status, () => doAddPasskey(newLabel.value)) }, '패스키 추가');

    const actList = el('ul', { class: 'pk-list' }, (act.json?.events ?? []).slice(0, 8).map((e) =>
      el('li', {}, el('div', {}, el('div', { class: 'pk-title' }, `${e.ok ? '성공' : '거절'} · ${e.event}`), el('div', { class: 'pk-meta' }, `${new Date(e.t).toLocaleString('ko-KR')}${e.challenge ? ` · 챌린지 ${e.challenge}` : ''}${e.detail ? ` · ${e.detail}` : ''}`)))));

    const logoutBtn = el('button', { class: 'pk-btn ghost', type: 'button', onclick: async () => { await api('POST', '/api/logout'); state = { authenticated: false }; renderLoggedOut(); } }, '로그아웃');

    body.replaceChildren(
      el('div', { class: 'pk-fake' }, '이 영역의 내용은 전부 제가 직접 만들어 넣은 가상의 내용입니다. 실제 개인정보는 들어 있지 않습니다.'),
      status,
      el('section', {}, el('h3', {}, '내 비공개 자료'), itemList, el('div', { class: 'pk-row', style: 'margin-top:8px' }, titleIn, bodyIn, addItemBtn)),
      el('section', {}, el('h3', {}, '내 패스키'),
        el('p', { class: 'pk-note' }, '하나를 잃어도 들어올 수 있도록 서로 다른 인증기(다른 기기·보안 키·다른 비밀번호 관리자)에 두 개 이상 등록해 두세요. 마지막 패스키는 삭제할 수 없습니다(비밀번호가 없어 복구할 방법이 없기 때문).'),
        keyList, el('div', { class: 'pk-row', style: 'margin-top:8px' }, newLabel, addKeyBtn)),
      el('section', {}, el('h3', {}, '내 활동 기록 (최근)'), actList),
      el('div', { class: 'pk-row' }, logoutBtn),
    );
  }

  // 버튼 잠금 + 오류 표시를 한 곳에서
  async function run(btn, status, fn) {
    btn.disabled = true;
    status.show('info', '인증기의 안내를 따라 주세요…');
    try {
      const result = await fn();
      if (result?.error) status.show('err', result.error);
    } catch (e) {
      status.show('err', explain(e));
    } finally {
      btn.disabled = false;
    }
  }

  // ── 흐름: 등록 / 로그인 / 추가 ───────────────────────────────────────
  async function doRegister(username, label, setupCode) {
    if (!supported()) return { error: '이 환경에서는 패스키를 쓸 수 없습니다.' };
    const o = await api('POST', '/api/register/options', { username, label, setupCode });
    if (!o.ok) return { error: o.json?.message ?? '등록을 시작하지 못했습니다.' };
    const cred = await navigator.credentials.create({ publicKey: creationOptions(o.json) });
    const v = await api('POST', '/api/register/verify', attestationJSON(cred));
    if (!v.ok) return { error: v.json?.message ?? '등록 검증에 실패했습니다.' };
    state = { authenticated: true, username: v.json.username };
    await renderLoggedIn({ kind: 'ok', text: '패스키를 등록했습니다. 서버에는 공개키와 공개 정보만 저장되었고, 개인키는 이 기기 밖으로 나가지 않았습니다.' });
  }

  async function doLogin() {
    if (!supported()) return { error: '이 환경에서는 패스키를 쓸 수 없습니다.' };
    const o = await api('POST', '/api/login/options');
    if (!o.ok) return { error: '로그인을 시작하지 못했습니다.' };
    const cred = await navigator.credentials.get({ publicKey: requestOptions(o.json) });
    const v = await api('POST', '/api/login/verify', assertionJSON(cred));
    if (!v.ok) return { error: v.json?.message ?? '로그인에 실패했습니다.' };
    state = { authenticated: true, username: v.json.username };
    await renderLoggedIn({ kind: 'ok', text: '서명 검증에 성공해 로그인했습니다.' });
  }

  async function doAddPasskey(label) {
    const o = await api('POST', '/api/passkeys/options', { label });
    if (!o.ok) return { error: o.json?.message ?? '시작하지 못했습니다.' };
    const cred = await navigator.credentials.create({ publicKey: creationOptions(o.json) });
    const v = await api('POST', '/api/passkeys/verify', attestationJSON(cred));
    if (!v.ok) return { error: v.json?.message ?? '추가에 실패했습니다.' };
    await renderLoggedIn({ kind: 'ok', text: '패스키를 추가했습니다.' });
  }

  async function refresh() {
    const r = await api('GET', '/api/session');
    state = r.json ?? { authenticated: false };
    if (state.authenticated) await renderLoggedIn(); else renderLoggedOut();
  }

  // ── 열고 닫기 ─────────────────────────────────────────────────────
  openBtn.addEventListener('click', async () => { await refresh(); dialog.showModal(); });
  document.getElementById('pk-close').addEventListener('click', () => dialog.close());
  dialog.addEventListener('click', (e) => { if (e.target === dialog) dialog.close(); });

  // 첫 로드 때 로그인 상태만 가볍게 확인해 버튼 문구를 맞춘다 (비공개 내용은 가져오지 않음)
  api('GET', '/api/session').then((r) => { if (r.json?.authenticated) openLabel.textContent = '비공개 영역 보기'; });
})();
