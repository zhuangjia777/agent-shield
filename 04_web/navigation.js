/* Shared navigation. Only local view preferences are stored; never model settings. */
(() => {
  'use strict';
  function mount() {
    const old = document.querySelector('.topbar');
    if (!old) return;
    const offline = location.protocol === 'file:';
    const base = offline ? 'http://127.0.0.1:8787' : location.origin;
    const sections = [['/', '首页'], ['/checkup', '体检本机'], ['/arena', '攻防演练'], ['/nvidia', 'Skill 审查'], ['/help', '使用说明']];
    const report = location.pathname.startsWith('/report/');
    const section = offline ? '/help' : (document.body.dataset.navSection || location.pathname);
    const label = document.body.dataset.navLabel || sections.find(([url]) => url === section)?.[1] || '页面';
    const fallback = report ? section : '/';
    const route = value => {
      try {
        const u = new URL(value, base);
        if (u.origin !== base || !(sections.some(([p]) => p === u.pathname) || /^\/report\/[^/]+$/.test(u.pathname))) return null;
        return u.pathname + u.search + u.hash;
      } catch { return null; }
    };
    const get = key => { try { return JSON.parse(sessionStorage.getItem(key)); } catch { return null; } };
    const put = (key, value) => { try { sessionStorage.setItem(key, JSON.stringify(value)); } catch {} };
    const current = () => location.pathname + location.search + location.hash;
    const pageKey = value => value.split('#')[0];
    const key = () => 'as-view:' + pageKey(current());
    let trail = [], restore = false;
    if (!offline) {
      const state = history.state?.asNavigation;
      const intent = get('as-navigation-next');
      try { sessionStorage.removeItem('as-navigation-next'); } catch {}
      if (state) { trail = state.trail || []; restore = true; }
      else if (intent && Date.now() - intent.at < 15000 && pageKey(intent.to) === pageKey(current())) {
        trail = intent.trail || []; restore = intent.back;
      } else {
        const previous = document.referrer ? route(document.referrer) : null;
        if (previous && pageKey(previous) !== pageKey(current())) trail = [previous];
      }
      trail = Array.isArray(trail) ? trail.map(route).filter(Boolean).slice(-24) : [];
      try { history.replaceState({...history.state, asNavigation:{trail}}, ''); } catch {}
    }
    const url = target => offline ? base + target : target;
    const link = (text, target, cls='btn outline small nav-control') => {
      const a = document.createElement('a'); a.textContent = text; a.href = url(target); a.className = cls; return a;
    };
    const header = document.createElement('header'); header.className = 'site-header';
    const top = document.createElement('div'); top.className = 'topbar';
    const actions = document.createElement('nav'); actions.className = 'nav-history'; actions.setAttribute('aria-label', '返回与首页');
    const back = link('← 返回', trail.at(-1) || fallback); back.dataset.navBack = 'true';
    back.title = trail.length ? '返回上一页面' : '返回' + (sections.find(([p]) => p === fallback)?.[1] || '首页');
    back.hidden = !offline && location.pathname === '/' && !trail.length;
    actions.append(back, link('首页', '/'));
    const brand = document.createElement('a'); brand.href = url('/'); brand.className = 'brand';
    brand.innerHTML = 'Agent<span class="brand-shield">Shield</span>';
    const utility = document.createElement('div'); utility.className = 'nav-utility';
    utility.append(link('设置', '/?settings=1'), link('使用说明', '/help'));
    top.append(brand, actions, utility);
    const toggle = document.createElement('button'); toggle.type = 'button'; toggle.className = 'btn outline small nav-control nav-toggle';
    toggle.textContent = '导航'; toggle.setAttribute('aria-expanded', 'false'); toggle.setAttribute('aria-controls', 'site-navigation');
    const nav = document.createElement('nav'); nav.id = 'site-navigation'; nav.className = 'site-navigation'; nav.setAttribute('aria-label', '主导航');
    for (const [target, text] of sections) {
      const a = link(text, target, 'nav-link nav-control');
      if (text.includes('攻防演练')) a.innerHTML = '<span class="nav-hl">' + text + '</span>';
      if (target === section) a.setAttribute('aria-current', report ? 'location' : 'page');
      nav.appendChild(a);
    }
    const closeMenu = () => { header.dataset.navOpen = 'false'; toggle.setAttribute('aria-expanded', 'false'); };
    toggle.onclick = () => { const open = header.dataset.navOpen !== 'true'; header.dataset.navOpen = String(open); toggle.setAttribute('aria-expanded', String(open)); };
    header.addEventListener('keydown', e => { if (e.key === 'Escape' && header.dataset.navOpen === 'true') { closeMenu(); toggle.focus(); } });
    document.addEventListener('click', e => { if (!header.contains(e.target)) closeMenu(); });
    const mobile = matchMedia('(max-width:640px)'); mobile.addEventListener('change', closeMenu);
    top.appendChild(toggle); header.append(top, nav); old.replaceWith(header);
    document.querySelectorAll('body > .breadcrumbs').forEach(e => e.remove());
    const crumbs = document.createElement('nav'); crumbs.className = 'breadcrumbs'; crumbs.setAttribute('aria-label', '当前位置');
    const separator = () => { const span = document.createElement('span'); span.textContent = '/'; span.setAttribute('aria-hidden', 'true'); crumbs.appendChild(span); };
    if (section !== '/' || report) { crumbs.appendChild(link('首页', '/', 'nav-control')); separator(); }
    if (report && section !== '/') { crumbs.appendChild(link(sections.find(([p]) => p === section)?.[1] || '报告', section, 'nav-control')); separator(); }
    const leaf = document.createElement('span'); leaf.textContent = label; leaf.setAttribute('aria-current', 'page'); crumbs.appendChild(leaf);
    header.after(crumbs);
    const measure = () => document.documentElement.style.setProperty('--nav-height', header.getBoundingClientRect().height + 'px');
    new ResizeObserver(measure).observe(header); measure();
    if (offline) return;

    const allowed = '#scan-system,#scan-network,#autoscroll,#depth,#arena-mode,#controls input[type="checkbox"],#sample,#use-model';
    const remember = () => {
      const fields = {};
      for (const e of document.querySelectorAll(allowed)) if (e.id) fields[e.id] = e.type === 'checkbox' ? e.checked : e.value;
      put(key(), {y:scrollY, fields, details:[...document.querySelectorAll('body > details')].map(e=>e.open)});
    };
    let scrollTimer;
    window.addEventListener('scroll', () => { clearTimeout(scrollTimer); scrollTimer = setTimeout(remember, 150); }, {passive:true});
    window.addEventListener('pagehide', () => { clearTimeout(scrollTimer); remember(); });
    document.addEventListener('click', e => {
      const a = e.target.closest('a[href]');
      if (!a || e.defaultPrevented || e.button !== 0 || e.metaKey || e.ctrlKey || e.shiftKey || e.altKey || a.hasAttribute('download') || (a.target && a.target !== '_self')) return;
      const to = route(a.href);
      if (!to || pageKey(to) === pageKey(current())) return;
      remember();
      const isBack = a.dataset.navBack === 'true';
      put('as-navigation-next', {to, trail:isBack ? trail.slice(0, -1) : [...trail, current()].slice(-24), back:isBack, at:Date.now()});
    });
    const saved = restore ? get(key()) : null;
    const restoreView = () => {
      if (!saved) return;
      for (const e of document.querySelectorAll(allowed)) {
        const value = saved.fields?.[e.id];
        if (e.type === 'checkbox' && typeof value === 'boolean') e.checked = value;
        else if (e.tagName === 'SELECT' && typeof value === 'string' && [...e.options].some(o => o.value === value)) { e.value = value; e.dispatchEvent(new Event('change', {bubbles:true})); }
      }
      document.querySelectorAll('body > details').forEach((e, i) => { if (typeof saved.details?.[i] === 'boolean') e.open = saved.details[i]; });
      requestAnimationFrame(() => requestAnimationFrame(() => scrollTo(0, Math.max(0, Number(saved.y) || 0))));
    };
    if (section === '/arena' && document.querySelector('#scenario')?.disabled) document.addEventListener('agentshield:scenario-ready', restoreView, {once:true});
    else restoreView();
  }
  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', mount, {once:true});
  else mount();
})();
