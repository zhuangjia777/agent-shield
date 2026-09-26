/* Shared display preferences; works both in the app and in the offline guide. */
(() => {
  'use strict';
  const root = document.documentElement;
  const system = window.matchMedia('(prefers-color-scheme: dark)');
  const read = key => { try { return localStorage.getItem(key); } catch { return null; } };
  const save = (key, value) => { try { localStorage.setItem(key, value); } catch {} };
  let chosen = read('as-theme');
  if (!['light', 'dark'].includes(chosen)) chosen = null;
  root.dataset.theme = chosen || (system.matches ? 'dark' : 'light');
  root.dataset.holo = read('as-holo') === 'off' ? 'off' : 'on';
  let themeButton, holoButton;
  let refreshMotion = () => {};
  function sync() {
    refreshMotion();
    if (!themeButton) return;
    const dark = root.dataset.theme === 'dark', holo = root.dataset.holo !== 'off';
    themeButton.textContent = dark ? 'LIGHT' : 'DARK';
    themeButton.setAttribute('aria-label', dark ? 'Switch to light theme' : 'Switch to dark theme');
    holoButton.textContent = holo ? 'HOLO ON' : 'HOLO OFF';
    holoButton.setAttribute('aria-pressed', String(holo));
    holoButton.title = holo ? '关闭立体悬浮、方柱背景与背景波纹' : '开启立体悬浮、方柱背景与背景波纹';
  }
  system.addEventListener('change', e => {
    if (!chosen) { root.dataset.theme = e.matches ? 'dark' : 'light'; sync(); }
  });
  function mount() {
    const host = document.querySelector('.topbar');
    if (!host) return;
    const controls = document.createElement('div');
    controls.className = 'display-controls';
    controls.setAttribute('role', 'group');
    controls.setAttribute('aria-label', '显示设置');
    themeButton = document.createElement('button');
    holoButton = document.createElement('button');
    for (const button of [themeButton, holoButton]) {
      button.type = 'button'; button.className = 'btn outline small'; controls.appendChild(button);
    }
    holoButton.setAttribute('aria-label', '全息效果');
    themeButton.onclick = () => {
      chosen = root.dataset.theme === 'dark' ? 'light' : 'dark';
      root.dataset.theme = chosen; save('as-theme', chosen); sync();
    };
    holoButton.onclick = () => {
      root.dataset.holo = root.dataset.holo === 'off' ? 'on' : 'off';
      save('as-holo', root.dataset.holo); sync();
    };
    host.appendChild(controls); sync();
    mountMotion();
  }
  function mountMotion() {
    const reduce = window.matchMedia('(prefers-reduced-motion: reduce)');
    const fine = window.matchMedia('(hover: hover) and (pointer: fine)');
    const surfaces = '.card,.metric,.config,.details-card,.topology,.lane,.guide-main,.scorehead,.answer,.agentinput,.event';
    const buttons = '.btn,.agent-launcher';
    const layer = document.createElement('div');
    layer.className = 'holo-fx';
    layer.setAttribute('aria-hidden', 'true');
    const ripples = document.createElement('div');
    ripples.className = 'holo-ripples';
    layer.appendChild(ripples);
    document.body.appendChild(layer);
    let enabled = false, frame = 0, pending = null, active = null, bounds = null;
    const timers = new Map();
    const variables = ['--holo-rx', '--holo-ry'];
    function release() {
      if (!active) return;
      active.classList.remove('holo-active');
      active.removeAttribute('data-holo-tilt');
      variables.forEach(name => active.style.removeProperty(name));
      active = bounds = null;
    }
    function clear() {
      if (frame) window.cancelAnimationFrame(frame);
      frame = 0; pending = null;
      release();
      for (const timer of timers.values()) window.clearTimeout(timer);
      timers.clear(); ripples.replaceChildren();
    }
    refreshMotion = () => {
      enabled = root.dataset.holo !== 'off' && !reduce.matches && fine.matches;
      root.dataset.holoMotion = enabled ? 'on' : 'off';
      layer.hidden = !enabled;
      if (!enabled) clear();
    };
    reduce.addEventListener('change', refreshMotion);
    fine.addEventListener('change', refreshMotion);
    refreshMotion();
    function paint() {
      frame = 0;
      const point = pending; pending = null;
      if (!enabled || !point || !point.target.isConnected) { release(); return; }
      const {x, y, target} = point;
      if (target.closest('.site-header,.breadcrumbs,.nav-control')) { release(); return; }
      // Event delegation includes cards inserted by the live arena stream.
      const button = target.closest(buttons);
      const surface = button || target.closest(surfaces);
      if (!surface || surface.matches(':disabled,[aria-disabled="true"]')) { release(); return; }
      if (surface !== active) {
        release();
        bounds = surface.getBoundingClientRect();
        active = surface;
        active.classList.add('holo-surface', 'holo-active');
        const stable = surface.matches('.lane,.guide-main,.config,.details-card,.event,.agentinput,.scorehead') ||
          surface.closest('.modal') || surface.querySelector('input,textarea,select') || bounds.height > 460 || bounds.width > 1000;
        active.dataset.holoTilt = !button && !stable ? 'true' : 'false';
      }
      const localX = Math.max(0, Math.min(bounds.width, x - bounds.left));
      const localY = Math.max(0, Math.min(bounds.height, y - bounds.top));
      const nx = localX / Math.max(bounds.width, 1) * 2 - 1;
      const ny = localY / Math.max(bounds.height, 1) * 2 - 1;
      active.style.setProperty('--holo-rx', `${(-ny * .25).toFixed(2)}deg`);
      active.style.setProperty('--holo-ry', `${(nx * .25).toFixed(2)}deg`);
    }
    document.addEventListener('pointermove', e => {
      if (!enabled || e.pointerType !== 'mouse') return;
      if (e.buttons) { clear(); return; } // Keep text selection and dragging still.
      pending = {x:e.clientX, y:e.clientY, target:e.target};
      if (!frame) frame = window.requestAnimationFrame(paint);
    }, {passive:true});
    document.addEventListener('pointerdown', e => {
      if (!enabled || e.pointerType !== 'mouse' || e.button !== 0) return;
      // Only blank page areas react; links, form controls, logs and dialogs do not.
      if (e.target.closest(`${surfaces},${buttons},a,button,input,textarea,select,label,summary,pre,code,.overlay`)) return;
      const ripple = document.createElement('div');
      ripple.className = 'holo-ripple';
      ripple.style.left = `${e.clientX}px`; ripple.style.top = `${e.clientY}px`;
      if (timers.size >= 3) {
        const oldest = timers.keys().next().value;
        window.clearTimeout(timers.get(oldest)); timers.delete(oldest); oldest.remove();
      }
      ripples.appendChild(ripple);
      timers.set(ripple, window.setTimeout(() => { ripple.remove(); timers.delete(ripple); }, 700));
    }, {passive:true});
    document.addEventListener('pointerout', e => { if (!e.relatedTarget) clear(); }, {passive:true});
    document.addEventListener('pointercancel', clear, {passive:true});
    document.addEventListener('scroll', clear, {passive:true, capture:true});
    document.addEventListener('visibilitychange', () => { if (document.hidden) clear(); });
    window.addEventListener('blur', clear);
    window.addEventListener('resize', clear, {passive:true});
    window.addEventListener('pagehide', clear);
  }
  window.addEventListener('storage', e => {
    if (e.key === 'as-theme' || e.key === null) {
      chosen = ['light', 'dark'].includes(e.newValue) ? e.newValue : null;
      root.dataset.theme = chosen || (system.matches ? 'dark' : 'light');
    }
    if (e.key === 'as-holo' || e.key === null) root.dataset.holo = e.newValue === 'off' ? 'off' : 'on';
    sync();
  });
  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', mount, {once:true});
  else mount();
})();
