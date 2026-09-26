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
  function sync() {
    if (!themeButton) return;
    const dark = root.dataset.theme === 'dark', holo = root.dataset.holo !== 'off';
    themeButton.textContent = dark ? '浅色' : '深色';
    themeButton.setAttribute('aria-label', dark ? '切换浅色主题' : '切换深色主题');
    holoButton.textContent = holo ? 'HOLO ON' : 'HOLO OFF';
    holoButton.setAttribute('aria-pressed', String(holo));
    holoButton.title = holo ? '关闭扫描纹理、定位角标与标题残影' : '开启扫描纹理、定位角标与标题残影';
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
  }
  window.addEventListener('storage', e => {
    if (e.key === 'as-theme') {
      chosen = ['light', 'dark'].includes(e.newValue) ? e.newValue : null;
      root.dataset.theme = chosen || (system.matches ? 'dark' : 'light');
    }
    if (e.key === 'as-holo') root.dataset.holo = e.newValue === 'off' ? 'off' : 'on';
    sync();
  });
  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', mount, {once:true});
  else mount();
})();
