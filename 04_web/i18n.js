/* Bilingual UI (中文 ↔ English). Default English.
 * zh is the source of truth in markup; when lang=en, walk text nodes and
 * replace exact-match strings from /i18n.json. A MutationObserver covers
 * dynamically inserted content (arena events, agent chat, toasts).
 * LLM-generated answers are never touched. Originals are stashed per-node so
 * switching back to 中文 restores exactly. */
(() => {
  'use strict';
  const root = document.documentElement;
  const read = k => { try { return localStorage.getItem(k); } catch { return null; } };
  const save = (k, v) => { try { localStorage.setItem(k, v); } catch {} };
  let lang = read('as-lang');
  if (!['zh', 'en'].includes(lang)) lang = 'en';          // default: English
  let DICT = null, REGEX = [];
  const SKIP_TAGS = new Set(['SCRIPT', 'STYLE', 'PRE', 'CODE', 'TEXTAREA', 'NOSCRIPT']);
  let translating = false;

  const t = s => {
    if (DICT) {
      const hit = DICT[s];
      if (hit !== undefined) return hit;
      const trimmed = s.trim();
      if (trimmed !== s) {
        const h2 = DICT[trimmed];
        if (h2 !== undefined) return s.replace(trimmed, h2);  // keep surrounding whitespace
      }
    }
    for (const [re, tpl] of REGEX) {
      const m = s.match(re);
      if (m) return tpl.replace(/\$(\d)/g, (_, i) => m[Number(i)]);
    }
    return null;
  };

  const wants = () => lang === 'en' && DICT !== null;

  function applyText(node) {
    if (translating) return;
    const zh = /[\u4e00-\u9fff]/.test(node.data);
    if (wants()) {
      if (!zh && node._asOrig === undefined) return;       // pure ASCII, never ours to manage
      const r = t(node.data);
      if (r !== null && r !== node.data) {
        if (node._asOrig === undefined) node._asOrig = node.data;
        translating = true; node.data = r; translating = false;
      }
    } else if (node._asOrig !== undefined) {
      translating = true; node.data = node._asOrig; translating = false;
      node._asOrig = undefined;
    }
  }

  function translateTextWalker(rootNode) {
    const walker = document.createTreeWalker(rootNode, NodeFilter.SHOW_TEXT, {
      acceptNode: n => (n.parentElement && SKIP_TAGS.has(n.parentElement.tagName)) || translating
        ? NodeFilter.FILTER_REJECT : NodeFilter.FILTER_ACCEPT
    });
    const batch = []; let tn;
    while ((tn = walker.nextNode())) batch.push(tn);
    for (const n of batch) applyText(n);
  }

  function translateAttrs(rootNode) {
    if (rootNode.nodeType !== 1 && rootNode.nodeType !== 9) return;
    const els = rootNode.nodeType === 9 ? rootNode.querySelectorAll('*') : [rootNode, ...rootNode.querySelectorAll('*')];
    for (const el of els) {
      for (const attr of ['placeholder', 'title', 'aria-label']) {
        const v = el.getAttribute(attr);
        if (!v) continue;
        const key = '_asOrig_' + attr;
        if (wants()) {
          if (!/[\u4e00-\u9fff]/.test(v)) continue;
          const r = t(v);
          if (r !== null && r !== v) { if (el[key] === undefined) el[key] = v; el.setAttribute(attr, r); }
        } else if (el[key] !== undefined) { el.setAttribute(attr, el[key]); el[key] = undefined; }
      }
    }
  }

  function titlePass() {
    if (titlePass.orig === undefined) titlePass.orig = document.title;
    const want = wants() ? (t(titlePass.orig) ?? titlePass.orig) : titlePass.orig;
    if (document.title !== want) document.title = want;   // never touch when unchanged: avoids observer feedback loop
  }

  function walkAll() { translateAttrs(document); translateTextWalker(document.body); titlePass(); }

  function syncButton() {
    const btn = document.getElementById('as-lang-btn');
    if (btn) {
      btn.textContent = lang === 'en' ? '中文' : 'EN';
      btn.setAttribute('aria-label', lang === 'en' ? '切换语言为中文' : 'Switch language to English');
      btn.title = btn.getAttribute('aria-label');
    }
  }

  function applyLang(next) {
    lang = next; save('as-lang', next);
    root.lang = next === 'en' ? 'en' : 'zh-CN';
    walkAll(); syncButton();
    document.dispatchEvent(new CustomEvent('as-language-change', { detail: { lang: next } }));
  }

  // dynamic content: translate subtrees as they appear
  new MutationObserver(muts => {
    if (translating) return;
    for (const m of muts) {
      if (m.type === 'characterData') {
        const node = m.target;
        if (node._asOrig !== undefined) {
          const expected = t(node._asOrig);
          if (node.data === node._asOrig || (expected !== null && node.data === expected)) continue;  // our own write (translate or restore)
          node._asOrig = undefined;                // application rewrote the text → retranslate fresh
        }
        applyText(node);
        continue;
      }
      for (const n of m.addedNodes) {
        if (n.nodeType === 3) { applyText(n); continue; }
        if (n.nodeType !== 1 || SKIP_TAGS.has(n.tagName)) continue;
        translateAttrs(n); translateTextWalker(n);
      }
      // removed nodes: nothing to do (originals die with them)
    }
    titlePass();
  }).observe(document.documentElement, { childList: true, subtree: true, characterData: true, attributes: false });

  function mountButton() {
    let host = document.querySelector('.display-controls');
    if (!host) {
      const top = document.querySelector('.topbar');
      if (!top) return false;
      host = document.createElement('div');
      host.className = 'display-controls';
      top.appendChild(host);
    }
    if (document.getElementById('as-lang-btn')) return true;
    const btn = document.createElement('button');
    btn.type = 'button'; btn.id = 'as-lang-btn'; btn.className = 'btn outline small';
    btn.onclick = () => applyLang(lang === 'en' ? 'zh' : 'en');
    host.insertBefore(btn, host.firstChild);
    syncButton();
    return true;
  }

  async function boot() {
    if (!mountButton()) { const iv = setInterval(() => { if (mountButton()) clearInterval(iv); }, 30); setTimeout(() => clearInterval(iv), 4000); }
    root.lang = lang === 'en' ? 'en' : 'zh-CN';
    if (window.__AS_I18N__) {                      // offline guide: dictionary inlined at build time
      DICT = window.__AS_I18N__.strings || {};
      REGEX = (window.__AS_I18N__.regex || []).map(([p, tpl]) => [new RegExp(p), tpl]);
      applyLang(lang); return;
    }
    try {
      const base = location.protocol === 'file:' ? 'http://127.0.0.1:8787' : location.origin;
      const res = await fetch(base + '/i18n.json');
      const data = await res.json();
      DICT = data.strings || {};
      REGEX = (data.regex || []).map(([p, tpl]) => [new RegExp(p), tpl]);
    } catch { DICT = null; }     // dictionary unavailable → stay Chinese source
    applyLang(lang);
  }
  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', boot, { once: true });
  else boot();

  window.AS_LANG = () => lang;
  window.AS_T = s => (lang === 'en' && DICT && DICT[s] !== undefined ? DICT[s] : s);
})();
