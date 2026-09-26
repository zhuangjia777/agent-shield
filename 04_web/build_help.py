"""Build the standalone user guide; run in .venv-skillspector (markdown-it-py)."""
import ast
from html import escape
from pathlib import Path
import re
from markdown_it import MarkdownIt

ROOT = Path(__file__).resolve().parents[1]
source = (ROOT / '使用说明.md').read_text()
markdown = MarkdownIt('commonmark', {'html': False}).enable('table')
tokens = markdown.parse(source)
sections = []
for index, token in enumerate(tokens):
    if token.type == 'heading_open' and token.tag == 'h2':
        title = tokens[index + 1].content
        anchor = f'section-{len(sections) + 1}'
        token.attrSet('id', anchor)
        sections.append((anchor, title))
body = markdown.renderer.render(tokens, markdown.options, {})
body = re.sub(r'<table>(.*?)</table>', r'<div class="table-wrap"><table>\1</table></div>', body, flags=re.S)
nav = ''.join(f'<a href="#{anchor}">{escape(title)}</a>' for anchor, title in sections)
# Embed the canonical application CSS so the guide also works offline.
module = ast.parse((ROOT / '04_web' / 'app.py').read_text())
shared_css = next(ast.literal_eval(node.value) for node in module.body
                  if isinstance(node, ast.Assign) and any(isinstance(t, ast.Name) and t.id == 'BASE_CSS' for t in node.targets))
theme_js = (ROOT / '04_web' / 'theme.js').read_text()
guide_css = """
body.guide-page{max-width:1288px}.guide-layout{display:grid;grid-template-columns:220px minmax(0,1fr);gap:22px;margin-top:22px}
aside{align-self:start;position:sticky;top:22px}aside small{display:block;color:var(--muted);font:12px ui-monospace,monospace;letter-spacing:1px;margin-bottom:12px}
aside a{display:block;color:var(--muted);font-size:12px;padding:8px 10px;border:0;border-left:2px solid var(--line)}aside a:hover,aside a:focus{color:var(--fg);border-left-color:var(--fg);background:var(--code)}
.guide-main{background:var(--card);border:1px solid var(--line);box-shadow:var(--bevel),var(--sh-1);padding:28px;min-width:0}
.guide-main h1{margin-top:0}.guide-main h2{font-size:22px;margin-top:40px;padding-top:22px;border-top:1px solid var(--fg)}.guide-main h3{font-size:16px;margin-top:22px}
.guide-main p{margin:16px 0}.guide-main li{margin:8px 0}.guide-main code{background:var(--code);padding:2px 5px;overflow-wrap:anywhere}.guide-main pre code{padding:0}
.table-wrap{overflow:auto;margin:22px 0}table{width:100%;border-collapse:collapse;font-size:13px}th,td{text-align:left;padding:12px;border:1px solid var(--line);vertical-align:top;min-width:95px}th{background:var(--accent-soft);color:var(--fg)}tr:nth-child(even) td{background:var(--code)}
@media(max-width:800px){.guide-layout{grid-template-columns:1fr}aside{position:static;display:grid;grid-template-columns:1fr 1fr}aside small{grid-column:1/-1}.guide-main{padding:18px}}
@media print{.guide-layout{display:block}aside,.topbar{display:none}.guide-main{border:0;padding:0}h2{break-after:avoid}.table-wrap{overflow:visible}tr{break-inside:avoid}table,th,td,code{font-size:12pt}}
"""
page = '<!doctype html><html lang="zh-CN"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>AgentShield 使用说明</title><style>' + shared_css + guide_css + '</style><script>' + theme_js + '</script></head><body class="guide-page"><header class="topbar"><div class="brand">AgentShield<small>使用说明 · 2026-09-26</small></div><a class="btn outline small" href="http://127.0.0.1:8787/">打开应用 ↗</a></header><div class="guide-layout"><aside><small>CONTENTS / 目录</small>' + nav + '</aside><main class="guide-main">' + body + '<footer>由项目根目录「使用说明.md」生成。浏览器可直接打开此文件，也可使用打印功能另存为 PDF。</footer></main></div></body></html>'
(ROOT / '使用说明.html').write_text(page)
print('Built 使用说明.html')
