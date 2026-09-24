"""Build the standalone user guide; run in .venv-skillspector (markdown-it-py)."""
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
page = '''<!doctype html><html lang="zh-CN"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>AgentShield 使用说明</title><style>
:root{color-scheme:light}*{box-sizing:border-box}html{scroll-behavior:smooth;scroll-padding-top:24px}body{margin:0;background:#f5f7f9;color:#243243;font:15px/1.8 -apple-system,BlinkMacSystemFont,"PingFang SC","Microsoft YaHei",sans-serif}header{background:#142131;color:#fff;padding:28px max(24px,calc((100vw - 1240px)/2));display:flex;justify-content:space-between;align-items:center;gap:20px}header strong{font-size:20px;letter-spacing:.5px}header span{color:#b4c2d2;font-size:12px}header a{color:#d4e7be;text-decoration:none;font-size:13px}.layout{max-width:1288px;margin:auto;display:grid;grid-template-columns:235px minmax(0,1fr);gap:32px;padding:30px 24px 60px}aside{align-self:start;position:sticky;top:24px}aside small{color:#778797;letter-spacing:2px}aside a{display:block;color:#566677;font-size:12px;text-decoration:none;padding:7px 10px;border-left:2px solid #dee5eb}aside a:hover,aside a:focus{color:#385b20;border-color:#7ca543;background:#eef3e8}main{background:#fff;border:1px solid #e0e6ec;border-radius:12px;padding:32px 40px;min-width:0}h1{font-size:30px;line-height:1.35;margin-top:0;color:#17283a}h2{font-size:22px;margin-top:42px;padding-top:22px;border-top:1px solid #e3e9ee;color:#22384b}h3{font-size:17px;margin-top:25px}p{margin:14px 0}a{color:#3b6c28;text-underline-offset:3px}code{font:12px/1.7 ui-monospace,SFMono-Regular,Consolas,monospace;background:#edf1f4;padding:2px 5px;border-radius:3px;overflow-wrap:anywhere}pre{background:#172536;color:#dce7f1;border-radius:8px;padding:17px;overflow:auto}pre code{background:none;padding:0;overflow-wrap:normal;font-size:12px}.table-wrap{overflow-x:auto;margin:20px 0}table{width:100%;border-collapse:collapse;font-size:13px}th,td{text-align:left;padding:12px;border:1px solid #dfe6ec;vertical-align:top;min-width:95px}th{background:#edf3e8;color:#375227}tr:nth-child(even) td{background:#fafbfd}li{margin:8px 0}strong{font-weight:650}footer{font-size:12px;color:#80909f;margin-top:30px;padding-top:15px;border-top:1px solid #e4e9ee}@media(max-width:800px){header{padding:20px;flex-wrap:wrap}.layout{grid-template-columns:1fr;padding:18px;gap:20px}aside{position:static;display:grid;grid-template-columns:1fr 1fr}aside small{grid-column:1/-1}main{padding:22px 18px}h1{font-size:25px}h2{font-size:20px}}@media print{body,main{background:#fff}.layout{display:block;padding:0}aside,header{display:none}main{border:0;padding:0}h2{break-after:avoid}pre{white-space:pre-wrap;color:#111;background:#eee}.table-wrap{overflow:visible}tr{break-inside:avoid}}@media(prefers-reduced-motion:reduce){html{scroll-behavior:auto}}
</style></head><body><header><div><strong>AgentShield</strong><br><span>使用说明 · 2026-09-24</span></div><a href="http://127.0.0.1:8787/">打开应用 ↗</a></header><div class="layout"><aside><small>CONTENTS / 目录</small>'''+nav+'''</aside><main>'''+body+'''<footer>由项目根目录「使用说明.md」生成。浏览器可直接打开此文件，也可使用打印功能另存为 PDF。</footer></main></div></body></html>'''
(ROOT / '使用说明.html').write_text(page)
print('Built 使用说明.html')
