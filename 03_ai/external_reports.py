"""Present external assessments without blending engines or score directions."""
import html
import json
from urllib.parse import quote


def external_html(rep, raw_prefix=""):
    esc = lambda value: html.escape(str(value if value is not None else "—"), quote=True)
    blocks = []
    for assessment in rep.get("external_assessments", []):
        p = assessment.get("provenance", {})
        risk = assessment.get("risk_assessment", {})
        meta = assessment.get("metadata", {})
        coverage = assessment.get("analysis_completeness", {})
        mode = "静态＋模型线索" if p.get("llm_requested") else "静态观察"
        status = {"complete": "已完成所选扫描范围", "partial": "部分完成，存在覆盖缺口", "failed": "扫描失败"}.get(assessment.get("status"), "状态未知")
        issues = []
        for issue in assessment.get("issues", []):
            loc = issue.get("location", {})
            issues.append(f'<details style="margin:10px 0"><summary>{esc(issue.get("severity"))} · {esc(issue.get("id"))} · {esc(issue.get("pattern") or issue.get("category"))}</summary>'
                          f'<p>{esc(issue.get("explanation"))}</p><p>建议：{esc(issue.get("remediation"))}</p>'
                          f'<p class="tip">证据：{esc(loc.get("file"))}:{esc(loc.get("start_line"))} · 原始 finding_id：{esc(issue.get("finding_id"))}</p>'
                          f'<pre style="white-space:pre-wrap;overflow-wrap:anywhere">{esc(issue.get("code_snippet") or issue.get("finding"))}</pre></details>')
        details = {"revision": p.get("revision"), "input_hash": p.get("input_manifest", {}).get("input_hash"),
                   "raw_sha256": p.get("raw_sha256"), "network_policy": p.get("network_policy"),
                   "io_events": p.get("io_events"), "signature_status": p.get("signature_status"),
                   "analysis_completeness": coverage}
        blocks.append(f'''<section class="card" style="margin:18px 0;border-top:3px solid #76b900">
<h2 style="font-size:18px;margin-top:0">{esc(assessment.get('engine'))} <small>{esc(assessment.get('version'))}</small></h2>
<p><b>官方引擎风险分 {esc(risk.get('score'))}/100</b>（越高风险越大） · {esc(risk.get('severity'))} · {esc(risk.get('recommendation'))}</p>
<p>{esc(status)} · {mode} · {len(assessment.get('issues', []))} 项线索</p>
<p class="tip">与本地规则健康分分开。静态观察／模型线索不等于动态漏洞复现，零发现不代表安全。</p>
<p class="tip">模型：{esc(p.get('model') or '未调用')} · 成功/尝试调用：{esc(meta.get('llm_calls_succeeded', 0))}/{esc(meta.get('llm_calls_attempted', 0))} · 来源签名：未验证</p>
<p><a href="{esc(raw_prefix + quote(str(p.get('raw_report', 'skillspector.json')), safe=''))}" download>下载官方原始 JSON</a></p>
{''.join(issues) or '<p>本次没有官方引擎发现；请核对下方覆盖范围。</p>'}
<details><summary>专业视图：版本、内容哈希与覆盖边界</summary><pre style="white-space:pre-wrap;overflow-wrap:anywhere">{esc(json.dumps(details,ensure_ascii=False,indent=2))}</pre></details>
</section>''')
    return "".join(blocks)


def external_markdown(rep):
    lines = []
    for item in rep.get("external_assessments", []):
        lines += ["## NVIDIA SkillSpector 独立评估", "",
                  "风险分越高风险越大；不并入本地规则健康分。未验证来源签名，不代表动态漏洞复现。", "",
                  "```json", json.dumps(item, ensure_ascii=False, indent=2).replace("```", "\\u0060\\u0060\\u0060"), "```", ""]
    return "\n".join(lines)
