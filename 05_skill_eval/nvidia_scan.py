"""Pinned NVIDIA SkillSpector adapter, preserving upstream findings and scores."""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile
import time
import uuid

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "02_scan"))
sys.path.insert(0, str(ROOT / "03_ai"))
from bundle_manifest import manifest
from cmd_scan import run_skill_eval
from findings import aggregate_score
import report

INTEGRATION = ROOT / "09_integrations" / "nvidia"
PYTHON = ROOT / ".venv-skillspector" / "bin" / "python"


def package_hash(root):
    digest = hashlib.sha256()
    for path in sorted(Path(root).rglob("*")):
        if path.is_file() and "__pycache__" not in path.parts and path.suffix != ".pyc":
            digest.update(path.relative_to(root).as_posix().encode() + b"\0")
            digest.update(hashlib.sha256(path.read_bytes()).digest())
    return digest.hexdigest()


def adapt(raw, provenance):
    if not isinstance(raw, dict) or not isinstance(raw.get("issues"), list) or not isinstance(raw.get("metadata"), dict):
        raise ValueError("Unsupported SkillSpector report schema")
    meta = raw["metadata"]
    attempted, succeeded = meta.get("llm_calls_attempted", 0), meta.get("llm_calls_succeeded", 0)
    requested = provenance["llm_requested"]
    complete = raw.get("analysis_completeness", {})
    degraded = requested and (not succeeded or meta.get("llm_degraded") or meta.get("llm_error") or attempted != succeeded)
    status = "complete"
    if raw.get("execution_successful") is not True:
        status = "failed"
    elif complete.get("status") != "complete" or degraded:
        status = "partial"
    return {"engine": "NVIDIA SkillSpector", "version": meta.get("skillspector_version"),
            "status": status, "mode": "static_and_model" if requested else "static",
            "evidence_type": "model_assisted_review" if requested else "static_observation",
            "risk_assessment": raw.get("risk_assessment", {}),
            "issues": raw["issues"], "metadata": meta, "analysis_completeness": complete,
            "provenance": provenance, "affects_agentshield_score": False,
            "notice": "原始风险分越高风险越大；不与 AgentShield 健康分相加。不代表动态漏洞复现。"}


def run_scan(skill_dir, use_llm=False, outdir=None, timeout=240):
    source = Path(skill_dir)
    original = manifest(source)
    lock = json.loads((INTEGRATION / "component-lock.json").read_text())
    installed = ROOT / lock["installed_package"]
    if not PYTHON.is_file() or package_hash(installed) != lock["installed_package_sha256"]:
        raise RuntimeError("SkillSpector 未安装或内容与锁定版本不符，请按集成说明重装。")
    rid = "nvidia-" + time.strftime("%Y%m%d-%H%M%S") + "-" + uuid.uuid4().hex[:6]
    outdir = Path(outdir) if outdir else ROOT / "reports" / rid
    outdir.mkdir(parents=True, exist_ok=False)
    outdir.chmod(0o700)
    started = time.monotonic()
    cfg = {}
    if use_llm:
        cfg = json.loads((ROOT / "config.json").read_text()).get("cloud", {})
        if not cfg.get("api_key") or not cfg.get("base_url"):
            raise ValueError("请先配置私有模型。")
    with tempfile.TemporaryDirectory(prefix="agentshield-nvidia-") as tmp:
        snapshot = Path(tmp) / source.name
        snapshot.mkdir()
        for entry in original["entries"]:
            dest = snapshot / entry["path"]
            dest.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(source / entry["path"], dest, follow_symlinks=False)
        if manifest(snapshot)["input_hash"] != original["input_hash"]:
            raise ValueError("扫描输入在建立快照时发生变化。")
        local = run_skill_eval(str(snapshot))
        raw_path = outdir.resolve() / "skillspector.json"
        io_path = outdir.resolve() / "io-policy.json"
        request = {"input": str(snapshot), "use_llm": use_llm, "model": cfg,
                   "revision": lock["revision"], "raw_output": str(raw_path), "io_output": str(io_path)}
        # Do not inherit cloud credentials, proxy routes, tracing or model overrides.
        env = {key: value for key, value in os.environ.items() if key in ("PATH", "HOME", "LANG", "TMPDIR", "SYSTEMROOT")}
        env["PYTHONNOUSERSITE"] = "1"
        try:
            process = subprocess.run([str(PYTHON), str(INTEGRATION / "worker.py")],
                                     input=json.dumps(request), text=True, capture_output=True,
                                     timeout=timeout, env=env, cwd=tmp)
        except subprocess.TimeoutExpired:
            (outdir / "failure.json").write_text(json.dumps({"status": "timeout", "timeout_s": timeout}))
            raise RuntimeError("官方扫描超时，未判定为通过；可查看 failure.json。") from None
        if process.returncode or not raw_path.is_file():
            # Keep error class/exit status, not raw logs that may contain model data.
            error_type = next((line.split(":", 1)[0] for line in reversed(process.stderr.splitlines())
                               if re.match(r"^[A-Za-z]+(?:Error|Exception):", line)), "UnknownError")
            (outdir / "failure.json").write_text(json.dumps({"status": "failed", "exit_code": process.returncode, "error_type": error_type}))
            raise RuntimeError(f"官方扫描未完成（{error_type}），不生成成功结论。")
        raw_bytes = raw_path.read_bytes()
        provenance = {"repository": lock["repository"], "revision": lock["revision"],
                      "installed_package_sha256": lock["installed_package_sha256"],
                      "input_manifest": original, "raw_report": raw_path.name,
                      "raw_sha256": hashlib.sha256(raw_bytes).hexdigest(),
                      "llm_requested": use_llm, "model": cfg.get("model") if use_llm else None,
                      "provider_configuration": {"extension": "AgentShieldCompatibleProvider",
                                                 "http_clients": "per_model_no_keepalive_no_proxy",
                                                 "request_context_budget": 8192,
                                                 "output_cap": min(4096, max(512, int(cfg.get("max_tokens", 2500)))),
                                                 "qwen_thinking_disabled": str(cfg.get("model", "")).lower().startswith("qwen")}
                                                if use_llm else None,
                      "network_policy": "model_endpoint_only" if use_llm else "deny_python_network",
                      "io_events": json.loads(io_path.read_text()),
                      "signature_status": "not_verified", "transitive": False}
        raw = json.loads(raw_bytes)
        if raw.get("metadata", {}).get("skillspector_version") != lock["version"]:
            raise RuntimeError("官方运行版本与安装锁定版本不符。")
        external = adapt(raw, provenance)
    results = {"report_id": outdir.name, "generated_at": time.strftime("%Y-%m-%d %H:%M:%S %Z"),
               "skill": {"manifest": original}, "findings": [f.to_dict() for f in local["findings"]],
               "score": aggregate_score(local["findings"]),
               "external_assessments": [external], "total_elapse_s": round(time.monotonic()-started, 2)}
    assembled = report.assemble(results, report.template_narrative(results), "template")
    (outdir / "results.json").write_text(json.dumps(results, ensure_ascii=False, indent=2))
    (outdir / "report.json").write_text(json.dumps(assembled, ensure_ascii=False, indent=2))
    (outdir / "report.html").write_text(report.to_html(assembled))
    (outdir / "report.md").write_text(report.to_markdown(assembled))
    for path in outdir.iterdir():
        if path.is_file():
            path.chmod(0o600)
    return {"ok": True, "report": outdir.name, "status": external["status"],
            "issues": len(external["issues"]), "llm_calls_succeeded": external["metadata"].get("llm_calls_succeeded", 0)}


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--skill", required=True)
    parser.add_argument("--with-llm", action="store_true")
    parser.add_argument("--out")
    args = parser.parse_args()
    print(json.dumps(run_scan(args.skill, args.with_llm, args.out), ensure_ascii=False))
