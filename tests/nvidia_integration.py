"""Offline regression tests for provenance, verdicts and report boundaries."""
import copy
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "05_skill_eval"))
import nvidia_scan
from bundle_manifest import manifest
from findings import Finding, aggregate_score
import report
from external_reports import external_html
sys.path.insert(0, str(ROOT / "04_web"))
import app


def raw_report(**metadata):
    return {"issues": [], "metadata": {"skillspector_version": "2.12.0", **metadata},
            "risk_assessment": {"score": 17, "severity": "LOW"},
            "execution_successful": True, "analysis_completeness": {"status": "complete"}}


class NvidiaIntegrationTests(unittest.TestCase):
    def test_content_hash_changes_without_rename(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "SKILL.md").write_text("first")
            before = manifest(root)
            (root / "SKILL.md").write_text("other")
            after = manifest(root)
            self.assertNotEqual(before["input_hash"], after["input_hash"])
            self.assertEqual(before["entries"][0]["path"], after["entries"][0]["path"])

    def test_symlinks_rejected_before_scan(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "SKILL.md").write_text("demo")
            (root / "linked").symlink_to(root / "SKILL.md")
            with self.assertRaises(ValueError):
                manifest(root)

    def test_missing_evidence_changes_effective_grade_and_total(self):
        finding = Finding(id="X", source="skill", rule_id="X", title="test", owasp="", nist="", impact=5, exploitability=5)
        self.assertEqual(finding.level, "medium")
        self.assertEqual(finding.to_dict()["risk"]["level"], finding.level)
        self.assertEqual(aggregate_score([finding]), 95)
        self.assertTrue(finding.to_dict()["evidence_gap"])

    def test_requested_model_with_no_calls_is_partial(self):
        adapted = nvidia_scan.adapt(raw_report(), {"llm_requested": True})
        self.assertEqual(adapted["status"], "partial")
        self.assertEqual(adapted["evidence_type"], "model_assisted_review")

    def test_failures_and_coverage_gaps_cannot_pass(self):
        for variant in ("failed", "partial", "missing"):
            raw = raw_report()
            if variant == "failed": raw["execution_successful"] = False
            elif variant == "partial": raw["analysis_completeness"]["status"] = "partial"
            else: raw.pop("analysis_completeness")
            self.assertNotEqual(nvidia_scan.adapt(raw, {"llm_requested": False})["status"], "complete")

    def test_successful_model_telemetry_kept_separate(self):
        raw = raw_report(llm_calls_attempted=3, llm_calls_succeeded=3)
        raw["issues"] = [{"id": "P1", "finding_id": "original-1", "severity": "HIGH", "location": {"file": "SKILL.md", "start_line": 4}}]
        original = copy.deepcopy(raw)
        result = nvidia_scan.adapt(raw, {"llm_requested": True})
        self.assertEqual(result["status"], "complete")
        self.assertEqual(result["issues"][0]["finding_id"], "original-1")
        self.assertFalse(result["affects_agentshield_score"])
        self.assertEqual(raw, original)

    def test_external_risk_does_not_change_local_health_score(self):
        result = {"findings": [], "external_assessments": [nvidia_scan.adapt(raw_report(), {"llm_requested": False})]}
        assembled = report.assemble(result, {"summary": "test", "top_actions": []}, "template")
        self.assertEqual(assembled["score"], 100)
        self.assertEqual(assembled["external_assessments"][0]["risk_assessment"]["score"], 17)

    def test_html_injection_is_escaped_in_both_engines(self):
        payload = '<script>alert("x")</script>'
        finding = Finding(id="x", source="skill", rule_id=payload, title=payload, owasp=payload, nist=payload, evidence={"file": payload}, fix=payload).to_dict()
        ext = nvidia_scan.adapt(raw_report(), {"llm_requested": False})
        ext["issues"] = [{"explanation": payload, "severity": payload, "location": {"file": payload}}]
        result = report.assemble({"findings": [finding], "external_assessments": [ext]}, {"summary": payload, "top_actions": [payload], "explains": {"x":payload}}, "template")
        document = report.to_html(result)
        self.assertNotIn("<script>", document)
        self.assertIn("&lt;script&gt;", document)
        self.assertNotIn("<script>", external_html(result))

    def test_invalid_upstream_schema_rejected(self):
        for raw in ({}, [], {"issues": {}, "metadata": {}}):
            with self.assertRaises(ValueError):
                nvidia_scan.adapt(raw, {"llm_requested": False})

    def test_web_rejects_paths_instead_of_builtin_samples(self):
        handler = object.__new__(app.Handler)
        handler.path = "/api/nvidia/scan"
        handler.headers = {"Content-Length": "100"}
        handler._body = lambda: {"sample": "../../config.json", "use_llm": True}
        handler._json = lambda status, body: (status, body)
        with patch.object(app.nvidia_scan, "run_scan") as runner:
            self.assertEqual(handler.do_POST()[0], 400)
            runner.assert_not_called()


if __name__ == "__main__":
    unittest.main()
