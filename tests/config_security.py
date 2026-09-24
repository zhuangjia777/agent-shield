"""Regression checks for credential-safe settings, with fake credentials only."""
import copy
import json
from pathlib import Path
import stat
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "04_web"))
import app


class ConfigSecurityTests(unittest.TestCase):
    def handler(self):
        h = object.__new__(app.Handler)
        h.path = "/api/config"
        h._json = lambda status, body: (status, body)
        return h

    def test_get_masks_without_mutating_saved_key(self):
        cfg = {"cloud": {"api_key": "FAKE_PRIVATE_CREDENTIAL"}}
        with patch.object(app.llm_mod, "load_config", return_value=cfg):
            status, body = self.handler().do_GET()
        self.assertEqual(status, 200)
        self.assertNotIn("api_key", body["cloud"])
        self.assertNotIn("FAKE_PRIVATE_CREDENTIAL", json.dumps(body))
        self.assertTrue(body["cloud"]["api_key_masked"])
        self.assertEqual(cfg["cloud"]["api_key"], "FAKE_PRIVATE_CREDENTIAL")

    def test_blank_preserves_key_and_nonempty_replaces(self):
        cfg = {"cloud": {"api_key": "FAKE_EXISTING", "model": "old"}}
        for value, expected in (("", "FAKE_EXISTING"), ("FAKE_NEW", "FAKE_NEW")):
            h = self.handler()
            h._body = lambda: {"cloud": {"api_key": value, "model": "new"}}
            with patch.object(app.llm_mod, "load_config", return_value=copy.deepcopy(cfg)), patch.object(app.llm_mod, "save_config") as save:
                self.assertEqual(h.do_POST()[0], 200)
                self.assertEqual(save.call_args.args[0]["cloud"]["api_key"], expected)
                self.assertEqual(save.call_args.args[0]["cloud"]["model"], "new")

    def test_saved_credentials_are_owner_only(self):
        with tempfile.TemporaryDirectory() as d, patch.object(app.llm_mod, "ROOT", Path(d)):
            p = Path(d) / "config.json"
            for existing in (False, True):
                if existing:
                    p.chmod(0o644)
                app.llm_mod.save_config({"cloud": {"api_key": "FAKE_VALUE"}})
                self.assertEqual(stat.S_IMODE(p.stat().st_mode), 0o600)
                self.assertEqual(json.loads(p.read_text())["cloud"]["api_key"], "FAKE_VALUE")


if __name__ == "__main__":
    unittest.main()
