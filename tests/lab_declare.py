"""M3 目标申报 hermetic 测试：申报闸、固定入口放行、清除恢复、CLI 直报。不碰 Docker。"""
import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "08_arena"))
import livelab as lab  # noqa: E402


def fake_sh_ok(args, timeout=60):
    return 0, ""


class DeclareTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.dir = Path(self.tmp.name)
        self.p_logo = patch.object(lab, "LOGDIR", self.dir)
        self.p_logo.start()
        self.addCleanup(lambda: (self.p_logo.stop(), self.tmp.cleanup()))

    # ---------- 申报参数闸（不需要 Docker） ----------

    def test_host_validation(self):
        # 字符集闸：空/带空格/前导横线/带 shell 元字符的都拒
        for bad in ("", "exa mple.com", "-evil", "a`b;id"):
            with self.subTest(host=bad):
                with patch.object(lab, "status", return_value={"running": True}), \
                     patch.object(lab, "_sh", side_effect=AssertionError("docker 不该被调")):
                    r = lab.declare_target(bad, 80)
                self.assertFalse(r["ok"])

    def test_port_validation(self):
        for bad in (0, 70000, "abc", None):
            with self.subTest(port=bad):
                with patch.object(lab, "status", return_value={"running": True}):
                    r = lab.declare_target("10.0.0.5", bad)
                self.assertFalse(r["ok"])

    def test_lab_targets_need_no_declaration(self):
        # 演练场内对象走原白名单，申报工具拒收
        for h in (lab.BLUE_NAME, lab.OPS_NAME, "localhost", lab.DECL_GW_NAME):
            with self.subTest(host=h):
                with patch.object(lab, "status", return_value={"running": True}):
                    self.assertFalse(lab.declare_target(h, 80)["ok"])

    def test_requires_running_lab(self):
        with patch.object(lab, "status", return_value={"running": False}):
            r = lab.declare_target("10.0.0.5", 8080)
        self.assertFalse(r["ok"])
        self.assertIn("lab_start", r["msg"])

    def test_url_forms_are_normalized(self):
        # 用户粘贴 http://10.0.0.5:8080/path：剥协议剥路径剥端口，host 落干净
        calls = []
        def fake(args, timeout=60):
            calls.append(list(args)); return 0, ""
        with patch.object(lab, "status", return_value={"running": True}), \
             patch.object(lab, "_sh", side_effect=fake):
            r = lab.declare_target("http://10.0.0.5:8080/some/path", 8080)
        self.assertTrue(r["ok"], r.get("msg"))
        self.assertEqual(r["declared"]["host"], "10.0.0.5")
        # URL 端口与 port 参数打架 → 拒
        with patch.object(lab, "status", return_value={"running": True}):
            r2 = lab.declare_target("http://10.0.0.5:8080/x", 9090)
        self.assertFalse(r2["ok"])

    # ---------- 申报开闸 / 固定入口 / 清除 ----------

    def _declare(self, host="10.0.0.5", port=8080, gw_up=True):
        """起一次申报，返回 (result, docker 命令流水)。"""
        calls = []

        def fake(args, timeout=60):
            calls.append(list(args))
            if args[:2] == ["docker", "inspect"] and not gw_up:
                return 1, "No such container"
            return 0, ""

        with patch.object(lab, "status", return_value={"running": True}), \
             patch.object(lab, "_sh", side_effect=fake):
            return lab.declare_target(host, port), calls

    def test_declare_records_and_entry_is_fixed(self):
        r, calls = self._declare()
        self.assertTrue(r["ok"], r.get("msg"))
        self.assertEqual(r["declared"]["entry"], f"http://{lab.DECL_GW_NAME}:{lab.DECL_LISTEN}")
        # 申报落盘文件存在且内容正确
        rec = json.loads((self.dir / "declared_target.json").read_text())
        self.assertEqual((rec["host"], rec["port"]), ("10.0.0.5", 8080))
        # 中继只挂申报网+隔离网，绝不让红队容器接申报网
        run = next(c for c in calls if c[:3] == ["docker", "run", "-d"])
        self.assertIn("--read-only", run)
        self.assertIn("--cap-drop", run)
        joined = " ".join(run)
        self.assertNotIn(f"--network {lab.NET_DECL} ", joined)  # 申报网只 connect 给中继
        self.assertIn("--network-alias", joined)

    def test_localhost_declare_maps_to_host_gateway(self):
        r, calls = self._declare(host="127.0.0.1", port=3000)
        self.assertTrue(r["ok"])
        run = next(c for c in calls if c[:3] == ["docker", "run", "-d"])
        self.assertIn(f"DECL_HOST={lab.HOST_GW_IP}", " ".join(run))

    def test_declare_success_opens_only_gateway_hostname_in_red_exec(self):
        self._declare()
        with patch.object(lab, "red_exec_guard") as guard, \
             patch.object(lab, "status", return_value={"running": True}), \
             patch.object(lab, "_sh", return_value=(0, "HTTP/1.1 200 OK")):
            guard.check.return_value = None
            # 固定入口放行
            r = lab.red_exec(f"curl -s http://{lab.DECL_GW_NAME}:{lab.DECL_LISTEN}/login", timeout=10)
            self.assertTrue(r["ok"], r.get("msg"))
            # 申报目标的真实 host 反而不放行（必须走固定入口）
            r2 = lab.red_exec("curl -s http://10.0.0.5:8080/login", timeout=10)
            self.assertFalse(r2["ok"])
            # 外网照旧拒
            r3 = lab.red_exec("curl -s http://evil.example.com/", timeout=10)
            self.assertFalse(r3["ok"])

    def test_clear_restores_pure_allowlist(self):
        self._declare()
        with patch.object(lab, "red_exec_guard") as guard, \
             patch.object(lab, "status", return_value={"running": True}), \
             patch.object(lab, "_sh", return_value=(0, "x")):
            guard.check.return_value = None
            self.assertTrue(lab.red_exec(f"curl -s http://{lab.DECL_GW_NAME}:8000/", timeout=10)["ok"])
            lab.clear_declared()
            r = lab.red_exec(f"curl -s http://{lab.DECL_GW_NAME}:8000/", timeout=10)
            self.assertFalse(r["ok"])
            self.assertIn("白名单外", r["msg"])
        self.assertFalse((self.dir / "declared_target.json").exists())

    def test_declared_target_reports_missing_gateway(self):
        # 记录在但容器没了 → declared=None + note，red_exec 不放行
        self._declare()
        with patch.object(lab, "_sh", return_value=(1, "No such container")):
            d = lab.declared_target()
        self.assertIsNone(d["declared"])
        self.assertIn("中继容器不在", d["note"])

    def test_stop_includes_declared_objects(self):
        with patch.object(lab, "_sh") as sh:
            sh.side_effect = lambda a, timeout=60: (
                (0, "aslab-red\tUp\naslab-declared\tUp") if a[:2] == ["docker", "ps"]
                else (0, "aslab-net\naslab-decl") if a[:2] == ["docker", "network"]
                else (0, ""))
            prev = lab.stop(dry_run=True)
        names = {p["name"] for p in prev["will_remove"]}
        self.assertIn(lab.DECL_GW_NAME, names)
        self.assertIn(lab.NET_DECL, names)


if __name__ == "__main__":
    unittest.main()
