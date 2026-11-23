import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
import sys
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
spec = importlib.util.spec_from_file_location('audit', Path(__file__).resolve().parents[1] / 'audit.py')
audit = importlib.util.module_from_spec(spec)
spec.loader.exec_module(audit)


class AuditTests(unittest.TestCase):
    def test_loopback_ipv6_and_wildcard_are_not_all_public(self):
        rows = audit.listeners('''tcp LISTEN 0 4096 127.0.0.1:5000 0.0.0.0:* users:(("docker-proxy",pid=2,fd=7))
tcp LISTEN 0 4096 [::1]:18090 [::]:* users:(("kubectl",pid=3,fd=8))
tcp LISTEN 0 4096 *:6443 *:* users:(("k3s-server",pid=4,fd=13))
udp UNCONN 0 0 192.0.2.10%eth0:68 0.0.0.0:*
''')
        self.assertEqual([r['scope'] for r in rows], ['loopback', 'loopback', 'all interfaces', 'private address'])
        self.assertEqual(rows[0]['processes'], ['docker-proxy'])
        self.assertEqual(audit.scope('[fe80::1234]%wlo1'), 'link-local')

    def test_missing_tool_is_unknown(self):
        a = audit.Audit()
        with patch.object(audit.shutil, 'which', return_value=None):
            self.assertIsNone(a.command('firewall', ['ufw', 'status']))
        self.assertEqual(a.findings[0]['status'], 'UNKNOWN')

    def test_reports_are_private_unique_and_do_not_follow_symlinks(self):
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp).resolve() / 'private'
            a = audit.Audit()
            first = audit.save_report(a, base)
            second = audit.save_report(a, base)
            self.assertNotEqual(first, second)
            self.assertEqual((first / 'report.json').stat().st_mode & 0o777, 0o600)
            self.assertEqual(first.stat().st_mode & 0o777, 0o700)
            self.assertEqual(json.loads((first / 'report.json').read_text())['findings'], [])
            link = Path(tmp).resolve() / 'link'
            link.symlink_to(base, target_is_directory=True)
            with self.assertRaises(ValueError):
                audit.save_report(a, link)

    def test_shared_report_directory_is_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp).resolve() / 'shared'
            base.mkdir(mode=0o755)
            with self.assertRaises(ValueError):
                audit.save_report(audit.Audit(), base)

    def test_failed_commands_do_not_report_success(self):
        a = audit.Audit()
        with patch.object(audit, 'run', return_value={'ok': False, 'error': 'permission denied'}):
            a.ssh()
        self.assertEqual([x['status'] for x in a.findings], ['UNKNOWN'])

    def test_control_characters_sanitized(self):
        self.assertEqual(audit.clean('hello\x1b[31m'), 'hello?[31m')


if __name__ == '__main__':
    unittest.main()
