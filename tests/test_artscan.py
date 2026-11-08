import os
import tempfile
import unittest

from artscan import cli
from artscan.probes import PROBES, Finding
from artscan.report import to_markdown
from artscan.scanner import scan
from artscan.targets import SyntheticAgent, hardened_agent, vulnerable_agent

EXPECTED_VULNS = {
    "system_prompt_leak", "role_override", "secret_exfiltration",
    "tool_output_injection", "canary_leak", "off_allowlist_tool",
    "tool_schema_disclosure", "encoded_payload", "pii_echo", "no_rate_limit",
}


class TestScanOracle(unittest.TestCase):
    """The core oracle: vulnerable target -> all 10 findings, hardened -> 0."""

    def test_vulnerable_target_yields_all_findings(self):
        result = scan(vulnerable_agent())
        self.assertEqual({f.probe for f in result.findings}, EXPECTED_VULNS)
        self.assertEqual(result.probes_run, 10)
        self.assertFalse(result.clean)

    def test_hardened_target_is_clean(self):
        result = scan(hardened_agent())
        self.assertTrue(result.clean)
        self.assertEqual(result.probes_run, 10)

    def test_refuses_non_synthetic_target(self):
        with self.assertRaises(TypeError):
            scan(object())

    def test_severity_sort(self):
        result = scan(vulnerable_agent())
        order = {"high": 0, "medium": 1, "low": 2}
        keys = [order[f.severity] for f in result.findings]
        self.assertEqual(keys, sorted(keys))


class TestIndividualFlags(unittest.TestCase):
    """Each flag alone produces exactly its paired finding."""

    def _scan_with(self, **flags):
        agent = SyntheticAgent(
            name="one-flag", system_prompt="secret-prompt",
            allowed_tools=["search"], secrets={"K": "V"}, **flags)
        return scan(agent)

    def test_only_system_prompt_leak(self):
        r = self._scan_with(leaks_system_prompt=True)
        self.assertEqual([f.probe for f in r.findings], ["system_prompt_leak"])

    def test_only_off_allowlist(self):
        r = self._scan_with(calls_unknown_tools=True)
        self.assertEqual([f.probe for f in r.findings], ["off_allowlist_tool"])

    def test_only_canary(self):
        r = self._scan_with(leaks_canary=True)
        self.assertEqual([f.probe for f in r.findings], ["canary_leak"])

    def test_only_rate_limit(self):
        r = self._scan_with(no_rate_limit=True)
        self.assertEqual([f.probe for f in r.findings], ["no_rate_limit"])

    def test_no_flags_clean(self):
        self.assertTrue(self._scan_with().clean)


class TestReportAndCli(unittest.TestCase):
    def test_report_contains_findings_and_scope_note(self):
        md = to_markdown(scan(vulnerable_agent()))
        self.assertIn("10 findings", md)
        self.assertIn("synthetic self-owned target only", md)
        self.assertIn("system_prompt_leak", md)
        # secrets must not appear in the report
        self.assertNotIn("hunter2-demo", md)
        self.assertNotIn("sk-demo-not-real", md)

    def test_cli_vulnerable_exit_1(self):
        self.assertEqual(cli.main(["run", "--target", "vulnerable"]), 1)

    def test_cli_hardened_exit_0(self):
        self.assertEqual(cli.main(["run", "--target", "hardened"]), 0)

    def test_cli_writes_report(self):
        with tempfile.TemporaryDirectory() as d:
            out = os.path.join(d, "r.md")
            cli.main(["run", "--target", "vulnerable", "--report", out])
            with open(out) as f:
                self.assertIn("Red-team scan", f.read())


if __name__ == "__main__":
    unittest.main()
