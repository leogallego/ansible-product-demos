"""Offline coverage of the security Web UI parser and status contract.

Fixtures for ``show ip http server status`` and ``show ip ssh`` are PROVISIONAL:
they are derived from documented IOS-XE behavior because no output has been
captured from the demo C8000V yet. Stage 3 must validate every accepted shape
against the real device before this parser gates live remediation.
"""

import importlib.util
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "security_webui", ROOT / "plugins/filter/security_webui.py"
)
SECURITY = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(SECURITY)

# Provisional documented shapes (validated in stage 3 against the demo image).
HTTP_BOTH_ENABLED = """HTTP server status: Enabled
HTTP server port: 80
HTTP server capabilities: ...
HTTP secure server capability: Present
HTTP secure server status: Enabled
HTTP secure server port: 443
"""

HTTP_BOTH_DISABLED = """HTTP server status: Disabled
HTTP server port: 80
HTTP server capabilities: ...
HTTP secure server capability: Present
HTTP secure server status: Disabled
HTTP secure server port: 443
"""

# Mixed drift: the running-config disabled only one of the two services.
HTTP_MIXED = """HTTP server status: Disabled
HTTP server port: 80
HTTP server capabilities: ...
HTTP secure server capability: Present
HTTP secure server status: Enabled
HTTP secure server port: 443
"""

SSH_ENABLED = """SSH Enabled - version 2.0
Authentication timeout: 120 secs; Authentication retries: 3
Minimum expected Diffie Hellman key size : 2048 bits
"""

SSH_DISABLED = """SSH Disabled - version 2.0
"""


def audit(http=HTTP_BOTH_DISABLED, ssh=SSH_ENABLED, **overrides):
    results = {"http_status": {"stdout": [http]}, "ssh_status": {"stdout": [ssh]}}
    results.update(overrides)
    return SECURITY.security_webui_status(results)


class SecurityWebuiStatusTests(unittest.TestCase):
    def test_both_enabled_is_confirmed_drift(self):
        status = audit(http=HTTP_BOTH_ENABLED)
        self.assertEqual(status["audit_status"], "fail")
        self.assertTrue(status["remediation_required"])
        self.assertEqual(status["http"]["state"], "enabled")
        self.assertEqual(status["https"]["state"], "enabled")

    def test_both_disabled_is_pass(self):
        status = audit()
        self.assertEqual(status["audit_status"], "pass")
        self.assertFalse(status["remediation_required"])
        self.assertEqual(status["http"]["state"], "disabled")
        self.assertEqual(status["https"]["state"], "disabled")

    def test_mixed_drift_is_fail_for_either_service(self):
        # Enable exactly one of the two services on the compliant fixture.
        enabled_http_only = HTTP_BOTH_DISABLED.replace(
            "HTTP server status: Disabled", "HTTP server status: Enabled"
        )
        enabled_https_only = HTTP_BOTH_DISABLED.replace(
            "HTTP secure server status: Disabled",
            "HTTP secure server status: Enabled",
        )
        for http, http_state, https_state in (
            (enabled_http_only, "enabled", "disabled"),
            (enabled_https_only, "disabled", "enabled"),
        ):
            with self.subTest(http=http_state, https=https_state):
                status = audit(http=http)
                self.assertEqual(status["audit_status"], "fail")
                self.assertEqual(status["http"]["state"], http_state)
                self.assertEqual(status["https"]["state"], https_state)

    def test_truncated_http_output_is_never_a_pass(self):
        status = audit(http="HTTP server status: Enabled\nHTTP server port: 80\n")
        self.assertEqual(status["audit_status"], "error")
        self.assertEqual(status["https"]["state"], "unknown")
        self.assertFalse(status["remediation_required"])

    def test_unrecognized_status_value_is_never_a_pass(self):
        status = audit(
            http=HTTP_BOTH_DISABLED.replace(
                "HTTP server status: Disabled", "HTTP server status: unknown"
            )
        )
        self.assertEqual(status["audit_status"], "error")
        self.assertEqual(status["http"]["state"], "unknown")

    def test_ambiguous_multiple_status_lines_are_an_error(self):
        status = audit(
            http=HTTP_BOTH_DISABLED + "HTTP server status: Enabled\n",
            ssh=SSH_ENABLED + "SSH Disabled - version 2.0\n",
        )
        self.assertEqual(status["audit_status"], "error")
        self.assertIn("ambiguous", str(status["errors"]))

    def test_empty_output_is_an_error(self):
        status = audit(http="", ssh="")
        self.assertEqual(status["audit_status"], "error")
        self.assertFalse(status["remediation_required"])

    def test_failed_command_is_an_error_not_a_crash(self):
        status = audit(
            http={"failed": True, "msg": "show ip http server status failed"}
        )
        self.assertEqual(status["audit_status"], "error")
        self.assertTrue(any("http_status" in error for error in status["errors"]))
        self.assertFalse(status["remediation_required"])

    def test_unreachable_device_is_an_error(self):
        status = audit(ssh={"unreachable": True, "msg": "Connection refused"})
        self.assertEqual(status["audit_status"], "error")
        self.assertTrue(any("ssh_status" in error for error in status["errors"]))

    def test_missing_results_are_an_error(self):
        for results in ({}, None, {"http_status": {}}):
            with self.subTest(results=results):
                status = SECURITY.security_webui_status(results)
                self.assertEqual(status["audit_status"], "error")

    def test_ssh_state_is_an_observation_not_drift(self):
        status = audit(ssh=SSH_DISABLED)
        self.assertEqual(status["audit_status"], "pass")
        self.assertEqual(status["ssh"]["state"], "disabled")

    def test_ssh_version_is_captured_for_the_sshv2_check(self):
        self.assertEqual(audit()["ssh"]["version"], "2.0")
        status = audit(ssh="SSH Enabled\n")
        self.assertEqual(status["ssh"]["state"], "enabled")
        self.assertIsNone(status["ssh"]["version"])

    def test_contract_shape_is_stable(self):
        status = audit()
        self.assertEqual(
            set(status),
            {
                "http",
                "https",
                "ssh",
                "audit_status",
                "remediation_required",
                "errors",
            },
        )
        for service in ("http", "https", "ssh"):
            self.assertIn("service", status[service])
            self.assertIn("state", status[service])


if __name__ == "__main__":
    unittest.main()
