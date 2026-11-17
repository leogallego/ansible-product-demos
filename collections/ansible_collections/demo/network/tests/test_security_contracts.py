"""Offline coverage of the intent, plan, event, and evidence contracts."""

import importlib.util
from pathlib import Path
import sys
import unittest

REPO = Path(__file__).resolve().parents[5]
sys.path.insert(0, str(REPO / "collections"))


def load(name):
    spec = importlib.util.spec_from_file_location(
        name,
        REPO / f"collections/ansible_collections/demo/network/plugins/filter/{name}.py",
    )
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


POLICY_FILTER = load("security_policy")
PLAN_FILTER = load("security_plan")
EVENT_FILTER = load("security_event")
EVIDENCE_FILTER = load("security_evidence")

T0 = "2026-11-17T10:00:00Z"
T1 = "2026-11-17T10:30:00Z"
T2 = "2026-11-17T10:59:00Z"
T3 = "2026-11-17T12:00:00Z"

BASE_POLICY = {
    "policy_id": "webui-disabled",
    "revision": 1,
    "control_id": "SEC-WEBUI-001",
    "desired_state": "disabled",
    "required_for_services": False,
    "change_window": {"start": T0, "end": T3},
}


def plan(policy=BASE_POLICY):
    return {
        "netbox_device_id": 7,
        "device_name": "cat8kv1",
        "management_ip": "172.20.20.12",
        "automation_host": "10.0.0.50",
        "automation_port": 2123,
        "topology_generation": "gen-42",
        "policy_hash": POLICY_FILTER.security_policy_hash(policy),
        "policy_revision": 1,
        "commands": ["no ip http server", "no ip http secure-server"],
        "source_job_id": 101,
        "plan_job_id": 202,
        "issued_at": T1,
        "expiry_at": T2,
    }


def event():
    return {
        "schema_version": 1,
        "type": "netbox.security.drift",
        "device_id": 7,
        "control_id": "SEC-WEBUI-001",
        "policy_hash": POLICY_FILTER.security_policy_hash(BASE_POLICY),
        "audit_job_id": 101,
        "topology_generation": "gen-42",
        "created_at": T1,
        "correlation_id": "corr-abc",
    }


def evidence():
    return {
        "netbox_device_id": 7,
        "device_name": "cat8kv1",
        "control_id": "SEC-WEBUI-001",
        "policy_hash": "a" * 64,
        "policy_revision": 1,
        "management_ip": "172.20.20.12",
        "automation_host": "10.0.0.50",
        "automation_port": 2123,
        "topology_generation": "gen-42",
        "timestamp": T1,
        "source_job_id": 101,
        "change_status": "no_change",
        "save_outcome": "not_requested",
        "services_before": {"http": "enabled", "https": "enabled"},
        "services_after": {"http": "disabled", "https": "disabled"},
    }


class PolicyContractTests(unittest.TestCase):
    def test_valid_policy_is_writable_inside_its_window(self):
        result = POLICY_FILTER.security_policy_validate(BASE_POLICY, now=T1)
        self.assertTrue(result["valid"])
        self.assertTrue(result["writable"])
        self.assertTrue(result["window_active"])

    def test_hash_covers_the_whole_effective_policy(self):
        override = {
            **BASE_POLICY,
            "desired_state": "disabled",
            "extra_override": {"x": 1},
        }
        self.assertNotEqual(
            POLICY_FILTER.security_policy_hash(BASE_POLICY),
            POLICY_FILTER.security_policy_hash(override),
        )
        # Identical revision, different effective document: hash must differ.
        self.assertEqual(BASE_POLICY["revision"], override["revision"])

    def test_missing_or_malformed_policy_is_an_error(self):
        for policy in ({}, None, "disabled", []):
            with self.subTest(policy=policy):
                result = POLICY_FILTER.security_policy_validate(policy)
                self.assertFalse(result["valid"])
                self.assertFalse(result["writable"])

    def test_required_services_block_writes_but_stay_reportable(self):
        policy = {**BASE_POLICY, "required_for_services": True}
        result = POLICY_FILTER.security_policy_validate(policy, now=T1)
        self.assertTrue(result["valid"])
        self.assertFalse(result["writable"])

    def test_expired_window_blocks_writes_not_assessment(self):
        result = POLICY_FILTER.security_policy_validate(
            BASE_POLICY, now="2026-11-18T10:00:00Z"
        )
        self.assertTrue(result["valid"])
        self.assertFalse(result["writable"])
        self.assertFalse(result["window_active"])

    def test_malformed_fields_are_rejected(self):
        for field, value in (
            ("policy_id", "has spaces"),
            ("revision", 0),
            ("revision", "1"),
            ("control_id", "SEC-OTHER-001"),
            ("desired_state", "enabled"),
            ("required_for_services", "no"),
            ("change_window", {"start": T3, "end": T0}),
        ):
            with self.subTest(field=field):
                policy = {**BASE_POLICY, field: value}
                self.assertFalse(
                    POLICY_FILTER.security_policy_validate(policy, now=T1)["valid"]
                )


class PlanContractTests(unittest.TestCase):
    def test_valid_plan(self):
        result = PLAN_FILTER.security_plan_validate(plan(), now=T1)
        self.assertTrue(result["valid"])
        self.assertFalse(result["expired"])
        self.assertEqual(
            result["commands"], ["no ip http server", "no ip http secure-server"]
        )

    def test_expired_plan_is_detected_for_write_blocking(self):
        result = PLAN_FILTER.security_plan_validate(plan(), now=T3)
        self.assertTrue(result["expired"])
        self.assertTrue(result["valid"])  # shape is valid; only the clock expired

    def test_validity_over_60_minutes_is_rejected(self):
        long_plan = {**plan(), "expiry_at": "2026-11-17T11:31:00Z"}
        self.assertFalse(PLAN_FILTER.security_plan_validate(long_plan)["valid"])

    def test_only_the_fixed_disable_allowlist_is_permitted(self):
        for commands in (
            ["ip http server", "ip http secure-server"],
            ["no ip http server"],
            ["no ip http server", "no ip http secure-server", "no ip ssh"],
            ["no ip http server; no ip http secure-server"],
            [],
        ):
            with self.subTest(commands=commands):
                bad = {**plan(), "commands": commands}
                self.assertFalse(PLAN_FILTER.security_plan_validate(bad)["valid"])
        self.assertTrue(
            PLAN_FILTER.security_command_allowed(plan(), "no ip http secure-server")
        )
        for command in (
            "ip http server",
            "no ip http server ",
            "no ip http secure-server --force",
            "copy running-config tftp:",
        ):
            with self.subTest(command=command):
                self.assertFalse(PLAN_FILTER.security_command_allowed(plan(), command))

    def test_forged_plan_data_is_rejected(self):
        for field, value in (
            ("netbox_device_id", "cat8kv1"),
            ("netbox_device_id", -1),
            ("management_ip", "not-an-ip"),
            ("automation_port", 70000),
            ("automation_port", "2123"),
            ("topology_generation", ""),
            ("policy_hash", "short"),
            ("policy_revision", 0),
            ("source_job_id", "x"),
            ("expiry_at", "not-a-time"),
        ):
            with self.subTest(field=field):
                forged = {**plan(), field: value}
                result = PLAN_FILTER.security_plan_validate(forged, now=T2)
                self.assertFalse(result["valid"])

    def test_policy_change_is_detected_against_the_plan(self):
        self.assertTrue(PLAN_FILTER.security_plan_policy_matches(plan(), BASE_POLICY))
        changed = {**BASE_POLICY, "revision": 2, "required_for_services": True}
        self.assertFalse(PLAN_FILTER.security_plan_policy_matches(plan(), changed))

    def test_launch_inputs_are_limited_to_scalar_identifiers(self):
        ok = PLAN_FILTER.security_launch_inputs_validate(
            {"plan_job_id": 202, "correlation_id": "corr-abc"}
        )
        self.assertTrue(ok["valid"])
        for inputs in (
            {"approved": True},
            {"approved_plan": {"commands": ["ip http server"]}},
            {"extra_vars": {"anything": 1}},
            {"plan_job_id": {"nested": "dict"}},
            {"plan_job_id": ["list"]},
            {"commands": ["ip http server"]},
        ):
            with self.subTest(inputs=inputs):
                self.assertFalse(
                    PLAN_FILTER.security_launch_inputs_validate(inputs)["valid"]
                )


class EventContractTests(unittest.TestCase):
    def test_valid_fresh_event(self):
        result = EVENT_FILTER.security_event_validate(event(), now=T1)
        self.assertTrue(result["valid"])
        self.assertFalse(result["stale"])

    def test_stale_event_is_rejected(self):
        result = EVENT_FILTER.security_event_validate(event(), now=T3)
        self.assertFalse(result["valid"])
        self.assertTrue(result["stale"])

    def test_future_dated_event_is_stale(self):
        result = EVENT_FILTER.security_event_validate(event(), now=T0)
        self.assertFalse(result["valid"])
        self.assertTrue(result["stale"])

    def test_events_carry_no_commands_or_authorization_flags(self):
        for key, value in (
            ("commands", ["no ip http server"]),
            ("approved", True),
            ("approved_plan", {"x": 1}),
            ("authorized", "yes"),
        ):
            with self.subTest(key=key):
                result = EVENT_FILTER.security_event_validate({**event(), key: value})
                self.assertFalse(result["valid"])
                self.assertTrue(any("forbidden" in error for error in result["errors"]))

    def test_malformed_event_fields_are_rejected(self):
        for field, value in (
            ("schema_version", 2),
            ("type", "something.else"),
            ("device_id", "cat8kv1"),
            ("device_id", 0),
            ("control_id", "SEC-OTHER-001"),
            ("policy_hash", "z" * 64),
            ("audit_job_id", 0),
            ("correlation_id", ""),
            ("created_at", "not-a-time"),
        ):
            with self.subTest(field=field):
                self.assertFalse(
                    EVENT_FILTER.security_event_validate({**event(), field: value})[
                        "valid"
                    ]
                )

    def test_missing_event_is_an_error(self):
        for empty in ({}, None):
            with self.subTest(empty=empty):
                self.assertFalse(EVENT_FILTER.security_event_validate(empty)["valid"])


class EvidenceContractTests(unittest.TestCase):
    def test_valid_evidence_survives_sanitization(self):
        result = EVIDENCE_FILTER.security_evidence_contract(evidence())
        self.assertTrue(result["valid"])
        self.assertEqual(result["evidence"]["device_name"], "cat8kv1")

    def test_missing_required_fields_are_rejected(self):
        for field in EVIDENCE_FILTER.REQUIRED_FIELDS:
            with self.subTest(field=field):
                incomplete = {k: v for k, v in evidence().items() if k != field}
                result = EVIDENCE_FILTER.security_evidence_contract(incomplete)
                self.assertFalse(result["valid"])
                self.assertIn("missing required field: " + field, result["errors"])

    def test_change_status_and_save_outcome_are_constrained(self):
        for field, value in (("change_status", "pass"), ("save_outcome", "maybe")):
            with self.subTest(field=field):
                self.assertFalse(
                    EVIDENCE_FILTER.security_evidence_contract(
                        {**evidence(), field: value}
                    )["valid"]
                )

    def test_partial_failure_is_representable_not_a_pass(self):
        failed = {
            **evidence(),
            "change_status": "failed",
            "services_after": {"http": "enabled", "https": "error"},
        }
        result = EVIDENCE_FILTER.security_evidence_contract(failed)
        self.assertTrue(result["valid"])
        self.assertEqual(result["evidence"]["change_status"], "failed")
        self.assertEqual(result["evidence"]["services_after"]["https"], "error")

    def test_evidence_escapes_html_and_redacts_secrets(self):
        hostile = {
            **evidence(),
            "device_name": '<script>alert("x")</script>',
            "credentials": {"password": "sensitive-value"},
        }
        result = EVIDENCE_FILTER.security_evidence_contract(hostile)
        serialized = str(result["evidence"])
        self.assertNotIn("<script>", serialized)
        self.assertIn("&lt;script&gt;", serialized)
        self.assertNotIn("sensitive-value", serialized)
        self.assertIn("[redacted]", serialized)


if __name__ == "__main__":
    unittest.main()
