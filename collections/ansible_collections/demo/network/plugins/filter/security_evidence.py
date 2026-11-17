"""Evidence contract for the security scenario (spec section 8).

Evidence is a compact latest-attempt result published to run-level stats and
NetBox ``security_evidence``. It must retain partial failures, carry job
references and before/after service observations, avoid secrets, and escape
HTML. A parse or writeback failure is never rewritten into a compliance pass.
"""

from __future__ import annotations

import html
import re
from collections.abc import Mapping

CONTROL_ID = "SEC-WEBUI-001"
REQUIRED_FIELDS = (
    "netbox_device_id",
    "device_name",
    "control_id",
    "policy_hash",
    "policy_revision",
    "management_ip",
    "automation_host",
    "automation_port",
    "topology_generation",
    "timestamp",
    "source_job_id",
    "change_status",
    "save_outcome",
    "services_before",
    "services_after",
)
CHANGE_STATUSES = {"no_change", "changed", "failed"}
SAVE_OUTCOMES = {"not_requested", "saved", "failed"}
SERVICE_STATES = {"enabled", "disabled", "unknown", "error"}
SENSITIVE = re.compile(r"password|secret|community|private.?key|token", re.I)


def _sanitize(value):
    """Escape HTML in strings and redact secret-bearing keys, recursively."""
    if isinstance(value, Mapping):
        return {
            str(key): "[redacted]"
            if SENSITIVE.search(str(key))
            else _sanitize(value[key])
            for key in value
        }
    if isinstance(value, (list, tuple)):
        return [_sanitize(item) for item in value]
    if isinstance(value, str):
        return html.escape(value, quote=True)
    return value


def security_evidence_contract(evidence):
    """Validate the required evidence fields and return the sanitized copy."""
    if not isinstance(evidence, Mapping) or not evidence:
        return {
            "valid": False,
            "evidence": {},
            "errors": ["missing or malformed evidence"],
        }

    errors = []
    for field in REQUIRED_FIELDS:
        if field not in evidence or evidence[field] in (None, ""):
            errors.append("missing required field: " + field)
    if evidence.get("control_id") != CONTROL_ID:
        errors.append("control_id must be the fixed control " + CONTROL_ID)
    if evidence.get("change_status") not in CHANGE_STATUSES:
        errors.append(
            "change_status must be one of: " + ", ".join(sorted(CHANGE_STATUSES))
        )
    if evidence.get("save_outcome") not in SAVE_OUTCOMES:
        errors.append(
            "save_outcome must be one of: " + ", ".join(sorted(SAVE_OUTCOMES))
        )
    for observation in ("services_before", "services_after"):
        services = evidence.get(observation)
        if not isinstance(services, Mapping) or not services:
            errors.append(observation + " must record observed service states")
            continue
        for service, state in services.items():
            if state not in SERVICE_STATES:
                errors.append(
                    observation
                    + "."
                    + str(service)
                    + " must be one of: "
                    + ", ".join(sorted(SERVICE_STATES))
                )

    return {"valid": not errors, "evidence": _sanitize(evidence), "errors": errors}


class FilterModule:
    def filters(self):
        return {
            "security_evidence_contract": security_evidence_contract,
        }
