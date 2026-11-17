"""EDA event contract for confirmed security drift (spec section 7).

Events contain identifiers and references only: schema version/type, numeric
device ID, fixed control ID, policy hash, source audit job ID, topology
generation, creation time, and correlation ID. They never carry executable
commands or authorization flags, and EDA can only launch the remediation
workflow from a fresh event.
"""

from __future__ import annotations

import re
from collections.abc import Mapping
from datetime import datetime, timezone

from ansible_collections.demo.network.plugins.filter.security_policy import (
    _timestamp,
)

EVENT_SCHEMA_VERSION = 1
EVENT_TYPE = "netbox.security.drift"
CONTROL_ID = "SEC-WEBUI-001"
DEFAULT_MAX_AGE = 600  # seconds; event freshness is short (~10 minutes)
SHA256 = re.compile(r"^[0-9a-f]{64}$")

# Events requesting action, not authorization: these keys must never appear.
FORBIDDEN_KEYS = {
    "commands",
    "command",
    "approved",
    "approved_plan",
    "authorized",
    "authorization",
    "remediate",
}


def _utc_now():
    return datetime.now(timezone.utc)


def security_event_validate(event, now=None, max_age=DEFAULT_MAX_AGE):
    """Validate an event against the contract, including freshness."""
    if not isinstance(now, datetime):
        now = _timestamp(now) if now else None

    def invalid(message):
        return {"valid": False, "stale": False, "errors": [message]}

    if not isinstance(event, Mapping) or not event:
        return invalid("missing or malformed event")

    errors = []
    leaked = FORBIDDEN_KEYS & set(event)
    if leaked:
        errors.append("event carries forbidden keys: " + ", ".join(sorted(leaked)))

    if event.get("schema_version") != EVENT_SCHEMA_VERSION:
        errors.append("schema_version must be " + str(EVENT_SCHEMA_VERSION))
    if event.get("type") != EVENT_TYPE:
        errors.append("type must be '" + EVENT_TYPE + "'")
    device_id = event.get("device_id")
    if not isinstance(device_id, int) or isinstance(device_id, bool) or device_id <= 0:
        errors.append("device_id must be a numeric NetBox device ID")
    if event.get("control_id") != CONTROL_ID:
        errors.append("control_id must be the fixed control " + CONTROL_ID)
    if not SHA256.match(str(event.get("policy_hash") or "")):
        errors.append("policy_hash must be a sha256 hex digest")
    audit_job_id = event.get("audit_job_id")
    if (
        not isinstance(audit_job_id, int)
        or isinstance(audit_job_id, bool)
        or audit_job_id <= 0
    ):
        errors.append("audit_job_id must be a positive AAP job ID")
    if not event.get("topology_generation") or not isinstance(
        event["topology_generation"], str
    ):
        errors.append("topology_generation is required")
    if not event.get("correlation_id") or not isinstance(event["correlation_id"], str):
        errors.append("correlation_id is required")

    created = _timestamp(event.get("created_at"))
    if created is None:
        errors.append("created_at must be a valid UTC timestamp")

    stale = False
    if now is not None and created is not None:
        age = (now - created).total_seconds()
        stale = age < -60 or age > max_age
        if stale:
            errors.append(
                "event is outside the freshness window of " + str(max_age) + "s"
            )

    return {"valid": not errors, "stale": stale, "errors": errors}


class FilterModule:
    def filters(self):
        return {
            "security_event_validate": security_event_validate,
        }
