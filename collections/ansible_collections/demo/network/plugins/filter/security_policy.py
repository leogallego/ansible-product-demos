"""Validate and canonicalize the ``apd_network_security`` intent contract.

The audit and plan roles pass the *effective merged* policy (NetBox config
context including any overrides) to ``demo.network.security_policy_validate``.
The hash covers the entire effective policy document, not just the revision:
revision alone is insufficient to detect intent changes (spec section 5).

Missing or malformed policy is an error. ``required_for_services: true`` is
blocked/report-only. An expired change window prohibits writes but not
read-only assessment.
"""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Mapping
from datetime import datetime

CONTROL_ID = "SEC-WEBUI-001"
DESIRED_STATE = "disabled"
IDENTIFIER = re.compile(r"^[A-Za-z0-9._-]{1,64}$")


def security_policy_hash(policy):
    """Return the sha256 digest of the canonical effective policy document."""
    canonical = json.dumps(policy, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(canonical.encode()).hexdigest()


def _timestamp(value):
    """Parse an ISO-8601 timestamp; returns an aware datetime or None."""
    if not isinstance(value, str):
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    return parsed if parsed.tzinfo is not None else None


def _window(policy):
    """Return (start, end) aware datetimes, or (None, None) when malformed."""
    window = policy.get("change_window")
    if not isinstance(window, Mapping):
        return None, None
    start = _timestamp(window.get("start"))
    end = _timestamp(window.get("end"))
    if start is None or end is None or start >= end:
        return None, None
    return start, end


def security_policy_validate(policy, now=None):
    """Validate the effective policy and return its contract.

    Returns validity, writability, window state, hash, and errors. The window
    is only evaluated when ``now`` (an aware datetime or ISO string) is given.
    """
    if not isinstance(now, datetime):
        now = _timestamp(now) if now else None

    if not isinstance(policy, Mapping) or not policy:
        return {
            "valid": False,
            "writable": False,
            "report_only": False,
            "window_active": None,
            "policy_hash": None,
            "revision": None,
            "control_id": None,
            "errors": ["missing or malformed apd_network_security policy"],
            "write_blocks": [],
        }

    errors = []
    blocks = []
    policy_id = policy.get("policy_id")
    if not isinstance(policy_id, str) or not IDENTIFIER.match(policy_id):
        errors.append("policy_id must be a short identifier string")
    revision = policy.get("revision")
    if not isinstance(revision, int) or isinstance(revision, bool) or revision <= 0:
        errors.append("revision must be a positive integer")
    control_id = policy.get("control_id")
    if control_id != CONTROL_ID:
        errors.append("control_id must be the fixed control " + CONTROL_ID)
    if policy.get("desired_state") != DESIRED_STATE:
        errors.append("desired_state must be '" + DESIRED_STATE + "'")
    required_for_services = policy.get("required_for_services")
    if not isinstance(required_for_services, bool):
        errors.append("required_for_services must be a boolean")

    start, end = _window(policy)
    if start is None:
        errors.append("change_window must have valid UTC start before end")

    window_active = None
    writable = True
    report_only = required_for_services is True
    if report_only:
        blocks.append("required_for_services is true: control is report-only")
        writable = False
    if now is not None and start is not None:
        window_active = start <= now <= end
        if not window_active:
            blocks.append("change window is not active: writes are blocked")
            writable = False

    return {
        "valid": not errors,
        "writable": writable,
        "report_only": report_only,
        "window_active": window_active,
        "policy_hash": security_policy_hash(policy),
        "revision": revision if isinstance(revision, int) else None,
        "control_id": control_id if control_id == CONTROL_ID else None,
        "errors": errors,
        "write_blocks": blocks,
    }


class FilterModule:
    def filters(self):
        return {
            "security_policy_hash": security_policy_hash,
            "security_policy_validate": security_policy_validate,
        }
