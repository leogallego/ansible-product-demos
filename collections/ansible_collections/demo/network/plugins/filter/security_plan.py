"""Plan and launch-input contracts for the NetBox security workflow.

A plan binds exactly one device, its endpoints, ownership, observed state,
policy hash/revision, and the exact command allowlist, with explicit issue and
expiry clocks (spec section 7). Apply re-validates the plan and re-computes the
policy hash immediately before writing; any change in policy, endpoints,
identity, generation, or expiry stops execution.

The configurable command payload is ONLY the two disable commands. Positive
enable commands can never enter the allowlist: ``Prepare Drift`` is a
separately authorized stage 3 adapter outside this contract.
"""

from __future__ import annotations

import ipaddress
import re
from collections.abc import Mapping
from datetime import datetime

from ansible_collections.demo.network.plugins.filter.security_policy import (
    _timestamp,
    security_policy_hash,
)

REMEDIATION_COMMANDS = ("no ip http server", "no ip http secure-server")
PLAN_VALIDITY_LIMIT = 3600  # seconds; spec section 7: both limits are 60 minutes
SHA256 = re.compile(r"^[0-9a-f]{64}$")

# Launch inputs are limited to expected scalar identifiers/references;
# arbitrary variables and authorization claims never reach Apply.
LAUNCH_INPUT_KEYS = {
    "workflow_job_id",
    "plan_job_id",
    "source_audit_job_id",
    "correlation_id",
    "event_id",
}


def security_plan_validate(plan, now=None):
    """Validate a plan artifact against the stage 1 contract."""
    if not isinstance(now, datetime):
        now = _timestamp(now) if now else None

    def invalid(message):
        return {
            "valid": False,
            "expired": False,
            "commands": [],
            "errors": [message],
        }

    if not isinstance(plan, Mapping) or not plan:
        return invalid("missing or malformed plan")

    errors = []
    if (
        not isinstance(plan.get("netbox_device_id"), int)
        or isinstance(plan.get("netbox_device_id"), bool)
        or plan["netbox_device_id"] <= 0
    ):
        errors.append("netbox_device_id must be a positive integer")
    if not plan.get("device_name") or not isinstance(plan["device_name"], str):
        errors.append("device_name is required")
    try:
        ipaddress.IPv4Address(plan.get("management_ip"))
    except (ipaddress.AddressValueError, TypeError, ValueError):
        errors.append("management_ip must be a valid IPv4 address")
    if not plan.get("automation_host") or not isinstance(plan["automation_host"], str):
        errors.append("automation_host is required")
    port = plan.get("automation_port")
    if not isinstance(port, int) or isinstance(port, bool) or not 1 <= port <= 65535:
        errors.append("automation_port must be a TCP port")
    if not plan.get("topology_generation") or not isinstance(
        plan["topology_generation"], str
    ):
        errors.append("topology_generation is required")
    if not SHA256.match(str(plan.get("policy_hash") or "")):
        errors.append("policy_hash must be a sha256 hex digest")
    if (
        not isinstance(plan.get("policy_revision"), int)
        or isinstance(plan["policy_revision"], bool)
        or plan["policy_revision"] <= 0
    ):
        errors.append("policy_revision must be a positive integer")
    for key in ("source_job_id", "plan_job_id"):
        value = plan.get(key)
        if not isinstance(value, int) or isinstance(value, bool) or value <= 0:
            errors.append(key + " must be a positive AAP job ID")

    issued = _timestamp(plan.get("issued_at"))
    expiry = _timestamp(plan.get("expiry_at"))
    if issued is None or expiry is None:
        errors.append("issued_at/expiry_at must be valid UTC timestamps")
    elif expiry <= issued:
        errors.append("expiry_at must be after issued_at")
    elif (expiry - issued).total_seconds() > PLAN_VALIDITY_LIMIT:
        errors.append("plan validity exceeds the 60-minute limit")

    commands = plan.get("commands")
    if commands != list(REMEDIATION_COMMANDS):
        errors.append(
            "commands must be exactly the fixed allowlist: "
            + ", ".join(REMEDIATION_COMMANDS)
        )

    expired = bool(now is not None and expiry is not None and now >= expiry)
    return {
        "valid": not errors,
        "expired": expired,
        "commands": list(commands or []),
        "errors": errors,
    }


def security_command_allowed(plan, command):
    """Only the exact fixed commands of a valid-shaped plan are permitted."""
    return (
        isinstance(plan, Mapping)
        and tuple(plan.get("commands") or ()) == REMEDIATION_COMMANDS
        and command in REMEDIATION_COMMANDS
    )


def security_plan_policy_matches(plan, policy):
    """Recomputed from the effective merged policy, not trusted from the plan."""
    return isinstance(plan, Mapping) and security_policy_hash(policy) == plan.get(
        "policy_hash"
    )


def security_launch_inputs_validate(inputs):
    """Reject launch inputs outside the scalar identifier allowlist."""
    if not isinstance(inputs, Mapping):
        return {"valid": False, "errors": ["launch inputs must be a mapping"]}
    errors = []
    for key, value in inputs.items():
        if key not in LAUNCH_INPUT_KEYS:
            errors.append("unexpected launch input: " + str(key))
        elif isinstance(value, bool) or not isinstance(value, (str, int)):
            errors.append("launch input " + str(key) + " must be a scalar identifier")
        elif isinstance(value, str) and len(value) > 128:
            errors.append("launch input " + str(key) + " is too long")
    return {"valid": not errors, "errors": errors}


class FilterModule:
    def filters(self):
        return {
            "security_plan_validate": security_plan_validate,
            "security_command_allowed": security_command_allowed,
            "security_plan_policy_matches": security_plan_policy_matches,
            "security_launch_inputs_validate": security_launch_inputs_validate,
        }
