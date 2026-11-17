"""Parse IOS-XE HTTP/HTTPS/SSH service status into the security audit contract.

The audit role runs ``show ip http server status`` and ``show ip ssh`` over SSH
and passes both module results to ``demo.network.security_webui_status``.

Contract (spec section 7): the assessment result is ``pass`` (both Web UI
services disabled), ``fail`` (confirmed drift), or ``error`` (assessment
failure). Unknown or ambiguous output, truncated responses, and failed or
unreachable commands are never a pass. SSH availability is an observation for
verification, not drift.

The parser accepts the documented IOS-XE status output shapes only. No output
has been captured from the demo C8000V yet; the accepted shapes are provisional
and must be validated against the real device in stage 3.
"""

from __future__ import annotations

import re

HTTP_STATUS_ANCHOR = re.compile(r"(?m)^HTTP server status:\s*(.+?)\s*$")
HTTPS_STATUS_ANCHOR = re.compile(r"(?m)^HTTP secure server status:\s*(.+?)\s*$")
SSH_STATUS_ANCHOR = re.compile(
    r"(?m)^SSH (Enabled|Disabled)(?:\s+-\s+version\s+(\S+))?\s*$"
)

SERVICE_STATES = {"Enabled": "enabled", "Disabled": "disabled"}


def _failed(result):
    return bool(result.get("failed") or result.get("unreachable"))


def _output(result):
    """Return the command output as a single string, or None if unusable."""
    stdout = result.get("stdout")
    if isinstance(stdout, str):
        return stdout
    if isinstance(stdout, list) and stdout:
        if len(stdout) > 1:
            return None  # one command expected; multiple responses are ambiguous
        return stdout[0] if isinstance(stdout[0], str) else None
    return None


def _status_from_anchor(anchor, output):
    """Resolve exactly one anchor match into a service state.

    Returns (state, detail). ``state`` is enabled/disabled, or unknown when the
    anchor is missing (truncated/foreign output) or matches more than once or
    carries an unrecognized value (ambiguous output).
    """
    if output is None:
        return "unknown", "missing or unusable command output"
    matches = anchor.findall(output)
    if len(matches) > 1:
        return "unknown", "ambiguous output: multiple status lines"
    if not matches:
        return "unknown", "truncated or unrecognized output: status line absent"
    value = matches[0] if isinstance(matches[0], str) else matches[0][0]
    state = SERVICE_STATES.get(value)
    if state is None:
        return "unknown", "unrecognized status value: " + value
    return state, "reported " + value


def _service_error(result):
    if _failed(result):
        return str(result.get("msg") or "command failed")
    return None


def security_webui_status(results):
    """Build the audit status contract from the two collected command results.

    ``results`` maps ``http_status`` and ``ssh_status`` to ios_command results.
    Returns per-service states, the overall audit status, whether confirmed
    drift requires remediation, and a list of assessment errors (sanitized
    enough for evidence: messages are truncated and never echoed wholesale).
    """
    results = results or {}
    http_result = results.get("http_status") or {}
    ssh_result = results.get("ssh_status") or {}

    errors = []
    for name, result in (("http_status", http_result), ("ssh_status", ssh_result)):
        command_error = _service_error(result)
        if command_error:
            errors.append(name + ": " + command_error[:200])

    output = _output(http_result)
    http_state, http_detail = _status_from_anchor(HTTP_STATUS_ANCHOR, output)
    # Some IOS-XE builds omit the secure-server section entirely when the
    # HTTPS service is disabled; a missing line is treated as unknown until
    # validated against the demo image (stage 3).
    https_state, https_detail = _status_from_anchor(HTTPS_STATUS_ANCHOR, output)
    ssh_output = _output(ssh_result)
    ssh_matches = (
        SSH_STATUS_ANCHOR.findall(ssh_output) if isinstance(ssh_output, str) else []
    )
    if len(ssh_matches) > 1 or not ssh_matches:
        ssh_state, ssh_version = "unknown", None
        ssh_detail = (
            "ambiguous output: multiple status lines"
            if len(ssh_matches) > 1
            else "truncated or unrecognized output: status line absent"
        )
        if not _service_error(ssh_result):
            errors.append("ssh_status: " + ssh_detail)
    else:
        ssh_state = ssh_matches[0][0].lower()
        ssh_version = ssh_matches[0][1] or None
        ssh_detail = "reported " + ssh_matches[0][0]

    if errors:
        audit_status = "error"
    elif "unknown" in (http_state, https_state):
        audit_status = "error"
        errors.append("http_status: " + http_detail)
        if https_state == "unknown":
            errors.append("https_status: " + https_detail)
    elif http_state == "enabled" or https_state == "enabled":
        audit_status = "fail"
    else:
        audit_status = "pass"

    return {
        "http": {"service": "http", "state": http_state, "detail": http_detail},
        "https": {"service": "https", "state": https_state, "detail": https_detail},
        "ssh": {
            "service": "ssh",
            "state": ssh_state,
            "version": ssh_version,
            "detail": ssh_detail,
        },
        "audit_status": audit_status,
        "remediation_required": audit_status == "fail",
        "errors": errors,
    }


class FilterModule:
    def filters(self):
        return {
            "security_webui_status": security_webui_status,
        }
