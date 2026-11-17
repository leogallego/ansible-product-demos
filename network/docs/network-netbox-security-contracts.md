# NetBox Network Security — Stage 1 contracts

Stage 1 deliverable per `specs/netbox-network-security.md` (§7 and review
finding #14): the per-node inventory/EE assignment table and the measurable
runtime/timeout budgets for the presenter-facing security jobs. Proposed
location: `network/docs/`, alongside the other Network demo contracts; the
registration document (`network-netbox-security.md`) follows at a later stage
per spec §10.

All budgets below are **targets** to be measured and adjusted during live
acceptance (spec §11, live check 1). They exclude human approval wait by
definition; the approval node has its own native 60-minute timeout.

## Per-node inventory and EE assignment

New jobs are assigned to two execution environments **by dependency, not job class** (spec §6 decision record):

- **EE-A** — `registry.redhat.io/ansible-automation-platform-27/ee-supported-rhel9`, pinned to a specific tag (latest known build 2026-10-30; final pinned tag recorded after verification). Zero build — Red Hat maintains it. Contents cover the AWS/AAP/EDA-side jobs (`amazon.aws` 10.3.0, `ansible.posix` 2.2.2, `ansible.controller` 4.8.12, `ansible.eda` 2.12.1, `cisco.ios` 11.3.0, `ansible.netcommon` 8.6.2, plus `paramiko`/`ncclient`/`pytz`/`packaging`). It lacks `netbox.netbox`, `pynetbox`, and `containers.podman` — no EE-A job needs them.
- **EE-B** — the dedicated **NetBox Security EE** (`apd-netbox-ee`, built in the user's ee-builds fork; definition record `execution_environments/apd-ee-netbox.yml`). Carries `netbox.netbox==3.23.1`, `pynetbox`, `cisco.ios`, `ansible.netcommon`, `paramiko` and nothing more.

The two EEs never share an inventory assignment: bootstrap jobs run on `localhost`/AWS control, device-security jobs on the NetBox Security Inventory.

| Job | Inventory | EE | Notes |
|---|---|---|---|
| NetBox Security Inventory (source) | — | EE-B (`apd-netbox-ee`) | Source file `network/netbox_security/inventory/netbox.yml`; explicit sync before Plan and Apply |
| NetBox inventory preflight | localhost | EE-B (`apd-netbox-ee`) | Rejects empty/unauthorized/missing-data inventories before any device play |
| Setup Lab (workflow) | per chained template | per chained template | Workflow composition only — chains existing Network templates (Product Demos EE, unchanged) plus the new NetBox/EDA templates below |
| Provision NetBox (EC2/SG/Compose/systemd) | localhost / AWS control | EE-A | `localhost` + AWS credentials; podman lives on the EC2 instance, not in the EE; must never depend on NetBox inventory that does not exist yet |
| Configure NetBox (on-instance) | provisioned instance | EE-A | Compose/systemd configuration via SSH; no NetBox dependency |
| Seed NetBox | localhost | EE-B (`apd-netbox-ee`) | NetBox object creation; first job needing `netbox.netbox` |
| Configure EDA | localhost / AWS control | EE-A | Controller/EDA registration; no NetBox inventory dependency |
| Cleanup — AWS/AAP side | localhost / AWS control | EE-A | Instance/SG/AAP-EDA teardown; split from NetBox-object cleanup |
| Cleanup — NetBox objects | localhost | EE-B (`apd-netbox-ee`) | NetBox-object removal via `netbox.netbox`; split avoids loading EE-B with AWS dependencies |
| Audit | NetBox Security Inventory | EE-B (`apd-netbox-ee`) | Read-only on devices; launches with no survey |
| Plan | NetBox Security Inventory | EE-B (`apd-netbox-ee`) | Fresh sync, intent/device reads, trusted deployment checks |
| Apply | NetBox Security Inventory | EE-B (`apd-netbox-ee`) | Workflow-only; revalidates then writes |
| Prepare Drift | NetBox Security Inventory | EE-B (`apd-netbox-ee`) | Presenter-launched lab-only enable adapter (separately authorized, stage 3) |
| Existing Network templates (Deploy, Configure Devices, Validate, Report, Backup, Troubleshoot, Destroy) | unchanged (ContainerLab Inventory etc.) | Product Demos EE | Untouched; Configure Devices keeps `save_when: modified` — races with security jobs are covered by the admission/maintenance procedure (spec §7) |
| Existing Staging / Upgrade jobs | unchanged | Product Demos EE | Not invoked by this scenario |

Rules enforced by this table:

- Bootstrap jobs run on `localhost`/AWS control and must never require the
  NetBox Security Inventory (avoids bootstrap circularity).
- Device-security jobs always target the NetBox Security Inventory; a play
  matching zero eligible hosts is an error, never a silent success (the
  inventory plugin turns HTTP 403 into empty lists — the localhost preflight
  rejects empty/unauthorized inventories before any device play).
- No existing template changes inventory or EE.

## Runtime and timeout budgets

Fail-fast budgets sized to a conference walkthrough. Inherited long waits
(device boot: 900–1800 s in the catalog) belong only to setup jobs and are
excluded here.

| Runtime element | Budget (target) | AAP timeout | Clock origin |
|---|---|---|---|
| NetBox Security Inventory sync | ≤ 60 s | 120 s | Sync start |
| Audit job | ≤ 90 s | 300 s | Job start |
| Plan job | ≤ 120 s | 300 s | Job start |
| Apply job (revalidate, backup, write, verify, evidence) | ≤ 180 s | 420 s | Job start |
| Prepare Drift job | ≤ 60 s | 180 s | Job start |
| Remediation workflow, device work total (sync + plan + sync + apply) | ≤ 8 min | — | Workflow start |
| Approval node | excluded (human) | 60 min native | Approval node start |
| Plan validity | — | 60 min max | Plan job completion |
| Event freshness | ~10 min | — | Audit event creation (contract `max_age=600`) |

Notes:

- An approval accepted within its native timeout can still reach an expired
  plan (post-approval sync and queueing consume budget); the workflow displays
  remaining validity and treats late approval as safe reassessment, not an
  approval failure.
- Budgets are enforced through fail-fast job timeouts on the new templates;
  timeouts are safety bounds, not performance claims. Measured actuals are
  recorded in the stage 6 acceptance run and this table updated.
- `Workflow job template timeout` is intentionally not set on the workflow:
  human approval wait must not be bounded by a device-work timeout.

## Stage 1 outputs

| Artifact | Path | Validation status |
|---|---|---|
| Web UI status parser | `collections/ansible_collections/demo/network/plugins/filter/security_webui.py` | Offline fixtures only — fixtures are provisional (documented IOS-XE shapes); **stage 3 must validate against the real C8000V** |
| Intent/policy contract | `plugins/filter/security_policy.py` (same collection) | Offline; canonical sha256 over the effective merged policy |
| Plan / launch-input contract | `plugins/filter/security_plan.py` | Offline; disable-only command allowlist; 60-minute validity |
| EDA event contract | `plugins/filter/security_event.py` | Offline; freshness 600 s; event type/schema are proposed and confirmed at stage 4 against the actual DE |
| Evidence contract | `plugins/filter/security_evidence.py` | Offline; sanitization and required fields |
| Inventory source draft | `network/netbox_security/inventory/netbox.yml` | Structure checks only — stage 2 must validate plugin variable shapes with a live sync |
| Dedicated EE definition | `execution_environments/apd-ee-netbox.yml`, `requirements-netbox.yml` | Redefined for the two-EE model; EE-B image built and published in the pre-Stage-2 session (final tag/digest recorded below once verified). EE-A is a Red Hat-maintained reference image — no definition file, recorded in the assignment table above |
| Tests | `collections/ansible_collections/demo/network/tests/test_security_*.py`, `test_netbox_*.py` | 79 passed + 97 subtests, offline |

## Known gaps (recorded, not guessed)

- AAP 2.7 Controller API details for approval-node/workflow provenance
  validation could not be retrieved from product docs (auth-blocked; spec §6).
  Stage 4 must confirm supported mechanisms against the live Controller.
- `nb_inventory` group-condition Jinja and `device_query_filters` behavior with
  extra vars (`use_extra_vars`) is unverified; the draft documents the
  preflight fallback if group expressions cannot see the deployment extra var.
- Actual `show ip http server status` / `show ip ssh` output shapes on the demo
  C8000V image are unconfirmed (provisional parser fixtures).
