# NetBox Network Security demo specification

**Status:** Agreed design for review; implementation and integration validation pending.

**Target:** Existing APD-provided AAP 2.7, NetBox 4.7.x, and the existing Network lab.

**Boundary:** Specification only. No demo implementation, provisioning, commits, pushes, or PRs are authorized by this document.

## 1. Purpose and attendee experience

> NetBox defines intended network state. Ansible detects drift, requests approval, makes a bounded correction, and verifies the result.

Show one device, one policy, and one approved change. Use existing NetBox and AAP screens rather than building another dashboard.

| Step | What the attendee sees | Point demonstrated |
|---|---|---|
| 1. Inventory | Existing APD devices in NetBox, then the C8000V in AAP's NetBox dynamic inventory | NetBox is an actual automation inventory source |
| 2. Intent | The device policy requires unneeded HTTP/HTTPS management services disabled | Desired state is explicit and separate from observed state |
| 3. Audit | A read-only SSH assessment finds the services enabled | Detection checks the device without changing it |
| 4. Event and approval | An authenticated EDA event starts a workflow showing one device and two commands; the presenter approves | An event requests action, not authorization |
| 5. Remediation | Fresh checks precede disabling the services; SSH remains available | The change is narrow and its effect is verified |
| 6. Evidence | AAP before/after results and approval history, a NetBox evidence reference, and a compliant repeat audit | The loop is auditable and does not repeat unnecessary changes |

The services being disabled are the router's Web UI, not HTTP traffic through the router or the NetBox application. A disabled Web UI proves configuration compliance, not patched firmware or absence of compromise.

Provisioning, inventory setup, and an explicit lab-only **Prepare Drift** job happen outside the main presentation. Existing APD reports are supporting material, not an additional mandatory demo chapter. Manual audit is the initial entry point; scheduling is optional.

## 2. Scope and agreed simplifications

- Reuse APD's Network deployment workflow, hypervisor provisioning, Containerlab, inventory patterns, validation, reporting, and teardown.
- Keep the complete `product_demos` topology. Initially remediate only its C8000V, `cat8kv1`.
- Add persistent NetBox Podman Compose services on that same hypervisor.
- Make NetBox dynamic inventory mandatory for the new security jobs; leave existing jobs on their current inventory.
- Use a dedicated NetBox EE for new jobs and inventory synchronization. Preserve Product Demos EE and existing working dependencies.
- Use restricted **HTTP** access to NetBox, default hypervisor port `8000`, consistent with APD's existing AWS service exposure pattern.
- Use native AAP workflow approval, a short-lived one-device plan, and a disable-only IOS-XE adapter.
- Assume the current hypervisor fits; measure during integration and increase existing provisioning parameters only if necessary.

**Non-goals:** New AAP or OpenShift deployments, a custom topology/provisioning framework, Gitea, exploitation, a deliberately vulnerable image, firmware upgrades, additional vendor remediation adapters, fleet concurrency, scanners/CVE matching, policy engines, ITSM, external evidence archives, or production-readiness claims.

## 3. Reviewed baseline and reuse

Repository instructions and local history were inspected before authoring. Existing changes were preserved.

| Repository | Reviewed baseline | Use |
|---|---|---|
| `~/ai/ansible-product-demos` | `feature/netbox-network-security`, `39b3a50`; clean before this specification | Implementation home; origin `leogallego/ansible-product-demos`, upstream `ansible/product-demos` |
| `~/ai/solution-guides` | `docs/netbox-network-security`, draft commit `c1796eb` | `README-NetBox-Network-Security-Drift.md` is design reference, not working-code evidence; origin `leogallego/ansible-solution-guides`, upstream `ansible-tmm/solution-guides` |
| `~/ai/summit-netbox-circuits-demo` | `fd319db`; unrelated modified/untracked work present | Read-only reference for Compose, seeding, and AAP/EDA registration |

Local APD history includes:

- **PR #381, `61250f8`:** Multivendor catalog/rendering, mapped-port inventory, configuration, validation, reporting, redaction, and tests.
- **PR #391, `39b3a50`:** Shared-service registration, prerequisite checks, multi-play host configuration, workflow convergence, and failure-edge patterns. Do not introduce Gitea or copy public ingress/printed-secret practices.
- **PR #386, `1849c3b`:** Later EE changes supersede some #381 pins and README descriptions. Inspect current definitions and actual images rather than assuming the earlier tested build is deployed.

Paths below are relative to APD unless another repository is identified.

| Reuse category | Existing content | Proposed treatment |
|---|---|---|
| Unchanged | `demo.network.containerlab` topology structure and `clab_device_catalog` | Retain all four network devices, SCP server, links, management IPs, and mapped ports |
| Unchanged | `network/configure_devices.yml`, `demo.network.configure_lab` | Keep ordinary multivendor baseline configuration independent of security remediation |
| Unchanged | Existing ContainerLab Inventory, device access, and hypervisor credentials | Continue serving existing jobs; reuse trusted deployment/connectivity information |
| Unchanged | Product Demos EE, existing Staging/Upgrade jobs | Do not replace their runtime or invoke upgrades from this scenario |
| Parameterized | Existing provisioning/deployment jobs | Restricted access ranges; capacity/image overrides only when required |
| Parameterized | `network/validate_containerlab.yml`, `network/report.yml`, troubleshooting | Invoke existing content with appropriate inventory/host selections |
| Extended | Containerlab deployment metadata and inventory update | Record current ownership, endpoint mapping, and topology generation for reconciliation and stale-plan rejection |
| Extended | Shared discovery and teardown guards | Bound operations to the deployment and explicitly protect/confirm destruction of persistent NetBox data |
| Extended | `network/setup.yml`, existing report filter/build role/template, tests | Register new resources; optionally add sanitized security evidence without changing default reports |
| Adapted into new APD content | Circuits `pb_setup_local_netbox.yml`, `pb_seed_netbox.yml`, `pb_setup_aap.yml` | Reuse patterns, not wholesale playbooks, old settings, circuit data, legacy crypto, or TLS bypasses |
| Genuinely new | NetBox inventory source, narrow IOS-XE adapter, plan/approval workflow, evidence contract, Prepare Drift | Implement only the missing security scenario |

## 4. Architecture and deployment

```text
Existing APD AAP 2.7 and EDA
  | existing Network provisioning/deployment
  v
Existing RHEL hypervisor
  +-- product_demos Containerlab topology
  |     cat8kv1, veos2, vjunos3, veos4, scp-server
  +-- persistent NetBox Compose project -> restricted HTTP :8000
  +-- existing APD report server :8088

Containerlab discovery + trusted catalog
  -> reconcile owned NetBox assets and endpoint metadata
  -> netbox.netbox.nb_inventory -> AAP NetBox Security Inventory
  -> Audit -> authenticated EDA Event Stream
  -> Plan -> native Approval -> Revalidate/Apply/Verify -> Evidence
```

There is no AAP hosting/deployment choice in this demo: use the supplied APD environment. Do not provision another AAP or OpenShift cluster.

### NetBox services and isolation

- Adapt the circuits Compose approach to a deployment-specific project and persistent systemd service on the hypervisor, not on an execution node.
- Pin a reviewed `netbox-docker` revision and compatible service image digests. NetBox **4.7.4** is the release-note-reviewed starting candidate; verify availability/security status before selecting the implementation lock set.
- Include the application, worker, PostgreSQL, and cache/queue services required by that Compose revision. NetBox 4.7 requires PostgreSQL 15+, the `ltree` extension/database permissions, and Redis 6+ or a verified supported equivalent.
- Keep Compose names, network, storage, and lifecycle separate from Containerlab. Do not use host networking, publish database/cache ports, or overlap lab/VPC address ranges.
- Publish only the NetBox application port, proposed `8000:8080`; preserve report port `8088` and all device mappings.
- Attach a deployment-owned **dedicated NetBox security group**, preserving existing attachments. Manage its rules independently: `network/deploy_containerlab.yml` uses `purge_rules: true` on the existing Containerlab group.
- Require restricted source CIDRs covering actual AAP execution egress and presenter access. Inspect the union of attached security-group rules; reject unrestricted management ingress for this demo. Coordinate the host firewall and SELinux without blanket disabling.
- HTTP is an explicit lab trade-off: NetBox passwords/API tokens travel unencrypted. Do not misrepresent it as TLS-secured or hide the issue with verification bypasses. Existing AAP/EDA HTTPS endpoints continue to use certificate verification and appropriate trust.

Use the current `c8i.4xlarge` baseline (16 vCPU/32 GiB) and existing 100 GiB data disk initially. Their documented validation covers the existing lab, not NetBox. Capture combined cold-boot/steady-state CPU, memory, disk and container usage; increase supported instance/disk parameters if actual tests show insufficient capacity. Do not create a second provisioning framework or shrink the topology just for this demo.

### Initial Cisco image

Use the existing catalog image `registry.gitlab.com/redhatautomation/cat8:17.13.01a` for now. The user will identify a replacement separately; image replacement is not a specification/implementation prerequisite.

Record the limitation: Cisco's 17.13.x bulletin lists security/software maintenance ending **2024-12-31**, with last support **2027-07-31**. Do not call the image security-maintained, infer vulnerability status, or require exploitation. Validate its effective commands, crypto, provenance, and actual image digest before presenting live behavior. Keep device HTTP/HTTPS ports unpublished externally. A later image choice remains a provisioning parameter, not a firmware-upgrade feature.

## 5. NetBox, inventory, and connectivity contracts

### Discovery and reconciliation

1. Use existing APD discovery and the catalog, supplemented by Containerlab inspection, to require exactly one owned hypervisor and the expected topology.
2. Idempotently seed/reconcile the four network devices, management interfaces/IPs, platform/type/site/role data, and automation endpoint metadata. Only `cat8kv1` is initially remediation-eligible.
3. Use stable names plus deployment ownership to preserve NetBox object IDs. Reruns update observed connectivity but do not silently overwrite operator-edited policy, rotate credentials, or erase evidence.
4. Publish a topology-generation identifier whenever devices are replaced. Keep a trusted deployment record outside the disposable topology directory; do not rely solely on its NetBox copy.

### Mandatory NetBox dynamic inventory

Create **NetBox Security Inventory**, sourced from `network/netbox_security/inventory/netbox.yml` with `netbox.netbox.nb_inventory`, using the dedicated EE and a NetBox read credential.

- Scope queries to owned demo assets and construct an explicit eligible security group. Require active status, platform `cisco-iosxe`, the security-demo tag, and the expected deployment.
- Keep merged context and custom fields namespaced/unflattened; use explicit composition for connection variables. Disable plugin caching for the demo, refresh at launch, and explicitly synchronize before planning and applying.
- Export `netbox_device_id`, actual management IP, deployment/generation metadata, `ansible_host`, `ansible_port`, `ansible_network_os`, and connection settings. Validate the selected plugin version's actual variable shapes with fixtures and a live sync; do not copy unvalidated guide expressions blindly.
- Keep existing ContainerLab Inventory intact. Security runtime device targeting comes from NetBox inventory, with independent APD deployment information used to validate it, not bypass it.

| Field | Authority / initial value |
|---|---|
| NetBox primary management IP | Actual device management interface address: `172.20.20.12` for `cat8kv1` |
| `custom_fields.apd_automation_endpoint.host` | Current owned hypervisor address, reconciled from APD discovery |
| `custom_fields.apd_automation_endpoint.port` | Catalog-mapped automation port: `2123` for `cat8kv1` |
| Endpoint ownership | APD deployment ID, hypervisor instance ID, topology generation |
| Ansible adapter | `cisco.ios.ios` over `ansible.netcommon.network_cli` |
| Intent | Current merged `config_context.apd_network_security` |
| Latest evidence | JSON custom field `security_evidence`, separate from intent |

The resolver accepts one positive numeric device ID and fixed control `SEC-WEBUI-001`. It requires exactly one eligible inventory host, re-reads the NetBox object, and cross-checks identity, management IP, **automation host and port**, ownership, and generation against trusted APD records/current hypervisor inspection. AAP read access and hypervisor SSH can supply this independent check; do not grant runtime jobs unrestricted provisioning credentials merely to resolve a target.

Never equate NetBox's primary IP with the mapped automation endpoint. Never interpolate event/user input into a host pattern or accept a supplied delegation hostname, endpoint, connection plugin, or command.

### Intent schema

`apd_network_security` contains: policy ID, positive revision, control ID, Web UI desired state `disabled`, boolean `required_for_services`, and a valid UTC change-window start/end. Canonicalize/hash the effective merged policy, including overrides; revision alone is insufficient.

Missing/malformed policy is an error. `required_for_services: true` is blocked/report-only. Expired windows prohibit writes, not read-only assessment. Seed the initial policy once; later seeding must not silently replace approved intent or refresh a window without authorization.

## 6. EE and documentation evidence

Create **NetBox Network Security EE** for the inventory source and new NetBox/security jobs. Include `netbox.netbox`, compatible `pynetbox`, `packaging`, `pytz`, `cisco.ios`, `ansible.netcommon`, and the existing SSH transport dependencies. Add AWS/Podman/AAP configuration collections only for new setup jobs that actually need them. Reuse APD's existing Decision Environment if sufficient; a DE is separate from this EE.

Preserve Product Demos EE for existing jobs. Choose compatible current dependencies for the dedicated EE, reusing proven network versions where appropriate; do not arbitrarily pin old collections, upgrade shared working dependencies, or treat the lookup environment's core 2.16 as an architectural constraint. A justified newer-core dedicated EE is acceptable. Consolidation into Product Demos EE is future work, not an initial task.

The project-configured **ansible-know 0.11.0** server was confirmed connected, including when saving this specification. Documentation results below are authoring evidence, not EE/integration validation:

| Content | Evidence | Remaining validation |
|---|---|---|
| `netbox.netbox` 3.23.1 | MCP discovery and docs for device/interface/config-context/custom-field modules, `nb_inventory`, `nb_lookup`; tagged metadata requires core >=2.15 and lists Python requirements | Actual NetBox 4.7 API/token behavior, inventory composition, seed idempotency, permissions |
| `cisco.ios` 11.6.0 | MCP `ios_command` and `ios_config` docs, including save semantics | APD currently constrains `<11.6.0`; inspect actual selected-version docs and test the chosen image |
| `ansible.netcommon` 8.7.1 | Collection discovered | APD currently constrains `<8.7.0`; `network_cli` docs hit an MCP output-schema error; validate selected transport/plugin in the EE |
| `ansible.eda` 2.13.0 | MCP credential, Event Stream, and activation docs; source-name mapping example | Supported-DE event envelope, rules/actions/throttle, stream authentication, workflow launch |
| Core built-ins | MCP local `uri` and `set_stats` documentation | Artifact propagation and failure handling in actual AAP jobs |
| Podman/AWS | MCP container/network/storage and security-group purge documentation | Returned latest versions differ from APD constraints; validate actual selected versions |

Documentation gaps: Hub servers reported `auth: none`; Controller approval-node module docs were unavailable through Galaxy fallback; AAP 2.7 conceptual-document retrieval returned 401 from the upstream RH Docs MCP. Its endpoint advertises OAuth, but the inspected ansible-know 0.11.0 nested client has no bearer/OAuth handling. A separate diagnostic handoff covers that issue. Do not confuse these gaps with a broken EE, infer certification from Galaxy results, or guess missing API parameters.

Before live acceptance, record exact AAP build, NetBox patch/Compose revision, device/container images, core/Python and collection/package versions, and EE/DE digests. Updating an APD project does not rebuild an EE.

## 7. Jobs and workflow behavior

Use the APD organization/project and `NETWORK ǀ NetBox Security` naming. Keep the presenter-visible runtime to Audit, one remediation workflow, and evidence. Additional synchronization/safety checks are internal mechanics, not separate presentation features.

| Proposed job | Behavior / credentials |
|---|---|
| Setup Lab | Wrap existing Network deployment/configuration/validation content; deploy NetBox, reconcile assets, configure inventory and EDA. Also support attaching to an existing lab without redeploying devices |
| Deploy NetBox / Seed NetBox | Service/bootstrap operations using existing AWS/hypervisor access and separate NetBox administrative credential; not runtime credentials |
| Configure EDA | Reuse APD's project/DE registration patterns; create scoped stream credentials, mapping and activation |
| Audit | NetBox read + device SSH + evidence writer + event producer; read-only on devices |
| Plan | Fresh inventory/intent/device reads and trusted deployment checks; publish one-device plan |
| Apply | Workflow-only write privileges, device SSH, NetBox read/evidence writer, and restricted provenance/discovery access; revalidate, apply, verify and conditionally save |
| Prepare Drift | Explicit presenter-launched, restricted and confirmed lab-only action enabling the two Web UI services on `cat8kv1`; never publishes their ports, never accepts arbitrary CLI, and does not save by default |
| Reset / Cleanup | Separate non-destructive reset, owned service removal, and explicitly confirmed destructive cleanup |

Setup reuses existing templates/workflows rather than cloning provisioning. Do not call Provision Hypervisor unconditionally when attaching to an existing lab. Reuse #391 prerequisite/convergence/failure patterns, without deploying shared Gitea services.

### Audit and event

- Read `show ip http server status` and `show ip ssh` through SSH. Require successful, complete output and exactly one supported HTTP, HTTPS, and SSH status. Unknown/ambiguous output or access/command failure is never a pass.
- Results are `pass` (both services disabled), `fail` (confirmed drift), `blocked` (dependency/safety restriction), or `error` (assessment failure). Confirmed drift is a finding, not an unexpected task crash.
- Publish sanitized evidence and emit an event only for actionable confirmed drift. Do not configure a NetBox evidence-update webhook, avoiding writeback loops.
- Event contract: schema version/type, numeric device ID, fixed control ID, policy hash, source audit job ID, topology generation, creation time, and correlation ID. Events contain no executable commands or authorization flags.
- Use the existing AAP Event Stream's generated HTTPS URL with token authentication. Start with forwarding disabled; verify rejected missing/bad tokens and actual payload shape, explicitly map the named source, then enable forwarding. No public direct rulebook listener.
- EDA can launch only this remediation workflow. Use short event freshness and throttle rules; do not claim exactly-once delivery.

### Plan, approval, application

```text
Sync NetBox inventory -> Plan -> Native AAP approval (15-minute timeout)
  -> Sync inventory again -> Revalidate / Apply / Verify / Evidence
```

The plan binds one device, management IP, automation **host and port**, ownership/generation, observed identity/state, policy hash/revision, content revision, exact command allowlist, source/plan job IDs, and issue/expiry times. Use a 15-minute initial event/plan lifetime; expiry during approval/synchronization fails safely and requires reassessment.

Only approval success reaches Apply. Native approval plus RBAC and trusted predecessor artifacts provide authorization; an event or caller-supplied `approved_plan`/`approved` value does not. Validate the actual predecessor/approval relationship using AAP-supported mechanisms, not a custom approval service. Limit launch inputs to the expected scalar identifiers/references; prohibit arbitrary variables and direct presenter/EDA launch of Apply.

Apply re-resolves the target, policy and device state immediately before writing. Changed policy, endpoint, identity, deployment generation, expired window/plan, failed reads, or unexpected state changes stop execution. If already compliant, do not force a configuration push or save.

The remediation adapter can send only:

```text
no ip http server
no ip http secure-server
```

Afterward verify both services effectively disabled and reconnect/check SSHv2. Save verified configuration only when this job changed running state; record no-op persistence as not requested unless separately checked. Saving can persist unrelated edits, so require an exclusive demo change window and protected pre-change backup. Reuse existing backup mechanisms, but do not describe an execution-node temporary path as durable storage.

Disable simultaneous execution of new workflows/jobs. Prepare/reset/redeployment must not race active security jobs: suspend new triggers, cancel/invalidate pending plans, and check active work before maintenance. A generation change invalidates old plans. No new locking service or event ledger is required for this one-device demo.

## 8. Evidence, credentials, and failure behavior

- Use run-level `set_stats` (`per_host: false`) for `security_results` and workflow plan artifacts. NetBox `security_evidence` stores a compact latest-attempt result/reference, not authoritative intent or immutable history.
- Include asset/control IDs, policy hash/revision, management/automation endpoints, generation, timestamps, source/plan/apply/workflow job references, before/after service observations, change status and save outcome. Retain approval/denial/timeout in native workflow history.
- Preserve AAP evidence before attempting NetBox writeback. On verification, save, event delivery, or writeback failure, fail/report partial completion accurately. Preserve any known observed state; do not claim the whole operation completed or erase earlier evidence.
- Never automatically re-enable Web UI as rollback. Stop and require operator review if access, verification or persistence fails.
- Separate NetBox read, bootstrap/admin, evidence-writer, event-producer and restricted EDA workflow-launch credentials. Runtime jobs must not receive NetBox admin or broad AAP/AWS admin credentials.
- Restrict the evidence writer to owned assets and trusted content; object-scoped NetBox permissions alone do not enforce field-only write access. Keep bootstrap and policy editing separate.
- Inject secrets through AAP credentials/protected files; suppress secret-bearing task output/diffs, sanitize HTML/JSON and command output, and never place tokens in surveys, context, artifacts or reports. Use established SSH trust rather than introducing legacy crypto or new host-key bypasses.
- Use existing APD reports for optional sanitized security summaries; no external archive/dashboard or separate retention-policy project is required.

## 9. Persistence, reset, and cleanup

Store deployment-owned Compose configuration, database/media, required secrets and service state outside disposable topology and report directories, proposed `/mnt/images/apd-services/<deployment-id>/netbox/`. Persist and protect credentials across normal runs. Do not copy circuits' forced checkout, default/admin secret printing, `.env` overwrite, or `compose down -v` teardown into ordinary operations.

| Operation | Contract |
|---|---|
| Ordinary reset | Preserve NetBox DB, device IDs, credentials, intent and historical evidence; invalidate pending plans; do not enable Web UI implicitly |
| Prepare Drift | Explicit isolated-device setup action for another presentation; record the action and subsequent audit, not a fabricated compliance result |
| Topology teardown/redeployment | Resets/removes device state and updates generation/eligibility; preserves NetBox services, data, and dedicated access rules |
| NetBox service removal | Remove owned containers/network/systemd exposure and ingress; preserve data unless explicitly authorized otherwise |
| Full stack destruction | Explicit confirmation identifying deployment/data loss; remove owned AWS/service resources and persistent data |

The current EBS volumes are deleted on instance termination. Persistence is across ordinary reset/redeployment, not an implicit guarantee across full teardown. Include a basic DB/media backup-and-restore acceptance check without adding an external backup service.

Existing discovery can select the first of multiple matches and hypervisor teardown searches more broadly than APD ownership. Add focused exact-target/ownership guards, not a replacement provisioner. The existing Destroy workflow uses an `always` edge to hypervisor teardown: authorize destructive cleanup before that graph and repeat the guard inside directly launchable destructive jobs. Uncertain ownership/data-preservation state must fail closed. Cleanup must remove only this deployment's AAP/EDA/NetBox/service resources, not shared platform credentials, projects or inventories.

## 10. Proposed files and staged implementation

These are proposed changes, not content implemented by this specification.

| Area | Proposed paths |
|---|---|
| Registration and documentation | Extend `network/setup.yml`, `network/README.md`; add `network/docs/network-netbox-security.md`; catalog entry after validation |
| Inventory | `network/netbox_security/inventory/netbox.yml` |
| Thin playbook entry points | `network/netbox_security/{setup_lab,deploy_netbox,seed_netbox,configure_eda,audit,plan,apply,prepare_drift,reset,cleanup}.yml` |
| Service role | `collections/ansible_collections/demo/network/roles/netbox_service/` with Compose/systemd templates, seeding data/tasks, readiness and owned cleanup |
| Security adapter | `collections/ansible_collections/demo/network/roles/security_webui/` and a narrow parser/contract filter under `plugins/filter/` |
| EDA | `extensions/eda/rulebooks/network_security.yml`, following the project's actual rulebook discovery conventions |
| Dedicated EE | Separate NetBox EE definition/requirements under `execution_environments/`; leave existing shared EE definitions unchanged initially |
| Focused reuse extensions | Containerlab metadata/defaults, deployment and teardown guards; optional existing report filter/build role/template extension |
| Tests | Security fixtures/unit and offline playbook checks under `collections/ansible_collections/demo/network/tests/` |

Stages:

1. **Contracts and EE:** inspect actual APD runtime, choose/build the dedicated EE, implement offline parser/inventory/policy/plan contracts and retain existing test coverage.
2. **Lab integration:** reuse Network workflows; add generation/ownership/persistence guards, persistent HTTP NetBox, idempotent reconciliation and mandatory dynamic inventory.
3. **Read-only story:** audit, evidence, optional existing report integration, and explicit Prepare Drift; validate without enabling automatic remediation.
4. **Event and approval:** authenticated Event Stream, restricted EDA activation, native approval and negative/provenance tests.
5. **Bounded correction:** revalidation, disable-only commands, operational/SSH verification, conditional save, accurate failure handling.
6. **Acceptance:** execute live scenario, persistence/cleanup and existing-demo regressions; record exact versions/digests and presenter instructions before claiming validation.

Do not change the solution-guide or circuits repositories as part of implementation without a separate request. Do not upgrade other demos merely to obtain matching documentation.

## 11. Acceptance tests

### Offline and selected-EE checks

- YAML/schema/syntax, includes, templates, repository lint and supported-DE rulebook semantics. Fixture tests are not live module validation.
- Inventory composition preserves the primary IP separately from the automation host/port; scope excludes other deployments and non-Cisco remediation targets. Test stale, absent, renamed, duplicate and partially seeded assets, auth failures and empty inventory.
- Parser fixtures cover both enabled, both disabled, mixed, truncated, unknown/ambiguous output, failed commands, unreachable devices and SSH safety checks.
- Reject malformed IDs, host patterns, arbitrary CLI/connection variables, missing/invalid policy, required-service dependencies and forged plan/approval data.
- Changing only the automation **port**, host, management IP, policy, device identity, generation, change window or plan expiry blocks writes. A compliant recheck produces no device/save operation.
- Workflow denial/timeout/failed sync/plan cannot reach Apply; duplicate events do not repeat a completed device change.
- Evidence retains partial failures, avoids secrets, escapes HTML and never turns parse/writeback failures into a compliance pass.
- Render/check Compose isolation, persistent paths, dedicated ingress, scoped cleanup and destructive confirmation. Normal reset/redeployment cannot remove NetBox data.
- Prepare Drift is an explicitly authorized separate adapter; positive enable commands cannot enter the remediation command map.

### Live AAP 2.7 acceptance

1. Record actual versions/digests and confirm combined resource capacity, readiness and reboot survival.
2. Run reconciliation twice: stable asset IDs, working credentials, preserved intent/evidence and no duplicate data. Confirm NetBox inventory is the new jobs' inventory source.
3. Verify the primary address `172.20.20.12` and mapped automation endpoint `<hypervisor>:2123` independently through the actual EE/AAP connection path.
4. Confirm NetBox HTTP is restricted, DB/cache and device Web UI ports are not externally published, secrets are not printed, and missing/bad EDA tokens cannot launch workflows.
5. Run Prepare Drift, audit and the event/plan/approval path; show exactly one target and the fixed disabling commands.
6. Approve; verify fresh checks, disabled HTTP/HTTPS, retained SSH, conditional startup persistence, AAP artifacts/approval history and NetBox evidence.
7. Repeat audit/apply: compliant/no unnecessary configuration or save; evidence timestamps may still update.
8. Exercise denial/timeout, stale/duplicate events, changed endpoint/intent/generation, parsing/access failures, failed verification/save, and NetBox writeback failure. No false completion or automatic re-enabling.
9. Exercise ordinary reset, database restore and topology teardown/redeployment: NetBox data/access survive, stale plans fail, and discovered connection metadata is reconciled before inventory sync.
10. In an explicitly authorized isolated test, verify scoped service removal and full destruction without affecting another deployment or shared APD resources.

### Existing-demo regression

Retain #381's unit tests and `render_topology.yml`, `render_resources.yml`, `collect_unsupported.yml`, and read-only `inspect_topology.yml`. Preserve expected topology membership and test report redaction/escaping/default behavior.

Live checks cover existing Deploy/Configure/Validate/Report, all four device connection mappings, cross-vendor pings, IOS backup, troubleshooting, topology redeployment and scoped teardown. Security remediation must not alter routes/interfaces or non-Cisco devices. Staging/Upgrade remain separate; no firmware activation is required for this regression. Broader cloud/Linux/Windows smoke coverage becomes necessary only if shared dependencies are changed later.

**Review-time status:** No EE, device, NetBox, or AAP integration was exercised. Earlier host unit-test discovery was blocked by missing Jinja2 and PyYAML; this is an environment gap, not a demonstrated regression. Static source/documentation review and the scenario narrative are not live acceptance evidence.

## 12. Remaining risks and optional research

No further architecture choices block implementing this reviewed design. Resolve technical compatibility during the staged work and report failures rather than broadening scope silently.

| Item | Treatment |
|---|---|
| Existing IOS-XE lifecycle/security suitability | Use current image as agreed; user selects a replacement separately; document isolation and avoid unsupported security claims |
| Exact NetBox/EE/DE compatibility and authentication | Select and validate actual versions; documentation checks alone do not establish compatibility |
| Combined hypervisor capacity | Assume current size fits; measure and increase existing parameters if necessary |
| Inventory freshness, mapped ports and device replacement | Fresh sync/read, independent endpoint checks, ownership and generation-bound plans |
| Concurrent maintenance and stale approvals | Serialize new jobs; invalidate/cancel pending work before reset/redeployment |
| HTTP carries credentials in cleartext | Explicit lab limitation; restricted ingress and no printed secrets; HTTPS is not a prerequisite |
| Evidence writer can affect more than one field | Object scope, trusted content, least privilege and negative permission tests |
| Save persists unrelated running changes | Dedicated lab device/exclusive window, pre-change backup and explicit save evidence |

**Optional HTTPS research, deferred:** compare (a) an APD OpenShift Route using existing ingress certificates, including secure connectivity to this external EC2 backend, and (b) the user's ACME/Let's Encrypt provider from `leogallego/aap-containerized-aws` (local checkout `~/ai/aws-aap-containerized`). Review DNS-01/HTTP-01, certificate deployment/renewal hooks and lifecycle cleanup. Do not add Route53/domain/IAM requirements, deploy OpenShift/AAP, or modify that reference repository for the initial HTTP implementation.

Further extensions: additional vendor adapters, scheduled/intent-change triggers, durable event deduplication/locking, and a separately designed firmware workflow. None are implied by the initial demo.

## References

- Local APD history: `61250f8` (#381), `39b3a50` (#391), `1849c3b` (#386).
- [Network demos](../network/README.md), [deployment](../network/docs/network-deploy-containerlab-stack.md), [network tests](../collections/ansible_collections/demo/network/tests/README.md), [EE definitions](../execution_environments/README.md).
- Solution-guide draft `c1796eb` and circuits reference `fd319db`, as identified above; neither proves this security integration works.
- [NetBox 4.7 release notes](https://netboxlabs.com/docs/netbox/release-notes/version-4.7/).
- [NetBox collection 3.23.1 runtime metadata](https://github.com/netbox-community/ansible_modules/blob/v3.23.1/meta/runtime.yml) and [inventory source](https://github.com/netbox-community/ansible_modules/blob/v3.23.1/plugins/inventory/nb_inventory.py), supplementing ansible-know documentation.
- [Cisco IOS-XE 17.13 lifecycle bulletin](https://www.cisco.com/c/en/us/products/collateral/ios-nx-os-software/ios-xe-17/ios-xe-17-13-x-eol.html).
- AAP 2.7 [workflow templates](https://docs.redhat.com/en/documentation/red_hat_ansible_automation_platform/2.7/develop-assembly_ug_controller_workflow_job_templates) and [event routing](https://docs.redhat.com/en/documentation/red_hat_ansible_automation_platform/2.7/administer-automate_responses_to_real_world_it_events): documentation targets; MCP content retrieval was authentication-blocked during review.
