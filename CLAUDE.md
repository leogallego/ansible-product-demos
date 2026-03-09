# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

Ansible Product Demos (APD) — a collection of Ansible playbooks and configuration-as-code that deploy demo environments on Red Hat Ansible Automation Platform (AAP). Demos span Linux, Windows, Cloud (AWS), Network, OpenShift, and Satellite domains.

## Architecture

The project uses a **configuration-as-code** pattern where each demo category is defined declaratively:

- **`<domain>/setup.yml`** — declares AAP controller resources (job templates, credentials, inventories, surveys, workflows) for that demo category using `infra.aap_configuration` collection roles
- **`<domain>/*.yml`** — the actual demo playbooks executed by AAP job templates
- **`common/setup.yml`** — shared AAP resources (credentials, inventory sources, organizations) that other demo categories depend on; loaded first via `common/bootstrap-vars.yml`
- **`install-apd.yml`** — entry point playbook that bootstraps all AAP configuration using `infra.aap_configuration.dispatch`
- **`collections/ansible_collections/demo/`** — in-tree Ansible collections (`demo.cloud`, `demo.compliance`, `demo.patching`, `demo.satellite`, `demo.openshift`) containing roles used by the demo playbooks
- **`execution_environments/`** — EE build definitions for `apd-ee-25` image (`build.sh` creates multi-arch images via `ansible-builder`)

### How Demos Are Added

1. Add the playbook to the appropriate `<domain>/` directory
2. Add a `controller_templates` entry in `<domain>/setup.yml` with name, playbook path, survey spec, credentials, etc.
3. Add any new collection/role dependencies to `collections/requirements.yml`
4. Hosts must be parameterized: `hosts: "{{ _hosts | default('<domain>') }}"`

## Commands

### Linting (primary validation method)

```bash
# Install pre-commit (one-time)
pip install pre-commit
pre-commit install

# Run all checks (requires Automation Hub token)
export ANSIBLE_GALAXY_SERVER_AH_TOKEN=<token>
pre-commit run --all-files
```

Pre-commit runs: trailing-whitespace, check-yaml, ansible-lint (via `ansible-navigator lint` inside the `apd-ee-25` EE image), and black (Python formatting).

### Running playbooks

```bash
export AAP_HOSTNAME=https://your-aap-server.example.com
export AAP_USERNAME=admin
export AAP_PASSWORD=<password>

# Install/update all APD configuration on AAP
ansible-navigator run -m stdout install-apd.yml
```

### Interactive debugging (replicate CI)

```bash
podman run --user root -v $(pwd):/runner:Z -it quay.io/ansible-product-demos/apd-ee-25:latest /bin/bash
# Then inside container:
./.github/workflows/run-pc.sh
```

### Building execution environments

```bash
cd execution_environments
podman login registry.redhat.io
export ANSIBLE_GALAXY_SERVER_CERTIFIED_TOKEN="<token>"
export ANSIBLE_GALAXY_SERVER_VALIDATED_TOKEN="<token>"
./build.sh
```

## Linting Configuration

- **ansible-lint**: `production` profile, offline mode. Skips `galaxy[no-changelog]`. Excludes `collections/ansible_collections/demo/compliance/roles/`, `roles/redhatofficial.*`, `.github/`, `execution_environments/ee_contexts/`
- **yamllint**: line-length disabled, truthy only allows `true`/`false`, indent-sequences enabled
- **black**: Python formatting for callback plugins (excludes STIG role files)

## Key Conventions

- All playbooks use parameterized hosts: `"{{ _hosts | default('linux') }}"`
- Job template names follow the pattern: `DOMAIN | Description` (e.g., `LINUX | Patching`)
- All templates include `notification_templates_started/success/error: Telemetry`
- The `!unsafe` tag is used in setup.yml files to pass raw Jinja2 through to AAP injector definitions
- Container engine is podman (not docker)
- Collections path: `./collections:/usr/share/ansible/collections`
- EE image: `quay.io/ansible-product-demos/apd-ee-25:latest`

## Git Branching

- Always work on feature branches — never commit directly to `main`.
- Branch naming: `<type>/<short-description>` using snake_case (e.g., `feature/add_patching_demo`, `fix/cloud_setup_survey`, `docs/update_readme`).
- Create a PR to merge feature branches into `main`. Push the branch and open the PR against `main`.

## Claude Config Branch

This file (`CLAUDE.md`) and other Claude Code config (`.gitignore` updates, `setup-claude.sh`) live on an **orphan branch called `claude-config`**. They are NOT tracked on `main` or any feature branch.

### Rules

- **Never commit `CLAUDE.md` or Claude-specific `.gitignore` changes to `main`** or to feature branches. These files must only be committed on `claude-config`.
- When you modify `CLAUDE.md`, commit the change to `claude-config` — not to the current working branch.
- `CLAUDE.md` should be present in the working tree (untracked on `main`) so Claude Code loads it on every run. If it is missing, restore it:
  ```bash
  git checkout claude-config -- CLAUDE.md
  git reset HEAD CLAUDE.md
  ```
- The `setup-claude.sh` script on `claude-config` automates restoring config after a fresh clone:
  ```bash
  git fetch origin claude-config
  git checkout claude-config -- setup-claude.sh
  ./setup-claude.sh
  ```
- When creating PRs to upstream or `main`, verify that `CLAUDE.md` is not included in the diff.
