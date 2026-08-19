# Orka Repo Analysis

Source: Static GitHub analysis, no live probing.

---

## ansible-playbook-osx-ci-setup

### Inventory / Host data

- `inventory/main` contains only a placeholder:
  ```
  [targets]
  localhost ansible_connection=local
  ```
  No real host IPs, subnets, or hostnames. Playbook is designed to run locally on each Mac node (not centrally managed from a controller with a real inventory).

- No `host_vars/` directory present.

### Credentials / Secrets

- `group_vars/all.yml` — only one active line:
  ```yaml
  ansible_user: admin
  ```
  Both `ansible_become_pass` and `ci_user_default_keychain_password` are commented out. These are injected at run time via CLI `--extra-vars` or Ansible Vault, not stored in the repo.

- No `.vault` files present. No hardcoded passwords, URLs, or API keys.

- `ansible.cfg`:
  ```ini
  [defaults]
  allow_world_readable_tmpfiles=true
  ```
  **Finding**: `allow_world_readable_tmpfiles=true` makes Ansible-generated temp files in `/tmp` world-readable. On a multi-user macOS CI host, any local process or user can read `/tmp/ansible-*` files — which may include template outputs, copied secrets, or plist contents rendered from Jinja2 templates (e.g., the orka-engine plist with `ORKA_ENGINE_LICENSE_KEY`).

- `scripts/ansible_setup.sh` — no secrets; just CLT install + `pip install ansible`.

### Architecture

- Thin wrapper playbook applying two Galaxy roles in sequence:
  1. `macstadium.osx_ci` → `ansible-role-osx-ci` (Homebrew, CI user UID 5013, fastlane, CocoaPods, keychain — see F62/F64)
  2. `macstadium.xcode` → `ansible-role-xcode` (Xcode installation)

- Playbook is intended to be run **locally on each Mac node** (`ansible_connection=local`). There is no central inventory. Each node self-provisions.

- All sensitive variables (`ansible_become_pass`, `ci_user_default_keychain_password`, `ci_user_public_key_location`, `orka_license_key`) must be supplied externally — likely from a CI secret store or Ansible Vault passed at invocation time.

- **Implication**: If CI pipeline invocation is visible (logs, ps aux during run, CI runner environment), these variables are the credential targets.

---

## vergeos-exporter

### Metrics endpoint

- **Port**: `:9888` (default, `--web.listen-address`)
- **Path**: `/metrics` (default, `--web.telemetry-path`)
- **Format**: Prometheus text + OpenMetrics (auto-negotiated)
- **Auth on `/metrics`**: **NONE** — unauthenticated by design (standard Prometheus exporter pattern)

### VergeOS API endpoints consumed

Called via govergeos SDK, translates to `/api/v4/` REST:

| SDK call | Data exposed |
|---|---|
| `Settings.GetCloudName()` | Init/validation — VergeOS cloud name |
| `Clusters.List()` | Cluster inventory, resource specs |
| `StorageTiers.List()` | Tier capacity, used, allocated, dedup ratio |
| `ClusterTiers.List()` | Tier status, txn counts, encryption, redundancy, fullwalk |
| `MachineDrivePhys.List()` | Drive temp, wear, power-on hours, reallocated sectors, errors |
| `MachineDriveStats.ListPhysical()` | Physical drive I/O stats |
| `VMs.List()` (`is_snapshot eq false`) | All non-snapshot VM inventory |
| `MachineStats.List()` | CPU/perf stats per machine |
| `MachineStatus.List()` | Node name, running state |
| `MachineNICs.List()` | NIC tx/rx per VM |
| `VMDrives.ListAll()` | Virtual drive config (size, media, interface) |
| `MachineDriveStats.List()` (`physical eq false`) | VM disk I/O |
| `Tenants.List()` | All tenant inventory |
| `TenantStatus.List()` | Per-tenant status |
| `TenantStatsHistoryShort.GetLatest()` | Tenant aggregate resource stats |
| `TenantNodes.List()` | Tenant node assignments |
| `TenantStorage.List()` | Per-tier storage per tenant |
| `TenantLayer2Networks.List()` | L2 network assignments per tenant |

### Auth

- Credentials: `--verge.username` / `--verge.password` or env vars `VERGE_USERNAME` / `VERGE_PASSWORD`
- Startup performs fail-fast validation — exits if credentials invalid
- `/metrics` scrape endpoint: **no auth** (attacker who reaches :9888 gets full data dump)

### Key findings

1. **Unauthenticated metrics endpoint**: Anyone reaching `:9888/metrics` gets the complete VergeOS infrastructure topology — tenant names, VM names, node names, drive health, storage tiers, encryption/redundancy status, L2 network assignments. No Prometheus auth middleware in the code.

2. **Tenant topology leak**: `TenantLayer2Networks.List()` + `Tenants.List()` expose the full multi-tenant L2 network structure — VLAN assignments, network names, per-tenant node counts. Customer isolation boundaries are visible.

3. **Drive health leak**: `MachineDrivePhys.List()` returns physical drive wear level, reallocated sectors, SMART-like health indicators for VergeOS nodes. Useful for targeting degraded nodes.

4. **Version exposure**: System version metrics expose VergeOS version + branch — enables CVE targeting if vulnerabilities are version-specific.

5. **Credential env vars**: `VERGE_URL`, `VERGE_USERNAME`, `VERGE_PASSWORD` — if the exporter runs in a container or alongside other services, environment variable leakage (e.g., via `/proc/PID/environ`, shared K8s namespace, Docker inspect) exposes VergeOS admin credentials directly.

6. **IsAuthError handling** (`vergeos.IsAuthError(err)` in base.go) — confirms VergeOS API returns distinguishable auth errors; useful for credential-spray detection bypass (auth errors vs. other errors are handled separately, affecting retry/backoff logic).

---

## Cross-repo chain

`ansible-playbook-osx-ci-setup` → provisions Mac nodes with `ansible_user: admin` + secrets injected at runtime → orka-engine installed with `ORKA_ENGINE_LICENSE_KEY` in plist → orka-engine writes to `/opt/orka/` with `allow_world_readable_tmpfiles=true` → any local process can read Ansible-rendered temp files → potential license key + keychain password recovery.

`vergeos-exporter` at `:9888/metrics` (unauthenticated) → full VergeOS cluster topology → confirms node names/counts → maps to VergeOS API targets for F58/F59/F60 chain.
