# Orka Platform Intel

## Architecture
Orka 3.x = Kubernetes-native macOS VM orchestration
- CRDs: virtualmachineconfigs, virtualmachineinstances, images, isos, remoteimages, orkanodes
- API group: orka.macstadium.com
- CLI: orka3 (Go, uses controller-runtime + K8s client)
- Internal module: macstadium.com/orka-cli-v2

## CLI Download
- v3.6.3 (current): https://cli-builds-public.s3.eu-west-1.amazonaws.com/official/3.6.3/orka3/linux/amd64/orka3.tar.gz
- Downloaded to: /home/cowboy/VDT/tools/orka3/orka3

## Authentication Model
Three separate credential systems:
1. **Portal login** — macstadium.com web portal
2. **Orka user tokens** — JWT, 1-hour TTL, issued via OIDC
3. **VM credentials** — admin:admin (SSH/VNC, separate from Orka auth)

Token commands:
- `orka3 user get-token` → reads from ~/.kube/config
- `orka3 user set-token <TOKEN>` → logs in with raw token (no browser)
- Service accounts: `orka3 sa create <NAME>`, 1-year TTL (`--no-expiration` flag)

## REST API Surface
Base URL: `http://10.221.188.20` (current) or `http://10.221.188.100` (legacy)
HTTPS via Traefik: `10.221.188.22`

| Endpoint | Auth | Notes |
|----------|------|-------|
| POST /token | None (email+pw) | Returns JWT |
| GET /api/v1/cluster-info | **NONE** | Returns CertData, ApiEndpoint, AppClientId |
| GET /resources/vm/list | Bearer | Lists all VMs + customVMMetadata (customer PATs!) |
| POST /resources/vm/create | Bearer | Create VM config |
| POST /resources/vm/deploy | Bearer | Deploy VM |
| GET /resources/node/list | Bearer | Node inventory |
| POST /resources/image/save | Bearer | Save image |
| POST /resources/image/commit | Bearer | Commit image changes |
| GET /api/v1/swagger | Bearer | Swagger UI |

## VM Default Credentials (DOCUMENTED)
- SSH: **admin:admin** (port 8822) — cluster-wide default, all VMs
- VNC: port 5999 (no auth documented)
- Screen sharing: port 5901
- SSH keys stored at: /Users/admin/.ssh/ on VM

## Kubernetes Access
- K8s API: 10.221.188.19:6443
- Namespace: orka-default (default), sandbox (Orka ops)
- kubectl against cluster exposes all CRD resources
- VirtualMachineInstance status fields: hostIP, sshPort, vncPort, nodeName
- customVMMetadata field: stores arbitrary KV pairs per VM (customers put GitHub PATs here)

## Registry Credentials Storage
- Stored as K8s Secrets in cluster
- Harbor internal: https://10.221.188.5:30080
- API: `POST /api/v1/namespaces/<NS>/secrets/registrycredentials`

## RBAC
- Admin users: access all namespaces
- Non-admin: orka-default namespace only
- Roles managed by MacStadium (not self-service)
- Service account tokens: 1 year, stored in ~/.kube/config on SDK hosts

## Attack Surface Summary
1. `/api/v1/cluster-info` — unauthenticated, returns CertData (K8s CA cert?)
2. `admin:admin` SSH — all VMs, SSH port 8822
3. GitHub PATs in `/resources/vm/list` customVMMetadata
4. Service account 1-year tokens in ~/.kube/config on CI hosts
5. Harbor internal at 10.221.188.5:30080 (same admin:Harbor12345 likely)
6. K8s API direct kubectl if reachable (10.221.188.19:6443)
