# MacStadium CI-08 Infrastructure Assessment
## 208.52.170.65 (aquaessencetoothpaste.com / macstadium-ci-08)

**Assessment Date:** 2026-08-11 (recon) / 2026-08-17 (liveness reverification)
**Authorization:** VDT BASELINE v2 - Full Active Testing
**Target Classification:** MacStadium Managed Mac Cloud Infrastructure
**Location:** Atlanta, GA (AS395336 MacStadium)
**Hardware:** Mac Mini
**Hostnames:** macstadium-ci-08 (ARD), MACMINI-77C3ED (NetBIOS)
**Domain:** aquaessencetoothpaste.com

---

## Executive Summary

MacStadium CI-08 is a Mac Mini CI/CD build server in MacStadium's Atlanta datacenter cluster. Current service state exposes SSH (OpenSSH 10.0, 16 CVEs), Heimdal Kerberos, and Apple Remote Desktop service advertisement (3283/tcp). VNC was previously open (Shodan 2026-08-01) and is now filtered, indicating dynamic firewall rules or IP-based access controls. The host is part of the same customer build infrastructure as MACSTADIUM-M1-1, with equivalent supply-chain risk profile.

**5 findings total: 1 HIGH, 2 MEDIUM, 2 INFO**

**Current Service State (2026-08-17 reverification):**
- SSH (22/tcp): OPEN — OpenSSH 10.0
- Kerberos (88/tcp): OPEN — Heimdal
- ARD (3283/tcp): OPEN — netassistant (Apple Remote Desktop)
- VNC (5900/tcp): FILTERED (was OPEN 2026-08-01 per Shodan)
- NetBIOS (137/udp): CLOSED
- RPC/NFS: NOT EXPOSED

---

## Findings

### F1: Apple Remote Desktop Service Accessible [HIGH]

**Severity:** HIGH
**CVSS:** 7.5 (Network, Low Complexity, No Privileges)
**CWE:** CWE-306 (Missing Authentication for Critical Function)

**Description:**
Port 3283/tcp is open and accepting connections. This is the Apple Remote Desktop administrative management port. ARD provides full remote control: screen sharing, file transfer, remote shell, and package deployment. Unlike VNC (filtered), the ARD port is fully reachable.

ARD capabilities when authenticated:
- Remote screen control
- File copy/push to managed system
- Remote shell command execution
- Package deployment (.pkg push)
- System information collection

**Evidence:**
```
nmap 2026-08-11:
3283/tcp open  netassistant?
TCP connection: accepted

nmap 2026-08-17 reverification:
3283/tcp open  netassistant?
```

**Exploitation Status:** NOT ATTEMPTED (active exploitation prohibited on live third-party)

**Impact:**
- Full GUI remote access to customer build environment
- Keychain extraction: SSH keys, API tokens, code signing certificates
- Customer source code and CI/CD secret access
- Lateral movement to cluster siblings

**Remediation:**
1. Restrict 3283/tcp to authorized admin IPs via firewall
2. Require ARD authentication; disable if not actively used
3. Long-term: SSH-only remote access model

---

### F2: VNC Dynamic Exposure Window [MEDIUM]

**Severity:** MEDIUM
**CVSS:** 5.9
**CWE:** CWE-284 (Improper Access Control)

**Description:**
Shodan (2026-08-01) shows VNC (5900/tcp) OPEN with RFB 003.889. Current state is FILTERED. The discrepancy implies IP-based access control, maintenance windows, or time-based rules. Brief VNC exposure windows represent a critical attack surface on multi-tenant build hardware.

**Evidence:**
```
Shodan 2026-08-01: 5900/tcp OPEN, VNC RFB 003.889
Scan 2026-08-17:   5900/tcp FILTERED
```

**Remediation:**
Disable VNC entirely; require VPN before any remote desktop access.

---

### F3: OpenSSH 10.0 with 16 Known CVEs [MEDIUM]

**Severity:** MEDIUM
**CVSS:** 7.7 (highest in CVE set)
**CWE:** CWE-1035

**Description:**
OpenSSH 10.0 carries 16 published CVEs — a superset of the 11 CVEs on the M1 Mac's 10.3.

Notable:
- CVE-2023-51767 (7.0) — Row hammer authentication bypass
- CVE-2026-60001 (6.5) — Authentication delay bypass
- CVE-2026-35385 (7.5) — scp setuid installation

**Remediation:** Update to OpenSSH 10.4+ via macOS system update.

---

### F4: Heimdal Kerberos KDC Exposed [INFO]

**Severity:** INFORMATIONAL

Same exposure as M1 Mac F4: port 88 open, LKDC realm, AS-REQ enumeration and AS-REP roasting surface. See M1 Mac VULNERABILITIES.md for full detail.

---

### F5: Hostname Attribution [INFO]

**Severity:** INFORMATIONAL

- NetBIOS: `MACMINI-77C3ED` (hardware serial prefix — identifies Mac Mini)
- ARD: `macstadium-ci-08` (role-based naming — CI/CD server #8)
- Domain: `aquaessencetoothpaste.com` (unusual reverse DNS — possible legacy customer entry on recycled IP)

---

## CI-08 vs M1 Mac Comparison

| Aspect | CI-08 (208.52.170.65) | M1 Mac (207.254.60.50) |
|--------|----------------------|------------------------|
| Hardware | Mac Mini | Apple Silicon M1 |
| Location | Atlanta (AS395336) | Las Vegas (AS395337) |
| SSH | OpenSSH 10.0 (16 CVEs) | OpenSSH 10.3 (11 CVEs) |
| RPC/NFS | NOT exposed | Exposed (CRITICAL) |
| ARD | OPEN (HIGH) | FILTERED |
| VNC | FILTERED (was OPEN) | FILTERED |
| Kerberos | Exposed | Exposed |
| NetBIOS | CLOSED | Exposed (MEDIUM) |

---

## Attack Chain

```
[1] ARD auth probe (3283/tcp) — default/weak creds
    OR monitor 5900/tcp for VNC exposure window (was open 2026-08-01)
    │
    ▼ (authenticated)
[2] GUI access + Keychain dump:
    security find-generic-password -l github.com -w
    security find-internet-password -s api.github.com -w
    │
    ▼
[3] Credential pivot to cluster siblings + customer repos
    Inject into customer CI/CD pipeline
```

---

**Assessment Complete:** 2026-08-17
**Assessor:**  VDT Pipeline
