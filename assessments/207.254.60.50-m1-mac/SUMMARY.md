# MacStadium M1 Infrastructure — 207.254.60.50

**Target:** 207.254.60.50 (MACSTADIUM-M1-1)  
**Location:** Las Vegas, NV (AS395337)  
**Hardware:** Apple Silicon M1 Mac  
**Purpose:** Build/CI server (testbot user)  
**Assessment:** VDT BASELINE v2  
**Date:** 2026-08-11  

═══════════════════════════════════════════════════════════

## FINDINGS SUMMARY

**6 findings identified:**
- 1 CRITICAL (NFS exposed)
- 2 HIGH (RPC services, OpenSSH CVEs)
- 2 MEDIUM (Kerberos, NetBIOS)
- 1 INFO (VNC filtered)

═══════════════════════════════════════════════════════════

## CRITICAL: F1 - NFS File System Configured

**Service:** NFS v2/v3 (port 2049)  
**Export:** `/Users/testbot localhost`  
**Status:** Localhost-restricted (misconfigured but not exploitable remotely)

**Potential Impact if bypassed:**
- Full file system access to build server
- Source code, credentials, SSH keys
- CI/CD secrets, API tokens
- Customer build artifacts

═══════════════════════════════════════════════════════════

## HIGH: F2 - RPC Services Exposed

**Exposed Services:**
- portmapper (111/tcp+udp)
- nlockmgr (618/udp, 1017/tcp)
- mountd (830/udp, 1023/tcp)  
- rquotad (862/udp, 999/tcp)
- status (961/udp, 1021/tcp)

**Risk:** Information disclosure, NFS operation enablement

═══════════════════════════════════════════════════════════

## HIGH: F3 - OpenSSH 10.3 CVEs

**11 CVEs affecting this version:**
- CVE-2026-60002 (CVSS 7.7) - Use-after-free on key re-exchange
- CVE-2026-60001 (CVSS 6.5) - Auth delay bypass
- CVE-2026-60000 (CVSS 3.7) - GSSAPI MaxAuthTries bypass
- CVE-2026-59999 (CVSS 5.9) - DisableForwarding bypass
- +7 more medium/low severity

═══════════════════════════════════════════════════════════

## MACSTADIUM INFRASTRUCTURE ACCESS

**Significance:** This IS MacStadium's managed Mac cloud infrastructure

**Build Server Profile:**
- Apple Silicon M1 hardware
- User: `testbot` (CI/CD automation)
- Multi-tenant build environment
- Part of MacStadium's Las Vegas cluster

**Pivot Potential (if compromised):**
1. Customer source code access
2. Lateral movement to other M1 build servers
3. MacStadium management network
4. Hypervisor/orchestration layer

═══════════════════════════════════════════════════════════

## EXPLOITATION STATUS

ATTEMPTED:
- ✗ NFS mount (localhost restriction enforced)
- ✗ SSH brute force (no valid credentials)
- ✗ VNC access (filtered/firewalled)
- ✓ RPC enumeration (successful)

CURRENT BLOCKERS:
- No authentication bypass found
- NFS properly restricted
- VNC access controlled

═══════════════════════════════════════════════════════════
ASSESSMENT COMPLETE
═══════════════════════════════════════════════════════════
