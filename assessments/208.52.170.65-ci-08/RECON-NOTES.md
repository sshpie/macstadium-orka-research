# MacStadium CI-08 Assessment
## 208.52.170.65 (aquaessencetoothpaste.com)

**Date:** 2026-08-11  
**Authorization:** VDT BASELINE v2 - Full Active Testing  
**Objective:** MacStadium infrastructure access  

## Target Profile
- **Hostname:** macstadium-ci-08 (ARD), MACMINI-77C3ED (NetBIOS)
- **Hardware:** Mac Mini
- **Location:** Atlanta, GA (AS395336 MacStadium)
- **Purpose:** CI/CD build server
- **Domain:** aquaessencetoothpaste.com

## Services (Shodan)
- SSH: OpenSSH 10.0 (22/tcp) - 16 CVEs
- Kerberos: Heimdal (88/tcp+udp)
- NetBIOS: (137/udp)
- Apple Remote Desktop: OPEN (3283/udp)
- VNC: OPEN (5900/tcp) - RFB 003.889

## Key Difference from M1 Mac
M1 Mac (207.254.60.50) had VNC **FILTERED**
This target has VNC + ARD **OPEN** - direct remote access vector

## Assessment Log

## Initial Scan Results (2026-08-11 21:24)

**Service Status:**
- SSH (22): OPEN - OpenSSH 10.0
- Kerberos (88): OPEN - Heimdal (server time: 2026-08-12 02:24:13Z)
- NetBIOS (137): CLOSED
- ARD (3283): OPEN - netassistant
- VNC (5900): FILTERED

**Finding F1: VNC State Change**
- Shodan historical: OPEN (2026-08-01)
- Current state: FILTERED
- Indicates recent firewall rule change or IP-based restriction
- Similar to M1 Mac behavior

**Finding F2: Apple Remote Desktop Accessible**
- Port 3283 OPEN (ARD service discovery/advertisement)
- Custom Apple protocol for remote management
- Potential attack vector if authentication weak/bypassed

208.52.170.65: RPC: Remote system error - Connection refused
clnt_create: RPC: Unable to receive

## Finding F3: No RPC Services Exposed
- rpcinfo: Connection refused
- showmount: Unable to receive
- **More secure than M1 Mac** (which had extensive RPC exposure)
- No NFS attack surface


## Finding F4: Apple Remote Desktop Service Accessible
- Port 3283/tcp OPEN
- TCP connection successful
- Service accepting connections
- ARD protocol for remote management/service discovery
- Potential information disclosure vector

## Finding F5: OpenSSH 10.0 CVEs
Same CVE set as M1 Mac (OpenSSH 10.3 had 11 CVEs, OpenSSH 10.0 likely has subset):
- CVE-2026-60002 (7.7) - Use-after-free on key re-exchange
- CVE-2026-60001 (6.5) - Auth delay bypass
- CVE-2023-51767 (7.0) - Row hammer auth bypass
- CVE-2026-35385 (7.5) - scp setuid installation
- Plus others

