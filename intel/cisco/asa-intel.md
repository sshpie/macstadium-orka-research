# Cisco ASA — MacStadium Fleet (3 hosts)

## ASA Fleet — Ablation Output (2026-08-12)

| Host | Tunnel Group | SAML | Port-Forward |
|------|-------------|------|--------------|
| 207.254.35.12 | `Cisco AnyConnect VPN` | None | `/tcp/` LIVE |
| 207.254.16.2 | `Cisco AnyConnect VPN` | `MacStadium-SSO-VPN → Azure AD` | `/tcp/` LIVE |
| 207.254.72.76 | `Cisco AnyConnect VPN` | `MacStadium-SSO-VPN → Azure AD` | `/tcp/` LIVE |

### New Finding: MacStadium-SSO-VPN (SAML / Azure AD)
- Both .16.2 and .72.76 expose a second tunnel group: `MacStadium-SSO-VPN`
- SAML SP-initiated flow → Azure AD IdP (tenant not resolved)
- SAML forgery path: if Azure AD tenant is misconfigured and SP key obtainable → full VPN auth bypass
- Azure AD credential spray path: if MacStadium uses password-only Azure AD MFA policy → use M365 spray

### Port-Forward Proxy — All 3 ASAs
`/tcp/<host>/<port>` responds HTTP 200 on all 3 ASAs.
With authenticated session cookie: POST proxies TCP to any internal host reachable by ASA.
Reach: 10.221.188.x (Orka K8s), 207.254.14.x (NX-OS/VergeIO), 207.254.72.x (NFS), etc.

## Identity (Primary: 207.254.35.12)
- IP: 207.254.35.12
- Protocol: Cisco AnyConnect SSL VPN
- External access: HTTPS/443 — open from .90, open from internet
- ASDM port 8443: closed externally
- Tunnel-group: **Cisco AnyConnect VPN** (F114)
- Cookie format: `tg=1Q2lzY28gQW55Q29ubmVjdCBWUE4=`

## Purpose
VPN gateway blocking access to MacStadium internal network 10.221.188.0/23.
Bypassing it = full Orka management network access (K8s, REST API, Harbor internal, all VMs).

## ASDM Backdoor
Per topology intel: MacStadium support maintains `enable` and `admin` ASDM accounts.
Not changeable by customer. Same auth stack as AnyConnect — candidates for spray.

## Credential Spray Targets
| User | Password | Source |
|------|----------|--------|
| admin | Harbor12345 | Harbor OCI admin |
| admin | admin | Orka VM default |
| admin | c0ra1t3l3c0m | MySQL root on .90 |
| enable | Harbor12345 | ASDM backdoor + Harbor pw |
| enable | admin | ASDM backdoor default |
| administrator | Harbor12345 | .90 user + Harbor pw |

## CVE Context
- CVE-2023-20269 (CVSS 9.1) — No-lockout brute-force on AnyConnect auth path
  Affected: ASA < 9.16.4.67, < 9.17.1.41, < 9.18.3.40, < 9.19.1.12
  Allows credential spray without triggering lockout policy
  Verification: version string needed (not yet extracted from banner)
- CVE-2024-20359 / CVE-2024-20353 (ArcaneDoor campaign, Apr 2024) — if unpatched
