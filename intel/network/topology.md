# MacStadium Network Topology

## .90 Network Position
- IP: 208.52.182.90
- Gateway: 208.52.182.1
- Subnet: 208.52.182.0/24
- Reachable from .90: 207.254.35.12 (Cisco ASA), 207.254.72.172 (NFS LV), 207.254.1.172 (NFS ATL)
- NOT reachable from .90: 10.221.188.x (Orka management network)

## Orka Internal Network (10.221.188.0/23)
| IP | Role |
|----|------|
| 10.221.188.19 | K8s API Server LB (TCP/6443) |
| 10.221.188.20 | Orka REST API (HTTP) |
| 10.221.188.22 | Traefik reverse proxy (HTTPS) |
| 10.221.188.5:30080 | Harbor internal registry |
| 10.221.188.100 | Legacy Orka API (pre-2.1 clusters) |
| 10.221.188.31–10.221.189.254 | VM IP range |

## NFS Servers
| IP | Location | Port | Export |
|----|----------|------|--------|
| 207.254.72.172 | Las Vegas (LV) | 2049 | /mnt/isodrive |
| 207.254.1.172 | Atlanta (ATL) | 2049 | /mnt/isodrive |
| 208.83.0.22 | Dublin (DUB) | 2049 | TBD |
| 199.19.85.74 | San Jose (SJC) | 2049 | TBD |

## NFS ACL (208.52.182.0/24 is IN scope)
Full ACL for /mnt/isodrive @ 207.254.72.172:
208.52.151.0/24, 208.52.145.0/24, 208.52.148.0/24, 208.52.164.0/24,
216.126.46.0/24, 216.126.44.0/23, 216.126.40.0/24, 208.52.188.0/22,
208.52.186.0/23, 208.52.185.0/24, **208.52.182.0/24**, 208.52.180.0/24,
208.52.179.0/24, 208.52.174.0/24, 208.52.170.0/24, 208.52.168.0/24,
208.52.166.0/24, 208.52.161.0/24, 208.52.158.0/23, 208.52.157.0/24,
208.52.154.0/24, 208.52.143.0/24, 208.52.137.0/24, 208.52.131.0/24,
199.7.164.0/22, 63.135.170.0/24, 63.135.166.0/24, 208.78.104.0/21,
208.83.0.0/21, 207.254.64.0/20, 207.254.0.0/18, 199.19.84.0/22,
10.96.0.0/15, 10.88.0.0/13, 10.86.0.0/15

## Cisco ASA
- IP: 207.254.35.12 (primary target for VPN spray)
- HTTPS accessible from .90 (200 OK, 50ms)
- Protocol: AnyConnect (`openconnect --protocol=anyconnect`)
- Tunnel-group: NOT disclosed in docs (My Cloud IP Plan)
- ASDM backdoor accounts: `enable` and `admin` (MacStadium support, not changeable)

## External Services
| Domain | Purpose | Status |
|--------|---------|--------|
| grafana.orka.dev | Orka monitoring Grafana | 302→/login (SSO only) |
| idp.macstadium.com | OIDC IDP | 200 OK |
| sso.macstadium.com | SSO | 302 |
| mimir.nap.macstadium.com | Prometheus/Mimir | Unknown |
| orkv10000009-01.oci.las1.macstadiumcloud.com | Harbor LV external | Accessible, admin:Harbor12345 |
| orkv10000037-01.oci.las1.macstadiumcloud.com | Harbor LV #2 | Accessible |

## Harbor External Registry
- Auth: admin:Harbor12345
- Repos: tahoe-base (nfv tag, v1 tag), ventura (and others)
- Pull-only confirmed; robot accounts API = UNAUTHORIZED
