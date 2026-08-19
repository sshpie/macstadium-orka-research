# Harbor Registry + New Surface Discovery — 2026-08-13

## Harbor Registries (4 hosts)
| IP | Hostname (cert CN) | Auth | Library Repos |
|----|-------------------|------|--------------|
| 207.254.35.53 | orkv10000076-01.oci.las1.macstadiumcloud.com | anon JWT issued | 3 |
| 207.254.35.60 | orkv10000086-01.oci.las1.macstadiumcloud.com | anon JWT issued | 0 |
| 207.254.35.77 | orkv10000010-01.oci.las1.macstadiumcloud.com | anon JWT issued | 0 |
| 207.254.35.126 | orkv10000016-01.oci.las1.macstadiumcloud.com | anon JWT issued | 2 |

## Anonymous Access
Token endpoint `/service/token?service=harbor-registry&scope=repository:library/*:pull`
issues a signed JWT without credentials. Library project is public.

## macOS VM Images (207.254.35.53)
| Image | Tags | Layers | Size (est.) |
|-------|------|--------|-------------|
| library/generic-14-sonoma-arm | 0.0.1, 0.0.2 | 39 | ~22GB |
| library/ventura-arm | latest | 33 | ~18GB |
| library/generic-15-sequoia-arm | 0.0.1 | 42 | ~24GB |

## OCI Layer Format (custom)
- `vnd.macstadium.orka-engine.disk.layer.v1+lz4` — lz4-compressed APFS disk chunks (~550MB each)
- `vnd.macstadium.orka-engine.disk-aux.v1+img` — ~33MB aux disk (NVRAM/EFI partition)
- `vnd.macstadium.orka-engine.metadata.v1+json` — 288-316 byte metadata blob

## Blob Store Backend
- **Host**: `1.obj.las1.macstadiumcloud.com`
- **Type**: S3-compatible (AWS4-HMAC-SHA256 presigned URLs)
- **Region**: us-west-1
- **Bucket**: `orkv10000076-01/docker/registry/v2/blobs/`
- **Access key in URL**: `PSFBSAZRAMFKBOOKAFJPIDBEOGDLMKMJAADNEBPIOB`
- **TTL**: 1200s presigned URLs

## GlobalProtect Portals (NEW surface)
| IP | TLS Issuer | SAML | CVE-2024-3400 probe |
|----|-----------|------|---------------------|
| 207.254.72.226 | CN=GlobalProtect-for-2026 (self-signed) | saml-default-browser=yes | HTTP 200 |
| 207.254.35.178 | CN=GlobalProtect (self-signed) | saml-default-browser=yes | HTTP 200 |

PAN-OS version NOT yet extracted. prelogin returns `panos-version: 1` (protocol version, not OS build).
CVE-2024-3400 requires specific PAN-OS builds (10.2/11.0/11.1) — version confirmation pending.

## ASA TLS Cert Hostnames
| IP | Cert CN |
|----|---------|
| 207.254.35.12 | ORKV10000002-FWC01.macstadium.com |
| 207.254.16.2 | atl-vpn.macstadium.com (GoDaddy) |
| 207.254.72.76 | las-vpn.macstadium.com (GoDaddy) |

## Other New Hosts
| IP | CN | Notes |
|----|-----|-------|
| 207.254.16.132 | shamrock19.com | MacStadium tenant |
| 207.254.16.133 | Claris International (FileMaker) | Apple subsidiary tenant |
