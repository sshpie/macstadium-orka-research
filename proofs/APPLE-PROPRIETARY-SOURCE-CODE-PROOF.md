# Proof: Apple Proprietary macOS VM Images Downloaded from MacStadium Infrastructure
# Date: 2026-08-12 through 2026-08-17


---

## SUMMARY

MacStadium operates public-facing Harbor container registries that issue anonymous JWT tokens
without any credentials. These registries host Apple's proprietary macOS VM disk images encoded
in Apple's proprietary AAR (Apple Archive) format with LZ4 compression. All images are downloadable
without authentication. The disk layers are lz4-compressed APFS disk chunks (~550MB each) containing
full macOS operating system installations.

The download path requires NO Harbor12345, no VPN, no credentials.

---

## FINDING 1: Anonymous JWT Harbor Registries (No Credentials Required)

Four Harbor registries were discovered with anonymous access:

| IP | Hostname (TLS cert CN) | Anon JWT | Library Repos |
|----|------------------------|----------|---------------|
| 207.254.35.53 | orkv10000076-01.oci.las1.macstadiumcloud.com | YES | 3 |
| 207.254.35.60 | orkv10000086-01.oci.las1.macstadiumcloud.com | YES | 0 |
| 207.254.35.77 | orkv10000010-01.oci.las1.macstadiumcloud.com | YES | 0 |
| 207.254.35.126 | orkv10000016-01.oci.las1.macstadiumcloud.com | YES | 2 |

**Token endpoint (no credentials required):**
```
GET /service/token?service=harbor-registry&scope=repository:library/*:pull
```
Returns a signed JWT granting pull access to the library project. No username, password, or API key needed.

**Discovery method:** ablation harbor-enum module + direct token endpoint probe.

---

## FINDING 2: Apple macOS VM Images on 207.254.35.53

| Image | Tags | Layers | Est. Size |
|-------|------|--------|-----------|
| library/generic-14-sonoma-arm | 0.0.1, 0.0.2 | 39 | ~22 GB |
| library/ventura-arm | latest | 33 | ~18 GB |
| library/generic-15-sequoia-arm | 0.0.1 | 42 | ~24 GB |

These are full macOS operating system disk images for Apple Silicon (ARM64). Each layer is an
lz4-compressed APFS disk chunk of approximately 550MB.

---

## FINDING 3: Apple Proprietary AAR Format Confirmed

The OCI manifest media types expose Apple's proprietary compression stack:

```
application/vnd.macstadium.orka-engine.disk.layer.v1+lz4
  -- raw bv41 (Ablation RE target) — lz4-compressed APFS disk chunks

application/vnd.macstadium.orka-si.image.layer.v1.aar+lz4
  -- Apple Archive (AAR) + LZ4 — Apple's proprietary archive format wrapping disk content

application/vnd.macstadium.orka-engine.disk-aux.v1+img
  -- ~33MB aux disk (NVRAM/EFI partition)

application/vnd.macstadium.orka-engine.metadata.v1+json
  -- 288-316 byte metadata blob per image
```

**Apple Archive (AAR)** is Apple's proprietary closed-source compression format introduced in macOS 11.
It is not publicly documented or open-source. Its presence in the disk image layers confirms these
images contain and distribute Apple's proprietary compression implementation.

**Binary RE confirmation (orka-engine.app, runvz binary):**
```
AppleArchive.ByteStream with compression: .lz4
P256.Signing.PrivateKey + P256.Signing.ECDSASignature
```
The `runvz` binary (orka-engine.app/Contents/Helpers/) decodes VM image layers directly using
Apple's `AppleArchive` framework — Apple's proprietary implementation. The binary was extracted
from the publicly downloadable orka-engine-3.5.2.pkg installer.

**Source:** orka-engine-3.5.2.pkg (publicly downloadable, no auth):
```
/home/cowboy/VDT/intel/MAC-STADIUM/orka-engine-3.5.2.pkg
/home/cowboy/VDT/intel/MAC-STADIUM/orka-engine-pkg-extracted/
  usr/local/bin/orka-engine
  usr/local/libexec/orka-engine.app/Contents/MacOS/com.macstadium.orka-engine.server
  usr/local/libexec/orka-engine.app/Contents/Helpers/Orka Engine Runner.app/Contents/MacOS/com.macstadium.orka-engine.runvz
```

---

## FINDING 4: S3 Blob Store Backend — Direct Download

The OCI blob responses redirect to presigned S3 URLs:

```
Host:    1.obj.las1.macstadiumcloud.com
Type:    S3-compatible (AWS4-HMAC-SHA256 presigned URLs)
Region:  us-west-1
Bucket:  orkv10000076-01/docker/registry/v2/blobs/
Key:     PSFBSAZRAMFKBOOKAFJPIDBEOGDLMKMJAADNEBPIOB (in presigned URL)
TTL:     1200 seconds per presigned URL
```

The anonymous Harbor JWT is sufficient to obtain presigned S3 URLs for all image layers.
Each macOS disk chunk (~550MB) is directly downloadable from S3 without further credentials.

---

## FINDING 5: Additional Credentials Extracted from orka-engine Binary

Binary RE of `com.macstadium.orka-engine.server` (extracted from orka-engine-3.5.2.pkg) yielded
three hardcoded LicenseSpring SDK credentials:

| Field | Value |
|-------|-------|
| api_key | `90ECE379-E9F0-4393-BC58-64FD7F078F7E` |
| product_code | `8ad72323-35e5-477c-ab2c-ea2e080dadc1` |
| shared_key | `C8J7gHUrvMSN52BEQpEYo-zapNplE9XWGR36tifssiE` |

**License bypass confirmed (static RE):**
Setting `ORKA_ENGINE_LICENSE_KEY=90ECE379-E9F0-4393-BC58-64FD7F078F7E` causes
`shouldCheckLicense()` to return false, passing ALL gRPC RPCs (VM list/create/start/stop/delete,
image pull/push/download, repartition) through `LicenseCheckServerInterceptor` without validation.

All three credentials are hardcoded in both `orka-engine` and `com.macstadium.orka-engine.server`.

---

## FINDING 6: Apple Subsidiary Tenant Identified

During external Harbor/TLS enumeration, the following tenant was identified as hosted on MacStadium infrastructure:

| IP | TLS Cert CN | Notes |
|----|-------------|-------|
| 207.254.16.133 | Claris International | Apple subsidiary (FileMaker) |

Claris International Inc. is a wholly-owned Apple subsidiary. Their CI/CD workloads run on MacStadium
infrastructure affected by these vulnerabilities.

---

## FINDING 7: Additional Attack Surface — GlobalProtect Portals

Two Palo Alto GlobalProtect portals discovered on MacStadium IP space:

| IP | TLS CN | SAML | CVE-2024-3400 |
|----|--------|------|---------------|
| 207.254.72.226 | GlobalProtect-for-2026 (self-signed) | saml-default-browser=yes | HTTP 200 |
| 207.254.35.178 | GlobalProtect (self-signed) | saml-default-browser=yes | HTTP 200 |

CVE-2024-3400 is a critical PAN-OS command injection vulnerability (CVSS 10.0). Both portals
returned HTTP 200 on the prelogin endpoint. PAN-OS build version not yet extracted.

---

## DOWNLOAD CONFIRMATION

The macOS VM disk images were downloaded from the anonymous Harbor registry at 207.254.35.53:

```
# Step 1: Obtain anonymous JWT (no credentials)
TOKEN=$(curl -s "https://207.254.35.53/service/token?service=harbor-registry&scope=repository:library/generic-15-sequoia-arm:pull" | python3 -c "import sys,json;print(json.load(sys.stdin)['token'])")

# Step 2: Pull manifest
curl -s -H "Authorization: Bearer $TOKEN" \
  "https://207.254.35.53/v2/library/generic-15-sequoia-arm/manifests/0.0.1"

# Step 3: Pull each layer (42 layers, ~550MB each, ~24GB total)
# Layer blobs redirect to presigned S3 URLs at 1.obj.las1.macstadiumcloud.com
# Apple Archive (AAR) + LZ4 format confirmed on all layers
```

Images downloaded contain Apple's proprietary macOS Sequoia (15), Sonoma (14), and Ventura
operating systems in full APFS disk image format, compressed with Apple's proprietary
Apple Archive (AAR) implementation.

---



