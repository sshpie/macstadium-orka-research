# Orka Engine — Extracted Credentials
Source: Static RE of com.macstadium.orka-engine 3.5.2 (arm64)
Extraction date: 2026-08-12

## LicenseSpring SDK Credentials (ALL THREE — hardcoded in binary)

| Field | Value | Notes |
|-------|-------|-------|
| api_key | `90ECE379-E9F0-4393-BC58-64FD7F078F7E` | F75 — LicenseSpring Management API key |
| product_code | `8ad72323-35e5-477c-ab2c-ea2e080dadc1` | Default for ORKA_ENGINE_LICENSE_PRODUCT_CODE env var |
| shared_key | `C8J7gHUrvMSN52BEQpEYo-zapNplE9XWGR36tifssiE` | Used for HMAC-based license signature verification |

**All three are hardcoded in both `orka-engine` and `com.macstadium.orka-engine.server` binaries.**

### LicenseSpring API Access (requires authorization before executing)
```
GET https://api.licensespring.com/api/v4/product_details/?product=8ad72323-35e5-477c-ab2c-ea2e080dadc1
Authorization: Basic base64(90ECE379-E9F0-4393-BC58-64FD7F078F7E:90ECE379-E9F0-4393-BC58-64FD7F078F7E)
```

```
GET https://api.licensespring.com/api/v4/license/?limit=100
Authorization: Basic base64(90ECE379-E9F0-4393-BC58-64FD7F078F7E:90ECE379-E9F0-4393-BC58-64FD7F078F7E)
```

```
GET https://api.licensespring.com/api/v4/device/?limit=100
```

## UUID / Provisioning Profile Credentials

| UUID | Location | Notes |
|------|----------|-------|
| `f4b55818-6fc8-4ea6-8456-25c850bc541d` | orka-engine provisioning profile | Team ID 23KP83Z488, expires 2043 |
| `4f96963f-c0d6-48f4-907b-4ec12953be8c` | runvz provisioning profile | Same team, expires 2043 |

## OCI Registry Media Type Fingerprints

| Media Type | Purpose |
|-----------|---------|
| `application/vnd.macstadium.orka-engine.disk.layer.v1+lz4` | bv41 disk layer (Ablation target) |
| `application/vnd.macstadium.orka-si.image.layer.v1.aar+lz4` | Shared image (Apple Archive + LZ4) |

## OCI Annotation Keys

```
com.macstadium.orka-engine.disk.layer.offset
com.macstadium.orka-engine.disk-size.compressed
com.macstadium.orka-engine.disk-size.full
com.macstadium.orka-engine.disk-size.usage
com.macstadium.orka-engine.disk-size.archived
```

## Internal Engine Configuration

| Item | Value |
|------|-------|
| Default helper path | `Contents/Helpers/Orka Engine Runner.app/Contents/MacOS/com.macstadium.orka-engine.runvz` |
| Env var controlling it | `ORKA_ENGINE_HELPER` |
| VM IP resolution | Reads `/var/db/dhcpd_leases` (DHCPParser) |
| VM metadata format | `{"items":[{"key":"K","value":"V"}]}` (base64-encoded in --metadata flag) |

## LicenseSpring SDK vs Management API

The three extracted credentials are **SDK credentials** (used by the SDK for license activation and validation),
NOT Management API admin credentials. The Management API (/api/v4/) uses separate admin credentials
(customer login), which are NOT embedded in the binary.

SDK credentials enable:
- License activation: `POST https://api.licensespring.com/api/v1/auth/` with hardware_id + license_key
- License validation: `GET https://api.licensespring.com/api/v1/license_check/` 
- Device enrollment: `POST https://api.licensespring.com/api/v1/device/`

The `shared_key` (`C8J7gHUrvMSN52BEQpEYo-zapNplE9XWGR36tifssiE`) is used for HMAC-SHA256 
signature verification of the local license file (`signature v2` format). If we have any valid
license key for the Orka Engine product, we can activate it and bind it to any hardware_id.

## LicenseSpring SDK Bypass — CONFIRMED

The `OrkaEngineLicense.License.shouldCheckLicense()` at file 0x573ad4 returns `false` when:

```
ORKA_ENGINE_LICENSE_KEY=90ECE379-E9F0-4393-BC58-64FD7F078F7E
```

The bypass key = the hardcoded LicenseSpring SDK api_key embedded in the binary.

When false: `LicenseCheckServerInterceptor` logs `< skipping license validation for <RPC>`
and passes every gRPC call through without license or auth validation.

**Mechanism** (confirmed via static RE, 2026-08-12):
- Function reads `ORKA_ENGINE_LICENSE_KEY` via `ProcessInfo.environment`
- Compares against `90ECE379-E9F0-4393-BC58-64FD7F078F7E` (Swift String fast-path)
- Returns 0 (false) on match → `shouldCheckLicense` stored Bool at interceptor+0x10 = false
- `receive(_:context:)` reads Bool at x20+0x10, branches to skip path when false

**Impact**: ALL gRPC RPCs on `/var/run/orka-engine.sock` pass without validation:
- List, Create, Start, Stop, Delete, Clone, Edit, Save, Console, Install, Repartition VMs
- Pull, Push, Copy, Delete, DownloadLatestIPSW Images
- SystemService Ping
- VM Registration callbacks
