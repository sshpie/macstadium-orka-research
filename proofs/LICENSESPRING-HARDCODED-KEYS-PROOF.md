# Proof: Hardcoded LicenseSpring SDK Credentials in orka-engine Binary
# Source: com.macstadium.orka-engine.server (extracted from orka-engine-3.5.2.pkg)
# Analysis Date: 2026-08-17

---

## BACKGROUND: What is LicenseSpring?

LicenseSpring (licensespring.com) is a commercial software license management platform.
MacStadium integrated the LicenseSpring SDK into orka-engine to enforce that only paying
customers can run the Orka3 macOS virtualization platform. On startup, orka-engine contacts
LicenseSpring's API to validate that the host machine holds a valid, activated license before
allowing any VM operations.

Three SDK credentials are required for this system to function. All three are hardcoded in
plaintext inside the `com.macstadium.orka-engine.server` binary shipped in MacStadium's
publicly downloadable `orka-engine-3.5.2.pkg` installer.

---


Three LicenseSpring SDK credentials, all hardcoded in the com.macstadium.orka-engine.server binary extracted from the same orka-engine-3.5.2.pkg


┌──────────────┬─────────────────────────────────────────────┐
│    Field     │                    Value                    │
├──────────────┼─────────────────────────────────────────────┤
│ api_key      │ 90ECE379-E9F0-4393-BC58-64FD7F078F7E        │
├──────────────┼─────────────────────────────────────────────┤
│ product_code │ 8ad72323-35e5-477c-ab2c-ea2e080dadc1        │
├──────────────┼─────────────────────────────────────────────┤
│ shared_key   │ C8J7gHUrvMSN52BEQpEYo-zapNplE9XWGR36tifssiE │
└──────────────┴─────────────────────────────────────────────┘


## EXTRACTED CREDENTIALS

### Credential 1: api_key

```
90ECE379-E9F0-4393-BC58-64FD7F078F7E
```

**What it is:** The SDK authentication key — the identity credential MacStadium's orka-engine
uses to authenticate itself to LicenseSpring's API on behalf of MacStadium's product account.

**What it enables:**
- Authenticate to `POST https://api.licensespring.com/api/v1/auth/` with any `hardware_id`
  to activate a license and bind it to an arbitrary machine
- Call `GET https://api.licensespring.com/api/v1/license_check/` to query existing license
  activations across all MacStadium customer deployments
- Call `POST https://api.licensespring.com/api/v1/device/` to enroll arbitrary devices into
  MacStadium's license account

**Secondary role — license bypass trigger (see Bypass section below):**
This same value is the hardcoded bypass key. Setting
`ORKA_ENGINE_LICENSE_KEY=90ECE379-E9F0-4393-BC58-64FD7F078F7E` causes the engine to skip
all license validation entirely.

---

### Credential 2: product_code

```
8ad72323-35e5-477c-ab2c-ea2e080dadc1
```

**What it is:** The UUID identifying MacStadium's "Orka Engine" product registration within
LicenseSpring's catalog. Every product a vendor registers with LicenseSpring receives a unique
UUID — this is Orka Engine's.

**What it enables:**
- Scope API calls to the Orka Engine product specifically:
  `GET https://api.licensespring.com/api/v4/product_details/?product=8ad72323-35e5-477c-ab2c-ea2e080dadc1`
- Combined with the api_key, retrieve full product configuration: feature flags, license types,
  seat limits, trial settings, and expiry policies for MacStadium's Orka Engine product
- This value is also the default for the `ORKA_ENGINE_LICENSE_PRODUCT_CODE` environment
  variable, confirming it is the canonical product identifier used in production

---

### Credential 3: shared_key

```
C8J7gHUrvMSN52BEQpEYo-zapNplE9XWGR36tifssiE
```

**What it is:** The HMAC-SHA256 signing secret for local license file integrity verification.
When LicenseSpring issues a license to a customer, orka-engine caches it locally in a license
file containing a `signature v2` field — an HMAC-SHA256 digest of the license data, keyed
with this shared_key. On every startup, orka-engine recomputes the HMAC and compares it
against the stored signature to detect tampering or forgery.

**What it enables:**
- Forge a valid local license file with arbitrary content: any expiry date, any seat count,
  any enabled feature flags
- Compute a valid `signature v2` HMAC-SHA256 over the forged license data using this key
- orka-engine will accept the forged license as authentic — the signature check passes

**Forge a license (proof of concept):**
```python
import hmac, hashlib, base64

shared_key = "C8J7gHUrvMSN52BEQpEYo-zapNplE9XWGR36tifssiE"
license_data = b'{"license_key":"FORGED-KEY","valid_until":"2099-12-31","seats":999}'

sig = hmac.new(shared_key.encode(), license_data, hashlib.sha256).digest()
print(base64.b64encode(sig).decode())
# Output is a valid signature v2 for the forged license — orka-engine accepts it
```

---

## LICENSE BYPASS — CONFIRMED (Static RE, 2026-08-12)

Beyond the individual credential impacts above, the api_key value functions as a hardcoded
debug bypass key embedded in `OrkaEngineLicense.License.shouldCheckLicense()`.

**Mechanism (confirmed via static reverse engineering of orka-engine 3.5.2, arm64):**

```
ORKA_ENGINE_LICENSE_KEY=90ECE379-E9F0-4393-BC58-64FD7F078F7E
```

1. orka-engine reads `ORKA_ENGINE_LICENSE_KEY` via `ProcessInfo.environment` at startup
2. Compares the value against `90ECE379-E9F0-4393-BC58-64FD7F078F7E` (Swift String fast-path comparison)
3. On match: `shouldCheckLicense()` returns `false`; the stored Bool at `interceptor+0x10` is set to false
4. `LicenseCheckServerInterceptor.receive(_:context:)` reads Bool at `x20+0x10`
5. Branches to skip path — logs `skipping license validation for <RPC>` and passes the call through

**All gRPC RPCs on `/var/run/orka-engine.sock` pass with no license required:**

| RPC Category | Operations Unlocked |
|---|---|
| VM lifecycle | Create, Start, Stop, Delete, Clone, Edit, Save, Console |
| VM management | Install, Repartition |
| Image operations | Pull, Push, Copy, Delete, DownloadLatestIPSW |
| System | Ping, VM Registration callbacks |

**Impact:** Any party with local access to an Orka node who can set an environment variable
(via the writable plist at `ORKA_ENGINE_HELPER`, via SSH with admin:admin, or via the
orka-engine.sock directly) obtains a fully unlicensed Orka engine — all VM and image
operations execute without license enforcement.

---

## SOURCE LOCATION IN BINARY

All three credentials are present in both of the following binaries extracted from
`orka-engine-3.5.2.pkg`:

```
orka-engine-pkg-extracted/usr/local/bin/orka-engine
orka-engine-pkg-extracted/usr/local/libexec/orka-engine.app/Contents/MacOS/com.macstadium.orka-engine.server
```

**Binary hash (com.macstadium.orka-engine.server):**
```
SHA-256: d50a0f8f5107743065c6887c0b5abbc9808eb1351c5979d17d842dbb4e66ed76
```

**Extraction method:** Static string extraction (`strings`) + ablation v2.4.0 licensespring
module (symbol resolution, HMAC key identification, bypass function offset 0x573ad4).

---

## SUMMARY

MacStadium hardcoded three LicenseSpring SDK credentials into the publicly downloadable
`orka-engine-3.5.2.pkg` installer:

1. **api_key** (`90ECE379-...`) — authenticates to LicenseSpring API; also functions as a
   hardcoded license bypass key that disables all license enforcement when set as an env var
2. **product_code** (`8ad72323-...`) — exposes MacStadium's full Orka Engine product
   configuration and license inventory via LicenseSpring's API
3. **shared_key** (`C8J7gHUrvMSN52BEQpEYo-...`) — enables forging of arbitrary local license
   files that orka-engine accepts as authentic, bypassing seat limits and expiry enforcement

Any person who downloads the public `orka-engine-3.5.2.pkg` installer can extract all three
credentials with a single `strings` command and use them to bypass MacStadium's commercial
license enforcement entirely.

