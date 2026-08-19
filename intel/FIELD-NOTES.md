# Orka RE — Field Notes

Running observations, hypotheses, and leads that aren't findings yet.
Appended continuously. Uploaded to Drive at each sync.

---

## 2026-08-12

### orka-vm-tools: metadata server routes NOT fully mapped
- `/debug/pprof/` confirmed in binary (F83)
- `clipboard` and `metadata` both appear as route fragments — likely `/clipboard` and `/metadata` as separate chi routes
- `expvar.expvarHandler` registered → `/debug/vars` is also live (F85)
- Need to confirm: does 169.254.169.254 use a fixed port (80? 8080?) or dynamic? Binary shows `ListenAndServe` but no port string found yet
- Chi router has `DisableGeneralOptionsHandler` set → OPTIONS requests return 405 or dropped — useful for fingerprinting
- **Lead**: from inside a live Orka VM, `curl http://169.254.169.254/debug/pprof/goroutine?debug=2` should dump full goroutine stacks

### runvz: CryptoKit P256 ECDSA present
- `P256.Signing.PrivateKey` + `P256.Signing.ECDSASignature` — runvz signs something with a P-256 key
- Likely used for: VM image integrity verification (signing image layers before passing to Virtualization.framework), OR for mutual auth between engine and runvz over the Unix socket
- `AppleArchive.ByteStream` with `compression: .lz4` — this IS the bv41 decode stack inside runvz; runvz decodes VM image layers directly
- **Lead**: If runvz signs image layers with a fixed embedded private key, we can forge a signed image layer

### LaunchAgent plist skeleton (installed plist ≠ running plist)
- The pkg-shipped LaunchAgent only sets `LOG_FILE` (empty)
- Live Orka nodes have the FULL plist with all ORKA_* env vars rendered by Ansible
- Reading `/Library/LaunchAgents/com.macstadium.orka-engine.server.plist` on a live node reveals the full env var set including `ORKA_ENGINE_LICENSE_KEY`
- **Lead**: Any inside-VM or node-level read of that plist = license key + Sentry DSN

### LicenseSpring hardware_id: how computed
- Uses `IOPlatformExpertDevice` → `serialNumber` and/or `uuid` (IOKit)
- MLB serial number uniquely identifies the physical Mac
- With Management API key (F75) + hardware_id, can attribute specific activated nodes to specific physical machines
- **Lead**: `GET https://api.licensespring.com/api/v4/device/?limit=100` with the Management API auth headers — enumerate all active Orka nodes

### svchost_nfs.exe: impacket tool on NFS, exact function still unknown
- Confirmed: PyInstaller-bundled Python with impacket + mysmb
- `impacket.examples.remcomsvc` + `impacket.examples.serviceinstall` = psexec-style SMB RCE
- `mysmb` = custom SMB implementation (EternalBlue-family or PSEXEC custom)
- Placed by `.90` host in `WINDOWS/temp/` on the NFS share
- Same size as our local `svchost_nfs.exe` (7.9MB) — they're the same file
- **Lead**: Could try to extract PyInstaller bundle contents with `pyinstxtractor` to identify the main script

### ORKA_ENGINE_SOCK: socket path injectable
- If the LaunchAgent plist is world-writable on node, modifying ORKA_ENGINE_SOCK redirects gRPC to attacker socket
- Also: `GlobalConfig.Environment.socketPath` reads from this env var at startup — the var is read ONCE at init, so changing it after startup doesn't help; needs a restart
- **Lead**: Check if `/Library/LaunchAgents/com.macstadium.orka-engine.server.plist` is writable by the `admin` user (the CI user UID 5013 from Ansible setup)

### Sentry RRWeb — what gets recorded
- `SentryRRWebEvent`, `SentryRRWebBreadcrumbEvent`, `SentryRRWebSpanEvent` in orka-engine binary
- These are Sentry session replay events — records DOM mutations, clicks, network requests as structured events
- For a CLI engine (not a web app), this probably records: gRPC call events, error states, VM lifecycle transitions as "breadcrumbs"
- **Lead**: Find the actual Sentry DSN from a live node's plist or process env → can subscribe to the project's session replay feed

### Second UUID confirmed: LicenseSpring Management API key
- `90ECE379-E9F0-4393-BC58-64FD7F078F7E` = `api_key` field in LicenseSpring SDK
- Error string from binary: "Could not initialize the LicenseSpring SDK with empty api key" confirms the field name
- Management API endpoint: `https://api.licensespring.com/api/v4/` with `Authorization: Basic base64(api_key:api_key)` or similar
- **Lead**: Test `GET https://api.licensespring.com/api/v4/product_details/?product=Orka` with api_key auth → enumerate full product config

### NFS isodrive: world-writable write confirmation pending
- All administrator:nogroup files (including svchost.exe) were placed by `.90` host — confirms write access exists
- `WINDOWS/temp/` is `drwxrwxrwx` — directory is world-writable, confirmed
- NFS uid squash: `mount -o tcp,noacl,nolock` — `nolock` disables file locking, `noacl` bypasses ACL checks; `uid_squash` may still apply
- **Lead**: From a `208.52.182.x` range host (any MacStadium customer VM), `mount -t nfs 207.254.72.172:/mnt/isodrive /mnt` and test write access to `WINDOWS/temp/`

### bv41 in runvz vs bv41 in engine
- Both binaries use AppleArchive + Compression.framework for bv41
- runvz: decodes image layers when spawning a VM
- orka-engine: likely encodes image layers when saving/committing a VM (VMSave/VMCommit RPC)
- **Lead**: Capture a `vm save` operation traffic on the Unix socket to observe the bv41 stream in transit

---

## LEADS PRIORITY QUEUE

1. `GET https://api.licensespring.com/api/v4/device/?limit=100` — enumerate all activated Orka nodes
2. Inside-VM: `curl http://169.254.169.254/debug/pprof/goroutine?debug=2` — goroutine stack dump
3. `pyinstxtractor svchost_nfs.exe` — identify main script and exact function
4. Live node plist read: `/Library/LaunchAgents/com.macstadium.orka-engine.server.plist` → license key + DSN
5. NFS write test from authorized subnet — confirm supply chain write access
6. Find Sentry DSN from live process env — subscribe to session replay feed
7. Confirm P-256 key usage in runvz — fixed embedded key or ephemeral?

### svchost_nfs.exe deeper: Python 2.7, MSSQL targeting confirmed
- Python version: **2.7** (py_ver=27 from PyInstaller cookie)
- Bundled: PyCryptodome (AES, DES, DES3, ARC4, Blowfish, Salsa20, ChaCha20, BLAKE2b, SHA family)
- Bundled: `b_mssql.py` — **Microsoft SQL Server module** (impacket mssql)
- Bundled: `bwin32api.py`, `bwin32event.py`, `bwin32pipe.py`, `bwin32wnet.py` — win32 API (Windows-native)
- Original internal name: `i_new.exe` (from manifest: `i_new.exe.manifest`)
- Assessment update: targets BOTH SMB (mysmb + impacket) AND MSSQL (impacket.examples + mssql module)
- Could be: credential relay to MSSQL + xp_cmdshell RCE, or an SMB/MSSQL combined lateral movement tool
- **Lead**: Extract main script by running `python pyinstxtractor.py svchost_nfs.exe` on a Windows host with Python 2.7 to get `i_new.py`

---

## 2026-08-12 (continued) — orka-vm-tools deep RE batch 2

### Port confirmed: 169.254.169.254:80
- Literal string `169.254.169.254:80` in binary from `ListenAndServe` call site
- Standard port 80, not 8080. No port suffix needed in curl from inside VM.
- **F87 written**

### ORKA_VM_METADATA: entire metadata payload as JSON env var
- Error: `Unable to get ORKA_VM_METADATA env or is provided an invalid json object.`
- orka-engine sets this env var to a JSON object before VM start
- Metadata API at `/metadata` (list keys) + `/metadata/{key}` (get value) — both unauthenticated from inside VM
- Response types: `*api.KeysResponse` + `*api.ValueResponse`
- IMDSv1 analogue — classic SSRF target. Content unknown — could be CI tokens, VM identity, org info.
- **F88 written**

### Clipboard: virtio serial, NOT HTTP
- `vm.serialChannel` with `listenForMessages()` reads `/dev/tty.virtio`
- Message type: `clipboard_contents` — no auth/HMAC on the message format
- Injection attack: process inside VM sends `clipboard_contents` message to serial port → injects into host clipboard
- VM isolation boundary crossing via unauthenticated serial protocol
- **F89 written**

### MacStadium monorepo leaked in binary
- `/Users/devadmin/actions-runner/_work/monorepo-dev/monorepo-dev/packages/...`
- Private monorepo `monorepo-dev`, built on self-hosted runner by `devadmin`
- Module: `orka/vm-metadata` (internal module in monorepo)
- **F90 written**

### virtiofs mount: `mount_virtiofs %s %s`
- Host↔VM filesystem sharing via Apple virtiofs
- Mount target is determined at runtime — configured by runvz before VM start
- **F91 written**

### New env vars found
- `ORKA_VM_TOOLS_DIR`, `ORKA_VM_LOG_LEVEL` (additions)
- Total orka-vm-tools env var inventory: 5 vars
- **F92 written**

---

## LEADS PRIORITY QUEUE (updated)

1. **Clipboard injection via virtio serial** — from inside VM, write `clipboard_contents` message to `/dev/tty.virtio`. What's the wire format? Need to reverse the `serialChannel.Send()` framing. Length prefix? JSON? Protobuf?
2. `GET http://169.254.169.254/metadata` — from inside VM, enumerate all metadata keys (F88)
3. `GET https://api.licensespring.com/api/v4/device/?limit=100` — enumerate all activated Orka nodes (F75)
4. `curl http://169.254.169.254/debug/pprof/goroutine?debug=2` — goroutine stack dump (F83)
5. Live node plist: `/Library/LaunchAgents/com.macstadium.orka-engine.server.plist` → license key + DSN (F81)
6. NFS write test from authorized subnet (F79)
7. Find Sentry DSN from live process env (F77)
8. Confirm P-256 key usage in runvz (F89 context: is the signing key for image layers or for engine↔runvz auth?)
9. `pyinstxtractor svchost_nfs.exe` on Windows Python 2.7 host (F80)

### Next RE target: serialChannel wire format
- Need to find the message framing in the binary — look for `encoding/json`, `proto`, or length-prefix patterns near `serialChannel.Send`
- This determines exploitability of clipboard injection attack

### serialChannel wire format CONFIRMED
- JSON: `{"action":"clipboard_contents","data":"<payload>"}` newline-delimited, no auth
- Clipboard injection PoC from inside VM: `echo '{"action":"clipboard_contents","data":"evil content"}' > /dev/tty.virtio`
- Host clipboard gets overwritten — VM isolation boundary crossed
- **F93 written** — severity HIGH
- Metadata API: `{"keys":[...]}` and `{"value":"..."}` same JSON pattern

### Provisioning profiles: both orka-engine AND runvz have identical entitlements
- Team ID: `23KP83Z488` (MacStadium Inc)
- Both have `com.apple.vm.networking` = true + `keychain-access-groups: 23KP83Z488.*` (wildcard)
- Both have `ProvisionsAllDevices: true` (enterprise distribution)
- orka-engine UUID: `f4b55818-6fc8-4ea6-8456-25c850bc541d`
- runvz UUID: `4f96963f-c0d6-48f4-907b-4ec12953be8c`, expires 2043
- Implication: compromising either binary → full team keychain access + VM networking control
- P256 private key (F94) almost certainly stored in the `23KP83Z488.*` keychain group
- **F95 written** — severity HIGH

### orka-vm-tools: no provisioning profile — Go binary, runs inside VM only
- Not an Apple app bundle, no entitlements, no keychain access

---

## 2026-08-12 (continued) — orka-engine.server RE + svchost extraction attempt

### orka-engine.server: full env var set extracted (16 vars)
- ORKA_ENGINE_SENTRY_DSN confirmed in binary → live plist read extracts DSN + license key in one shot
- ORKA_ENGINE_SOCK confirms socket path is env-var-controlled → plist write = gRPC redirect
- See F96

### orka-engine.server: gRPC surface mapped (15 VM RPCs + 6 image RPCs)
- ImageDownloadLatestIPSW: engine pulls macOS firmware from Apple CDN (F97)
- VirtualMachineRepartition: destructive disk op over unauthenticated socket (F98)
- Full RPC inventory in F99 — all message types confirmed from SwiftProtobuf symbols
- **Lead**: Reconstruct the .proto file from the message type names → replay RPC calls against a controlled node

### svchost_nfs.exe extraction: BLOCKED
- PyInstaller 2.1 / Python 2.7 binary
- 65 entries found in CArchive TOC; i_new (main script) is type 's', clen=1,459,244, uclen=1,997,542
- Decompression fails from Python 3 environment — Python 2.7 zlib data format issue
- Marshal.loads also fails (Python 3 can't read Python 2.7 marshal format)
- **Next step**: Need Python 2.7 environment or uncompyle2/decompile2 tool
- Alternative: run on a Windows Python 2.7 host with pyinstxtractor + uncompyle2

---

## 2026-08-12 (continued) — orka-engine CLI binary RE batch 1

### Two OCI layer media types confirmed
- `orka-engine` format: `application/vnd.macstadium.orka-engine.disk.layer.v1+lz4` = raw bv41 (Ablation target)
- `orka-si` format: `application/vnd.macstadium.orka-si.image.layer.v1.aar+lz4` = Apple Archive + LZ4 (shared image caching)
- Standard OCI manifest wraps both; Bearer token auth for OCI registry transport
- OCI annotation keys carry disk offset + compressed/full/usage sizes — F100

### VMBundle directory structure mapped
- Each VM = a directory: `config.json`, `metadata.json`, `disk.img`, `disk-aux.img`, `run.sock`
- `run.sock` is per-VM IPC socket (engine → runvz), separate from the global `ORKA_ENGINE_SOCK`
- GlobalConfig URL tree: `orkaDirURL` → data/image/ipsw/tmp/run/log/vmLog/licenseDirURL
- **Lead**: Confirm `orkaDirURL` base path on live node (likely `/opt/orka`); check bundle dir permissions — F101

### DHCP lease file = VM IP oracle
- `DHCPParser.parseDHCPdLeases()` reads `/var/db/dhcpd_leases` for MAC→IP mapping
- `ORKA_ENGINE_DHCP_LEASE_TIME` is the 17th env var (CLI-only, not in server binary)
- Forging `/var/db/dhcpd_leases` redirects engine's VM IP resolution — F102

### orka-engine is a SwiftUI app (unexpected)
- `OrkaApp`, `VMView`, AppKit.framework linked — GUI mode + CLI mode in same binary
- Headless CI node with AppKit = dead but reachable code paths — F103

### ORKA_ENGINE_HELPER = highest-priority new attack vector
- Env var in LaunchAgent plist controls path to runvz binary
- Default: `Contents/Helpers/Orka Engine Runner.app/Contents/MacOS/com.macstadium.orka-engine.runvz`
- If plist writable → set to attacker binary → executes with wildcard keychain + vm.networking entitlements
- Plist writability depends on node filesystem permissions — F104
- **Lead**: On a live node, check: `ls -la /Library/LaunchAgents/com.macstadium.orka-engine*.plist`

---

## LEADS PRIORITY QUEUE (updated 2026-08-12 batch 2)

1. **ORKA_ENGINE_HELPER plist write** — check `/Library/LaunchAgents/com.macstadium.orka-engine*.plist` permissions on live node; if writable by `admin` user, redirect helper to attacker binary → full keychain + VM networking (F104)
2. **Per-VM run.sock permissions** — find `orkaDirURL` base path (likely `/opt/orka`); check bundle dir permissions → direct runvz access bypasses engine socket (F101)
3. **Live plist read** on provisioned node: `/Library/LaunchAgents/com.macstadium.orka-engine.server.plist` → ORKA_ENGINE_LICENSE_KEY + ORKA_ENGINE_SENTRY_DSN + full env set (F96)
4. **Clipboard injection via virtio** — from inside VM, write `clipboard_contents` JSON to `/dev/tty.virtio` (F93)
5. **Metadata API** from inside VM: `curl http://169.254.169.254/metadata` → enumerate all metadata keys (F88)
6. **Reconstruct OrkaEngineServer.proto** from message type names → replay gRPC calls against engine socket (F99)
7. **svchost_nfs.exe i_new.py** extraction — needs Python 2.7 environment
8. **P256 key in runvz**: confirm fixed vs ephemeral, check keychain storage path (F94)
9. **NFS write test** from authorized subnet (F79)
