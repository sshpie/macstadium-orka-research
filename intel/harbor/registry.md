# Harbor OCI Registry Analysis

## External Registries
- orkv10000009-01.oci.las1.macstadiumcloud.com
- orkv10000037-01.oci.las1.macstadiumcloud.com
- Auth: admin:Harbor12345 (pull-only; robot accounts API = UNAUTHORIZED)
- Internal Harbor: https://10.221.188.5:30080 (likely same credentials)

## tahoe-base Image Analysis (Inspector Report)
Run: `python3 /home/cowboy/VDT/tools/ClaudeIP-max/orka_inspector.py /tmp/.../tahoe_base_v1.json`
Full anatomy: /tmp/.../scratchpad/tahoe_base_v1.anatomy.json

### Stats
- Full disk: 756GB, Usage: 186GB, Compressed: 187GB
- Total layers: 369
- Layers with offset: 367
- Layers WITHOUT offset: 2 (config/metadata blobs)

### Critical Findings
1. **364/367 layers exceed INT32_MAX (2,147,483,647)** — systemic 32-bit overflow
   - Any Orka engine component using signed 32-bit offsets would corrupt writes to sectors beyond 3GB
   - Affects layers 4+ (offset 2.2GB, 2.75GB, 3.37GB, ...)
   
2. **260 overlapping layer pairs** — consecutive layers overlap by ~51MB
   - Write order determines which data wins at overlapped sectors
   - INJECTION VECTOR: a crafted late layer with correct offset can overwrite any earlier sector
   
3. **Critical gaps in APFS container region** — ~107 gaps total
   - Largest: 83GB (595GB–664GB range)
   - APFS container region mostly uncovered

### Overlap Pattern
Most overlaps are exactly 51MB between consecutive layers:
L01↔L02: 51MB at 1664MB-1715MB
L02↔L03: 57MB at 2240MB-2297MB
L53-L97: consistent 51MB overlap every consecutive pair
...

### Media Types (Custom OCI)
- Layers: `application/vnd.macstadium.orka-engine.disk.layer.v1+lz4`
- Config: `application/vnd.macstadium.orka-engine.image.config.v1+json`
- Offset annotation: `com.macstadium.orka-engine.disk.layer.offset`

## Supply Chain Attack Vector
Chain: Harbor access → modify layer → push crafted image → all future VMs get implant
- `orka3 vm push VM_NAME server.com/repo/image:tag` — push running VM back
- admin:Harbor12345 = sufficient to pull; write access needs investigation
- Overlap injection: craft a layer at correct offset to write to macOS boot sectors

## Tools
- Inspector: /home/cowboy/VDT/tools/ClaudeIP-max/orka_inspector.py
- orka3 CLI: /home/cowboy/VDT/tools/orka3/orka3
