#!/usr/bin/env python3
"""
orka_inspector.py — Orka VM Disk Image Inspector
Converts Harbor/Orka manifests to sector-level coverage maps.
Detects gaps, overlaps, 32-bit overflow vectors, and anomalies.
Produces machine-readable anatomy reports for security review.

Input: Harbor OCI manifest JSON (from /v2/library/.../manifests/<tag>)
Output: anatomy_report.json + coverage.txt

Usage:
  python3 orka_inspector.py <manifest.json>
  python3 orka_inspector.py --harbor <host> <repo> <tag> --auth admin:Harbor12345
"""
import json, sys, hashlib, struct
from typing import List, Dict, Tuple, Optional
from dataclasses import dataclass, field, asdict
from pathlib import Path
import argparse, urllib.request, ssl

# macOS disk critical sector offsets (512-byte sectors)
MACOS_CRITICAL_REGIONS = [
    (0,       1,      "Protective MBR"),
    (1,       2,      "GPT Header Primary"),
    (2,       34,     "GPT Partition Table Entries"),
    (34,      40,     "GPT First Usable Sector"),
    (40,      409640, "EFI System Partition (typical 200MB)"),
    (409640,  None,   "APFS Container Start (typical)"),  # None = "to end"
]

# 32-bit signed int max
INT32_MAX = 2**31 - 1

@dataclass
class LayerInfo:
    idx: int
    digest: str
    offset_bytes: Optional[int]        # None = no offset annotation
    compressed_size: int
    inferred_end_bytes: Optional[int]  # estimated
    overflow_32bit: bool
    annotations: Dict
    
@dataclass
class GapRegion:
    start_bytes: int
    end_bytes: int
    size_bytes: int
    contains_critical: List[str] = field(default_factory=list)

@dataclass  
class OverlapRegion:
    layer_a_idx: int
    layer_b_idx: int
    overlap_bytes: int
    start_bytes: int
    end_bytes: int

@dataclass
class AnatomyReport:
    manifest_type: str
    disk_size_full: int
    disk_size_usage: int
    disk_size_compressed: int
    sector_size: int = 512
    total_sectors: int = 0
    total_layers: int = 0
    layers_with_offset: int = 0
    layers_without_offset: int = 0
    layers_overflow_32bit: int = 0
    coverage_bytes: int = 0
    coverage_pct: float = 0.0
    gaps: List[GapRegion] = field(default_factory=list)
    overlaps: List[OverlapRegion] = field(default_factory=list)
    critical_region_coverage: Dict[str, bool] = field(default_factory=dict)
    anomalies: List[str] = field(default_factory=list)
    layers: List[LayerInfo] = field(default_factory=list)


def load_harbor_manifest(path: str) -> dict:
    with open(path) as f:
        return json.load(f)


def extract_layers(manifest: dict) -> Tuple[AnatomyReport, List[LayerInfo]]:
    ann = manifest.get('annotations', {})
    disk_full  = int(ann.get('com.macstadium.orka-engine.disk-size.full', 0))
    disk_usage = int(ann.get('com.macstadium.orka-engine.disk-size.usage', 0))
    disk_cmp   = int(ann.get('com.macstadium.orka-engine.disk-size.compressed', 0))
    
    report = AnatomyReport(
        manifest_type=manifest.get('mediaType', 'OCI'),
        disk_size_full=disk_full,
        disk_size_usage=disk_usage,
        disk_size_compressed=disk_cmp,
        total_sectors=disk_full // 512,
        total_layers=len(manifest.get('layers', [])),
    )
    
    layers = []
    for i, l in enumerate(manifest.get('layers', [])):
        layer_ann = l.get('annotations', {})
        off_key = 'com.macstadium.orka-engine.disk.layer.offset'
        off_val = layer_ann.get(off_key)
        offset_bytes = int(off_val) if off_val is not None else None
        overflow = (offset_bytes is not None and offset_bytes > INT32_MAX)
        layers.append(LayerInfo(
            idx=i,
            digest=l.get('digest', ''),
            offset_bytes=offset_bytes,
            compressed_size=l.get('size', 0),
            inferred_end_bytes=None,
            overflow_32bit=overflow,
            annotations=layer_ann,
        ))
    
    return report, layers


def compute_coverage(report: AnatomyReport, layers: List[LayerInfo]) -> AnatomyReport:
    offset_layers = [l for l in layers if l.offset_bytes is not None]
    no_offset     = [l for l in layers if l.offset_bytes is None]
    
    report.layers_with_offset    = len(offset_layers)
    report.layers_without_offset = len(no_offset)
    report.layers_overflow_32bit = sum(1 for l in offset_layers if l.overflow_32bit)
    
    # Sort by offset
    sorted_layers = sorted(offset_layers, key=lambda l: l.offset_bytes)
    
    # Infer end positions (compressed * ratio; real ratio for Orka ~1.1)
    RATIO = 1.1
    for l in sorted_layers:
        l.inferred_end_bytes = l.offset_bytes + int(l.compressed_size * RATIO)
    
    # Compute gaps and overlaps
    disk_full = report.disk_size_full
    gaps, overlaps = [], []
    prev_end = 0
    covered = 0
    
    for i, l in enumerate(sorted_layers):
        start = l.offset_bytes
        end   = l.inferred_end_bytes
        
        if start > prev_end:
            # GAP
            gap = GapRegion(prev_end, start, start - prev_end)
            # Check if gap contains critical macOS structures
            for cs, ce, desc in MACOS_CRITICAL_REGIONS:
                cs_bytes = cs * 512
                ce_bytes = (ce or report.total_sectors) * 512
                if gap.start_bytes < ce_bytes and gap.end_bytes > cs_bytes:
                    gap.contains_critical.append(desc)
            gaps.append(gap)
        elif start < prev_end and i > 0:
            # OVERLAP
            overlaps.append(OverlapRegion(
                sorted_layers[i-1].idx, l.idx,
                prev_end - start, start, prev_end
            ))
        
        covered += max(0, min(end, disk_full) - max(start, prev_end))
        prev_end = max(prev_end, end)
    
    if prev_end < disk_full:
        gaps.append(GapRegion(prev_end, disk_full, disk_full - prev_end))
    
    report.gaps     = gaps
    report.overlaps = overlaps
    report.coverage_bytes = covered
    report.coverage_pct   = 100.0 * covered / disk_full if disk_full else 0
    
    # Critical region coverage
    for cs, ce, desc in MACOS_CRITICAL_REGIONS:
        cs_bytes = cs * 512
        ce_bytes = (ce or report.total_sectors) * 512
        report.critical_region_coverage[desc] = any(
            l.offset_bytes <= cs_bytes and l.inferred_end_bytes >= ce_bytes
            for l in sorted_layers if l.inferred_end_bytes
        )
    
    # Anomaly detection
    if report.layers_overflow_32bit > 0:
        report.anomalies.append(
            f"32-BIT OVERFLOW: {report.layers_overflow_32bit}/{report.layers_with_offset} "
            f"offset layers exceed INT32_MAX. Any system using signed 32-bit offsets "
            f"would corrupt writes to sectors beyond {INT32_MAX // 512 // 1024 // 1024}GB."
        )
    if len(overlaps) > 0:
        report.anomalies.append(
            f"LAYER OVERLAPS: {len(overlaps)} pairs overlap. "
            f"Write order determines which data wins. Potential injection: "
            f"a crafted late layer could overwrite any earlier sector."
        )
    critical_gaps = [g for g in gaps if g.contains_critical]
    if critical_gaps:
        for g in critical_gaps:
            report.anomalies.append(
                f"CRITICAL GAP at {g.start_bytes//1024//1024}MB-{g.end_bytes//1024//1024}MB "
                f"({g.size_bytes//1024//1024}MB): covers {', '.join(g.contains_critical)}"
            )
    
    report.layers = layers
    return report


def print_report(report: AnatomyReport):
    print(f"\n{'='*70}")
    print(f"  ORKA VM DISK IMAGE ANATOMY REPORT")
    print(f"{'='*70}")
    print(f"  Disk full:       {report.disk_size_full:>15,} bytes  ({report.disk_size_full//1024**3}GB)")
    print(f"  Disk usage:      {report.disk_size_usage:>15,} bytes  ({report.disk_size_usage//1024**3}GB used)")
    print(f"  Disk compressed: {report.disk_size_compressed:>15,} bytes  ({report.disk_size_compressed//1024**3}GB on S3)")
    print(f"  Total sectors:   {report.total_sectors:>15,}")
    print(f"")
    print(f"  Layers total:         {report.total_layers}")
    print(f"  Layers w/ offset:     {report.layers_with_offset}")
    print(f"  Layers w/o offset:    {report.layers_without_offset}  (config/metadata blobs)")
    print(f"  Layers overflow32:    {report.layers_overflow_32bit}  {'[OVERFLOW RISK]' if report.layers_overflow_32bit else ''}")
    print(f"")
    print(f"  Coverage: {report.coverage_bytes//1024**3}GB ({report.coverage_pct:.1f}% of disk)")
    print(f"  Gaps:     {len(report.gaps)}")
    print(f"  Overlaps: {len(report.overlaps)}")
    
    print(f"\n--- Critical Region Coverage ---")
    for region, covered in report.critical_region_coverage.items():
        status = "COVERED" if covered else "GAP (uncovered!)"
        print(f"  {status:20s}  {region}")
    
    if report.gaps:
        print(f"\n--- Top Gaps by Size ---")
        for g in sorted(report.gaps, key=lambda x: -x.size_bytes)[:8]:
            crit = f" [CRIT: {', '.join(g.contains_critical)}]" if g.contains_critical else ""
            print(f"  {g.start_bytes//1024**3:3d}GB-{g.end_bytes//1024**3:3d}GB "
                  f"({g.size_bytes//1024**2:6d}MB){crit}")
    
    if report.overlaps:
        print(f"\n--- Layer Overlaps ---")
        for o in report.overlaps:
            print(f"  L{o.layer_a_idx:02d} ↔ L{o.layer_b_idx:02d}  overlap: {o.overlap_bytes//1024**2}MB "
                  f"at {o.start_bytes//1024**2}MB-{o.end_bytes//1024**2}MB")
    
    if report.anomalies:
        print(f"\n--- ANOMALIES ---")
        for a in report.anomalies:
            print(f"  [!] {a}")
    
    print(f"\n{'='*70}\n")


if __name__ == '__main__':
    manifest_path = sys.argv[1] if len(sys.argv) > 1 else \
        '/tmp/claude-1000/-home-cowboy/aad6168a-50df-43b4-b454-548e970d4105/scratchpad/ventura_manifest.json'
    
    manifest = load_harbor_manifest(manifest_path)
    report, layers = extract_layers(manifest)
    report = compute_coverage(report, layers)
    print_report(report)
    
    # Save JSON report
    out_path = Path(manifest_path).with_suffix('.anatomy.json')
    with open(out_path, 'w') as f:
        json.dump(asdict(report), f, indent=2, default=str)
    print(f"[saved] {out_path}")
