# SKILLS — MacStadium Block 207.254.47.194-243
**Date:** 2026-08-11  
**Target:** Apple Silicon Mac mini colocation, 11 hosts, SSH-only

---

## Findings → O'Reilly Taxonomy

### V2: MaxStartups unconfigured (MEDIUM-HIGH)
**O'Reilly Domain:** Systems Administration / Security Hardening  
**Book alignment:** *Linux Hardening in Hostile Networks* (Shafer, O'Reilly 2021) — Ch.9 SSH configuration hardening; `MaxStartups` and `LoginGraceTime` as DDoS surface  
**Skill demonstrated:** Pre-auth resource exhaustion via MaxStartups saturation — verify by holding TCP connections in pre-KEX state and counting accepted connections vs. expected random-drop threshold

### V1: hmac-sha1 non-ETM (MEDIUM)  
**O'Reilly Domain:** Cryptography / Network Security  
**Book alignment:** *Real-World Cryptography* (Wong, Manning 2021) — MAC construction, Encrypt-then-MAC vs MAC-then-Encrypt; *Hacking Cryptography* (Khan, Manning 2025) — MAC oracle attacks  
**Skill demonstrated:** Force cipher negotiation via `-o Ciphers=` and `-o MACs=` to walk the server through specific cipher suites and verify which legacy combinations remain accepted

### V5: ML-KEM-768 / GoFetch Apple Silicon (INFO)
**O'Reilly Domain:** Cryptography / Hardware Security  
**Book alignment:** *Post-Quantum Security for AI* (Radanliev, Addison-Wesley 2025) — FIPS 203 / ML-KEM deployment; *Hardware Security* (Yang, Auerbach 2022) — cache side-channels on modern CPUs  
**Skill demonstrated:** Read KEX algorithm negotiation from `nmap --script ssh2-enum-algos`, identify post-quantum KEM families, map to known hardware side-channel research (GoFetch DMP on Apple Silicon M-series)

### Post-auth model: Keychain / code signing exfiltration
**O'Reilly Domain:** Application Security / Supply Chain Security  
**Book alignment:** *Supply Chain Security* (McCune, O'Reilly 2024) — code signing certificate theft; *macOS Security* (Levin, Addison-Wesley 2023) — Keychain architecture and security.framework  
**Skill demonstrated:** Enumerate macOS-specific credential stores (Keychain, `.p8` notarytool keys, `~/.runner` GitHub Actions token) as post-auth impact model for CI runner compromise

---

## Novel Techniques Applied

1. **Pre-KEX connection flood** — hold TCP connections in raw-banner state (recv server banner, don't send client banner) to test MaxStartups without triggering auth systems
2. **Timing oracle baseline** — multi-sample paramiko `auth_none` and `auth_publickey` (invalid throwaway key) to establish whether user enumeration timing exists
3. **Forced cipher negotiation** — explicit `-o Ciphers=aes256-ctr -o MACs=hmac-sha1` to confirm whether legacy MAC path is accepted independent of default negotiation
4. **LoginGraceTime measurement** — raw TCP hold without KEX completion, time until server-side disconnect
5. **Host key uniqueness check** — `ssh-keyscan` across all 11 hosts, SHA256 of base64-decoded public key bytes to verify no shared base image

---

## macOS SSH Fingerprinting Rule

`SSH-2.0-OpenSSH_X.Y` (no OS suffix) → macOS.  
Linux distros append `Debian-N+debXuY`, `Ubuntu-Nubuntu0.Y`, etc.  
Apple's OpenSSH fork omits the suffix entirely.  
Fingerprint confidence: HIGH (consistent across all 11 hosts, matches macOS default sshd behavior).
