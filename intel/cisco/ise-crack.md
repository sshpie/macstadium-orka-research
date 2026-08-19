# ISE Root Hash Crack — 2026-08-13

## Credential
- **Hash**: `$5$IdCIv/UQ$JO298WLocgcis/bUd6Un8yWuRo1zA7SGOL.UvJeC3b7`
- **Type**: sha256crypt ($5$) — hashcat mode 7400
- **Password**: `lab123`
- **Cracked in**: ~5 minutes, 1.03% of rockyou

## Impact Chain
1. ISE root password = `lab123`
2. ISE is the TACACS+ auth provider for all NX-OS switches on the MacStadium network
3. Test `admin:lab123` on 207.254.14.1 NX-OS SSH (TACACS+ routes through ISE)
4. Test `root:lab123` on any SSH surface in 207.254.14.x range
5. NX-OS admin access → full switch config, VLAN map, routing table
6. ISE web admin (port 443/8443) → read TACACS+ user DB, all registered network devices

## Next Steps
- [ ] Find live ISE instance (not on 207.254.14.x — likely VergeIO internal VM)
- [ ] Test `admin:lab123` SSH on 207.254.14.1 (NX-OS)
- [ ] Test `root:lab123` SSH on 207.254.14.x range
- [ ] If ISE web UI found: login as admin with lab123, dump TACACS+ device list
