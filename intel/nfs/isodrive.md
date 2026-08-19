# NFS isodrive — MacStadium Image Store

## Access
- Server: 207.254.72.172 (Las Vegas)
- Export: /mnt/isodrive
- Mount: `mount -t nfs -o tcp,noacl,nolock 207.254.72.172:/mnt/isodrive /tmp/nfs_orka`
- Auth: None (IP-based ACL only, 208.52.182.0/24 authorized)

## Security Risk
Any host in the 25+ authorized subnets can mount this share unauthenticated.
This includes all MacStadium customer subnets — customers can read each other's images.

## World-Writable Files (*** SUPPLY CHAIN RISK ***)
Write access verification pending — NFS server may squash uid 501.
```
OSX/OSX_10.10.iso         10GB  -rwxrwxrwx 1000:1001  Sep 2016  (Yosemite)
OSX/OS_X_Server_2.2.2.dmg 171MB -rwxrwxrwx 1000:1001  Feb 2014
OSX/OSX_10.7.4.iso         4.0G -rwxrwxrwx 1000:1001  Dec 2012  (Lion)
OSX/OSX_10.8.iso            4.5G -rwxrwxrwx 1000:1001  Dec 2012  (Mountain Lion)
OSX/OSX_10.9.iso            5.6G -rwxrwxrwx 1000:1001  Sep 2016  (Mavericks)
WINDOWS/* (most ISOs)       3-5GB -rwxrwxrwx 1000:1001
WINDOWS/WIN10_EVALS/       dir   drwxrwxrwx
WINDOWS/temp/              dir   drwxrwxrwx
UBUNTU_SERVER/* (all ISOs) 600MB-700MB -rwxrwxrwx
UTILTIES/gparted-*         -rwxrwxrwx
```

## Root-Owned (Read Only)
```
OSX/HighSierra.iso          5.4G  root:wheel  Dec 2019
OSX/Mac OS Catalina.iso     8.3G  root:wheel  Oct 2019
OSX/Mac OS Mojave.iso       6.3G  root:wheel  Oct 2019
OSX/MacOS-13.3.iso          13G   root:wheel  May 2023
OSX/OSX_11.0.1-20B29.iso    12G   root:wheel  Dec 2020
UTILTIES/ise-3.1.0.518c.SPA.x86_64_SNS-37x5.iso  11G root:wheel (Cisco ISE 3.1)
Win11_English_x64.iso       5.1G  root:wheel
WindowsServer2016.ISO       5.5G  root:wheel
```

## Suspicious Files
```
/mnt/isodrive/JxjEKoTV.exe         55KB PE32  owner=administrator:nogroup  created Jun 18 2026
/mnt/isodrive/NORAahMV.exe         0B   empty  owner=administrator:nogroup
/mnt/isodrive/aOrTIjxQ.exe         0B   empty  owner=administrator:nogroup
/mnt/isodrive/itUmzxJV.exe         0B   empty  owner=administrator:nogroup
/mnt/isodrive/wDsCMHPO.exe         0B   empty  owner=administrator:nogroup
/mnt/isodrive/WINDOWS/temp/svchost.exe  8MB PE32  owner=administrator:nogroup  created Aug 6 2026
```

Note: All administrator:nogroup files were placed from .90 in prior sessions.

## Directories
```
APPLIANCES/ — PBX: ELASTIX_PBX, PBX_INA_FLASH, PROXMOX
ARCH_LINUX/
BETO/ — empty
BOOTCAMP/
CENTOS/
CITRIX/
CPANEL/
DEBIAN/
ESXi/
FEDORA/
FREE_BSD/
OSX/ — macOS 10.7–13.3 ISO images
PLESK/
RHEL/
SCIENTIFICLINUX/
SUSE/
UBUNTU_SERVER/ — Ubuntu 10.04–12.10 ISOs (all world-writable)
UBUNTU_WORKSTATION/
UTILTIES/ — gparted, Cisco ISE, sysmgr
VMWARE/ — VMware ESXi 6.7, vCenter 6.x ISOs
WINDOWS/ — Windows 7/8/10/11, Server 2008/2012/2016 (most world-writable)
```
