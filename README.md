# Network Automation using Python

This repository showcases an end-to-end networking and systems administration project that brings together three core domains:  
- **Cisco CCNA concepts** for designing and configuring enterprise-grade networks  
- **Linux administration** for server and endpoint management  
- **Python automation** for streamlining repetitive network tasks and ensuring consistent configurations  

It provides a fully documented lab environment with configurations, scripts, and automation tools, making it an ideal resource for students, network engineers, and sysadmins who want to practice hands-on networking, Linux, and automation skills in an integrated way.

## Network Topology

![Project Topology](topologie_proiect_cu_notite.jpg)

## Project Structure

ccna/

├── ipv4/ # IPv4 subnetting and configurations

├── ipv6/ # IPv6 configurations

├── nat/ # NAT configurations

├── acl/ # Standard and extended ACLs

├── spanning_tree/ # STP configurations

├── dhcp/ # DHCP and DHCP snooping

├── ntp/ # NTP configurations

├── syslog/ # Syslog setup

└── loopbacks/ # Loopback interfaces

linux/

├── day1_setup.sh # Initial setup (users, groups, directories)

├── day2_user_group.sh # Interactive script for user/group creation

├── day3_backup.sh # Backup & archive log files

├── day4_services.sh # Extract unique services from /etc/services

python/

└── network_automation/ # Automation scripts and configuration backups

└── network_automation/ # Automation scripts and configuration backups

## Main features

### CCNA
- IPv4 and IPv6 subnetting
- VLAN configuration (Site A: VLAN 10, 20 / Site B: VLAN 30, 40)
- RIPv2 + RIPng
- Default routes and propagation
- DHCP (R3 server for Site A)
- SSH on all devices (Telnet only on SW5)
- NTP, STP, ACL, NAT, DHCP Snooping, Syslog
- Loopback interfaces on all intermediate devices

### Linux
- **Day 1**: users, groups, and directories
- **Day 2**: interactive script for user/group creation with validation
- **Day 3**: backup and archive of log files
- **Day 4**: extract unique services from `/etc/services`

### Python
- Automated configuration and IP address assignment
- Backup of `running-config` from devices
- Save configurations as `<hostname>_before.txt` and `<hostname>_after.txt`
- Optional: automation for IPv6, DHCP, ACL, NAT

## License
MIT License - free for educational and personal use
