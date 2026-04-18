\# Sprint 1 Complete



\## What was built

\- 4 Ubuntu 24.04 VMs deployed in VMware Workstation Pro

\- Custom VMnet2 configured at 192.168.100.0/24

\- Static IPs assigned to all VMs

\- Splunk Enterprise 10.2.2 installed on VM1

\- Splunk web UI accessible at http://192.168.100.10:8000



\## VM Network Reference

| VM | Hostname | Internal IP |

|---|---|---|

| VM1 | vm1-splunk | 192.168.100.10 |

| VM2 | vm2-agent | 192.168.100.20 |

| VM3 | vm3-forwarder | 192.168.100.30 |

| VM4 | vm4-qdrant | 192.168.100.40 |

| Host | windows-host | 192.168.100.1 |



\## VM Specs

| VM | RAM | vCPUs | Storage | Purpose |

|---|---|---|---|---|

| VM1 | 8GB | 6 | 100GB | Splunk SIEM |

| VM2 | 6GB | 6 | 40GB | AI Agent |

| VM3 | 2GB | 2 | 20GB | Log Forwarder |

| VM4 | 3GB | 2 | 40GB | Qdrant Vector DB |



\## Tools installed

\- Splunk Enterprise 10.2.2

\- Ubuntu 24.04.4 LTS on all VMs



\## Issues encountered and resolved

\- VMnet2 host adapter assigned APIPA address — fixed by

&#x20; manually setting static IP to 192.168.100.1

\- Splunk running as root warning — resolved by creating

&#x20; dedicated splunk user and reconfiguring boot start

\- VM reboot caused host system freeze — resolved, no data lost

