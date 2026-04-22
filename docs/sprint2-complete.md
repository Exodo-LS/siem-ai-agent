# Sprint 2 Complete



## What was built

- Splunk Universal Forwarder installed and configured on VM3

- Splunk receiving port 9997 enabled on VM1

- Dedicated soc-logs index created in Splunk

- Sysmon for Linux v1.5.1 installed on VM3 with SwiftOnSecurity config

- Sysmon telemetry flowing into Splunk via Universal Forwarder

- 5 SPL detection searches written and saved as reports

- SOC Overview dashboard built in Dashboard Studio



## SPL Detections written

| Report Name | Description | EventID |

|---|---|---|

| SOC - Process Creation (EventID=1) | All process creation events | 1 |

| SOC - Suspicious Process Execution | wget, curl, nc, nmap, python | 1 |

| SOC - Root Process Execution | All processes run as root | 1 |

| SOC - Authentication Failures | Failed auth events from syslog | N/A |

| SOC - Cron Job Executions | Cron activity from syslog | N/A |



## Log sources configured

- sourcetype=sysmon — Sysmon for Linux events via journald

- sourcetype=syslog — System logs via /var/log/syslog



## Event volumes (first session)

- Total events indexed: 2,291+ in first 15 minutes

- Root executions detected: 3,935

- Auth failure events: 98



## Issues encountered and resolved

- Sysmon for Linux only generates EventID=1 (process creation)

&#x20; unlike Windows Sysmon which generates network, file, registry events

&#x20; Resolved by building detections around EventID=1 and syslog sources

- SPL field extraction required rex commands due to XML raw format

&#x20; of Sysmon for Linux events



## Architecture notes

- VM3 runs both Sysmon (telemetry generator) and

&#x20; Universal Forwarder (log shipper) simultaneously

- Logs route: VM3 Sysmon → journald → Universal Forwarder → VM1 Splunk port 9997 → soc-logs index

