# Sprint 9 Complete — Polish, Dashboard, Final Cleanup

## Goal
Add T1548.001 to the attack chain, build the AI Triage Overview dashboard in Splunk,
fix forwarder issues, and get the full demo production-ready for CyberCon May 31st.

## What Was Built

### T1548.001 — Setuid Privilege Escalation
- build-essential installed on VM3 (make + gcc)
- T1548.001 verified running — compiles hello.c, chown root, chmod u+s
- Sysmon captures: sudo chown, sudo chmod u+s, /tmp/hello execution
- Added to demo.py attack chain and cleanup
- NOPASSWD sudo configured on VM3 via visudo

### AI Triage Overview Dashboard (Splunk VM1)
- Panel 1 — Event volume single value (red/green)
- Panel 2 — Escalation status ESCALATE/CLEAR (red/green)
- Panel 3 — High severity event count (red/green)
- Panel 4 — MITRE ATT&CK technique coverage bar chart
- Panel 5 — Process execution timeline area chart
- Panel 6 — Attack commands detected table with Time, User, Process, Command Line
- All panels use rex extraction on Sysmon XML format
- Fixed source filter to journald://sysmon for accurate results

### Forwarder Fix
- Identified journal cursor freeze after VM3 restart
- Restarted SplunkForwarder to reset cursor
- Verified forwarding with test event
- Events now flowing in real time

### Demo Stability
- 5 successful clean demo runs across Sprint 9
- SSH key auth confirmed working VM2 → VM3
- All 4 ART techniques executing and cleaning up
- useradd working via SSH with NOPASSWD sudo

## Attack Technique Summary

| Technique | Name | Sysmon Captures | Status |
|---|---|---|---|
| T1059.004 | Unix Shell Execution | art.sh creation, chmod +x, execution | Active |
| T1053.003 | Cron Persistence | crontab modification, evil.sh | Active |
| T1136.001 | Local Account Creation | useradd evil_user | Active |
| T1548.001 | Setuid Privilege Escalation | cc compile, chown root, chmod u+s | Active |

## VMs Used
- VM1 — Splunk + AI Triage Overview dashboard
- VM2 — Agent runtime
- VM3 — Attack target, Atomic Red Team, NOPASSWD sudo
- VM4 — Qdrant memory

## CyberCon Demo Command
    python agent/demo.py --clean

## Next
Sprint 10 — Cert push (Splunk Core Certified User, SAL1)
