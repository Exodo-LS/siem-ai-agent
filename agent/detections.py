# agent/detections.py
# Detection rules grounded in actual soc-logs sourcetypes:
#   - syslog  (/var/log/syslog)     — system events, cron, apt, systemd
#   - sysmon  (journald://sysmon)   — process execution, attack simulations

DETECTION_RULES = [

    # ── Credential Access ────────────────────────────────────────────────────
    {
        "id": "DR-001",
        "name": "Brute Force - Repeated Failed Logons",
        "sourcetype": "sysmon",
        "spl": 'index=soc-logs sourcetype=sysmon ("Failed logon" OR "EventCode=4625") | head 50',
        "mitre_tactic": "TA0006 - Credential Access",
        "mitre_technique": "T1110.001 - Password Guessing",
        "severity_hint": "high",
        "enabled": True,
    },

    # ── Privilege Escalation ─────────────────────────────────────────────────
    {
        "id": "DR-002",
        "name": "Privilege Escalation - Local Admin Group Modification",
        "sourcetype": "sysmon",
        "spl": 'index=soc-logs sourcetype=sysmon ("net localgroup" OR "EventCode=4728" OR "EventCode=4732") | head 50',
        "mitre_tactic": "TA0004 - Privilege Escalation",
        "mitre_technique": "T1078.003 - Local Accounts",
        "severity_hint": "critical",
        "enabled": True,
    },

    # ── Execution ────────────────────────────────────────────────────────────
    {
        "id": "DR-003",
        "name": "Suspicious Execution - Encoded PowerShell",
        "sourcetype": "sysmon",
        "spl": 'index=soc-logs sourcetype=sysmon ("powershell -enc" OR "powershell -e " OR "powershell -EncodedCommand") | head 50',
        "mitre_tactic": "TA0002 - Execution",
        "mitre_technique": "T1059.001 - PowerShell",
        "severity_hint": "critical",
        "enabled": True,
    },

    # ── Persistence ──────────────────────────────────────────────────────────
    {
        "id": "DR-004",
        "name": "Persistence - Scheduled Task Creation",
        "sourcetype": "sysmon",
        "spl": 'index=soc-logs sourcetype=sysmon ("schtasks" OR "EventCode=4698") | head 50',
        "mitre_tactic": "TA0003 - Persistence",
        "mitre_technique": "T1053.005 - Scheduled Task",
        "severity_hint": "high",
        "enabled": True,
    },
    {
        "id": "DR-005",
        "name": "Persistence - Registry Run Key Modification",
        "sourcetype": "sysmon",
        "spl": 'index=soc-logs sourcetype=sysmon ("reg add" OR "CurrentVersion\\Run") | head 50',
        "mitre_tactic": "TA0003 - Persistence",
        "mitre_technique": "T1547.001 - Registry Run Keys",
        "severity_hint": "high",
        "enabled": True,
    },

    # ── Discovery ────────────────────────────────────────────────────────────
    {
        "id": "DR-006",
        "name": "Discovery - Privilege and Account Enumeration",
        "sourcetype": "sysmon",
        "spl": 'index=soc-logs sourcetype=sysmon ("whoami" OR "net user" OR "net localgroup administrators") | head 50',
        "mitre_tactic": "TA0007 - Discovery",
        "mitre_technique": "T1069.001 - Local Groups",
        "severity_hint": "medium",
        "enabled": True,
    },

    # ── System Events (syslog) ───────────────────────────────────────────────
    {
        "id": "DR-007",
        "name": "System - Repeated Service Failures",
        "sourcetype": "syslog",
        "spl": 'index=soc-logs sourcetype=syslog ("failed" OR "error" OR "fatal") | head 50',
        "mitre_tactic": "TA0040 - Impact",
        "mitre_technique": "T1489 - Service Stop",
        "severity_hint": "medium",
        "enabled": True,
    },
    {
        "id": "DR-008",
        "name": "System - Cron Job Execution Anomaly",
        "sourcetype": "syslog",
        "spl": 'index=soc-logs sourcetype=syslog source="/var/log/syslog" ("CRON" OR "cron") | head 50',
        "mitre_tactic": "TA0003 - Persistence",
        "mitre_technique": "T1053.003 - Cron",
        "severity_hint": "low",
        "enabled": True,
    },

    # ── Lateral Movement ─────────────────────────────────────────────────────
    {
        "id": "DR-009",
        "name": "Lateral Movement - Remote Desktop Activity",
        "sourcetype": "sysmon",
        "spl": 'index=soc-logs sourcetype=sysmon ("rdp" OR "remote desktop" OR "mstsc") | head 50',
        "mitre_tactic": "TA0008 - Lateral Movement",
        "mitre_technique": "T1021.001 - Remote Desktop Protocol",
        "severity_hint": "medium",
        "enabled": True,
    },

    # ── Defense Evasion ──────────────────────────────────────────────────────
    {
        "id": "DR-010",
        "name": "Defense Evasion - Script Interpreter Abuse",
        "sourcetype": "sysmon",
        "spl": 'index=soc-logs sourcetype=sysmon ("wscript" OR "mshta" OR "cscript") | head 50',
        "mitre_tactic": "TA0005 - Defense Evasion",
        "mitre_technique": "T1218 - System Binary Proxy Execution",
        "severity_hint": "high",
        "enabled": True,
    },
]
