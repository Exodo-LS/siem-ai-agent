# siem-ai-agent

AI-powered SIEM triage agent using Splunk, LangGraph, and Claude Sonnet

## VM Network

| VM | Hostname | IP | Role |
|---|---|---|---|
| VM1 | vm1-splunk | 192.168.100.10 | Splunk 10.2.2 |
| VM2 | vm2-agent | 192.168.100.20 | AI Agent + LangGraph |
| VM3 | vm3-forwarder | 192.168.100.30 | Sysmon + Universal Forwarder + Atomic Red Team |
| VM4 | vm4-qdrant | 192.168.100.40 | Qdrant Vector Database |

## Architecture

    VM3 (Sysmon + Atomic Red Team) -> VM1 (Splunk) -> VM2 (LangGraph + Claude Sonnet) -> VM4 (Qdrant Memory)

## Sprint Progress

| Sprint | Goal | Status |
|---|---|---|
| Sprint 1 | Splunk install + index setup | Done |
| Sprint 2 | Sysmon + Universal Forwarder | Done |
| Sprint 3 | Splunk REST API + Python CLI | Done |
| Sprint 4 | LangGraph agent + Claude triage | Done |
| Sprint 5 | Qdrant vector memory integration | Done |
| Sprint 6 | Demo-ready polish for CyberCon | Done |
| Sprint 7 | Agent v2 multi-step reasoning | Done |
| Sprint 8 | Atomic Red Team simulations | Done |
| Sprint 9 | Polish, dashboard, final cleanup | Next |

## Agent Pipeline

    Splunk Events
         |
    Detection Rules (10 rules, MITRE ATT&CK mapped)
         |
    LangGraph Agent
      |- Node 1: Ingest Events
      |- Node 2: Classify Severity
      |- Node 3: Reason with Claude Sonnet (+ Qdrant memory context)
      |- Node 4: Generate Follow-up Queries (multi-step reasoning)
      |- Node 5: Execute Follow-up Queries against Splunk
      |- Node 6: Produce Triage Report + Store to Qdrant
         |
    triage_output.json + triage_reports/

## Detection Rules

| ID | Name | MITRE Tactic |
|---|---|---|
| DR-001 | Brute Force - Repeated Failed Logons | TA0006 - Credential Access |
| DR-002 | Privilege Escalation - Local Admin Group Modification | TA0004 - Privilege Escalation |
| DR-003 | Suspicious Execution - Encoded PowerShell | TA0002 - Execution |
| DR-004 | Persistence - Scheduled Task Creation | TA0003 - Persistence |
| DR-005 | Persistence - Registry Run Key Modification | TA0003 - Persistence |
| DR-006 | Discovery - Privilege and Account Enumeration | TA0007 - Discovery |
| DR-007 | System - Repeated Service Failures | TA0040 - Impact |
| DR-008 | System - Cron Job Execution Anomaly | TA0003 - Persistence |
| DR-009 | Lateral Movement - Remote Desktop Activity | TA0008 - Lateral Movement |
| DR-010 | Defense Evasion - Script Interpreter Abuse | TA0005 - Defense Evasion |

## Atomic Red Team Techniques

| Technique | Name | Status |
|---|---|---|
| T1059.004 | Unix Shell Script Execution | Active |
| T1053.003 | Cron Persistence | Active |
| T1136.001 | Local Account Creation | Active |
| T1548.001 | Setuid Privilege Escalation | Active |

## Usage

    # Live demo — real Atomic Red Team attacks + full pipeline
    python agent/demo.py

    # Clean demo — resets Qdrant memory before run
    python agent/demo.py --clean

    # Run all detection rules
    python -m agent.run_agent

    # Run a single rule
    python -m agent.run_agent --rule DR-001

    # Custom SPL query
    python -m agent.run_agent 'index=soc-logs "Failed logon" | head 50'

    # Continuous polling (60s interval)
    python agent/watcher.py

    # Threat hunting - semantic search over past incidents
    python agent/memory_search.py "privilege escalation"
    python agent/memory_search.py "brute force 192.168.100.99"
    python agent/memory_search.py "encoded powershell"

## Setup

    git clone https://github.com/Exodo-LS/siem-ai-agent
    cd siem-ai-agent
    python3 -m venv venv
    source venv/bin/activate
    pip install -r requirements.txt
    cp .env.example .env
    # Edit .env with your credentials

## Docs

- [Sprint 1 Complete](docs/sprint1-complete.md)
- [Sprint 2 Complete](docs/sprint2-complete.md)
- [Sprint 3 Complete](docs/sprint3-complete.md)
- [Sprint 4 Complete](docs/sprint4-complete.md)
- [Sprint 5 Complete](docs/sprint5-complete.md)
- [Sprint 6 Complete](docs/sprint6-complete.md)
- [Sprint 7 Complete](docs/sprint7-complete.md)
- [Sprint 8 Complete](docs/sprint8-complete.md)
