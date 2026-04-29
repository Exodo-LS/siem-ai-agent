# Sprint 4 Complete — LangGraph Agent Integration

## Goal
Build a LangGraph agent on VM2 that consumes structured Splunk output, reasons over security events using Claude Sonnet, and produces triage decisions.

## What Was Built

### Core Pipeline
- `agent/state.py` — TriageState TypedDict flowing through all nodes
- `agent/graph.py` — LangGraph StateGraph with conditional routing
- `agent/nodes.py` — Four nodes: ingest → classify → reason → report

### Detection Rules Engine
- `agent/detections.py` — 10 named detection rules mapped to MITRE ATT&CK
- Rules cover: Credential Access, Privilege Escalation, Execution, Persistence, Discovery, Lateral Movement, Defense Evasion
- Supports full-run and single-rule (`--rule DR-001`) modes

### Agent Hardening
- `agent/retry.py` — Exponential backoff retry for Claude API calls (3 attempts)
- `agent/watcher.py` — 60s polling loop with timestamped report persistence
- `agent/validator.py` — JSON schema validation on Claude output

## Test Results
- 124 events analyzed across 10 detection rules
- Severity breakdown: critical: 4, high: 28, medium: 2, low: 90
- Claude correctly identified full attack chain: brute force → account creation → privilege escalation → persistence → encoded PowerShell
- MITRE ATT&CK coverage: TA0006, TA0004, TA0003, TA0002, TA0007
- Schema validation passed all cycles
- Watcher ran 3 continuous cycles with escalation flagging

## Attack Simulation
Injected via `logger` on VM3:
- EventCode=4625 x5 (brute force)
- net user hacker /add
- net localgroup administrators hacker /add  
- powershell -enc (encoded payload)
- schtasks /create backdoor
- reg add Run key persistence
- whoami /priv discovery

## VMs Used
- VM1 (192.168.100.10) — Splunk REST API data source
- VM2 (192.168.100.20) — LangGraph agent runtime

## Next Sprint
Sprint 5 — Qdrant vector memory on VM4 for semantic search over past incidents
