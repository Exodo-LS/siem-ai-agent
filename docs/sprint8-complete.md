# Sprint 8 Complete — Atomic Red Team Simulations

## Goal
Replace logger-based simulation with real Atomic Red Team attack techniques generating genuine Sysmon telemetry, triggering multi-step reasoning naturally.

## What Was Built

### Atomic Red Team on VM3
- PowerShell 7.6.1 installed
- Invoke-AtomicRedTeam 2.3.0 installed
- Atomics folder downloaded — full technique library available

### Attack Techniques Used
| Technique | Name | Detection Rule |
|---|---|---|
| T1059.004 | Unix Shell Script Execution | DR-003 adjacent |
| T1053.003 | Cron Persistence | DR-004 |
| T1136.001 | Local Account Creation | DR-002 |

### Demo v2
- `agent/demo.py` updated to run real Atomic Red Team tests via SSH
- SSH key auth configured VM2 → VM3 (no password prompt)
- 20s wait for Sysmon + Universal Forwarder pipeline
- Automatic cleanup after demo run

### Pipeline Improvements
- Follow-up query timeout (20s) added to prevent hanging on bad SPL
- Time constraint injected into Claude-generated SPL (`earliest=-15m`)
- Round cap enforced at 3 reasoning rounds max

## Test Results
- 3 reasoning rounds completed automatically
- 29 additional events retrieved via follow-up queries
- 4 incidents identified with real MITRE mappings
- ESCALATE: YES
- Cleanup runs automatically after every demo

## Real Telemetry vs Logger Simulation
| | Logger Simulation | Atomic Red Team |
|---|---|---|
| Process hashes | No | Yes — MD5 + SHA256 |
| Parent-child chain | No | Yes — full process tree |
| Real command execution | No | Yes |
| Claude dismisses as fake | Yes | No |
| Multi-step reasoning triggered | No | Yes |

## VMs Used
- VM1 — Splunk data source
- VM2 — Agent runtime
- VM3 — Attack target (Atomic Red Team)
- VM4 — Qdrant memory

## Next Sprint
Sprint 9 — Polish, dashboard update, final repo cleanup, Demo v2 rehearsal
