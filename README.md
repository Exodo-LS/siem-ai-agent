# siem-ai-agent
AI-powered SIEM triage agent using Splunk, LangGraph, and Claude Sonnet

## VM Network
| VM | Hostname | IP | Role |
|---|---|---|---|
| VM1 | vm1-splunk | 192.168.100.10 | Splunk 10.2.2 |
| VM2 | vm2-agent | 192.168.100.20 | AI Agent |
| VM3 | vm3-forwarder | 192.168.100.30 | Sysmon + UF |
| VM4 | vm4-qdrant | 192.168.100.40 | Qdrant (upcoming) |

## Sprint Progress
| Sprint | Goal | Status |
|---|---|---|
| Sprint 1 | Splunk install + index setup | ✅ Done |
| Sprint 2 | Sysmon + Universal Forwarder | ✅ Done |
| Sprint 3 | Splunk REST API + Python CLI | ✅ Done |
| Sprint 4 | LangGraph agent integration | 🔲 Next |

## Docs
- [Sprint 1 Complete](docs/sprint1-complete.md)
- [Sprint 2 Complete](docs/sprint2-complete.md)
- [Sprint 3 Complete](docs/sprint3-complete.md)
