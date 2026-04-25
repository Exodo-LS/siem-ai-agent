# Sprint 3 — Splunk API & Python CLI

## Goal
Python CLI tool on VM2 that queries Splunk REST API and returns structured data ready for the agent to consume.

## Completed
- Python 3 venv configured on VM2
- Splunk REST API authenticated via session token
- SPL search execution with job polling
- Result parsing and formatting (table + JSON)
- CLI tool with `--format` flag
- Error handling for bad auth, invalid SPL, empty results
- Logging with query, result count, and duration

## Usage
```bash
python splunk_query.py "index=soc-logs | head 10"
python splunk_query.py "index=soc-logs | head 5" --format json
```

## Key Files
| File | Purpose |
|---|---|
| `splunk/auth.py` | Splunk REST API authentication |
| `splunk/search.py` | SPL query execution and polling |
| `splunk/formatter.py` | Result parsing and display |
| `splunk_query.py` | CLI entry point |

## Lessons Learned
- Splunk REST API requires form-encoded POST data, not basic auth via `-u` flag
- Use `requests.post(url, data=data)` not `-u user:pass` in curl
- Session token must be passed as `Authorization: Splunk <token>` header

## Next — Sprint 4
LangGraph agent integration on VM2, consuming structured output from this CLI tool.
