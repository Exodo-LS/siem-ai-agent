from rich.console import Console
from rich.table import Table
import json

console = Console()

def parse_results(raw_results):
    """Extract key fields from raw Splunk JSON response."""
    events = []
    for result in raw_results.get("results", []):
        event = {
            "time":       result.get("_time", "N/A"),
            "host":       result.get("host", "N/A"),
            "sourcetype": result.get("sourcetype", "N/A"),
            "source":     result.get("source", "N/A"),
            "raw":        result.get("_raw", "N/A")
        }
        events.append(event)
    return events

def display_table(events):
    """Display events as a rich formatted table."""
    table = Table(title="Splunk Search Results", show_lines=True)
    table.add_column("Time", style="cyan", no_wrap=True)
    table.add_column("Host", style="green")
    table.add_column("Sourcetype", style="yellow")
    table.add_column("Raw Event", style="white", max_width=60)

    for event in events:
        table.add_row(
            event["time"],
            event["host"],
            event["sourcetype"],
            event["raw"]
        )
    console.print(table)

def display_json(events):
    """Display events as structured JSON."""
    print(json.dumps(events, indent=2))

if __name__ == "__main__":
    # Test with mock data
    mock = {
        "results": [
            {
                "_time": "2026-04-22T20:16:51.945+00:00",
                "host": "vm3-forwarder",
                "sourcetype": "sysmon",
                "source": "journald://sysmon",
                "_raw": "run-parts: executing /usr/share/finalrd/open-iscsi.finalrd setup"
            }
        ]
    }
    events = parse_results(mock)
    print("--- TABLE FORMAT ---")
    display_table(events)
    print("--- JSON FORMAT ---")
    display_json(events)
