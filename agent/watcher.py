# agent/watcher.py
# Polling loop — runs all detection rules on a schedule

import time
import json
import os
import logging
from datetime import datetime
from dotenv import load_dotenv
load_dotenv()

import sys
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from splunk.search import run_search
from splunk.formatter import parse_results
from agent.graph import build_graph
from agent.detections import DETECTION_RULES

POLL_INTERVAL = 60  # seconds
OUTPUT_DIR = "triage_reports"
LOG_FILE = "watcher.log"

logging.basicConfig(
    filename=LOG_FILE,
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s"
)

def collect_events():
    all_events = []
    enabled_rules = [r for r in DETECTION_RULES if r["enabled"]]
    for rule in enabled_rules:
        try:
            results = run_search(rule["spl"])
            events = parse_results(results)
            for e in events:
                e["_rule_id"] = rule["id"]
                e["_rule_name"] = rule["name"]
                e["_mitre_tactic"] = rule["mitre_tactic"]
                e["_mitre_technique"] = rule["mitre_technique"]
                e["_severity_hint"] = rule["severity_hint"]
            all_events.extend(events)
        except Exception as ex:
            logging.warning(f"Rule {rule['id']} failed: {ex}")
    return all_events

def save_report(report):
    os.makedirs(OUTPUT_DIR, exist_ok=True)
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    path = os.path.join(OUTPUT_DIR, f"triage_{timestamp}.json")
    with open(path, "w") as f:
        json.dump(report, f, indent=2)
    logging.info(f"Report saved: {path}")
    print(f"[*] Report saved: {path}")
    return path

def run_cycle(graph):
    print(f"\n[{datetime.now().strftime('%H:%M:%S')}] Running triage cycle...")
    logging.info("Triage cycle started")

    events = collect_events()
    if not events:
        print("[*] No events matched any rules this cycle.")
        logging.info("No events matched")
        return

    print(f"[*] {len(events)} events collected across all rules")
    final_state = graph.invoke({"raw_events": events})

    if final_state.get("error"):
        logging.error(f"Agent error: {final_state['error']}")
        print(f"[!] Error: {final_state['error']}")
        return

    report = final_state["triage_report"]
    save_report(report)

    escalate = report.get("escalate", False)
    logging.info(f"Cycle complete. Escalate={escalate}. Events={len(events)}")

    if escalate:
        print(f"[!] 🔴 ESCALATION REQUIRED — review {OUTPUT_DIR}/")

def main():
    print(f"[*] SIEM Watcher starting. Poll interval: {POLL_INTERVAL}s")
    print(f"[*] Press Ctrl+C to stop.\n")
    graph = build_graph()

    while True:
        try:
            run_cycle(graph)
        except KeyboardInterrupt:
            print("\n[*] Watcher stopped.")
            break
        except Exception as ex:
            logging.error(f"Cycle failed: {ex}")
            print(f"[!] Cycle error: {ex}")

        print(f"[*] Next cycle in {POLL_INTERVAL}s...")
        time.sleep(POLL_INTERVAL)

if __name__ == "__main__":
    main()
