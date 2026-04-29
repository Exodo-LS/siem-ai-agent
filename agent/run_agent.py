import json
import sys
import os
from dotenv import load_dotenv
load_dotenv()

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
from splunk.search import run_search
from splunk.formatter import parse_results
from agent.graph import build_graph
from agent.detections import DETECTION_RULES

OUTPUT_FILE = "triage_output.json"

def run_all_rules():
    all_events = []
    enabled_rules = [r for r in DETECTION_RULES if r["enabled"]]
    print(f"[*] Running {len(enabled_rules)} detection rules...")

    for rule in enabled_rules:
        print(f"[*] Rule {rule['id']}: {rule['name']}")
        try:
            results = run_search(rule["spl"])
            events = parse_results(results)
            if events:
                # Tag each event with rule metadata
                for e in events:
                    e["_rule_id"] = rule["id"]
                    e["_rule_name"] = rule["name"]
                    e["_mitre_tactic"] = rule["mitre_tactic"]
                    e["_mitre_technique"] = rule["mitre_technique"]
                    e["_severity_hint"] = rule["severity_hint"]
                print(f"    → {len(events)} events matched")
                all_events.extend(events)
            else:
                print(f"    → No matches")
        except Exception as ex:
            print(f"    → Error: {ex}")

    return all_events

def main():
    # Single rule mode: python -m agent.run_agent --rule DR-001
    if len(sys.argv) == 3 and sys.argv[1] == "--rule":
        rule_id = sys.argv[2]
        rule = next((r for r in DETECTION_RULES if r["id"] == rule_id), None)
        if not rule:
            print(f"[!] Rule {rule_id} not found.")
            sys.exit(1)
        print(f"[*] Running single rule: {rule['name']}")
        results = run_search(rule["spl"])
        events = parse_results(results)
        for e in events:
            e["_rule_id"] = rule["id"]
            e["_rule_name"] = rule["name"]
            e["_mitre_tactic"] = rule["mitre_tactic"]
            e["_mitre_technique"] = rule["mitre_technique"]
            e["_severity_hint"] = rule["severity_hint"]
        all_events = events

    # Custom SPL mode: python -m agent.run_agent 'index=soc-logs ...'
    elif len(sys.argv) == 2:
        query = sys.argv[1]
        print(f"[*] Custom query: {query}")
        results = run_search(query)
        all_events = parse_results(results)

    # Default: run all rules
    else:
        all_events = run_all_rules()

    if not all_events:
        print("[!] No events matched any rules. Exiting.")
        sys.exit(0)

    print(f"\n[*] Total events for triage: {len(all_events)}")
    graph = build_graph()
    final_state = graph.invoke({"raw_events": all_events})

    if final_state.get("error"):
        print(f"[!] Agent error: {final_state['error']}")
        sys.exit(1)

    with open(OUTPUT_FILE, "w") as f:
        json.dump(final_state["triage_report"], f, indent=2)
    print(f"[*] Triage report saved to {OUTPUT_FILE}")

if __name__ == "__main__":
    main()
