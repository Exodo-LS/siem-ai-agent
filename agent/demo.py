import os
os.environ["HF_HUB_DISABLE_IMPLICIT_TOKEN"] = "1"

import sys
import time
import json
from datetime import datetime
from dotenv import load_dotenv
os.environ["DEMO_MODE"] = "1"
load_dotenv()

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from splunk.search import run_search
from splunk.formatter import parse_results
from agent.graph import build_graph

BANNER = """
╔══════════════════════════════════════════════════════════════╗
║           SIEM AI AGENT — LIVE TRIAGE DEMO                  ║
║     Splunk + LangGraph + Claude Sonnet + Qdrant Memory      ║
╚══════════════════════════════════════════════════════════════╝
"""

ATTACK_EVENTS = [
    "EventCode=4625 Failed logon attempt for user Administrator from 192.168.100.99",
    "EventCode=4625 Failed logon attempt for user Administrator from 192.168.100.99",
    "EventCode=4625 Failed logon attempt for user Administrator from 192.168.100.99",
    "EventCode=4748 net user hacker P@ssw0rd /add",
    "EventCode=4728 net localgroup administrators hacker /add",
    "powershell -enc JABjAGwAaQBlAG4AdA",
    "EventCode=4624 Successful logon for user hacker from 192.168.100.99",
    "whoami /priv privilege escalation check from 192.168.100.99",
    "schtasks /create /tn backdoor /tr cmd.exe /sc onlogon",
    "reg add HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run /v backdoor",
]

def print_step(step, msg):
    print(f"\n[{step}] {msg}")
    time.sleep(0.5)

def inject_attack_events():
    """Inject simulated attack events into Splunk via VM3 logger."""
    print_step("SETUP", "Injecting simulated attack scenario into Splunk...")
    for event in ATTACK_EVENTS:
        os.system(f'ssh -o StrictHostKeyChecking=no socadmin@192.168.100.30 "logger -t sysmon \'{event}\'" 2>/dev/null')
    print("         Attack chain injected: brute force → privilege escalation → persistence")
    print("         Waiting 15s for Universal Forwarder to ship logs to Splunk...")
    time.sleep(15)

def reset_qdrant():
    """Clear Qdrant memory for a clean demo run."""
    import requests
    base = f"http://192.168.100.40:6333"
    print("[RESET] Clearing Qdrant memory for clean demo...")
    requests.delete(f"{base}/collections/triage_memory")
    requests.put(
        f"{base}/collections/triage_memory",
        json={"vectors": {"size": 384, "distance": "Cosine"}}
    )
    print("         Qdrant memory cleared.")

def run_demo():
    clean = "--clean" in sys.argv
    if clean:
        reset_qdrant()

    print(BANNER)
    print(f"  Demo started: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"  VM1 Splunk:   192.168.100.10")
    print(f"  VM2 Agent:    192.168.100.20")
    print(f"  VM4 Qdrant:   192.168.100.40")

    # Step 1 — Inject attack events
    inject_attack_events()

    # Step 2 — Query Splunk for attack events
    print_step("SPLUNK", "Querying Splunk soc-logs index for attack indicators...")
    query = 'index=soc-logs ("Failed logon" OR "net user" OR "net localgroup" OR "powershell" OR "schtasks" OR "reg add" OR "whoami") | head 50'
    results = run_search(query)
    events = parse_results(results)
    print(f"         {len(events)} matching events retrieved from Splunk")

    if not events:
        print("[!] No events found. Check that VM3 forwarder is running.")
        sys.exit(1)

    # Step 3 — Run LangGraph agent
    print_step("AGENT", "Starting LangGraph triage pipeline...")
    graph = build_graph()
    final_state = graph.invoke({"raw_events": events, "reasoning_round": 1, "followup_queries": [], "followup_results": [], "reasoning_chain": []})

    if final_state.get("error"):
        print(f"[!] Agent error: {final_state['error']}")
        sys.exit(1)

    report = final_state["triage_report"]

    # Step 4 — Print demo report
    escalate = report.get("escalate", False)
    incidents = report.get("incidents", [])

    print(f"\n{'═'*62}")
    print(f"  TRIAGE REPORT — {report['event_count']} events analyzed")
    print(f"  ESCALATE: {'🔴 YES — Immediate action required' if escalate else '🟢 NO — No immediate threat'}")
    print(f"{'═'*62}")
    print(f"\n  SUMMARY:\n  {report['summary']}\n")

    for inc in incidents:
        print(f"  {'─'*58}")
        print(f"  [{inc['severity'].upper()}] {inc['id']} — {inc['threat']}")
        print(f"  MITRE:  {inc.get('mitre_tactic')} / {inc.get('mitre_technique')}")
        print(f"  Action: {inc['recommended_action'][:200]}")
        print(f"  FP:     {inc['false_positive_likelihood']}")

    print(f"\n{'═'*62}")
    print(f"  {len(incidents)} incident(s) identified")
    print(f"  Report saved to triage_output.json")
    print(f"  Memory stored to Qdrant — searchable via memory_search.py")
    print(f"{'═'*62}")
    # Show reasoning chain if follow-ups were run
    chain = final_state.get("reasoning_chain", [])
    followup_results = final_state.get("followup_results", [])
    if followup_results:
        print(f"\n  REASONING CHAIN:")
        for step in chain:
            print(f"  Round {step['round']}: {len(step.get('followup_queries', []))} follow-up queries generated")
        print(f"  {len(followup_results)} additional events retrieved via follow-up queries")

    print(f"\n  Demo completed: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")

if __name__ == "__main__":
    run_demo()
