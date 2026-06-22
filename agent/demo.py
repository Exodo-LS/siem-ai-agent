import os
os.environ["HF_HUB_DISABLE_IMPLICIT_TOKEN"] = "1"
os.environ["DEMO_MODE"] = "1"

import sys
import time
import json
from datetime import datetime
from dotenv import load_dotenv
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

def print_step(step, msg):
    print(f"\n[{step}] {msg}")
    time.sleep(0.5)

def reset_qdrant():
    import requests
    base = "http://192.168.100.40:6333"
    print("[RESET] Clearing Qdrant memory for clean demo...")
    requests.delete(f"{base}/collections/triage_memory")
    requests.put(
        f"{base}/collections/triage_memory",
        json={"vectors": {"size": 384, "distance": "Cosine"}}
    )
    print("         Qdrant memory cleared.")

def check_sysmon_health():
    """Verify Sysmon is running on VM3, restart if needed before demo."""
    print_step("HEALTH", "Verifying Sysmon is active on VM3...")
    status = os.popen('ssh -o StrictHostKeyChecking=no socadmin@192.168.100.30 "systemctl is-active sysmon" 2>/dev/null').read().strip()
    if status == "active":
        print("         Sysmon is active.")
    else:
        print(f"         Sysmon status: {status} — restarting...")
        os.system('ssh -o StrictHostKeyChecking=no socadmin@192.168.100.30 "sudo systemctl reset-failed sysmon; sudo systemctl restart sysmon" 2>/dev/null')
        import time as _t
        _t.sleep(3)
        recheck = os.popen('ssh -o StrictHostKeyChecking=no socadmin@192.168.100.30 "systemctl is-active sysmon" 2>/dev/null').read().strip()
        print(f"         Sysmon now: {recheck}")

def run_atomic_attacks():
    print_step("ATTACK", "Executing Atomic Red Team simulations on VM3...")
    cmd = (
        "ssh -o StrictHostKeyChecking=no socadmin@192.168.100.30 "
        "\"pwsh -Command \\\"Import-Module ~/AtomicRedTeam/invoke-atomicredteam/Invoke-AtomicRedTeam.psd1; "
        "Invoke-AtomicTest T1059.004 -TestNumbers 1; "
        "Invoke-AtomicTest T1053.003 -TestNumbers 1; "
        "Invoke-AtomicTest T1548.001 -TestNumbers 1\\\"\""
    )
    os.system(cmd)
    # T1136.001 needs root for useradd — run via sudo with TTY
    useradd_cmd = (
        "ssh -tt -o StrictHostKeyChecking=no socadmin@192.168.100.30 "
        "\"sudo useradd -M -N -r -s /bin/bash -c evil_account evil_user\""
    )
    os.system(useradd_cmd)
    print("         T1059.004 — Bash script execution")
    print("         T1053.003 — Cron persistence")
    print("         T1136.001 — Local account creation")
    print("         T1548.001 — Setuid privilege escalation")
    print("         Waiting 20s for Sysmon + Universal Forwarder...")
    time.sleep(20)

def cleanup_atomic():
    print_step("CLEANUP", "Removing Atomic Red Team artifacts from VM3...")
    cmd = (
        "ssh -o StrictHostKeyChecking=no socadmin@192.168.100.30 "
        "\"pwsh -Command \\\"Import-Module ~/AtomicRedTeam/invoke-atomicredteam/Invoke-AtomicRedTeam.psd1; "
        "Invoke-AtomicTest T1053.003 -TestNumbers 1 -Cleanup; "
        "Invoke-AtomicTest T1059.004 -TestNumbers 1 -Cleanup; "
        "Invoke-AtomicTest T1548.001 -TestNumbers 1 -Cleanup\\\"\"" 
    )
    os.system(cmd)
    # T1136.001 cleanup — remove root-created evil_user via sudo
    os.system("ssh -tt -o StrictHostKeyChecking=no socadmin@192.168.100.30 \"sudo userdel evil_user 2>/dev/null\"")
    print("         Artifacts cleaned.")

def run_demo():
    clean = "--clean" in sys.argv
    if clean:
        reset_qdrant()

    print(BANNER)
    print(f"  Demo started: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"  VM1 Splunk:   192.168.100.10")
    print(f"  VM2 Agent:    192.168.100.20")
    print(f"  VM3 Attacker: 192.168.100.30 (Atomic Red Team)")
    print(f"  VM4 Qdrant:   192.168.100.40")

    check_sysmon_health()
    run_atomic_attacks()

    print_step("SPLUNK", "Querying Splunk for Atomic Red Team telemetry...")
    query = "index=soc-logs sourcetype=sysmon earliest=-3m | head 50"
    results = run_search(query)
    events = parse_results(results)
    print(f"         {len(events)} Sysmon process creation events retrieved")

    if not events:
        print("[!] No events found. Check VM3 forwarder and Sysmon.")
        sys.exit(1)

    print_step("AGENT", "Starting LangGraph multi-step triage pipeline...")
    graph = build_graph()
    final_state = graph.invoke({
        "raw_events": events,
        "reasoning_round": 1,
        "followup_queries": [],
        "followup_results": [],
        "reasoning_chain": []
    })

    if final_state.get("error"):
        print(f"[!] Agent error: {final_state['error']}")
        cleanup_atomic()
        sys.exit(1)

    report = final_state["triage_report"]
    escalate = report.get("escalate", False)
    incidents = report.get("incidents", [])
    chain = final_state.get("reasoning_chain", [])
    followup_results = final_state.get("followup_results", [])

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

    if followup_results or len(chain) > 1:
        print(f"\n  {'─'*58}")
        print(f"  MULTI-STEP REASONING:")
        print(f"  {len(chain)} reasoning round(s) completed")
        if followup_results:
            print(f"  {len(followup_results)} additional events retrieved via follow-up queries")
        for step in chain:
            fq = step.get("followup_queries", [])
            if fq:
                for q in fq:
                    print(f"  → Follow-up: {q.get('reason', '')[:80]}")

    print(f"\n{'═'*62}")
    print(f"  {len(incidents)} incident(s) identified")
    print(f"  Memory stored to Qdrant — searchable via memory_search.py")
    print(f"{'═'*62}")

    cleanup_atomic()
    print(f"\n  Demo completed: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")

if __name__ == "__main__":
    run_demo()
