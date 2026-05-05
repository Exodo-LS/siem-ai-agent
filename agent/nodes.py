import json
import os
import re
import anthropic
from agent.state import TriageState

client = anthropic.Anthropic(api_key=os.getenv("ANTHROPIC_API_KEY"))

# ── Node 1 ───────────────────────────────────────────────────────────────────
def ingest_events(state: TriageState) -> TriageState:
    events = state.get("raw_events", [])
    if not events:
        return {**state, "error": "No events received from Splunk."}
    print(f"[ingest] {len(events)} events received.")
    return {**state, "error": None}

# ── Node 2 ───────────────────────────────────────────────────────────────────
SEVERITY_KEYWORDS = {
    "critical": ["mimikatz", "lsass", "pass-the-hash", "lateral movement",
                 "ransomware", "exfiltration", "privilege escalation"],
    "high":     ["failed logon", "brute force", "powershell -enc", "net user",
                 "whoami", "schtasks", "reg add"],
    "medium":   ["rdp", "remote desktop", "net localgroup", "wscript", "mshta"],
    "low":      []
}

def classify_severity(state: TriageState) -> TriageState:
    classified = []
    for event in state["raw_events"]:
        raw = json.dumps(event).lower()
        severity = "low"
        for level in ["critical", "high", "medium"]:
            if any(kw in raw for kw in SEVERITY_KEYWORDS[level]):
                severity = level
                break
        classified.append({**event, "_severity": severity})
    counts = {lvl: sum(1 for e in classified if e["_severity"] == lvl)
              for lvl in ["critical", "high", "medium", "low"]}
    print(f"[classify] Severity counts: {counts}")
    return {**state, "classified_events": classified}

# ── Node 3 ───────────────────────────────────────────────────────────────────
SYSTEM_PROMPT = """You are a Tier-2 SOC analyst AI assistant.
You will receive a batch of security events pre-classified by severity.
Your job:
1. Identify the most significant threats and attack patterns.
2. Group related events into incidents if possible.
3. For each incident, produce: threat name, MITRE ATT&CK tactic, recommended action.
4. Flag any false positive candidates with reasoning.
5. Return your analysis as structured JSON only — no prose outside the JSON.

JSON schema:
{
  "incidents": [
    {
      "id": "INC-001",
      "threat": "string",
      "severity": "critical|high|medium|low",
      "mitre_tactic": "string",
      "mitre_technique": "string",
      "affected_hosts": ["string"],
      "recommended_action": "string",
      "false_positive_likelihood": "low|medium|high",
      "fp_reasoning": "string or null"
    }
  ],
  "summary": "string",
  "escalate": true
}"""

def reason_with_claude(state: TriageState) -> TriageState:
    events_payload = json.dumps(state["classified_events"], indent=2)
    message = client.messages.create(
        model="claude-sonnet-4-5",
        max_tokens=2048,
        system=SYSTEM_PROMPT,
        messages=[
            {
                "role": "user",
                "content": f"Analyze these security events and return triage JSON:\n\n{events_payload}"
            }
        ]
    )
    analysis_text = message.content[0].text
    print(f"[claude] Analysis received ({len(analysis_text)} chars).")
    return {**state, "claude_analysis": analysis_text}

# ── Node 4 ───────────────────────────────────────────────────────────────────
def produce_triage_report(state: TriageState) -> TriageState:
    raw = state["claude_analysis"]
    raw = re.sub(r"```json|```", "", raw).strip()
    try:
        parsed = json.loads(raw)
    except json.JSONDecodeError as e:
        return {**state, "error": f"Failed to parse Claude JSON: {e}", "triage_report": None}

    report = {
        "event_count": len(state["classified_events"]),
        "escalate": parsed.get("escalate", False),
        "summary": parsed.get("summary", ""),
        "incidents": parsed.get("incidents", []),
    }

    print(f"\n{'='*60}")
    print(f"  TRIAGE REPORT — {report['event_count']} events analyzed")
    print(f"  ESCALATE: {'🔴 YES' if report['escalate'] else '🟢 NO'}")
    print(f"  Summary: {report['summary']}")
    print(f"{'='*60}")
    for inc in report["incidents"]:
        print(f"\n  [{inc['severity'].upper()}] {inc['id']} — {inc['threat']}")
        print(f"    MITRE: {inc.get('mitre_tactic')} / {inc.get('mitre_technique')}")
        print(f"    Action: {inc['recommended_action']}")
        print(f"    FP likelihood: {inc['false_positive_likelihood']}")
    print(f"{'='*60}\n")

    return {**state, "triage_report": report}

# ── Retry-wrapped Claude call ─────────────────────────────────────────────────
from agent.retry import with_retry

def reason_with_claude_safe(state: TriageState) -> TriageState:
    """reason_with_claude with retry logic."""
    def _call():
        return reason_with_claude(state)
    return with_retry(_call, max_attempts=3, base_delay=2)

# ── Validation-wrapped report node ────────────────────────────────────────────
from agent.validator import validate_triage_json

def produce_triage_report_validated(state: TriageState) -> TriageState:
    """produce_triage_report with schema validation."""
    state = produce_triage_report(state)
    if state.get("triage_report"):
        is_valid, errors = validate_triage_json({
            "incidents": state["triage_report"].get("incidents", []),
            "summary": state["triage_report"].get("summary", ""),
            "escalate": state["triage_report"].get("escalate", False),
        })
        if not is_valid:
            print(f"[!] Schema validation warnings: {errors}")
            logging.warning(f"Schema validation errors: {errors}")
        else:
            print("[*] Schema validation passed.")
    return state

# ── Memory-augmented Claude node ─────────────────────────────────────────────
from agent.memory import get_memory_context, store_incidents

def reason_with_claude_memory(state: TriageState) -> TriageState:
    """reason_with_claude with Qdrant memory context injected into prompt."""
    events_payload = json.dumps(state["classified_events"], indent=2)

    # Build a query from the current event batch for memory lookup
    severity_counts = {}
    for e in state["classified_events"]:
        s = e.get("_severity", "low")
        severity_counts[s] = severity_counts.get(s, 0) + 1
    query = f"severity {severity_counts} security events triage"

    # Fetch similar past incidents from Qdrant
    memory_context = get_memory_context(query, top_k=3)
    if memory_context:
        print(f"[memory] Injecting context:\n{memory_context}")
    else:
        print("[memory] No similar past incidents found.")

    # Build system prompt with memory context
    system_with_memory = SYSTEM_PROMPT
    if memory_context:
        system_with_memory += f"\n\n{memory_context}"

    def _call():
        return client.messages.create(
            model="claude-sonnet-4-5",
            max_tokens=2048,
            system=system_with_memory,
            messages=[
                {
                    "role": "user",
                    "content": f"Analyze these security events and return triage JSON:\n\n{events_payload}"
                }
            ]
        )

    message = with_retry(_call, max_attempts=3, base_delay=2)
    analysis_text = message.content[0].text
    print(f"[claude] Analysis received ({len(analysis_text)} chars).")
    return {**state, "claude_analysis": analysis_text}

def store_triage_memory(state: TriageState) -> TriageState:
    """Store completed triage report incidents into Qdrant."""
    if state.get("triage_report"):
        store_incidents(state["triage_report"])
    return state
