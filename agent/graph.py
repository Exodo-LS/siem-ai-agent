from langgraph.graph import StateGraph, END
from agent.state import TriageState
from agent.nodes import (
    ingest_events,
    classify_severity,
    reason_with_claude_memory,
    generate_followup_queries,
    execute_followup_queries,
    produce_triage_report_validated,
    store_triage_memory,
)

def should_followup(state: TriageState) -> str:
    """Route to follow-up execution or straight to report."""
    queries = state.get("followup_queries", [])
    round_num = state.get("reasoning_round", 1)
    if queries and round_num < 3:
        return "execute"
    return "report"

def build_graph():
    graph = StateGraph(TriageState)

    graph.add_node("ingest", ingest_events)
    graph.add_node("classify", classify_severity)
    graph.add_node("reason", reason_with_claude_memory)
    graph.add_node("followup_queries", generate_followup_queries)
    graph.add_node("followup_execute", execute_followup_queries)
    graph.add_node("report", produce_triage_report_validated)
    graph.add_node("store_memory", store_triage_memory)

    graph.set_entry_point("ingest")

    graph.add_conditional_edges(
        "ingest",
        lambda s: "error" if s.get("error") else "ok",
        {"error": END, "ok": "classify"}
    )

    graph.add_edge("classify", "reason")
    graph.add_edge("reason", "followup_queries")

    graph.add_conditional_edges(
        "followup_queries",
        should_followup,
        {"execute": "followup_execute", "report": "report"}
    )

    graph.add_edge("followup_execute", "reason")
    graph.add_edge("report", "store_memory")
    graph.add_edge("store_memory", END)

    return graph.compile()
