from langgraph.graph import StateGraph, END
from agent.state import TriageState
from agent.nodes import (
    ingest_events,
    classify_severity,
    reason_with_claude,
    produce_triage_report,
)

def build_graph():
    graph = StateGraph(TriageState)

    graph.add_node("ingest", ingest_events)
    graph.add_node("classify", classify_severity)
    graph.add_node("reason", reason_with_claude)
    graph.add_node("report", produce_triage_report)

    graph.set_entry_point("ingest")

    graph.add_conditional_edges(
        "ingest",
        lambda s: "error" if s.get("error") else "ok",
        {"error": END, "ok": "classify"}
    )

    graph.add_edge("classify", "reason")
    graph.add_edge("reason", "report")
    graph.add_edge("report", END)

    return graph.compile()
