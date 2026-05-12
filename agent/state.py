from typing import TypedDict, List, Optional

class TriageState(TypedDict):
    raw_events: List[dict]
    classified_events: List[dict]
    claude_analysis: Optional[str]
    triage_report: Optional[dict]
    error: Optional[str]
    reasoning_round: int
    followup_queries: Optional[List[str]]
    followup_results: Optional[List[dict]]
    reasoning_chain: Optional[List[dict]]
