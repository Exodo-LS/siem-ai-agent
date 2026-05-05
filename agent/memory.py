# agent/memory.py
# Handles embedding and storage of triage incidents in Qdrant

import os
import uuid
import logging
from datetime import datetime
from qdrant_client import QdrantClient
from qdrant_client.models import PointStruct
from sentence_transformers import SentenceTransformer

QDRANT_HOST = os.getenv("QDRANT_HOST", "192.168.100.40")
QDRANT_PORT = int(os.getenv("QDRANT_PORT", 6333))
COLLECTION_NAME = "triage_memory"

logger = logging.getLogger(__name__)

# Load embedding model once at import time
print("[memory] Loading embedding model...")
embedder = SentenceTransformer("all-MiniLM-L6-v2")
client = QdrantClient(host=QDRANT_HOST, port=QDRANT_PORT)
print("[memory] Ready.")

def embed_text(text: str) -> list[float]:
    """Embed a string into a 384-dim vector."""
    return embedder.encode(text).tolist()

def store_incidents(triage_report: dict) -> int:
    """
    Embed and store each incident from a triage report into Qdrant.
    Returns the number of incidents stored.
    """
    incidents = triage_report.get("incidents", [])
    if not incidents:
        return 0

    points = []
    timestamp = datetime.now().isoformat()

    for inc in incidents:
        # Build text to embed — summary of the incident
        text = (
            f"{inc.get('threat', '')} "
            f"{inc.get('mitre_tactic', '')} "
            f"{inc.get('mitre_technique', '')} "
            f"{inc.get('recommended_action', '')} "
            f"{triage_report.get('summary', '')}"
        )
        vector = embed_text(text)

        point = PointStruct(
            id=str(uuid.uuid4()),
            vector=vector,
            payload={
                "incident_id": inc.get("id"),
                "threat": inc.get("threat"),
                "severity": inc.get("severity"),
                "mitre_tactic": inc.get("mitre_tactic"),
                "mitre_technique": inc.get("mitre_technique"),
                "recommended_action": inc.get("recommended_action"),
                "false_positive_likelihood": inc.get("false_positive_likelihood"),
                "fp_reasoning": inc.get("fp_reasoning"),
                "affected_hosts": inc.get("affected_hosts", []),
                "summary": triage_report.get("summary", ""),
                "escalate": triage_report.get("escalate", False),
                "timestamp": timestamp,
            }
        )
        points.append(point)

    client.upsert(collection_name=COLLECTION_NAME, points=points)
    logger.info(f"Stored {len(points)} incidents in Qdrant at {timestamp}")
    print(f"[memory] Stored {len(points)} incidents in Qdrant.")
    return len(points)

def search_similar(query: str, top_k: int = 5) -> list[dict]:
    """
    Search Qdrant for incidents similar to the query string.
    Returns top_k results with payload and score.
    """
    vector = embed_text(query)
    results = client.query_points(
        collection_name=COLLECTION_NAME,
        query=vector,
        limit=top_k,
        with_payload=True,
        score_threshold=0.0,
    )
    return [
        {
            "score": round(r.score, 4),
            "incident_id": r.payload.get("incident_id"),
            "threat": r.payload.get("threat"),
            "severity": r.payload.get("severity"),
            "mitre_tactic": r.payload.get("mitre_tactic"),
            "recommended_action": r.payload.get("recommended_action"),
            "timestamp": r.payload.get("timestamp"),
            "escalate": r.payload.get("escalate"),
        }
        for r in results.points
    ]

def get_memory_context(query: str, top_k: int = 3) -> str:
    """
    Returns a formatted string of similar past incidents
    to inject into Claude's prompt.
    """
    results = search_similar(query, top_k=top_k)
    if not results:
        return ""

    lines = ["Relevant past incidents from memory:"]
    for r in results:
        lines.append(
            f"- [{r['severity'].upper()}] {r['threat']} | "
            f"{r['mitre_tactic']} | "
            f"Similarity: {r['score']} | "
            f"Seen: {r['timestamp'][:10]}"
        )
    return "\n".join(lines)
