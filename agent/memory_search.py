import os
os.environ["HF_HUB_DISABLE_IMPLICIT_TOKEN"] = "1"
# agent/memory_search.py
# Threat hunting CLI — semantic search over past triage incidents

import sys
import os
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
from dotenv import load_dotenv
load_dotenv()

from agent.memory import search_similar

def main():
    if len(sys.argv) < 2:
        print("Usage: python agent/memory_search.py <query>")
        print('Example: python agent/memory_search.py "privilege escalation"')
        sys.exit(1)

    query = " ".join(sys.argv[1:])
    print(f"\n[*] Searching memory for: '{query}'")
    print("=" * 60)

    results = search_similar(query, top_k=5)

    if not results:
        print("[*] No similar incidents found in memory.")
        sys.exit(0)

    for i, r in enumerate(results, 1):
        escalate_flag = "🔴" if r["escalate"] else "🟢"
        print(f"\n#{i} — Similarity: {r['score']}")
        print(f"  {escalate_flag} [{r['severity'].upper()}] {r['threat']}")
        print(f"  MITRE: {r['mitre_tactic']}")
        print(f"  Action: {r['recommended_action'][:120]}...")
        print(f"  Seen: {r['timestamp']}")

    print(f"\n{'='*60}")
    print(f"[*] {len(results)} results returned from Qdrant memory.")

if __name__ == "__main__":
    main()
