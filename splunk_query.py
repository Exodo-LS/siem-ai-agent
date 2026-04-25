import argparse
import sys
import logging
import time
from splunk.search import run_search
from splunk.formatter import parse_results, display_table, display_json

# Logging setup
logging.basicConfig(
    filename="siem_agent.log",
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s"
)

def main():
    parser = argparse.ArgumentParser(
        description="SIEM AI Agent — Splunk CLI Query Tool"
    )
    parser.add_argument(
        "query",
        type=str,
        help="SPL search query e.g. 'index=soc-logs | head 10'"
    )
    parser.add_argument(
        "--format",
        choices=["table", "json"],
        default="table",
        help="Output format: table (default) or json"
    )

    args = parser.parse_args()

    try:
        start_time = time.time()
        logging.info(f"Query started: {args.query}")
        print(f"[*] Running query: {args.query}")

        results = run_search(args.query)
        events = parse_results(results)
        elapsed = round(time.time() - start_time, 2)

        if not events:
            logging.warning(f"Query returned no results. | SPL: {args.query} | Duration: {elapsed}s")
            print("[!] No results returned.")
            sys.exit(0)

        logging.info(f"Query succeeded | SPL: {args.query} | Results: {len(events)} | Duration: {elapsed}s")

        if args.format == "json":
            display_json(events)
        else:
            display_table(events)

    except Exception as e:
        elapsed = round(time.time() - start_time, 2)
        logging.error(f"Query failed | SPL: {args.query} | Error: {e} | Duration: {elapsed}s")
        print(f"[!] Error: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
