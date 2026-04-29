import requests
import time
import os
import urllib3
from dotenv import load_dotenv
from splunk.auth import get_session_token

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

load_dotenv()

SPLUNK_HOST = os.getenv("SPLUNK_HOST")
SPLUNK_PORT = os.getenv("SPLUNK_PORT")
BASE_URL = f"https://{SPLUNK_HOST}:{SPLUNK_PORT}"

def run_search(spl_query):
    token = get_session_token()
    headers = {"Authorization": f"Splunk {token}"}

    # Step 1 — Submit search job
    search_url = f"{BASE_URL}/services/search/jobs"
    data = {
        "search": f"search {spl_query}",
        "output_mode": "json"
    }
    response = requests.post(search_url, headers=headers, data=data, verify=False)
    response.raise_for_status()
    sid = response.json()["sid"]
    print(f"[+] Search job created. SID: {sid}")

    # Step 2 — Poll until complete
    job_url = f"{BASE_URL}/services/search/jobs/{sid}?output_mode=json"
    while True:
        status = requests.get(job_url, headers=headers, verify=False).json()
        state = status["entry"][0]["content"]["dispatchState"]
        print(f"[*] Job state: {state}")
        if state == "DONE":
            break
        time.sleep(1)

    # Step 3 — Fetch results
    results_url = f"{BASE_URL}/services/search/jobs/{sid}/results?output_mode=json&count=50"
    results = requests.get(results_url, headers=headers, verify=False)
    results.raise_for_status()
    return results.json()

if __name__ == "__main__":
    from splunk.formatter import parse_results, display_table, display_json
    results = run_search("index=soc-logs | head 10")
    events = parse_results(results)
    display_table(events)
