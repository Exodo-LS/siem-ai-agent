import requests
import os
from dotenv import load_dotenv
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

load_dotenv()

SPLUNK_HOST = os.getenv("SPLUNK_HOST")
SPLUNK_PORT = os.getenv("SPLUNK_PORT")
SPLUNK_USERNAME = os.getenv("SPLUNK_USERNAME")
SPLUNK_PASSWORD = os.getenv("SPLUNK_PASSWORD")

BASE_URL = f"https://{SPLUNK_HOST}:{SPLUNK_PORT}"

def get_session_token():
    url = f"{BASE_URL}/services/auth/login"
    data = {
        "username": SPLUNK_USERNAME,
        "password": SPLUNK_PASSWORD,
        "output_mode": "json"
    }
    response = requests.post(url, data=data, verify=False)
    response.raise_for_status()
    token = response.json()["sessionKey"]
    print(f"[+] Auth successful. Session token: {token[:20]}...")
    return token

if __name__ == "__main__":
    get_session_token()
