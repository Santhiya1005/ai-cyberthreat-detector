import os
import requests
import pandas as pd
from dotenv import load_dotenv

# Load API keys from .env
load_dotenv()
ABUSEIPDB_KEY = os.getenv("ABUSEIPDB_KEY")

# File to save
CSV_PATH = "ai/features.csv"

# -------------------------
# 1. Benign samples
# -------------------------
benign_samples = [
    {"input": "https://google.com", "label": "benign"},
    {"input": "https://microsoft.com", "label": "benign"},
    {"input": "https://github.com", "label": "benign"},
    {"input": "1.1.1.1", "label": "benign"},
    {"input": "8.8.8.8", "label": "benign"},
]

# -------------------------
# 2. Fetch malicious IPs from AbuseIPDB
# -------------------------
malicious_ips = []
if ABUSEIPDB_KEY:
    url = "https://api.abuseipdb.com/api/v2/blacklist"
    headers = {"Key": ABUSEIPDB_KEY, "Accept": "application/json"}
    try:
        res = requests.get(url, headers=headers, timeout=10)
        if res.status_code == 200:
            data = res.json()
            for ip in data.get("data", [])[:10]:  # Take top 10
                malicious_ips.append({"input": ip["ipAddress"], "label": "malware"})
        else:
            print("⚠️ AbuseIPDB API error:", res.status_code, res.text)
    except Exception as e:
        print("⚠️ Error fetching AbuseIPDB:", e)
else:
    print("⚠️ No ABUSEIPDB_KEY found in .env, skipping malicious IP fetch.")

# -------------------------
# 3. Fetch phishing URLs from PhishTank
# -------------------------
phishing_samples = []
try:
    res = requests.get("http://data.phishtank.com/data/online-valid.json", timeout=10)
    if res.status_code == 200:
        data = res.json()
        for item in data[:10]:  # Take first 10 phishing samples
            phishing_samples.append({"input": item["url"], "label": "phishing"})
    else:
        print("⚠️ PhishTank API error:", res.status_code)
except Exception as e:
    print("⚠️ Error fetching PhishTank data:", e)

# -------------------------
# 4. Combine all samples
# -------------------------
all_samples = benign_samples + malicious_ips + phishing_samples
df_new = pd.DataFrame(all_samples)

# -------------------------
# 5. Append to features.csv
# -------------------------
if os.path.exists(CSV_PATH):
    df_old = pd.read_csv(CSV_PATH)
    df_final = pd.concat([df_old, df_new], ignore_index=True)
else:
    df_final = df_new

df_final.to_csv(CSV_PATH, index=False)

print(f"✅ Added {len(all_samples)} new samples. Total dataset size: {len(df_final)}")
