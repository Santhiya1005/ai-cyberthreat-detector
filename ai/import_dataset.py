import pandas as pd
import requests
import random
import re
# -------------------------------
# 1. Load phishing URLs (GitHub feed)
# -------------------------------
print("⬇️ Downloading phishing URLs from GitHub...")
phishing_url = "https://raw.githubusercontent.com/mitchellkrogza/Phishing.Database/master/phishing-links-ACTIVE.txt"
resp = requests.get(phishing_url)

phish_data = []
if resp.status_code == 200:
    for line in resp.text.splitlines():
        phish_data.append({"input": line.strip(), "label": "phishing"})
else:
    print("⚠️ Could not fetch phishing dataset")

df_phish = pd.DataFrame(phish_data)
print(f"✅ Phishing dataset loaded with {len(df_phish)} rows")


# -------------------------------
# 2. Load malware hashes (Backup GitHub repo)
# -------------------------------
print("⬇️ Downloading malware hashes from GitHub (backup)...")
malware_url = "https://raw.githubusercontent.com/StevenBlack/hosts/master/data/StevenBlack/hosts"
resp = requests.get(malware_url)

malware_hashes = []
if resp.status_code == 200:
    for line in resp.text.splitlines():
        line = line.strip()
        # Skip empty lines and comments
        if not line or line.startswith("#"):
            continue
        # Extract only domain names (skip IP mappings)
        parts = line.split()
        if len(parts) == 1:
            domain = parts[0]
        else:
            domain = parts[1]  # host file format: 0.0.0.0 domain.com
        # Validate domain with regex
        if re.match(r"^(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}$", domain):
            malware_hashes.append({"input": "http://" + domain, "label": "malware"})
else:
    print("⚠️ Could not fetch malware hashes")

df_malware = pd.DataFrame(malware_hashes)
print(f"✅ Malware dataset cleaned with {len(df_malware)} rows")


# -------------------------------
# 3. Add some benign URLs
# -------------------------------
benign_samples = [
    {"input": "http://google.com", "label": "benign"},
    {"input": "http://github.com", "label": "benign"},
    {"input": "http://microsoft.com", "label": "benign"},
    {"input": "http://wikipedia.org", "label": "benign"},
    {"input": "http://openai.com", "label": "benign"},
    {"input": "http://yahoo.com", "label": "benign"},
    {"input": "http://bbc.com", "label": "benign"},
    {"input": "http://cnn.com", "label": "benign"},
    {"input": "http://linkedin.com", "label": "benign"},
    {"input": "http://apple.com", "label": "benign"},
] * 1000

df_benign = pd.DataFrame(benign_samples)

# -------------------------------
# 4. Balance the dataset
# -------------------------------
# To avoid imbalance, take only up to 10k phishing + 10k malware
max_samples = 10000
df_phish = df_phish.sample(n=min(max_samples, len(df_phish)), random_state=42)
df_malware = df_malware.sample(n=min(max_samples, len(df_malware)), random_state=42)

# Merge all datasets
# Merge all datasets
df_all = pd.concat([df_phish, df_malware, df_benign], ignore_index=True)

# Shuffle (optional)
df_all = df_all.sample(frac=1, random_state=42).reset_index(drop=True)

# Save to features.csv
df_all.to_csv("ai/features.csv", index=False)

print(f"🎯 Final dataset saved to ai/features.csv with {len(df_all)} rows")
print(df_all['label'].value_counts())

print(df_all.head())
