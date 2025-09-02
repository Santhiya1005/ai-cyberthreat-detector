import pandas as pd

# Sample dataset with URLs, IPs, Hashes, and labels
data = [
    {"input": "http://malware.wicar.org/", "label": "malware"},
    {"input": "http://example.com", "label": "benign"},
    {"input": "185.220.101.1", "label": "phishing"},
    {"input": "1.1.1.1", "label": "benign"},
    {"input": "44d88612fea8a8f36de82e1278abb02f", "label": "malware"},  # EICAR test hash
    {"input": "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f", "label": "malware"}
]

# Convert to DataFrame
df = pd.DataFrame(data)

# Save to CSV
df.to_csv("ai/features.csv", index=False)

print("✅ Dataset saved to ai/features.csv")
print(df.head())
