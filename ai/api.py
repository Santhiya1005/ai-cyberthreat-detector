from fastapi import FastAPI
from pydantic import BaseModel
import pandas as pd
import re
import ipaddress

# -------------------------------
# FastAPI setup
# -------------------------------
app = FastAPI(title="Cyber Threat Dummy AI API")

# -------------------------------
# Input model
# -------------------------------
class InputItem(BaseModel):
    input: str

# -------------------------------
# Label mapping
# -------------------------------
label_mapping = {0: "benign", 1: "phishing", 2: "malware"}

# -------------------------------
# Helper functions
# -------------------------------
def extract_url_features(url):
    return pd.DataFrame([{
        'url_length': len(url),
        'num_dots': url.count('.'),
        'has_at': int('@' in url),
        'has_dash': int('-' in url),
        'num_query': url.count('?'),
        'is_https': int(url.startswith('https')),
        'num_digits': sum(c.isdigit() for c in url)
    }])

def is_ip(value):
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False

def is_hash(value):
    return bool(re.fullmatch(r"[a-fA-F0-9]{32}|[a-fA-F0-9]{40}|[a-fA-F0-9]{64}", value))

# -------------------------------
# Dummy prediction logic
# -------------------------------
def dummy_predict(value):
    val_lower = value.lower()
    
    # URLs
    if val_lower.startswith("http"):
        if "eicar" in val_lower or "malware" in val_lower:
            return 2  # malware
        if "login" in val_lower or "secure" in val_lower:
            return 1  # phishing
        return 0  # benign
    
    # IPs
    if is_ip(value):
        if value.startswith("192.") or value.startswith("10."):
            return 0  # private IP = benign
        return 2  # public IP = potential malware for demo
    
    # Hashes
    if is_hash(value):
        if value.startswith("d41d8"):  # empty hash example
            return 0  # benign
        return 2  # all other hashes = malware
    
    return 0  # fallback = benign

# -------------------------------
# Prediction endpoint
# -------------------------------
@app.post("/predict")
def predict_input(item: InputItem):
    value = item.input.strip()
    pred_num = dummy_predict(value)
    pred_label = label_mapping[pred_num]
    return {"input": value, "prediction": pred_label}

# -------------------------------
# Health check
# -------------------------------
@app.get("/health")
def health():
    return {"status": "ok"}

# -------------------------------
# Run server
# -------------------------------
if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="127.0.0.1", port=8000)
