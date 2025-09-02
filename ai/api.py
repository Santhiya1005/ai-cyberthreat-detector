from fastapi import FastAPI
from pydantic import BaseModel
import joblib
import pandas as pd

# -------------------------------
# Load trained model
# -------------------------------
model = joblib.load("ai/url_classifier.pkl")

# Feature columns
feature_cols = ['url_length', 'num_dots', 'has_at', 'has_dash', 'num_query', 'is_https', 'num_digits']

# Label mapping
label_mapping = {0: "benign", 1: "phishing", 2: "malware"}

# -------------------------------
# FastAPI setup
# -------------------------------
app = FastAPI(title="URL Threat Detector API")

class URLItem(BaseModel):
    url: str

# -------------------------------
# Helper function to extract features
# -------------------------------
def extract_features(url):
    return pd.DataFrame([{
        'url_length': len(url),
        'num_dots': url.count('.'),
        'has_at': int('@' in url),
        'has_dash': int('-' in url),
        'num_query': url.count('?'),
        'is_https': int(url.startswith('https')),
        'num_digits': sum(c.isdigit() for c in url)
    }])

# -------------------------------
# Prediction endpoint
# -------------------------------
@app.post("/predict")
def predict_url(item: URLItem):
    features = extract_features(item.url)
    pred_num = model.predict(features)[0]
    pred_label = label_mapping[pred_num]
    return {"url": item.url, "prediction": pred_label}
