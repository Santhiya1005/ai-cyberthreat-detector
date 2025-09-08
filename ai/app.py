from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
import json, re, ipaddress
from pathlib import Path
from typing import Optional

APP_DIR = Path(__file__).parent
DATA_FILE = APP_DIR / "dataset.json"

app = FastAPI(title="Cyber Threat AI")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

class InputItem(BaseModel):
    input: str

class TrainItem(BaseModel):
    input: str
    label: str

VALID_LABELS = {"benign", "phishing", "malware", "unknown"}

def is_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False

def is_hash(value: str) -> bool:
    return bool(re.fullmatch(r"[A-Fa-f0-9]{32}|[A-Fa-f0-9]{40}|[A-Fa-f0-9]{64}", value))

def normalize_input(value: str) -> str:
    return value.strip()

def load_dataset():
    if not DATA_FILE.exists():
        return []
    try:
        with DATA_FILE.open("r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return []

def save_dataset(data):
    try:
        with DATA_FILE.open("w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)
    except Exception as e:
        print("Error saving dataset:", e)

def dataset_lookup(value: str) -> Optional[str]:
    ds = load_dataset()
    v = value.lower()
    for entry in ds:
        if str(entry.get("input", "")).lower() == v:
            return str(entry.get("label", "")).capitalize()
    return None

def heuristic_predict(value: str) -> str:
    v = value.lower()
    if v.startswith("http"):
        if "eicar" in v or "malware" in v or "virus" in v:
            return "Malware"
        if any(x in v for x in ["login", "secure", "verify", "bank"]):
            return "Phishing"
        return "Benign"
    if is_ip(v):
        if v.startswith(("10.", "192.", "127.", "172.")):
            return "Benign"
        if v in ("8.8.8.8", "1.1.1.1", "9.9.9.9"):
            return "Benign"
        return "Unknown"
    if is_hash(v):
        if v.startswith("d41d8"):
            return "Benign"
        return "Unknown"
    return "Unknown"

@app.post("/predict")
def predict_input(item: InputItem):
    value = normalize_input(item.input)
    if not value:
        raise HTTPException(status_code=400, detail="input required")

    ds_label = dataset_lookup(value)
    if ds_label:
        return {"input": value, "prediction": ds_label}

    pred = heuristic_predict(value)
    return {"input": value, "prediction": pred}

@app.post("/train")
def train_input(item: TrainItem):
    value = normalize_input(item.input)
    label = (item.label or "").strip().lower()
    if not value or not label:
        raise HTTPException(status_code=400, detail="input and label required")
    if label not in VALID_LABELS:
        raise HTTPException(status_code=400, detail=f"label must be one of {sorted(VALID_LABELS)}")

    ds = load_dataset()
    lower = value.lower()
    updated = False
    for e in ds:
        if str(e.get("input", "")).lower() == lower:
            e["label"] = label.capitalize()
            updated = True
            break
    if not updated:
        ds.append({"input": value, "label": label.capitalize()})
    save_dataset(ds)
    return {"status": "ok", "input": value, "label": label.capitalize(), "updated": updated}

@app.get("/health")
def health():
    return {"status": "ok"}

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("app:app", host="127.0.0.1", port=8000, reload=True)
