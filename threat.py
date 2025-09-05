from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from auth import get_current_user  # import from auth.py

router = APIRouter()

# Example model for scanning request
class URLItem(BaseModel):
    url: str

# Fake in-memory history per user
db_history = {}

@router.post("/scan")
def scan_url(item: URLItem, user: str = Depends(get_current_user)):
    # Mock logic for scanning
    threat_detected = "malware" if "bad" in item.url else "clean"

    # Save to history
    if user not in db_history:
        db_history[user] = []
    db_history[user].append({"url": item.url, "status": threat_detected})

    return {"url": item.url, "status": threat_detected}

@router.get("/history")
def get_history(user: str = Depends(get_current_user)):
    return db_history.get(user, [])
