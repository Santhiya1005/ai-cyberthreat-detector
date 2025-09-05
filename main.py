from fastapi import FastAPI
from auth import router as auth_router
from threat import router as threat_router

app = FastAPI(title="AI Cyber Threat Detector")

# include authentication routes
app.include_router(auth_router, prefix="/auth", tags=["Authentication"])

# include threat detection routes
app.include_router(threat_router, prefix="/threats", tags=["Threat Detection"])

@app.get("/")
def root():
    return {"message": "Welcome to AI Cyber Threat Detector API"}
