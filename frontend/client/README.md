## AI Cyber Threat Detector
🛡️ Project Overview

The AI Cyber Threat Detector is a full-stack application that detects malicious URLs, IPs, and file hashes. It combines:

* External threat databases (VirusTotal, AbuseIPDB)
* Local database (custom threat dataset)
* AI Model (predicts phishing/malware/benign)

This hybrid approach ensures detection of both known and new threats.

⚡ Features

* Scan URLs, IP addresses, and file hashes for threats.
* AI model predicts threats even when external databases have no reports.
* History of scans stored locally in the browser.
* Combined verdicts from External APIs + LocalDB + AI.
* Simple, responsive frontend for ease of use.

🛠️ Tech Stack

Frontend: React.js
Backend: Node.js + Express
AI Model: Python + FastAPI + scikit-learn
Database: MongoDB
External APIs: VirusTotal, AbuseIPDB

📁 Folder Structure
ai-cyberthreat-detector/
│── backend/         # Node.js API
│── ai/              # FastAPI AI model
│── frontend/        # React app
│── .env.example     # Sample environment variables
│── README.md

🚀 Setup & Run Instructions
1️⃣ Backend (Node.js + Express)
cd backend
npm install
npm start
Server runs at: http://localhost:4000

2️⃣ AI Backend (FastAPI)
cd ai
pip install -r requirements.txt
uvicorn api:app --reload --port 8000
AI endpoint: http://127.0.0.1:8000/predict

3️⃣ Frontend (React)
cd frontend
npm install
npm run dev
Frontend runs at: http://localhost:5173

🧪 Testing Examples

✅ Safe URL: https://www.google.com

🚨 Malware file hash: http://www.eicar.org/download/eicar.com

⚠️ Suspicious IP: 34.174.232.228

🔐 Notes

* Make sure to set your API keys in .env (VirusTotal, AbuseIPDB).
* The AI model is currently a basic prototype. Retraining with more data improves accuracy.
* For production deployment, consider authentication, scaling, and hiding sensitive keys.

👩‍💻 Author

Santhiya S. – Full-Stack Developer & AI Enthusiast