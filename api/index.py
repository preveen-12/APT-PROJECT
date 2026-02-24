from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from sqlalchemy import create_engine, Column, Integer, String, DateTime
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
import requests
import base64
import os
import datetime

# --- DATABASE SETUP ---
DATABASE_URL = "sqlite:///./apt_radar.db"
engine = create_engine(DATABASE_URL, connect_args={"check_same_thread": False})
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

class ScanLog(Base):
    __tablename__ = "scan_logs"
    id = Column(Integer, primary_key=True, index=True)
    scan_type = Column(String)  # "URL" or "FILE"
    target = Column(String)     # The URL or File Hash
    result = Column(String)     # Summary of malicious/harmless
    timestamp = Column(DateTime, default=datetime.datetime.utcnow)

Base.metadata.create_all(bind=engine)

app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

VT_API_KEY = os.getenv("VT_API_KEY")
VT_BASE_URL = "https://www.virustotal.com/api/v3"
BASE_DIR = os.path.dirname(os.path.abspath(__file__))

# --- HELPER: SAVE TO DB ---
def log_scan(stype, target, result_text):
    db = SessionLocal()
    try:
        new_log = ScanLog(scan_type=stype, target=target, result=result_text)
        db.add(new_log)
        db.commit()
    finally:
        db.close()

# --- ROUTES ---
@app.get("/")
async def serve_home():
    return FileResponse(os.path.join(BASE_DIR, "home.html"))

@app.get("/url-page")
async def serve_url_page():
    return FileResponse(os.path.join(BASE_DIR, "url_scanner.html"))

@app.get("/file-page")
async def serve_file_page():
    return FileResponse(os.path.join(BASE_DIR, "file_analyzer.html"))

@app.get("/history")
def get_history(scan_type: str):
    db = SessionLocal()
    logs = db.query(ScanLog).filter(ScanLog.scan_type == scan_type).order_by(ScanLog.timestamp.desc()).limit(5).all()
    db.close()
    return logs

@app.get("/scan-url")
def scan_url(url: str):
    if not VT_API_KEY:
        raise HTTPException(status_code=500, detail="API Key missing")
    url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
    headers = {"x-apikey": VT_API_KEY}
    response = requests.get(f"{VT_BASE_URL}/urls/{url_id}", headers=headers)
    
    if response.status_code == 200:
        data = response.json()
        stats = data['data']['attributes']['last_analysis_stats']
        res_text = f"Malicious: {stats['malicious']}, Harmless: {stats['harmless']}"
        log_scan("URL", url, res_text) # Save to DB
        return data
    elif response.status_code == 404:
        requests.post(f"{VT_BASE_URL}/urls", headers=headers, data={"url": url})
        return {"message": "Scanning initiated. Please wait 30 seconds."}
    return {"error": "VirusTotal API Error", "status": response.status_code}

@app.get("/scan-file")
def scan_file(file_hash: str):
    if not VT_API_KEY:
        raise HTTPException(status_code=500, detail="API Key missing")
    headers = {"x-apikey": VT_API_KEY}
    response = requests.get(f"{VT_BASE_URL}/files/{file_hash}", headers=headers)
    if response.status_code == 200:
        data = response.json()
        stats = data['data']['attributes']['last_analysis_stats']
        res_text = f"Malicious: {stats['malicious']}, Harmless: {stats['harmless']}"
        log_scan("FILE", file_hash, res_text) # Save to DB
        return data
    return {"message": "Hash not found."}