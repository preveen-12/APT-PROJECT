from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
import requests
import base64
import os

app = FastAPI()

# Enable CORS for frontend-backend communication
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# 1. Pull the API Key from Vercel's Environment Variables
VT_API_KEY = os.getenv("VT_API_KEY")
VT_BASE_URL = "https://www.virustotal.com/api/v3"

# --- HELPER TO FIND FRONTEND FILES ---
# os.getcwd() gets the root directory of the project on Vercel
BASE_DIR = os.getcwd()
FRONTEND_DIR = os.path.join(BASE_DIR, "frontend")

# --- PAGE ROUTING ---
@app.get("/")
async def serve_home():
    path = os.path.join(FRONTEND_DIR, "index.html")
    if os.path.exists(path):
        return FileResponse(path)
    return {"error": f"File not found at {path}. Check your folder structure."}

@app.get("/url-page")
async def serve_url_page():
    return FileResponse(os.path.join(FRONTEND_DIR, "url_scanner.html"))

@app.get("/file-page")
async def serve_file_page():
    return FileResponse(os.path.join(FRONTEND_DIR, "file_analyzer.html"))

# --- API LOGIC ---
@app.get("/scan-url")
def scan_url(url: str):
    if not VT_API_KEY:
        raise HTTPException(status_code=500, detail="API Key not configured in Vercel")
        
    url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
    headers = {"x-apikey": VT_API_KEY}
    response = requests.get(f"{VT_BASE_URL}/urls/{url_id}", headers=headers)
    
    if response.status_code == 200:
        return response.json()
    elif response.status_code == 404:
        requests.post(f"{VT_BASE_URL}/urls", headers=headers, data={"url": url})
        return {"message": "Scanning initiated. Please wait 30 seconds."}
    else:
        return {"error": "VirusTotal API Error", "status": response.status_code}

@app.get("/scan-file")
def scan_file(file_hash: str):
    if not VT_API_KEY:
        raise HTTPException(status_code=500, detail="API Key not configured")
        
    headers = {"x-apikey": VT_API_KEY}
    response = requests.get(f"{VT_BASE_URL}/files/{file_hash}", headers=headers)
    return response.json() if response.status_code == 200 else {"message": "Hash not found."}