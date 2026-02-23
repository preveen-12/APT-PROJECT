from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
import requests
import base64
import os

app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

VT_API_KEY = os.getenv("VT_API_KEY")
VT_BASE_URL = "https://www.virustotal.com/api/v3"

# --- PAGE ROUTING ---
# Render runs from the root, so we look inside the 'api' folder
BASE_DIR = os.path.dirname(os.path.abspath(__file__))

@app.get("/")
async def serve_home():
    return FileResponse(os.path.join(BASE_DIR, "home.html"))

@app.get("/url-page")
async def serve_url_page():
    return FileResponse(os.path.join(BASE_DIR, "url_scanner.html"))

@app.get("/file-page")
async def serve_file_page():
    return FileResponse(os.path.join(BASE_DIR, "file_analyzer.html"))

# --- API LOGIC ---
@app.get("/scan-url")
def scan_url(url: str):
    if not VT_API_KEY:
        raise HTTPException(status_code=500, detail="API Key missing")
    url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
    headers = {"x-apikey": VT_API_KEY}
    response = requests.get(f"{VT_BASE_URL}/urls/{url_id}", headers=headers)
    if response.status_code == 200:
        return response.json()
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
    return response.json() if response.status_code == 200 else {"message": "Hash not found."}