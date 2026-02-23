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

VT_API_KEY = "445cf8e8ccb9e1f94c645e6634d0cbc45f562e3a21235b542f61bb456c8c4aef"
VT_BASE_URL = "https://www.virustotal.com/api/v3"

# --- HELPER TO FIND FRONTEND FILES ---
# This ensures the backend finds the frontend folder even if you run from different directories
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
FRONTEND_DIR = os.path.join(BASE_DIR, "..", "frontend")

# --- PAGE ROUTING ---
# These routes deliver the actual HTML pages to your browser
@app.get("/")
async def serve_home():
    return FileResponse(os.path.join(FRONTEND_DIR, "index.html"))

@app.get("/url-page")
async def serve_url_page():
    return FileResponse(os.path.join(FRONTEND_DIR, "url_scanner.html"))

@app.get("/file-page")
async def serve_file_page():
    return FileResponse(os.path.join(FRONTEND_DIR, "file_analyzer.html"))

# --- API LOGIC ---
# These are the "hidden" functions your HTML pages call to get data
@app.get("/scan-url")
def scan_url(url: str):
    url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
    headers = {"x-apikey": VT_API_KEY}
    response = requests.get(f"{VT_BASE_URL}/urls/{url_id}", headers=headers)
    
    if response.status_code == 200:
        return response.json()
    elif response.status_code == 404:
        requests.post(f"{VT_BASE_URL}/urls", headers=headers, data={"url": url})
        return {"message": "Scanning initiated. Please wait 30 seconds."}
    else:
        raise HTTPException(status_code=response.status_code, detail="VT Error")

@app.get("/scan-file")
def scan_file(file_hash: str):
    headers = {"x-apikey": VT_API_KEY}
    response = requests.get(f"{VT_BASE_URL}/files/{file_hash}", headers=headers)
    return response.json() if response.status_code == 200 else {"message": "Hash not found."}

if __name__ == "__main__":
    import uvicorn
    # Google Cloud provides a 'PORT' environment variable
    port = int(os.environ.get("PORT", 8000))
    # We use 0.0.0.0 so the cloud can 'see' the app
    uvicorn.run(app, host="0.0.0.0", port=port)