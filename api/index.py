from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
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

@app.get("/scan-url")
def scan_url(url: str):
    # ... (keep your existing scan_url logic here)
    pass

@app.get("/scan-file")
def scan_file(file_hash: str):
    # ... (keep your existing scan_file logic here)
    pass