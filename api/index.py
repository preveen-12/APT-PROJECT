from fastapi import FastAPI, HTTPException, Depends, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse
from sqlalchemy import create_engine, Column, Integer, String, DateTime, ForeignKey
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, Session
from passlib.context import CryptContext
from pydantic import BaseModel
import requests
import base64
import os
import datetime

# --- DATABASE & SECURITY SETUP ---
DATABASE_URL = "sqlite:///./apt_radar.db"
engine = create_engine(DATABASE_URL, connect_args={"check_same_thread": False})
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# --- MODELS ---
class User(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True, index=True)
    username = Column(String, unique=True, index=True)
    hashed_password = Column(String)

class ScanLog(Base):
    __tablename__ = "scan_logs"
    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"))
    scan_type = Column(String)
    target = Column(String)
    result = Column(String)
    timestamp = Column(DateTime, default=datetime.datetime.utcnow)

class UserAuth(BaseModel):
    username: str
    password: str

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

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

# --- AUTH LOGIC ---
@app.post("/register")
async def register(auth: UserAuth, db: Session = Depends(get_db)):
    db_user = db.query(User).filter(User.username == auth.username).first()
    if db_user:
        raise HTTPException(status_code=400, detail="Username already registered")
    
    hashed_pass = pwd_context.hash(auth.password)
    new_user = User(username=auth.username, hashed_password=hashed_pass)
    db.add(new_user)
    db.commit()
    return {"message": "User created successfully"}

@app.post("/login")
async def login(auth: UserAuth, db: Session = Depends(get_db)):
    db_user = db.query(User).filter(User.username == auth.username).first()
    if not db_user or not pwd_context.verify(auth.password, db_user.hashed_password):
        raise HTTPException(status_code=401, detail="Invalid username or password")
    
    return {"message": "Login successful", "username": db_user.username}

# --- PAGE ROUTING ---
@app.get("/")
async def serve_gateway():
    return FileResponse(os.path.join(BASE_DIR, "gateway.html"))

@app.get("/login-page")
async def serve_login():
    return FileResponse(os.path.join(BASE_DIR, "login.html"))

@app.get("/register-page")
async def serve_register():
    return FileResponse(os.path.join(BASE_DIR, "register.html"))

@app.get("/dashboard")
async def serve_home():
    return FileResponse(os.path.join(BASE_DIR, "home.html"))

@app.get("/url-page")
async def serve_url_page():
    return FileResponse(os.path.join(BASE_DIR, "url_scanner.html"))

@app.get("/file-page")
async def serve_file_page():
    return FileResponse(os.path.join(BASE_DIR, "file_analyzer.html"))

@app.get("/history")
def get_history(scan_type: str, db: Session = Depends(get_db)):
    return db.query(ScanLog).filter(ScanLog.scan_type == scan_type).order_by(ScanLog.timestamp.desc()).limit(5).all()

@app.get("/scan-url")
def scan_url(url: str, db: Session = Depends(get_db)):
    if not VT_API_KEY:
        raise HTTPException(status_code=500, detail="API Key missing")
    url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
    headers = {"x-apikey": VT_API_KEY}
    response = requests.get(f"{VT_BASE_URL}/urls/{url_id}", headers=headers)
    
    if response.status_code == 200:
        data = response.json()
        stats = data['data']['attributes']['last_analysis_stats']
        res_text = f"Malicious: {stats['malicious']}, Harmless: {stats['harmless']}"
        new_log = ScanLog(scan_type="URL", target=url, result=res_text)
        db.add(new_log)
        db.commit()
        return data
    return {"message": "Scanning initiated or URL not found."}

@app.get("/scan-file")
def scan_file(file_hash: str, db: Session = Depends(get_db)):
    if not VT_API_KEY:
        raise HTTPException(status_code=500, detail="API Key missing")
    headers = {"x-apikey": VT_API_KEY}
    response = requests.get(f"{VT_BASE_URL}/files/{file_hash}", headers=headers)
    if response.status_code == 200:
        data = response.json()
        stats = data['data']['attributes']['last_analysis_stats']
        res_text = f"Malicious: {stats['malicious']}, Harmless: {stats['harmless']}"
        new_log = ScanLog(scan_type="FILE", target=file_hash, result=res_text)
        db.add(new_log)
        db.commit()
        return data
    return {"message": "Hash not found."}