from fastapi import FastAPI, HTTPException, Depends, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from sqlalchemy import create_engine, Column, Integer, String, DateTime, ForeignKey
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, Session
from passlib.context import CryptContext
from pydantic import BaseModel
import requests
import base64
import os
import datetime

# Use an absolute path for the DB to avoid Render file-system confusion
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DATABASE_URL = f"sqlite:///{os.path.join(BASE_DIR, 'apt_radar.db')}"

engine = create_engine(DATABASE_URL, connect_args={"check_same_thread": False})
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

class User(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True, index=True)
    username = Column(String, unique=True, index=True)
    hashed_password = Column(String)

class ScanLog(Base):
    __tablename__ = "scan_logs"
    id = Column(Integer, primary_key=True, index=True)
    username = Column(String) # Track by username for simplicity
    scan_type = Column(String)
    target = Column(String)
    result = Column(String)
    timestamp = Column(DateTime, default=datetime.datetime.utcnow)

class UserAuth(BaseModel):
    username: str
    password: str

Base.metadata.create_all(bind=engine)

app = FastAPI()
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])

VT_API_KEY = os.getenv("VT_API_KEY")
VT_BASE_URL = "https://www.virustotal.com/api/v3"
BASE_DIR = os.path.dirname(os.path.abspath(__file__))

def get_db():
    db = SessionLocal()
    try: yield db
    finally: db.close()

@app.post("/register")
async def register(auth: UserAuth, db: Session = Depends(get_db)):
    db_user = db.query(User).filter(User.username == auth.username).first()
    if db_user: raise HTTPException(status_code=400, detail="Username taken")
    new_user = User(username=auth.username, hashed_password=pwd_context.hash(auth.password))
    db.add(new_user); db.commit()
    return {"message": "Success"}

@app.post("/login")
async def login(auth: UserAuth, db: Session = Depends(get_db)):
    db_user = db.query(User).filter(User.username == auth.username).first()
    if not db_user or not pwd_context.verify(auth.password, db_user.hashed_password):
        raise HTTPException(status_code=401, detail="Invalid credentials")
    return {"username": db_user.username}

@app.get("/")
async def serve_gateway(): return FileResponse(os.path.join(BASE_DIR, "gateway.html"))
@app.get("/login-page")
async def serve_login(): return FileResponse(os.path.join(BASE_DIR, "login.html"))
@app.get("/register-page")
async def serve_register(): return FileResponse(os.path.join(BASE_DIR, "register.html"))
@app.get("/dashboard")
async def serve_home(): return FileResponse(os.path.join(BASE_DIR, "home.html"))
@app.get("/url-page")
async def serve_url_page(): return FileResponse(os.path.join(BASE_DIR, "url_scanner.html"))
@app.get("/file-page")
async def serve_file_page(): return FileResponse(os.path.join(BASE_DIR, "file_analyzer.html"))

@app.get("/history")
def get_history(scan_type: str, user: str, db: Session = Depends(get_db)):
    return db.query(ScanLog).filter(ScanLog.scan_type == scan_type, ScanLog.username == user).order_by(ScanLog.timestamp.desc()).limit(5).all()

@app.get("/scan-url")
def scan_url(url: str, user: str, db: Session = Depends(get_db)):
    url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
    response = requests.get(f"{VT_BASE_URL}/urls/{url_id}", headers={"x-apikey": VT_API_KEY})
    if response.status_code == 200:
        stats = response.json()['data']['attributes']['last_analysis_stats']
        res_text = f"Malicious: {stats['malicious']}, Harmless: {stats['harmless']}"
        db.add(ScanLog(username=user, scan_type="URL", target=url, result=res_text))
        db.commit()
        return response.json()
    return {"message": "Scan initiated"}

@app.get("/scan-file")
def scan_file(file_hash: str, user: str, db: Session = Depends(get_db)):
    response = requests.get(f"{VT_BASE_URL}/files/{file_hash}", headers={"x-apikey": VT_API_KEY})
    if response.status_code == 200:
        stats = response.json()['data']['attributes']['last_analysis_stats']
        res_text = f"Malicious: {stats['malicious']}, Harmless: {stats['harmless']}"
        db.add(ScanLog(username=user, scan_type="FILE", target=file_hash, result=res_text))
        db.commit()
        return response.json()
    return {"message": "Hash not found"}