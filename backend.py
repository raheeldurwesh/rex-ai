import os
import random
import json
import hashlib
import secrets
from datetime import datetime, timedelta
from fastapi import FastAPI, HTTPException, Depends
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import StreamingResponse
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from groq import Groq
from dotenv import load_dotenv
from pymongo import MongoClient
from bson import ObjectId
import jwt

load_dotenv()

app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# ── MongoDB ──
MONGODB_URL = os.getenv("MONGODB_URL", "mongodb+srv://nandedauditor68_db_user:Raheel123@cluster0.q35bivl.mongodb.net/?appName=Cluster0")
client = MongoClient(MONGODB_URL)
db = client["rexai"]
users_col = db["users"]
chats_col = db["chats"]
memories_col = db["memories"]

# ── JWT ──
JWT_SECRET = os.getenv("JWT_SECRET", secrets.token_hex(32))
JWT_EXPIRY_DAYS = 30

# ── Groq API Keys ──
API_KEYS = [
    os.getenv("GROQ_API_KEY"),
    os.getenv("GROQ_API_KEY_1"),
    os.getenv("GROQ_API_KEY_2"),
    os.getenv("GROQ_API_KEY_3"),
]
API_KEYS = [k for k in API_KEYS if k]

security = HTTPBearer(auto_error=False)

def hash_password(password: str) -> str:
    return hashlib.sha256(password.encode()).hexdigest()

def create_token(user_id: str, username: str) -> str:
    payload = {
        "user_id": user_id,
        "username": username,
        "exp": datetime.utcnow() + timedelta(days=JWT_EXPIRY_DAYS)
    }
    return jwt.encode(payload, JWT_SECRET, algorithm="HS256")

def verify_token(credentials: HTTPAuthorizationCredentials = Depends(security)):
    if not credentials:
        raise HTTPException(status_code=401, detail="Not authenticated")
    try:
        payload = jwt.decode(credentials.credentials, JWT_SECRET, algorithms=["HS256"])
        return payload
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token expired")
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=401, detail="Invalid token")

@app.get("/")
def root():
    return {"status": "Rex AI backend running ✅", "keys_loaded": len(API_KEYS)}

# ── AUTH ──
@app.post("/auth/signup")
async def signup(data: dict):
    username = data.get("username", "").strip().lower()
    password = data.get("password", "")
    if not username or not password:
        raise HTTPException(status_code=400, detail="Username and password required")
    if len(username) < 3:
        raise HTTPException(status_code=400, detail="Username must be at least 3 characters")
    if len(password) < 6:
        raise HTTPException(status_code=400, detail="Password must be at least 6 characters")
    if users_col.find_one({"username": username}):
        raise HTTPException(status_code=400, detail="Username already taken")
    user = {
        "username": username,
        "password": hash_password(password),
        "created_at": datetime.utcnow()
    }
    result = users_col.insert_one(user)
    token = create_token(str(result.inserted_id), username)
    return {"token": token, "username": username}

@app.post("/auth/login")
async def login(data: dict):
    username = data.get("username", "").strip().lower()
    password = data.get("password", "")
    user = users_col.find_one({"username": username, "password": hash_password(password)})
    if not user:
        raise HTTPException(status_code=401, detail="Invalid username or password")
    token = create_token(str(user["_id"]), username)
    return {"token": token, "username": username}

# ── CHATS ──
@app.get("/chats")
async def get_chats(user=Depends(verify_token)):
    chats = list(chats_col.find({"user_id": user["user_id"]}).sort("updated_at", -1))
    for c in chats:
        c["id"] = str(c["_id"])
        del c["_id"]
    return chats

@app.post("/chats")
async def create_chat(data: dict, user=Depends(verify_token)):
    chat = {
        "user_id": user["user_id"],
        "title": data.get("title", "New Chat"),
        "messages": data.get("messages", []),
        "created_at": datetime.utcnow(),
        "updated_at": datetime.utcnow()
    }
    result = chats_col.insert_one(chat)
    return {"id": str(result.inserted_id), **chat}

@app.put("/chats/{chat_id}")
async def update_chat(chat_id: str, data: dict, user=Depends(verify_token)):
    chats_col.update_one(
        {"_id": ObjectId(chat_id), "user_id": user["user_id"]},
        {"$set": {
            "title": data.get("title"),
            "messages": data.get("messages", []),
            "updated_at": datetime.utcnow()
        }}
    )
    return {"status": "ok"}

@app.delete("/chats/{chat_id}")
async def delete_chat(chat_id: str, user=Depends(verify_token)):
    chats_col.delete_one({"_id": ObjectId(chat_id), "user_id": user["user_id"]})
    return {"status": "ok"}

# ── MEMORIES ──
@app.get("/memories")
async def get_memories(user=Depends(verify_token)):
    mems = list(memories_col.find({"user_id": user["user_id"]}).sort("created_at", 1))
    return [m["memory"] for m in mems]

@app.post("/memories")
async def add_memory(data: dict, user=Depends(verify_token)):
    memory = data.get("memory", "").strip()
    if not memory:
        raise HTTPException(status_code=400, detail="Memory text required")
    existing = memories_col.find_one({"user_id": user["user_id"], "memory": memory})
    if not existing:
        memories_col.insert_one({
            "user_id": user["user_id"],
            "memory": memory,
            "created_at": datetime.utcnow()
        })
    return {"status": "ok"}

@app.delete("/memories/{memory}")
async def delete_memory(memory: str, user=Depends(verify_token)):
    memories_col.delete_one({"user_id": user["user_id"], "memory": memory})
    return {"status": "ok"}

@app.delete("/memories")
async def clear_memories(user=Depends(verify_token)):
    memories_col.delete_many({"user_id": user["user_id"]})
    return {"status": "ok"}

# ── CHAT ──
@app.post("/chat")
async def chat(request: dict, user=Depends(verify_token)):
    async def generate():
        if not API_KEYS:
            yield f"data: {json.dumps({'error': 'No API keys configured'})}\n\n"
            yield "data: [DONE]\n\n"
            return
        keys_to_try = API_KEYS.copy()
        random.shuffle(keys_to_try)
        last_error = None
        for key in keys_to_try:
            try:
                client = Groq(api_key=key)
                stream = client.chat.completions.create(
                    model=request.get("model", "llama-3.3-70b-versatile"),
                    messages=request.get("messages", []),
                    stream=True,
                    max_tokens=4096,
                )
                for chunk in stream:
                    text = chunk.choices[0].delta.content or ""
                    if text:
                        yield f"data: {json.dumps({'text': text})}\n\n"
                yield "data: [DONE]\n\n"
                return
            except Exception as e:
                last_error = str(e)
                continue
        yield f"data: {json.dumps({'error': last_error})}\n\n"
        yield "data: [DONE]\n\n"
    return StreamingResponse(generate(), media_type="text/event-stream")