from fastapi import FastAPI, Request, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import StreamingResponse
from pydantic import BaseModel
from groq import Groq
import json, os, httpx, re, hashlib, hmac, time, secrets
import asyncio
from contextlib import asynccontextmanager

async def supabase_keepalive():
    """Ping Supabase every 4 days to prevent inactivity pause"""
    while True:
        await asyncio.sleep(4 * 24 * 60 * 60)  # 4 days
        try:
            if SUPABASE_URL and SUPABASE_KEY:
                async with httpx.AsyncClient(timeout=10) as client:
                    await client.get(
                        f"{SUPABASE_URL}/rest/v1/users?select=id&limit=1",
                        headers={"apikey": SUPABASE_KEY, "Authorization": f"Bearer {SUPABASE_KEY}"}
                    )
                print("Supabase keep-alive ping sent")
        except Exception as e:
            print(f"Supabase keep-alive failed: {e}")

@asynccontextmanager
async def lifespan(app):
    asyncio.create_task(supabase_keepalive())
    yield

app = FastAPI(lifespan=lifespan)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

GROQ_KEYS = [k for k in [
    os.getenv("GROQ_API_KEY"),
    os.getenv("GROQ_API_KEY_1"),
    os.getenv("GROQ_API_KEY_2"),
    os.getenv("GROQ_API_KEY_3"),
] if k]

# Round-robin counter — spreads load evenly across all keys
KEY_INDEX = 0

def get_keys_rotated():
    global KEY_INDEX
    if not GROQ_KEYS:
        return []
    start = KEY_INDEX % len(GROQ_KEYS)
    KEY_INDEX = (KEY_INDEX + 1) % len(GROQ_KEYS)
    return GROQ_KEYS[start:] + GROQ_KEYS[:start]

FALLBACK_MODELS = [
    "llama-3.3-70b-versatile",
    "llama-3.1-8b-instant",
    "meta-llama/llama-4-scout-17b-16e-instruct",
    "openai/gpt-oss-120b",
    "moonshotai/kimi-k2-instruct-0905",
]

# ── Rate limiting (capped to prevent memory growth) ────────
RATE_LIMIT: dict = {}
MAX_REQUESTS = 30
WINDOW_SEC = 60
MAX_IPS = 500

def check_rate(ip: str):
    now = time.time()
    if len(RATE_LIMIT) > MAX_IPS:
        oldest = sorted(RATE_LIMIT.keys(), key=lambda k: max(RATE_LIMIT[k], default=0))
        for old_ip in oldest[:100]:
            del RATE_LIMIT[old_ip]
    ts = [t for t in RATE_LIMIT.get(ip, []) if now - t < WINDOW_SEC]
    if len(ts) >= MAX_REQUESTS:
        raise HTTPException(status_code=429, detail="Too many requests. Slow down.")
    ts.append(now)
    RATE_LIMIT[ip] = ts

# ── Password hashing ───────────────────────────────────────
PEPPER = os.getenv("HASH_PEPPER", "rex-ai-secret-pepper-2024")

def hash_password(password: str) -> str:
    return hashlib.pbkdf2_hmac('sha256', (password + PEPPER).encode(), b'rex-ai-salt', 200000).hex()

def verify_password(password: str, stored_hash: str) -> bool:
    if hmac.compare_digest(hash_password(password), stored_hash):
        return True
    return hmac.compare_digest(hashlib.sha256(password.encode()).hexdigest(), stored_hash)

# ── Config ─────────────────────────────────────────────────
SUPABASE_URL = os.getenv("SUPABASE_URL", "")
SUPABASE_KEY = os.getenv("SUPABASE_KEY", "")
ADMIN_EMAILS = ["raheeldurwesh@gmail.com", "durweshraheel@gmail.com"]
ALLOWED_ORIGINS = ["https://rex-ai-raheel.vercel.app", "http://localhost:3000"]

def check_origin(request: Request):
    origin = request.headers.get("origin", "")
    if origin and not any(origin.startswith(o) for o in ALLOWED_ORIGINS):
        raise HTTPException(status_code=403, detail="Forbidden origin")

# ── Share links stored in Supabase (survives restarts) ────

# ── Pydantic models ────────────────────────────────────────
class Message(BaseModel):
    role: str
    content: str

class ChatRequest(BaseModel):
    messages: list[Message]
    model: str = "llama-3.3-70b-versatile"

class HashRequest(BaseModel):
    password: str

class VerifyRequest(BaseModel):
    password: str
    hash: str

class UserData(BaseModel):
    id: str = None
    email: str = None
    username: str = None
    password_hash: str = None
    last_seen: str = None
    message_count: int = None
    searches: list = None
    chats: list = None
    created_at: str = None

class UpdateData(BaseModel):
    id: str
    data: dict

class ShareData(BaseModel):
    title: str
    messages: list
    expires_hours: int = 72

# ── Endpoints ──────────────────────────────────────────────
@app.get("/ping")
async def ping():
    # Keep Supabase alive (prevents 1-week inactivity pause on free tier)
    if SUPABASE_URL and SUPABASE_KEY:
        try:
            async with httpx.AsyncClient(timeout=5) as client:
                await client.get(
                    f"{SUPABASE_URL}/rest/v1/users?select=id&limit=1",
                    headers={"apikey": SUPABASE_KEY, "Authorization": f"Bearer {SUPABASE_KEY}"}
                )
        except:
            pass
    return {"status": "ok"}

@app.post("/hash")
async def hash_pwd(req: HashRequest, request: Request):
    check_rate(request.client.host)
    if not req.password or len(req.password) > 128:
        raise HTTPException(status_code=400, detail="Invalid password")
    return {"hash": hash_password(req.password)}

@app.post("/verify")
async def verify_pwd(req: VerifyRequest, request: Request):
    check_rate(request.client.host)
    if not req.password or not req.hash:
        raise HTTPException(status_code=400, detail="Missing fields")
    return {"valid": verify_password(req.password, req.hash)}

@app.post("/chat")
async def chat(req: ChatRequest, request: Request):
    check_rate(request.client.host)
    if not req.messages or len(req.messages) > 100:
        raise HTTPException(status_code=400, detail="Invalid messages")
    for m in req.messages:
        if len(m.content) > 32000:
            raise HTTPException(status_code=400, detail="Message too long")

    models = [req.model] + [m for m in FALLBACK_MODELS if m != req.model]

    def generate():
        for key in get_keys_rotated():
            for model in models:
                try:
                    client = Groq(api_key=key)
                    stream = client.chat.completions.create(
                        model=model,
                        messages=[m.dict() for m in req.messages],
                        stream=True,
                        max_tokens=4096,
                    )
                    yield f"data: {json.dumps({'model': model})}\n\n"
                    for chunk in stream:
                        delta = chunk.choices[0].delta.content
                        if delta:
                            yield f"data: {json.dumps({'text': delta})}\n\n"
                    yield "data: [DONE]\n\n"
                    return
                except Exception as e:
                    if "rate_limit" in str(e) or "429" in str(e):
                        continue
                    continue
        yield f"data: {json.dumps({'text': 'All models are busy. Please try again.'})}\n\n"
        yield "data: [DONE]\n\n"

    return StreamingResponse(generate(), media_type="text/event-stream")

@app.get("/search")
async def search(q: str, request: Request):
    check_rate(request.client.host)
    if not q or len(q) > 500:
        raise HTTPException(status_code=400, detail="Invalid query")
    try:
        results = []
        headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"}
        async with httpx.AsyncClient(timeout=8, follow_redirects=True) as client:
            resp = await client.get("https://html.duckduckgo.com/html/", params={"q": q}, headers=headers)
            blocks = re.findall(
                r'class="result__a"[^>]*href="([^"]+)"[^>]*>(.*?)</a>.*?class="result__snippet"[^>]*>(.*?)</span>',
                resp.text, re.DOTALL
            )
            for url, title, snippet in blocks[:5]:
                title = re.sub(r'<[^>]+>', '', title).strip()
                snippet = re.sub(r'<[^>]+>', '', snippet).strip()
                for ent, ch in [('&amp;','&'),('&lt;','<'),('&gt;','>'),('&#x27;',"'"),('&quot;','"')]:
                    title = title.replace(ent, ch); snippet = snippet.replace(ent, ch)
                if title and snippet:
                    results.append({"title": title, "snippet": snippet, "url": url})
            if not results:
                ia = await client.get("https://api.duckduckgo.com/", params={"q": q, "format": "json", "no_redirect": "1", "no_html": "1"})
                data = ia.json()
                if data.get("AbstractText"):
                    results.append({"title": data.get("Heading", q), "snippet": data["AbstractText"], "url": data.get("AbstractURL", "")})
                for rt in data.get("RelatedTopics", [])[:4]:
                    if isinstance(rt, dict) and rt.get("Text"):
                        results.append({"title": rt.get("Text","")[:60], "snippet": rt.get("Text",""), "url": rt.get("FirstURL","")})
        return {"results": results[:5], "query": q}
    except Exception as e:
        return {"results": [], "query": q, "error": str(e)}

# ── DB proxy ───────────────────────────────────────────────
@app.get("/db/user")
async def get_user(id: str = None, email: str = None, request: Request = None):
    if not SUPABASE_URL or not SUPABASE_KEY:
        raise HTTPException(status_code=500, detail="DB not configured")
    async with httpx.AsyncClient(timeout=10) as client:
        q = f"id=eq.{id}&select=id,email,username,chats,searches,message_count,last_seen,created_at" if id else \
            f"email=eq.{email}&select=id,email,username,password_hash,last_seen,created_at"
        r = await client.get(f"{SUPABASE_URL}/rest/v1/users?{q}",
            headers={"apikey": SUPABASE_KEY, "Authorization": f"Bearer {SUPABASE_KEY}"})
        return r.json()

@app.post("/db/user")
async def create_user(data: UserData, request: Request):
    check_origin(request)
    if not SUPABASE_URL or not SUPABASE_KEY:
        raise HTTPException(status_code=500, detail="DB not configured")
    async with httpx.AsyncClient(timeout=10) as client:
        r = await client.post(f"{SUPABASE_URL}/rest/v1/users",
            headers={"apikey": SUPABASE_KEY, "Authorization": f"Bearer {SUPABASE_KEY}",
                     "Content-Type": "application/json", "Prefer": "return=representation"},
            json=data.dict(exclude_none=True))
        return r.json()

@app.patch("/db/user")
async def update_user(req: UpdateData, request: Request):
    check_origin(request)
    if not SUPABASE_URL or not SUPABASE_KEY:
        raise HTTPException(status_code=500, detail="DB not configured")
    async with httpx.AsyncClient(timeout=10) as client:
        await client.patch(f"{SUPABASE_URL}/rest/v1/users?id=eq.{req.id}",
            headers={"apikey": SUPABASE_KEY, "Authorization": f"Bearer {SUPABASE_KEY}",
                     "Content-Type": "application/json"},
            json=req.data)
        return {"ok": True}

@app.get("/db/users")
async def get_all_users(request: Request, admin_email: str = None):
    if admin_email not in ADMIN_EMAILS:
        raise HTTPException(status_code=403, detail="Admin only")
    if not SUPABASE_URL or not SUPABASE_KEY:
        raise HTTPException(status_code=500, detail="DB not configured")
    async with httpx.AsyncClient(timeout=10) as client:
        r = await client.get(f"{SUPABASE_URL}/rest/v1/users?select=*&order=last_seen.desc",
            headers={"apikey": SUPABASE_KEY, "Authorization": f"Bearer {SUPABASE_KEY}"})
        return r.json()

# ── Share ──────────────────────────────────────────────────
@app.post("/share")
async def create_share(data: ShareData, request: Request):
    check_origin(request)
    if not SUPABASE_URL or not SUPABASE_KEY:
        raise HTTPException(status_code=500, detail="DB not configured")
    token = secrets.token_urlsafe(16)
    from datetime import datetime, timezone, timedelta
    expires_at = (datetime.now(timezone.utc) + timedelta(hours=data.expires_hours)).isoformat()
    async with httpx.AsyncClient(timeout=10) as client:
        r = await client.post(
            f"{SUPABASE_URL}/rest/v1/shares",
            headers={"apikey": SUPABASE_KEY, "Authorization": f"Bearer {SUPABASE_KEY}",
                     "Content-Type": "application/json", "Prefer": "return=minimal"},
            json={"token": token, "title": data.title, "messages": data.messages, "expires_at": expires_at}
        )
        if r.status_code not in (200, 201):
            raise HTTPException(status_code=500, detail="Failed to save share")
    return {"token": token, "expires_hours": data.expires_hours}

@app.get("/share/{token}")
async def get_share(token: str):
    if not SUPABASE_URL or not SUPABASE_KEY:
        raise HTTPException(status_code=500, detail="DB not configured")
    from datetime import datetime, timezone
    async with httpx.AsyncClient(timeout=10) as client:
        r = await client.get(
            f"{SUPABASE_URL}/rest/v1/shares?token=eq.{token}&select=token,title,messages,expires_at",
            headers={"apikey": SUPABASE_KEY, "Authorization": f"Bearer {SUPABASE_KEY}"}
        )
        rows = r.json()
        if not rows:
            raise HTTPException(status_code=404, detail="Share link not found or expired")
        share = rows[0]
        # Check expiry
        expires_at = datetime.fromisoformat(share["expires_at"].replace("Z", "+00:00"))
        if datetime.now(timezone.utc) > expires_at:
            # Delete expired share
            await client.delete(
                f"{SUPABASE_URL}/rest/v1/shares?token=eq.{token}",
                headers={"apikey": SUPABASE_KEY, "Authorization": f"Bearer {SUPABASE_KEY}"}
            )
            raise HTTPException(status_code=410, detail="Share link has expired")
        return share
