from fastapi import FastAPI, Request, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import StreamingResponse
from pydantic import BaseModel
from groq import Groq
import json, os, httpx, re, hashlib, hmac, time, secrets
import asyncio
from contextlib import asynccontextmanager

BREVO_API_KEY = os.getenv("BREVO_API_KEY", "")
BREVO_SENDER_EMAIL = os.getenv("BREVO_SENDER_EMAIL", "raheeldurwesh@gmail.com")
BREVO_SENDER_NAME = "Rex AI"

async def send_brevo_email(to_email: str, to_name: str, subject: str, html_content: str):
    if not BREVO_API_KEY:
        raise Exception("Brevo API key not configured")
    async with httpx.AsyncClient(timeout=10) as client:
        r = await client.post(
            "https://api.brevo.com/v3/smtp/email",
            headers={"api-key": BREVO_API_KEY, "Content-Type": "application/json"},
            json={
                "sender": {"name": BREVO_SENDER_NAME, "email": BREVO_SENDER_EMAIL},
                "to": [{"email": to_email, "name": to_name}],
                "subject": subject,
                "htmlContent": html_content
            }
        )
        if r.status_code not in (200, 201):
            raise Exception(f"Brevo error: {r.text}")
        return r.json()

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
    global _semaphore
    _semaphore = asyncio.Semaphore(MAX_CONCURRENT)
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
    os.getenv("GROQ_API_KEY_4"),
    os.getenv("GROQ_API_KEY_5"),
    os.getenv("GROQ_API_KEY_6"),
    os.getenv("GROQ_API_KEY_7"),
    os.getenv("GROQ_API_KEY_8"),
    os.getenv("GROQ_API_KEY_9"),
] if k]

# Concurrency queue
MAX_CONCURRENT = 20
MAX_QUEUE      = 50
_semaphore     = None

def get_semaphore():
    global _semaphore
    if _semaphore is None:
        _semaphore = asyncio.Semaphore(MAX_CONCURRENT)
    return _semaphore

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

class OtpRequest(BaseModel):
    email: str

class WelcomeRequest(BaseModel):
    email: str
    username: str

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

    sem = get_semaphore()
    if sem._value == 0 and len(getattr(sem, '_waiters', [])) >= MAX_QUEUE:
        raise HTTPException(status_code=503, detail="Rex is a bit busy right now. Please try again in a moment!")

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

    async def guarded_generate():
        async with get_semaphore():
            for chunk in generate():
                yield chunk

    return StreamingResponse(guarded_generate(), media_type="text/event-stream")

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
        q = f"id=eq.{id}&select=id,email,username,chats,searches,message_count,last_seen,created_at,response_style" if id else \
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


# ── Brevo Email Endpoints ─────────────────────────────────
@app.post("/email/otp")
async def send_otp_email(req: OtpRequest, request: Request):
    check_rate(request.client.host)
    if not req.email or "@" not in req.email:
        raise HTTPException(status_code=400, detail="Invalid email")
    import random
    from datetime import datetime, timezone, timedelta
    otp = str(random.randint(100000, 999999))
    expires_at = (datetime.now(timezone.utc) + timedelta(minutes=10)).isoformat()
    async with httpx.AsyncClient(timeout=10) as client:
        await client.delete(
            f"{SUPABASE_URL}/rest/v1/otps?email=eq.{req.email}",
            headers={"apikey": SUPABASE_KEY, "Authorization": f"Bearer {SUPABASE_KEY}"}
        )
        await client.post(
            f"{SUPABASE_URL}/rest/v1/otps",
            headers={"apikey": SUPABASE_KEY, "Authorization": f"Bearer {SUPABASE_KEY}",
                     "Content-Type": "application/json", "Prefer": "return=minimal"},
            json={"email": req.email, "otp": otp, "expires_at": expires_at}
        )
    otp_html = (
        "<div style='font-family:Arial,sans-serif;max-width:480px;margin:0 auto;background:#111;padding:32px;border-radius:12px;'>"
        "<div style='font-size:24px;font-weight:800;color:#c9a84c;margin-bottom:8px;'>Rex AI</div>"
        "<p style='color:rgba(255,255,255,0.7);font-size:15px;margin:16px 0;'>Your password reset OTP is:</p>"
        f"<div style='font-size:36px;font-weight:900;letter-spacing:8px;color:#c9a84c;text-align:center;padding:20px;background:#1a1a1a;border-radius:10px;margin:20px 0;'>{otp}</div>"
        "<p style='color:rgba(255,255,255,0.4);font-size:12px;'>This OTP expires in 10 minutes.</p>"
        "<p style='color:rgba(255,255,255,0.3);font-size:11px;margin-top:24px;'>— Raheel Durwesh, Rex AI</p>"
        "</div>"
    )
    await send_brevo_email(req.email, req.email.split("@")[0], "Your Rex AI OTP Code", otp_html)
    return {"ok": True}

@app.post("/email/verify-otp")
async def verify_otp_endpoint(email: str, otp: str, request: Request):
    check_rate(request.client.host)
    from datetime import datetime, timezone
    async with httpx.AsyncClient(timeout=10) as client:
        r = await client.get(
            f"{SUPABASE_URL}/rest/v1/otps?email=eq.{email}&select=otp,expires_at",
            headers={"apikey": SUPABASE_KEY, "Authorization": f"Bearer {SUPABASE_KEY}"}
        )
        rows = r.json()
        if not rows:
            raise HTTPException(status_code=400, detail="OTP not found or expired")
        row = rows[0]
        expires_at = datetime.fromisoformat(row["expires_at"].replace("Z", "+00:00"))
        if datetime.now(timezone.utc) > expires_at:
            raise HTTPException(status_code=400, detail="OTP expired")
        if row["otp"] != otp:
            raise HTTPException(status_code=400, detail="Wrong OTP")
        await client.delete(
            f"{SUPABASE_URL}/rest/v1/otps?email=eq.{email}",
            headers={"apikey": SUPABASE_KEY, "Authorization": f"Bearer {SUPABASE_KEY}"}
        )
    return {"ok": True}

@app.post("/email/welcome")
async def send_welcome_email(req: WelcomeRequest, request: Request):
    check_rate(request.client.host)
    if not req.email or "@" not in req.email:
        raise HTTPException(status_code=400, detail="Invalid email")
    welcome_html = (
        "<div style='font-family:Arial,sans-serif;max-width:520px;margin:0 auto;background:#111;padding:32px;border-radius:12px;'>"
        "<div style='font-size:28px;font-weight:800;color:#c9a84c;margin-bottom:4px;'>Rex AI</div>"
        f"<p style='color:rgba(255,255,255,0.8);font-size:16px;margin:20px 0 8px;'>Hey {req.username}! 👋</p>"
        "<p style='color:rgba(255,255,255,0.6);font-size:14px;line-height:1.7;'>Welcome to Rex AI! I am Raheel, the developer behind Rex AI. I built this from scratch and I am thrilled to have you on board.</p>"
        "<p style='color:rgba(255,255,255,0.6);font-size:14px;line-height:1.7;margin-top:12px;'>Rex AI is your personal AI assistant — ask anything, search the web, and customize your experience.</p>"
        "<div style='text-align:center;margin:28px 0;'>"
        "<a href='https://rex-ai-raheel.vercel.app' style='background:linear-gradient(135deg,#c9a84c,#f0d97a);color:#111;font-weight:800;padding:14px 32px;border-radius:10px;text-decoration:none;font-size:14px;'>Open Rex AI</a>"
        "</div>"
        "<p style='color:rgba(255,255,255,0.3);font-size:12px;'>Follow updates: <a href='https://instagram.com/raheeldurwesh' style='color:#c9a84c;'>@raheeldurwesh</a></p>"
        "<p style='color:rgba(255,255,255,0.2);font-size:11px;margin-top:8px;'>— Raheel Durwesh, Rex AI</p>"
        "</div>"
    )
    await send_brevo_email(req.email, req.username, "Welcome to Rex AI! 🚀", welcome_html)
    return {"ok": True}

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
