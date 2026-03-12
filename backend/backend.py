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
BREVO_API_KEY = os.getenv("BREVO_API_KEY", "")
BREVO_SENDER  = os.getenv("BREVO_SENDER_EMAIL", "support.rexai@gmail.com")
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

class OtpRequest(BaseModel):
    email: str

class VerifyOtpRequest(BaseModel):
    email: str
    otp: str

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

# ── Brevo email helper ─────────────────────────────────────
async def send_brevo_email(to_email: str, to_name: str, subject: str, html_body: str):
    if not BREVO_API_KEY:
        raise HTTPException(status_code=500, detail="Email service not configured")
    async with httpx.AsyncClient(timeout=10) as client:
        r = await client.post(
            "https://api.brevo.com/v3/smtp/email",
            headers={"api-key": BREVO_API_KEY, "Content-Type": "application/json"},
            json={
                "sender":   {"name": "Rex AI", "email": BREVO_SENDER},
                "to":       [{"email": to_email, "name": to_name}],
                "subject":  subject,
                "htmlContent": html_body,
            }
        )
        if r.status_code not in (200, 201):
            raise HTTPException(status_code=500, detail=f"Brevo error: {r.text}")
        return r.json()

# ── OTP: send ─────────────────────────────────────────────
@app.post("/email/otp")
async def send_otp(req: OtpRequest, request: Request):
    check_rate(request.client.host)
    if not req.email:
        raise HTTPException(status_code=400, detail="Email required")
    import random
    otp = str(random.randint(100000, 999999))
    expires = int(time.time() * 1000) + 10 * 60 * 1000  # 10 min in ms
    # Store in Supabase otps table
    if SUPABASE_URL and SUPABASE_KEY:
        async with httpx.AsyncClient(timeout=10) as client:
            await client.post(
                f"{SUPABASE_URL}/rest/v1/otps",
                headers={"apikey": SUPABASE_KEY, "Authorization": f"Bearer {SUPABASE_KEY}",
                         "Content-Type": "application/json", "Prefer": "resolution=merge-duplicates"},
                json={"email": req.email, "otp": otp, "expires": expires,
                      "mode": "reset", "created_at": __import__('datetime').datetime.utcnow().isoformat()}
            )
    # Send via Brevo
    html = f"""
    <div style="font-family:sans-serif;max-width:480px;margin:0 auto;padding:24px;">
      <h2 style="color:#c9a84c;font-family:Georgia,serif;">Rex AI</h2>
      <p style="font-size:15px;color:#333;">Your password reset code is:</p>
      <div style="font-size:38px;font-weight:bold;letter-spacing:12px;color:#c9a84c;
                  background:#f9f6ee;border:1px solid #e8dfc4;border-radius:10px;
                  padding:18px 24px;text-align:center;margin:20px 0;">{otp}</div>
      <p style="font-size:13px;color:#888;">This code expires in <b>10 minutes</b>.<br>
         If you did not request this, ignore this email.</p>
      <hr style="border:none;border-top:1px solid #eee;margin:20px 0;">
      <p style="font-size:11px;color:#aaa;">Rex AI · Developed by Raheel Durwesh</p>
    </div>"""
    await send_brevo_email(req.email, req.email.split("@")[0], "Rex AI — Password Reset OTP", html)
    return {"success": True, "message": "OTP sent"}

# ── OTP: verify ───────────────────────────────────────────
@app.post("/email/verify-otp")
async def verify_otp(req: VerifyOtpRequest, request: Request):
    check_rate(request.client.host)
    if not req.email or not req.otp:
        raise HTTPException(status_code=400, detail="Email and OTP required")
    if not SUPABASE_URL or not SUPABASE_KEY:
        raise HTTPException(status_code=500, detail="DB not configured")
    async with httpx.AsyncClient(timeout=10) as client:
        r = await client.get(
            f"{SUPABASE_URL}/rest/v1/otps?email=eq.{req.email}&select=otp,expires&order=created_at.desc&limit=1",
            headers={"apikey": SUPABASE_KEY, "Authorization": f"Bearer {SUPABASE_KEY}"}
        )
        rows = r.json()
        if not rows:
            raise HTTPException(status_code=400, detail="OTP not found. Please request a new one.")
        row = rows[0]
        if str(row["otp"]) != str(req.otp).strip():
            raise HTTPException(status_code=400, detail="Wrong OTP. Please check and try again.")
        if int(time.time() * 1000) > int(row["expires"]):
            raise HTTPException(status_code=400, detail="OTP expired. Please request a new one.")
        # Delete used OTP
        await client.delete(
            f"{SUPABASE_URL}/rest/v1/otps?email=eq.{req.email}",
            headers={"apikey": SUPABASE_KEY, "Authorization": f"Bearer {SUPABASE_KEY}"}
        )
    return {"success": True, "message": "OTP verified"}

# ── Welcome email ─────────────────────────────────────────
@app.post("/email/welcome")
async def welcome_email(request: Request):
    check_rate(request.client.host)
    data = await request.json()
    email = data.get("email", "")
    username = data.get("username", email.split("@")[0])
    if not email:
        raise HTTPException(status_code=400, detail="Email required")
    html = f"""
    <div style="font-family:sans-serif;max-width:480px;margin:0 auto;padding:24px;">
      <h2 style="color:#c9a84c;font-family:Georgia,serif;">Welcome to Rex AI, {username}! 🎉</h2>
      <p style="font-size:15px;color:#333;">Your intelligent AI assistant is ready.</p>
      <p style="font-size:13px;color:#555;">Rex AI features:<br>
        ✨ Multiple AI models · 🌐 Web search · 🧠 Memory · 💾 Chat history · 📄 PDF export</p>
      <a href="https://rex-ai-raheel.vercel.app" style="display:inline-block;background:#c9a84c;
         color:#1a1a1a;font-weight:700;padding:12px 24px;border-radius:8px;text-decoration:none;
         margin-top:16px;">Start Chatting →</a>
      <hr style="border:none;border-top:1px solid #eee;margin:20px 0;">
      <p style="font-size:11px;color:#aaa;">Rex AI · Developed by Raheel Durwesh</p>
    </div>"""
    await send_brevo_email(email, username, "Welcome to Rex AI! 🎉", html)
    return {"success": True}

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
        headers = {
            "User-Agent": "Mozilla/5.0 (compatible; RexAI/1.0)",
            "Accept": "application/json",
        }
        async with httpx.AsyncClient(timeout=12, follow_redirects=True) as client:

            # ── Strategy 1: DuckDuckGo Instant Answer JSON ─────────────────────
            try:
                ia = await client.get(
                    "https://api.duckduckgo.com/",
                    params={"q": q, "format": "json", "no_redirect": "1",
                            "no_html": "1", "skip_disambig": "1"},
                    headers=headers
                )
                if ia.status_code == 200:
                    data = ia.json()
                    if data.get("AbstractText"):
                        results.append({
                            "title":   data.get("Heading", q),
                            "snippet": data["AbstractText"][:400],
                            "url":     data.get("AbstractURL", "")
                        })
                    for rt in data.get("RelatedTopics", []):
                        if isinstance(rt, dict) and rt.get("Text") and rt.get("FirstURL"):
                            results.append({
                                "title":   rt["Text"][:80],
                                "snippet": rt["Text"][:250],
                                "url":     rt["FirstURL"]
                            })
                        elif isinstance(rt, dict) and rt.get("Topics"):
                            for sub in rt["Topics"]:
                                if isinstance(sub, dict) and sub.get("Text") and sub.get("FirstURL"):
                                    results.append({
                                        "title":   sub["Text"][:80],
                                        "snippet": sub["Text"][:250],
                                        "url":     sub["FirstURL"]
                                    })
                        if len(results) >= 5:
                            break
            except Exception:
                pass

            # ── Strategy 2: DuckDuckGo HTML scrape (updated selectors) ─────────
            if len(results) < 3:
                try:
                    html_headers = {
                        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
                        "Accept-Language": "en-US,en;q=0.9",
                        "Accept": "text/html,application/xhtml+xml",
                    }
                    resp = await client.post(
                        "https://html.duckduckgo.com/html/",
                        data={"q": q, "b": "", "kl": "us-en"},
                        headers=html_headers
                    )
                    if resp.status_code == 200:
                        html = resp.text
                        # Extract result links and snippets
                        titles   = re.findall(r'class="result__a"[^>]*>(.*?)</a>', html, re.DOTALL)
                        snippets = re.findall(r'class="result__snippet"[^>]*>(.*?)</(?:span|a)>', html, re.DOTALL)
                        urls_raw = re.findall(r'class="result__url"[^>]*>(.*?)</a>', html, re.DOTALL)

                        def clean(s):
                            s = re.sub(r'<[^>]+>', '', s).strip()
                            for ent, ch in [('&amp;','&'),('&lt;','<'),('&gt;','>'),('&#x27;',"'"),('&quot;','"'),('&#39;',"'"),('&nbsp;',' ')]:
                                s = s.replace(ent, ch)
                            return s

                        for i in range(min(len(titles), len(snippets), 5)):
                            t = clean(titles[i])
                            s = clean(snippets[i])
                            u = clean(urls_raw[i]) if i < len(urls_raw) else ""
                            if not u.startswith("http"):
                                u = "https://" + u
                            if t and s and t not in [r["title"] for r in results]:
                                results.append({"title": t, "snippet": s, "url": u})
                except Exception:
                    pass

            # ── Strategy 3: Wikipedia API (always reliable) ────────────────────
            if len(results) < 2:
                try:
                    wiki = await client.get(
                        "https://en.wikipedia.org/api/rest_v1/page/summary/" + q.replace(" ", "_"),
                        headers=headers
                    )
                    if wiki.status_code == 200:
                        wd = wiki.json()
                        if wd.get("extract"):
                            results.append({
                                "title":   wd.get("title", q),
                                "snippet": wd["extract"][:400],
                                "url":     wd.get("content_urls", {}).get("desktop", {}).get("page", "")
                            })
                except Exception:
                    pass

            # ── Strategy 4: Wikipedia Search ───────────────────────────────────
            if len(results) < 2:
                try:
                    ws = await client.get(
                        "https://en.wikipedia.org/w/api.php",
                        params={"action":"query","list":"search","srsearch":q,
                                "srlimit":3,"format":"json","utf8":1},
                        headers=headers
                    )
                    if ws.status_code == 200:
                        for item in ws.json().get("query",{}).get("search",[]):
                            snippet = re.sub(r'<[^>]+>', '', item.get("snippet","")).strip()
                            if snippet:
                                results.append({
                                    "title":   item.get("title",""),
                                    "snippet": snippet[:300],
                                    "url":     f"https://en.wikipedia.org/wiki/{item['title'].replace(' ','_')}"
                                })
                except Exception:
                    pass

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

# ── API Keys Health Check ──────────────────────────────────
@app.get("/admin/keys-health")
async def keys_health(request: Request, admin_email: str = None):
    if admin_email not in ADMIN_EMAILS:
        raise HTTPException(status_code=403, detail="Admin only")

    all_keys = {
        "groq": [k for k in [
            os.getenv("GROQ_API_KEY"),
            *[os.getenv(f"GROQ_API_KEY_{i}") for i in range(1, 10)],
        ] if k],
        "openrouter": [k for k in [
            os.getenv("OPENROUTER_API_KEY"),
            os.getenv("OPENROUTER_API_KEY_1"),
        ] if k],
        "gemini": [k for k in [
            os.getenv("GEMINI_API_KEY"),
            os.getenv("GEMINI_API_KEY_1"),
        ] if k],
    }

    results = []
    ok_count = 0
    rl_count = 0
    err_count = 0

    async with httpx.AsyncClient(timeout=8) as client:
        # Test Groq keys
        for i, key in enumerate(all_keys["groq"]):
            name = f"Groq #{i+1}"
            masked = key[:8] + "..." + key[-4:]
            try:
                r = await client.post(
                    "https://api.groq.com/openai/v1/chat/completions",
                    headers={"Authorization": f"Bearer {key}", "Content-Type": "application/json"},
                    json={"model": "llama-3.1-8b-instant", "messages": [{"role": "user", "content": "hi"}], "max_tokens": 1}
                )
                if r.status_code == 200:
                    status = "ok"; ok_count += 1
                elif r.status_code == 429:
                    status = "rate_limited"; rl_count += 1
                else:
                    status = "error"; err_count += 1
            except Exception:
                status = "error"; err_count += 1
            results.append({"name": name, "provider": "groq", "key": masked, "status": status})

        # Test OpenRouter keys
        for i, key in enumerate(all_keys["openrouter"]):
            name = f"OpenRouter #{i+1}"
            masked = key[:8] + "..." + key[-4:]
            try:
                r = await client.post(
                    "https://openrouter.ai/api/v1/chat/completions",
                    headers={"Authorization": f"Bearer {key}", "Content-Type": "application/json"},
                    json={"model": "meta-llama/llama-3.3-70b-instruct", "messages": [{"role": "user", "content": "hi"}], "max_tokens": 1}
                )
                if r.status_code == 200:
                    status = "ok"; ok_count += 1
                elif r.status_code == 429:
                    status = "rate_limited"; rl_count += 1
                else:
                    status = "error"; err_count += 1
            except Exception:
                status = "error"; err_count += 1
            results.append({"name": name, "provider": "openrouter", "key": masked, "status": status})

        # Test Gemini keys
        for i, key in enumerate(all_keys["gemini"]):
            name = f"Gemini #{i+1}"
            masked = key[:8] + "..." + key[-4:]
            try:
                r = await client.post(
                    f"https://generativelanguage.googleapis.com/v1beta/models/gemini-2.0-flash:generateContent?key={key}",
                    headers={"Content-Type": "application/json"},
                    json={"contents": [{"parts": [{"text": "hi"}]}], "generationConfig": {"maxOutputTokens": 1}}
                )
                if r.status_code == 200:
                    status = "ok"; ok_count += 1
                elif r.status_code == 429:
                    status = "rate_limited"; rl_count += 1
                else:
                    status = "error"; err_count += 1
            except Exception:
                status = "error"; err_count += 1
            results.append({"name": name, "provider": "gemini", "key": masked, "status": status})

    return {
        "ok": ok_count,
        "rate_limited": rl_count,
        "error": err_count,
        "total": len(results),
        "keys": results
    }

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
