from fastapi import FastAPI, Request, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import StreamingResponse
from pydantic import BaseModel
from groq import Groq
import json, os, httpx, re, hashlib, hmac, time, secrets, asyncio, random
from contextlib import asynccontextmanager
from datetime import datetime, timezone, timedelta

# ── Env ────────────────────────────────────────────────────
BREVO_API_KEY       = os.getenv("BREVO_API_KEY", "")
BREVO_SENDER_EMAIL  = os.getenv("BREVO_SENDER_EMAIL", "raheeldurwesh@gmail.com")
BREVO_SENDER_NAME   = "Rex AI"
SUPABASE_URL        = os.getenv("SUPABASE_URL", "")
SUPABASE_KEY        = os.getenv("SUPABASE_KEY", "")
PEPPER              = os.getenv("HASH_PEPPER", "rex-ai-secret-pepper-2024")
ADMIN_EMAILS        = ["raheeldurwesh@gmail.com", "durweshraheel@gmail.com"]
ALLOWED_ORIGINS     = ["https://rex-ai-raheel.vercel.app", "https://rex-ai-coral.vercel.app", "http://localhost:3000"]

# ── API Keys ───────────────────────────────────────────────
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

OPENROUTER_KEYS = [k for k in [
    os.getenv("OPENROUTER_API_KEY"),
    os.getenv("OPENROUTER_API_KEY_1"),
] if k]

GEMINI_KEYS = [k for k in [
    os.getenv("GEMINI_API_KEY"),
    os.getenv("GEMINI_API_KEY_1"),
] if k]

CLOUDFLARE_TOKENS   = [k for k in [os.getenv("CLOUDFLARE_API_TOKEN")] if k]
CLOUDFLARE_ACCOUNT_ID = os.getenv("CLOUDFLARE_ACCOUNT_ID", "")

# ── Models ─────────────────────────────────────────────────
GROQ_MODELS = [
    "llama-3.3-70b-versatile",
    "llama-3.1-8b-instant",
    "meta-llama/llama-4-scout-17b-16e-instruct",
    "openai/gpt-oss-120b",
    "moonshotai/kimi-k2-instruct-0905",
]

OPENROUTER_MODELS = [
    "meta-llama/llama-3.3-70b-instruct",
    "google/gemini-flash-1.5",
    "mistralai/mistral-7b-instruct",
]

GEMINI_MODELS = [
    "gemini-2.0-flash",
    "gemini-1.5-flash",
]

CLOUDFLARE_MODELS = [
    "@cf/meta/llama-3.3-70b-instruct-fp8-fast",
    "@cf/meta/llama-3.1-8b-instruct",
]

# ── Round-robin key rotation ───────────────────────────────
_key_idx  = {"groq": 0, "openrouter": 0, "gemini": 0}

def rotate(keys: list, name: str) -> list:
    if not keys: return []
    i = _key_idx[name] % len(keys)
    _key_idx[name] = (i + 1) % len(keys)
    return keys[i:] + keys[:i]

# ── Concurrency ────────────────────────────────────────────
MAX_CONCURRENT = 20
MAX_QUEUE      = 50
_semaphore     = None

def get_sem():
    global _semaphore
    if _semaphore is None:
        _semaphore = asyncio.Semaphore(MAX_CONCURRENT)
    return _semaphore

# ── Rate limiting ──────────────────────────────────────────
RATE_LIMIT: dict = {}
MAX_REQUESTS = 30
WINDOW_SEC   = 60
MAX_IPS      = 500

def check_rate(ip: str):
    now = time.time()
    if len(RATE_LIMIT) > MAX_IPS:
        oldest = sorted(RATE_LIMIT, key=lambda k: max(RATE_LIMIT[k], default=0))
        for old in oldest[:100]:
            del RATE_LIMIT[old]
    ts = [t for t in RATE_LIMIT.get(ip, []) if now - t < WINDOW_SEC]
    if len(ts) >= MAX_REQUESTS:
        raise HTTPException(status_code=429, detail="Too many requests. Slow down.")
    ts.append(now)
    RATE_LIMIT[ip] = ts

# ── Password hashing ───────────────────────────────────────
def hash_password(pw: str) -> str:
    return hashlib.pbkdf2_hmac("sha256", (pw + PEPPER).encode(), b"rex-ai-salt", 200000).hex()

def verify_password(pw: str, stored: str) -> bool:
    return hmac.compare_digest(hash_password(pw), stored) or \
           hmac.compare_digest(hashlib.sha256(pw.encode()).hexdigest(), stored)

# ── Supabase helpers ───────────────────────────────────────
def sb_headers():
    return {"apikey": SUPABASE_KEY, "Authorization": f"Bearer {SUPABASE_KEY}",
            "Content-Type": "application/json"}

def check_origin(request: Request):
    origin = request.headers.get("origin", "")
    if origin and not any(origin.startswith(o) for o in ALLOWED_ORIGINS):
        raise HTTPException(status_code=403, detail="Forbidden origin")

# ── Brevo email ────────────────────────────────────────────
async def send_brevo_email(to_email: str, to_name: str, subject: str, html: str):
    if not BREVO_API_KEY:
        raise Exception("Brevo API key not configured")
    async with httpx.AsyncClient(timeout=10) as c:
        r = await c.post(
            "https://api.brevo.com/v3/smtp/email",
            headers={"api-key": BREVO_API_KEY, "Content-Type": "application/json"},
            json={"sender": {"name": BREVO_SENDER_NAME, "email": BREVO_SENDER_EMAIL},
                  "to": [{"email": to_email, "name": to_name}],
                  "subject": subject, "htmlContent": html}
        )
        if r.status_code not in (200, 201):
            raise Exception(f"Brevo error: {r.text}")

# ── Supabase keepalive ─────────────────────────────────────
async def supabase_keepalive():
    while True:
        await asyncio.sleep(4 * 24 * 60 * 60)
        try:
            if SUPABASE_URL and SUPABASE_KEY:
                async with httpx.AsyncClient(timeout=5) as c:
                    await c.get(f"{SUPABASE_URL}/rest/v1/users?select=id&limit=1",
                                headers=sb_headers())
        except:
            pass

# ── App ────────────────────────────────────────────────────
@asynccontextmanager
async def lifespan(app):
    global _semaphore
    _semaphore = asyncio.Semaphore(MAX_CONCURRENT)
    asyncio.create_task(supabase_keepalive())
    yield

app = FastAPI(lifespan=lifespan)
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])

# ── Pydantic models ────────────────────────────────────────
class Message(BaseModel):
    role: str
    content: str

class ChatRequest(BaseModel):
    messages: list[Message]
    model: str    = "llama-3.3-70b-versatile"
    provider: str = "groq"
    user_id: str  = None

class HashRequest(BaseModel):
    password: str

class VerifyRequest(BaseModel):
    password: str
    hash: str

class UserData(BaseModel):
    id: str           = None
    email: str        = None
    username: str     = None
    password_hash: str= None
    last_seen: str    = None
    message_count: int= None
    searches: list    = None
    chats: list       = None
    created_at: str   = None

class UpdateData(BaseModel):
    id: str
    data: dict

class ShareData(BaseModel):
    title: str
    messages: list
    expires_hours: int = 72

class SendEmailRequest(BaseModel):
    to_email: str
    to_name: str
    subject: str
    html_content: str

class OtpRequest(BaseModel):
    email: str

class WelcomeRequest(BaseModel):
    email: str
    username: str

class TokenUpdateRequest(BaseModel):
    user_id: str
    model: str
    prompt_tokens: int
    completion_tokens: int

class DocQuestion(BaseModel):
    user_id: str
    doc_name: str
    question: str
    answer: str

# ── /ping ──────────────────────────────────────────────────
@app.get("/ping")
async def ping():
    if SUPABASE_URL and SUPABASE_KEY:
        try:
            async with httpx.AsyncClient(timeout=5) as c:
                await c.get(f"{SUPABASE_URL}/rest/v1/users?select=id&limit=1", headers=sb_headers())
        except:
            pass
    return {"status": "ok"}

# ── /hash  /verify ─────────────────────────────────────────
@app.post("/hash")
async def hash_pwd(req: HashRequest, request: Request):
    check_rate(request.client.host)
    if not req.password or len(req.password) > 128:
        raise HTTPException(400, "Invalid password")
    return {"hash": hash_password(req.password)}

@app.post("/verify")
async def verify_pwd(req: VerifyRequest, request: Request):
    check_rate(request.client.host)
    if not req.password or not req.hash:
        raise HTTPException(400, "Missing fields")
    return {"valid": verify_password(req.password, req.hash)}

# ── /chat ──────────────────────────────────────────────────
@app.post("/chat")
async def chat(req: ChatRequest, request: Request):
    check_rate(request.client.host)
    if not req.messages or len(req.messages) > 100:
        raise HTTPException(400, "Invalid messages")
    for m in req.messages:
        if len(m.content) > 32000:
            raise HTTPException(400, "Message too long")

    sem = get_sem()
    if sem._value == 0 and len(getattr(sem, "_waiters", [])) >= MAX_QUEUE:
        raise HTTPException(503, "Rex is a bit busy right now. Please try again in a moment!")

    msgs      = [m.dict() for m in req.messages]
    provider  = (req.provider or "groq").lower()
    model_req = req.model or "llama-3.3-70b-versatile"

    async def stream_groq():
        # Build model list: requested model first, then rest as fallback
        ordered = [model_req] + [m for m in GROQ_MODELS if m != model_req]
        for key in rotate(GROQ_KEYS, "groq"):
            for model in ordered:
                try:
                    client = Groq(api_key=key)
                    s = client.chat.completions.create(
                        model=model, messages=msgs, stream=True, max_tokens=4096)
                    yield f"data: {json.dumps({'model': model})}\n\n"
                    for chunk in s:
                        delta = chunk.choices[0].delta.content
                        if delta:
                            yield f"data: {json.dumps({'text': delta})}\n\n"
                    yield "data: [DONE]\n\n"
                    return
                except Exception as e:
                    err = str(e)
                    if any(x in err for x in ["rate_limit", "429", "503", "model_not_found"]):
                        continue
                    continue

    async def stream_openrouter():
        ordered = [model_req] + [m for m in OPENROUTER_MODELS if m != model_req]
        for key in rotate(OPENROUTER_KEYS, "openrouter"):
            for model in ordered:
                try:
                    async with httpx.AsyncClient(timeout=60) as hc:
                        async with hc.stream(
                            "POST",
                            "https://openrouter.ai/api/v1/chat/completions",
                            headers={
                                "Authorization": f"Bearer {key}",
                                "Content-Type": "application/json",
                                "HTTP-Referer": "https://rex-ai-raheel.vercel.app",
                                "X-Title": "Rex AI",
                            },
                            json={"model": model, "messages": msgs,
                                  "max_tokens": 4096, "stream": True},
                        ) as resp:
                            if resp.status_code in (429, 402):
                                continue
                            if resp.status_code != 200:
                                continue
                            yield f"data: {json.dumps({'model': model})}\n\n"
                            async for line in resp.aiter_lines():
                                if not line.startswith("data: "):
                                    continue
                                raw = line[6:].strip()
                                if raw == "[DONE]":
                                    break
                                try:
                                    d = json.loads(raw)
                                    delta = d["choices"][0]["delta"].get("content", "")
                                    if delta:
                                        yield f"data: {json.dumps({'text': delta})}\n\n"
                                except:
                                    pass
                            yield "data: [DONE]\n\n"
                            return
                except Exception:
                    continue

    async def stream_gemini():
        ordered = [model_req] + [m for m in GEMINI_MODELS if m != model_req]
        # Convert messages to Gemini format
        gem_msgs = []
        for m in msgs:
            role = "user" if m["role"] == "user" else "model"
            gem_msgs.append({"role": role, "parts": [{"text": m["content"]}]})
        for key in rotate(GEMINI_KEYS, "gemini"):
            for model in ordered:
                try:
                    url = (f"https://generativelanguage.googleapis.com/v1beta/models/"
                           f"{model}:streamGenerateContent?alt=sse&key={key}")
                    async with httpx.AsyncClient(timeout=60) as hc:
                        async with hc.stream(
                            "POST", url,
                            headers={"Content-Type": "application/json"},
                            json={"contents": gem_msgs,
                                  "generationConfig": {"maxOutputTokens": 4096}},
                        ) as resp:
                            if resp.status_code == 429:
                                continue
                            if resp.status_code != 200:
                                continue
                            yield f"data: {json.dumps({'model': model})}\n\n"
                            async for line in resp.aiter_lines():
                                if not line.startswith("data: "):
                                    continue
                                raw = line[6:].strip()
                                try:
                                    d = json.loads(raw)
                                    parts = d.get("candidates", [{}])[0].get(
                                        "content", {}).get("parts", [{}])
                                    delta = parts[0].get("text", "") if parts else ""
                                    if delta:
                                        yield f"data: {json.dumps({'text': delta})}\n\n"
                                except:
                                    pass
                            yield "data: [DONE]\n\n"
                            return
                except Exception:
                    continue

    async def stream_cloudflare():
        if not CLOUDFLARE_TOKENS or not CLOUDFLARE_ACCOUNT_ID:
            return
        ordered = [model_req] + [m for m in CLOUDFLARE_MODELS if m != model_req]
        for token in CLOUDFLARE_TOKENS:
            for model in ordered:
                try:
                    url = (f"https://api.cloudflare.com/client/v4/accounts/"
                           f"{CLOUDFLARE_ACCOUNT_ID}/ai/run/{model}")
                    async with httpx.AsyncClient(timeout=60) as hc:
                        async with hc.stream(
                            "POST", url,
                            headers={"Authorization": f"Bearer {token}",
                                     "Content-Type": "application/json"},
                            json={"messages": msgs, "stream": True, "max_tokens": 4096},
                        ) as resp:
                            if resp.status_code != 200:
                                continue
                            yield f"data: {json.dumps({'model': model})}\n\n"
                            async for line in resp.aiter_lines():
                                if not line.startswith("data: "):
                                    continue
                                raw = line[6:].strip()
                                if raw == "[DONE]":
                                    break
                                try:
                                    d = json.loads(raw)
                                    delta = d.get("response", "")
                                    if delta:
                                        yield f"data: {json.dumps({'text': delta})}\n\n"
                                except:
                                    pass
                            yield "data: [DONE]\n\n"
                            return
                except Exception:
                    continue

    async def generate():
        # Route to requested provider first, then fallback chain
        done = False

        if provider == "groq" or not done:
            async for chunk in stream_groq():
                yield chunk
                if chunk == "data: [DONE]\n\n":
                    done = True
            if done:
                return

        if provider == "openrouter" or not done:
            async for chunk in stream_openrouter():
                yield chunk
                if chunk == "data: [DONE]\n\n":
                    done = True
            if done:
                return

        if provider == "gemini" or not done:
            async for chunk in stream_gemini():
                yield chunk
                if chunk == "data: [DONE]\n\n":
                    done = True
            if done:
                return

        if provider == "cloudflare" or not done:
            async for chunk in stream_cloudflare():
                yield chunk
                if chunk == "data: [DONE]\n\n":
                    done = True
            if done:
                return

        yield f"data: {json.dumps({'text': 'All providers are busy. Please try again in a moment.'})}\n\n"
        yield "data: [DONE]\n\n"

    async def guarded():
        async with get_sem():
            async for chunk in generate():
                yield chunk

    return StreamingResponse(guarded(), media_type="text/event-stream")

# ── /search ────────────────────────────────────────────────
@app.get("/search")
async def search(q: str, request: Request):
    check_rate(request.client.host)
    if not q or len(q) > 500:
        raise HTTPException(400, "Invalid query")
    try:
        results = []
        hdrs = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"}
        async with httpx.AsyncClient(timeout=8, follow_redirects=True) as c:
            resp = await c.get("https://html.duckduckgo.com/html/", params={"q": q}, headers=hdrs)
            blocks = re.findall(
                r'class="result__a"[^>]*href="([^"]+)"[^>]*>(.*?)</a>.*?class="result__snippet"[^>]*>(.*?)</span>',
                resp.text, re.DOTALL)
            for url, title, snippet in blocks[:5]:
                title   = re.sub(r"<[^>]+>", "", title).strip()
                snippet = re.sub(r"<[^>]+>", "", snippet).strip()
                for ent, ch in [("&amp;","&"),("&lt;","<"),("&gt;",">"),("&#x27;","'"),("&quot;",'"')]:
                    title = title.replace(ent, ch); snippet = snippet.replace(ent, ch)
                if title and snippet:
                    results.append({"title": title, "snippet": snippet, "url": url})
            if not results:
                ia = await c.get("https://api.duckduckgo.com/",
                                 params={"q": q, "format": "json", "no_redirect": "1", "no_html": "1"})
                data = ia.json()
                if data.get("AbstractText"):
                    results.append({"title": data.get("Heading", q),
                                    "snippet": data["AbstractText"],
                                    "url": data.get("AbstractURL", "")})
                for rt in data.get("RelatedTopics", [])[:4]:
                    if isinstance(rt, dict) and rt.get("Text"):
                        results.append({"title": rt.get("Text","")[:60],
                                        "snippet": rt.get("Text",""),
                                        "url": rt.get("FirstURL","")})
        return {"results": results[:5], "query": q}
    except Exception as e:
        return {"results": [], "query": q, "error": str(e)}

# ── /tokens ────────────────────────────────────────────────
@app.post("/tokens/update")
async def update_tokens(req: TokenUpdateRequest, request: Request):
    if not SUPABASE_URL or not SUPABASE_KEY:
        raise HTTPException(500, "DB not configured")
    async with httpx.AsyncClient(timeout=10) as c:
        r = await c.get(
            f"{SUPABASE_URL}/rest/v1/users?id=eq.{req.user_id}&select=total_tokens,model_usage",
            headers=sb_headers())
        users = r.json()
        if not users:
            raise HTTPException(404, "User not found")
        u = users[0]
        total = req.prompt_tokens + req.completion_tokens
        new_total = (u.get("total_tokens") or 0) + total
        mu = u.get("model_usage") or {}
        if req.model not in mu:
            mu[req.model] = {"prompt": 0, "completion": 0, "total": 0}
        mu[req.model]["prompt"]     += req.prompt_tokens
        mu[req.model]["completion"] += req.completion_tokens
        mu[req.model]["total"]      += total
        await c.patch(
            f"{SUPABASE_URL}/rest/v1/users?id=eq.{req.user_id}",
            headers=sb_headers(),
            json={"total_tokens": new_total, "model_usage": mu})
    return {"ok": True, "total_tokens": new_total}

# ── /admin/keys-health ─────────────────────────────────────
@app.get("/admin/keys-health")
async def keys_health(admin_email: str, request: Request):
    if admin_email not in ADMIN_EMAILS:
        raise HTTPException(403, "Not authorized")
    results = []

    # Groq
    for i, key in enumerate(GROQ_KEYS):
        name   = "GROQ_API_KEY" if i == 0 else f"GROQ_API_KEY_{i}"
        masked = key[:8] + "..." + key[-4:]
        try:
            client = Groq(api_key=key)
            r = client.chat.completions.create(
                model="llama-3.1-8b-instant",
                messages=[{"role": "user", "content": "Hi"}],
                max_tokens=5, stream=False)
            results.append({"name": name, "key": masked, "provider": "Groq",
                            "status": "ok", "model": r.model})
        except Exception as e:
            err = str(e)
            st  = "rate_limited" if "429" in err or "rate_limit" in err else "error"
            results.append({"name": name, "key": masked, "provider": "Groq",
                            "status": st, "error": err[:120]})

    # OpenRouter
    for i, key in enumerate(OPENROUTER_KEYS):
        name   = "OPENROUTER_API_KEY" if i == 0 else f"OPENROUTER_API_KEY_{i}"
        masked = key[:8] + "..." + key[-4:]
        try:
            async with httpx.AsyncClient(timeout=10) as hc:
                r = await hc.post(
                    "https://openrouter.ai/api/v1/chat/completions",
                    headers={"Authorization": f"Bearer {key}",
                             "Content-Type": "application/json",
                             "HTTP-Referer": "https://rex-ai-raheel.vercel.app"},
                    json={"model": "meta-llama/llama-3.3-70b-instruct",
                          "messages": [{"role": "user", "content": "Hi"}],
                          "max_tokens": 5})
            if r.status_code == 429:
                results.append({"name": name, "key": masked, "provider": "OpenRouter", "status": "rate_limited"})
            elif r.status_code == 200:
                results.append({"name": name, "key": masked, "provider": "OpenRouter",
                                "status": "ok", "model": r.json().get("model","")})
            else:
                results.append({"name": name, "key": masked, "provider": "OpenRouter",
                                "status": "error", "error": r.text[:120]})
        except Exception as e:
            results.append({"name": name, "key": masked, "provider": "OpenRouter",
                            "status": "error", "error": str(e)[:120]})

    # Gemini
    for i, key in enumerate(GEMINI_KEYS):
        name   = "GEMINI_API_KEY" if i == 0 else f"GEMINI_API_KEY_{i}"
        masked = key[:8] + "..." + key[-4:]
        try:
            async with httpx.AsyncClient(timeout=10) as hc:
                r = await hc.post(
                    f"https://generativelanguage.googleapis.com/v1beta/models/gemini-2.0-flash:generateContent?key={key}",
                    headers={"Content-Type": "application/json"},
                    json={"contents": [{"role": "user", "parts": [{"text": "Hi"}]}],
                          "generationConfig": {"maxOutputTokens": 5}})
            if r.status_code == 429:
                results.append({"name": name, "key": masked, "provider": "Gemini", "status": "rate_limited"})
            elif r.status_code == 200:
                results.append({"name": name, "key": masked, "provider": "Gemini",
                                "status": "ok", "model": "gemini-2.0-flash"})
            else:
                results.append({"name": name, "key": masked, "provider": "Gemini",
                                "status": "error", "error": r.text[:120]})
        except Exception as e:
            results.append({"name": name, "key": masked, "provider": "Gemini",
                            "status": "error", "error": str(e)[:120]})

    # Cloudflare
    if CLOUDFLARE_TOKENS and CLOUDFLARE_ACCOUNT_ID:
        for token in CLOUDFLARE_TOKENS:
            masked = token[:8] + "..." + token[-4:]
            try:
                async with httpx.AsyncClient(timeout=10) as hc:
                    r = await hc.post(
                        f"https://api.cloudflare.com/client/v4/accounts/{CLOUDFLARE_ACCOUNT_ID}/ai/run/@cf/meta/llama-3.1-8b-instruct",
                        headers={"Authorization": f"Bearer {token}", "Content-Type": "application/json"},
                        json={"messages": [{"role": "user", "content": "Hi"}], "max_tokens": 5})
                if r.status_code == 200:
                    results.append({"name": "CLOUDFLARE_API_TOKEN", "key": masked,
                                    "provider": "Cloudflare", "status": "ok", "model": "llama-3.1-8b"})
                else:
                    results.append({"name": "CLOUDFLARE_API_TOKEN", "key": masked,
                                    "provider": "Cloudflare", "status": "error", "error": r.text[:120]})
            except Exception as e:
                results.append({"name": "CLOUDFLARE_API_TOKEN", "key": masked,
                                "provider": "Cloudflare", "status": "error", "error": str(e)[:120]})
    else:
        results.append({"name": "CLOUDFLARE_API_TOKEN", "key": "not set",
                        "provider": "Cloudflare", "status": "error",
                        "error": "CLOUDFLARE_API_TOKEN or CLOUDFLARE_ACCOUNT_ID not set"})

    ok = sum(1 for r in results if r["status"] == "ok")
    rl = sum(1 for r in results if r["status"] == "rate_limited")
    return {"total": len(results), "ok": ok, "rate_limited": rl,
            "error": len(results) - ok - rl, "keys": results}

# ── /db ────────────────────────────────────────────────────
@app.get("/db/user")
async def get_user(id: str = None, email: str = None, request: Request = None):
    if not SUPABASE_URL or not SUPABASE_KEY:
        raise HTTPException(500, "DB not configured")
    async with httpx.AsyncClient(timeout=10) as c:
        q = (f"id=eq.{id}&select=id,email,username,chats,searches,message_count,last_seen,created_at,response_style"
             if id else f"email=eq.{email}&select=id,email,username,password_hash,last_seen,created_at")
        r = await c.get(f"{SUPABASE_URL}/rest/v1/users?{q}", headers=sb_headers())
        return r.json()

@app.post("/db/user")
async def create_user(data: UserData, request: Request):
    check_origin(request)
    if not SUPABASE_URL or not SUPABASE_KEY:
        raise HTTPException(500, "DB not configured")
    async with httpx.AsyncClient(timeout=10) as c:
        r = await c.post(f"{SUPABASE_URL}/rest/v1/users",
                         headers={**sb_headers(), "Prefer": "return=representation"},
                         json=data.dict(exclude_none=True))
        return r.json()

@app.patch("/db/user")
async def update_user(req: UpdateData, request: Request):
    check_origin(request)
    if not SUPABASE_URL or not SUPABASE_KEY:
        raise HTTPException(500, "DB not configured")
    async with httpx.AsyncClient(timeout=10) as c:
        await c.patch(f"{SUPABASE_URL}/rest/v1/users?id=eq.{req.id}",
                      headers=sb_headers(), json=req.data)
    return {"ok": True}

@app.get("/db/users")
async def get_all_users(request: Request, admin_email: str = None):
    if admin_email not in ADMIN_EMAILS:
        raise HTTPException(403, "Admin only")
    if not SUPABASE_URL or not SUPABASE_KEY:
        raise HTTPException(500, "DB not configured")
    async with httpx.AsyncClient(timeout=10) as c:
        r = await c.get(f"{SUPABASE_URL}/rest/v1/users?select=*&order=last_seen.desc",
                        headers=sb_headers())
        return r.json()

# ── /email ─────────────────────────────────────────────────
@app.post("/email/send")
async def send_email(req: SendEmailRequest, request: Request):
    check_rate(request.client.host)
    if not req.to_email or "@" not in req.to_email:
        raise HTTPException(400, "Invalid email")
    await send_brevo_email(req.to_email, req.to_name, req.subject, req.html_content)
    return {"ok": True}

@app.post("/email/otp")
async def send_otp_email(req: OtpRequest, request: Request):
    check_rate(request.client.host)
    if not req.email or "@" not in req.email:
        raise HTTPException(400, "Invalid email")
    otp = str(random.randint(100000, 999999))
    expires_ts = int((datetime.now(timezone.utc) + timedelta(minutes=10)).timestamp() * 1000)
    async with httpx.AsyncClient(timeout=10) as c:
        await c.delete(f"{SUPABASE_URL}/rest/v1/otps?email=eq.{req.email}", headers=sb_headers())
        await c.post(f"{SUPABASE_URL}/rest/v1/otps",
                     headers={**sb_headers(), "Prefer": "return=minimal"},
                     json={"email": req.email, "otp": otp, "expires": expires_ts})
    otp_html = (
        "<div style='font-family:Arial,sans-serif;max-width:480px;margin:0 auto;"
        "background:#111;padding:32px;border-radius:12px;'>"
        "<div style='font-size:24px;font-weight:800;color:#c9a84c;margin-bottom:8px;'>Rex AI</div>"
        "<p style='color:rgba(255,255,255,0.7);font-size:15px;margin:16px 0;'>Your password reset OTP is:</p>"
        f"<div style='font-size:36px;font-weight:900;letter-spacing:8px;color:#c9a84c;"
        f"text-align:center;padding:20px;background:#1a1a1a;border-radius:10px;margin:20px 0;'>{otp}</div>"
        "<p style='color:rgba(255,255,255,0.4);font-size:12px;'>This OTP expires in 10 minutes.</p>"
        "<p style='color:rgba(255,255,255,0.3);font-size:11px;margin-top:24px;'>— Raheel Durwesh, Rex AI</p>"
        "</div>"
    )
    await send_brevo_email(req.email, req.email.split("@")[0], "Your Rex AI OTP Code", otp_html)
    return {"ok": True}

@app.post("/email/verify-otp")
async def verify_otp_endpoint(email: str, otp: str, request: Request):
    check_rate(request.client.host)
    async with httpx.AsyncClient(timeout=10) as c:
        r = await c.get(f"{SUPABASE_URL}/rest/v1/otps?email=eq.{email}&select=otp,expires",
                        headers=sb_headers())
        rows = r.json()
        if not isinstance(rows, list) or not rows:
            raise HTTPException(400, "OTP not found or expired")
        row = rows[0]
        if int(time.time() * 1000) > row["expires"]:
            raise HTTPException(400, "OTP expired")
        if row["otp"] != otp:
            raise HTTPException(400, "Wrong OTP")
        await c.delete(f"{SUPABASE_URL}/rest/v1/otps?email=eq.{email}", headers=sb_headers())
    return {"ok": True}

@app.post("/email/welcome")
async def send_welcome_email(req: WelcomeRequest, request: Request):
    check_rate(request.client.host)
    if not req.email or "@" not in req.email:
        raise HTTPException(400, "Invalid email")
    welcome_html = (
        "<div style='font-family:Arial,sans-serif;max-width:520px;margin:0 auto;"
        "background:#111;padding:32px;border-radius:12px;'>"
        "<div style='font-size:28px;font-weight:800;color:#c9a84c;margin-bottom:4px;'>Rex AI</div>"
        f"<p style='color:rgba(255,255,255,0.8);font-size:16px;margin:20px 0 8px;'>Hey {req.username}! 👋</p>"
        "<p style='color:rgba(255,255,255,0.6);font-size:14px;line-height:1.7;'>Welcome to Rex AI! "
        "I am Raheel, the developer behind Rex AI. I built this from scratch and I am thrilled to have you on board.</p>"
        "<p style='color:rgba(255,255,255,0.6);font-size:14px;line-height:1.7;margin-top:12px;'>"
        "Rex AI is your personal AI assistant — ask anything, search the web, and customize your experience.</p>"
        "<div style='text-align:center;margin:28px 0;'>"
        "<a href='https://rex-ai-raheel.vercel.app' style='background:linear-gradient(135deg,#c9a84c,#f0d97a);"
        "color:#111;font-weight:800;padding:14px 32px;border-radius:10px;text-decoration:none;font-size:14px;'>"
        "Open Rex AI</a></div>"
        "<p style='color:rgba(255,255,255,0.3);font-size:12px;'>Follow updates: "
        "<a href='https://instagram.com/raheeldurwesh' style='color:#c9a84c;'>@raheeldurwesh</a></p>"
        "<p style='color:rgba(255,255,255,0.2);font-size:11px;margin-top:8px;'>— Raheel Durwesh, Rex AI</p>"
        "</div>"
    )
    await send_brevo_email(req.email, req.username, "Welcome to Rex AI! 🚀", welcome_html)
    return {"ok": True}

# ── /share ─────────────────────────────────────────────────
@app.post("/share")
async def create_share(data: ShareData, request: Request):
    check_origin(request)
    if not SUPABASE_URL or not SUPABASE_KEY:
        raise HTTPException(500, "DB not configured")
    token      = secrets.token_urlsafe(16)
    expires_at = (datetime.now(timezone.utc) + timedelta(hours=data.expires_hours)).isoformat()
    async with httpx.AsyncClient(timeout=10) as c:
        r = await c.post(f"{SUPABASE_URL}/rest/v1/shares",
                         headers={**sb_headers(), "Prefer": "return=minimal"},
                         json={"token": token, "title": data.title,
                               "messages": data.messages, "expires_at": expires_at})
        if r.status_code not in (200, 201):
            raise HTTPException(500, "Failed to save share")
    return {"token": token, "expires_hours": data.expires_hours}

@app.get("/share/{token}")
async def get_share(token: str):
    if not SUPABASE_URL or not SUPABASE_KEY:
        raise HTTPException(500, "DB not configured")
    async with httpx.AsyncClient(timeout=10) as c:
        r = await c.get(f"{SUPABASE_URL}/rest/v1/shares?token=eq.{token}&select=token,title,messages,expires_at",
                        headers=sb_headers())
        rows = r.json()
        if not rows:
            raise HTTPException(404, "Share link not found or expired")
        share = rows[0]
        expires_at = datetime.fromisoformat(share["expires_at"].replace("Z", "+00:00"))
        if datetime.now(timezone.utc) > expires_at:
            await c.delete(f"{SUPABASE_URL}/rest/v1/shares?token=eq.{token}", headers=sb_headers())
            raise HTTPException(410, "Share link has expired")
        return share

# ── /doc ───────────────────────────────────────────────────
@app.post("/doc/question")
async def save_doc_question(req: DocQuestion, request: Request):
    check_rate(request.client.host)
    if not SUPABASE_URL or not SUPABASE_KEY:
        raise HTTPException(500, "DB not configured")
    async with httpx.AsyncClient(timeout=10) as c:
        r = await c.post(f"{SUPABASE_URL}/rest/v1/doc_questions",
                         headers={**sb_headers(), "Prefer": "return=representation"},
                         json={"user_id": req.user_id, "doc_name": req.doc_name,
                               "question": req.question, "answer": req.answer,
                               "created_at": datetime.utcnow().isoformat()})
        if r.status_code not in (200, 201):
            raise HTTPException(500, "Failed to save question")
    return {"ok": True}

@app.get("/doc/questions")
async def get_doc_questions(user_id: str, request: Request):
    check_rate(request.client.host)
    if not SUPABASE_URL or not SUPABASE_KEY:
        raise HTTPException(500, "DB not configured")
    async with httpx.AsyncClient(timeout=10) as c:
        r = await c.get(
            f"{SUPABASE_URL}/rest/v1/doc_questions?user_id=eq.{user_id}&order=created_at.desc&limit=100",
            headers=sb_headers())
        return r.json()

@app.delete("/doc/questions")
async def delete_doc_questions(user_id: str, doc_name: str, request: Request):
    check_rate(request.client.host)
    if not SUPABASE_URL or not SUPABASE_KEY:
        raise HTTPException(500, "DB not configured")
    async with httpx.AsyncClient(timeout=10) as c:
        await c.delete(
            f"{SUPABASE_URL}/rest/v1/doc_questions?user_id=eq.{user_id}&doc_name=eq.{doc_name}",
            headers=sb_headers())
    return {"ok": True}
