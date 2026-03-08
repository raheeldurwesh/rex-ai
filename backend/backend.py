from fastapi import FastAPI, Request, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from groq import Groq
from fastapi.responses import StreamingResponse
import json, os, httpx, re, hashlib, hmac, time
from collections import defaultdict

app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

GROQ_KEYS = [
    os.getenv("GROQ_API_KEY"),
    os.getenv("GROQ_API_KEY_1"),
    os.getenv("GROQ_API_KEY_2"),
    os.getenv("GROQ_API_KEY_3"),
]
GROQ_KEYS = [k for k in GROQ_KEYS if k]

FALLBACK_MODELS = [
    "llama-3.3-70b-versatile",
    "llama-3.1-8b-instant",
    "meta-llama/llama-4-scout-17b-16e-instruct",
    "openai/gpt-oss-120b",
    "moonshotai/kimi-k2-instruct-0905",
]

# ── Rate limiting ──────────────────────────────────────────
RATE_LIMIT = defaultdict(list)  # ip -> [timestamps]
MAX_REQUESTS = 30   # per window
WINDOW_SEC   = 60   # 1 minute

def check_rate(ip: str):
    now = time.time()
    RATE_LIMIT[ip] = [t for t in RATE_LIMIT[ip] if now - t < WINDOW_SEC]
    if len(RATE_LIMIT[ip]) >= MAX_REQUESTS:
        raise HTTPException(status_code=429, detail="Too many requests. Please slow down.")
    RATE_LIMIT[ip].append(now)

# ── Secret pepper for password hashing ────────────────────
PEPPER = os.getenv("HASH_PEPPER", "rex-ai-secret-pepper-2024")

def hash_password(password: str) -> str:
    """Secure password hashing using PBKDF2 with pepper"""
    peppered = (password + PEPPER).encode()
    return hashlib.pbkdf2_hmac('sha256', peppered, b'rex-ai-salt', 200000).hex()

def verify_password(password: str, stored_hash: str) -> bool:
    """Verify password against stored hash - also supports old SHA-256 hashes"""
    # Try new PBKDF2 hash first
    new_hash = hash_password(password)
    if hmac.compare_digest(new_hash, stored_hash):
        return True
    # Fallback: check old client-side SHA-256 hash (migration)
    old_hash = hashlib.sha256(password.encode()).hexdigest()
    return hmac.compare_digest(old_hash, stored_hash)

# ── Models ─────────────────────────────────────────────────
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

# ── Endpoints ──────────────────────────────────────────────
@app.get("/ping")
async def ping():
    return {"status": "ok"}

@app.post("/hash")
async def hash_pwd(req: HashRequest, request: Request):
    ip = request.client.host
    check_rate(ip)
    if not req.password or len(req.password) < 1:
        raise HTTPException(status_code=400, detail="Password required")
    if len(req.password) > 128:
        raise HTTPException(status_code=400, detail="Password too long")
    return {"hash": hash_password(req.password)}

@app.post("/verify")
async def verify_pwd(req: VerifyRequest, request: Request):
    ip = request.client.host
    check_rate(ip)
    if not req.password or not req.hash:
        raise HTTPException(status_code=400, detail="Password and hash required")
    return {"valid": verify_password(req.password, req.hash)}

@app.post("/chat")
async def chat(req: ChatRequest, request: Request):
    ip = request.client.host
    check_rate(ip)
    # Validate input
    if not req.messages:
        raise HTTPException(status_code=400, detail="No messages provided")
    if len(req.messages) > 100:
        raise HTTPException(status_code=400, detail="Too many messages")
    for m in req.messages:
        if len(m.content) > 32000:
            raise HTTPException(status_code=400, detail="Message too long")

    models = [req.model] if req.model not in FALLBACK_MODELS else FALLBACK_MODELS
    if req.model not in models:
        models = [req.model] + FALLBACK_MODELS

    def generate():
        for key in GROQ_KEYS:
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
                    err = str(e)
                    if "rate_limit" in err or "429" in err or "model" in err.lower():
                        continue
                    continue
        yield f"data: {json.dumps({'text': 'All models are busy. Please try again.'})}\n\n"
        yield "data: [DONE]\n\n"

    return StreamingResponse(generate(), media_type="text/event-stream")


@app.get("/search")
async def search(q: str, request: Request):
    ip = request.client.host
    check_rate(ip)
    if not q or len(q) > 500:
        raise HTTPException(status_code=400, detail="Invalid query")
    try:
        results = []
        headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"}
        async with httpx.AsyncClient(timeout=8, follow_redirects=True) as client:
            resp = await client.get("https://html.duckduckgo.com/html/", params={"q": q}, headers=headers)
            html = resp.text
            result_blocks = re.findall(
                r'class="result__a"[^>]*href="([^"]+)"[^>]*>(.*?)</a>.*?class="result__snippet"[^>]*>(.*?)</span>',
                html, re.DOTALL
            )
            for url, title, snippet in result_blocks[:5]:
                title = re.sub(r'<[^>]+>', '', title).strip()
                snippet = re.sub(r'<[^>]+>', '', snippet).strip()
                for ent, ch in [('&amp;','&'),('&lt;','<'),('&gt;','>'),('&#x27;',"'"),('&quot;','"')]:
                    title = title.replace(ent, ch)
                    snippet = snippet.replace(ent, ch)
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
