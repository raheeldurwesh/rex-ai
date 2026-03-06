import os
import random
import json
import re
import urllib.parse
import httpx
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import StreamingResponse
from groq import Groq
from dotenv import load_dotenv

load_dotenv()

app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

API_KEYS = [
    os.getenv("GROQ_API_KEY"),
    os.getenv("GROQ_API_KEY_1"),
    os.getenv("GROQ_API_KEY_2"),
    os.getenv("GROQ_API_KEY_3"),
]
API_KEYS = [k for k in API_KEYS if k]

FALLBACK_MODELS = [
    "llama-3.3-70b-versatile",
    "llama-3.1-8b-instant",
    "meta-llama/llama-4-scout-17b-16e-instruct",
    "openai/gpt-oss-120b",
    "moonshotai/kimi-k2-instruct-0905",
]

def is_rate_limit(err):
    return '429' in str(err) or 'rate_limit' in str(err).lower() or 'rate limit' in str(err).lower()

def get_reset_time(err):
    match = re.search(r'try again in ([\dm\s\.]+s)', str(err), re.IGNORECASE)
    if match:
        return match.group(1).strip()
    return None

@app.get("/")
def root():
    return {"status": "Rex AI backend running ✅", "keys_loaded": len(API_KEYS)}

@app.get("/search")
async def search(q: str):
    try:
        async with httpx.AsyncClient(follow_redirects=True) as client:
            r = await client.get(
                "https://html.duckduckgo.com/html/",
                params={"q": q},
                headers={
                    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0.0.0 Safari/537.36",
                    "Accept": "text/html,application/xhtml+xml",
                    "Accept-Language": "en-US,en;q=0.9",
                },
                timeout=10
            )
            html = r.text
            results = []
            result_blocks = re.split(r'<div class="result ', html)
            for block in result_blocks[1:]:
                url_match = re.search(r'uddg=(https?[^&">\s]+)', block)
                title_match = re.search(r'class="result__a"[^>]*>([^<]+)<', block)
                snippet_match = re.search(r'class="result__snippet"[^>]*>([^<]+)<', block)
                if url_match and title_match:
                    real_url = urllib.parse.unquote(url_match.group(1))
                    if 'duckduckgo.com' in real_url:
                        continue
                    results.append({
                        "title": title_match.group(1).strip(),
                        "url": real_url,
                        "snippet": snippet_match.group(1).strip() if snippet_match else ""
                    })
                if len(results) >= 5:
                    break
            return {"results": results}
    except Exception as e:
        return {"results": [], "error": str(e)}

@app.post("/chat")
async def chat(request: dict):
    async def generate():
        if not API_KEYS:
            yield f"data: {json.dumps({'text': '⚠️ Service unavailable. Please try again later.'})}\n\n"
            yield "data: [DONE]\n\n"
            return

        requested_model = request.get("model", "llama-3.3-70b-versatile")
        messages = request.get("messages", [])
        models_to_try = [requested_model] + [m for m in FALLBACK_MODELS if m != requested_model]
        keys_to_try = API_KEYS.copy()
        random.shuffle(keys_to_try)
        last_reset_time = None

        for model in models_to_try:
            for key in keys_to_try:
                try:
                    client = Groq(api_key=key)
                    stream = client.chat.completions.create(
                        model=model,
                        messages=messages,
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
                    if is_rate_limit(e):
                        t = get_reset_time(e)
                        if t:
                            last_reset_time = t
                        continue
                    else:
                        continue

        # All exhausted - show clean message
        if last_reset_time:
            msg = f"⏳ I'm currently at capacity. Please try again in **{last_reset_time}**."
        else:
            msg = "⏳ I'm currently at capacity. Please try again in a few minutes."

        yield f"data: {json.dumps({'text': msg})}\n\n"
        yield "data: [DONE]\n\n"

    return StreamingResponse(generate(), media_type="text/event-stream")