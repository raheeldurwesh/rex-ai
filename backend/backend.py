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

            # Extract uddg= redirect URLs (these are the real URLs encoded)
            # DuckDuckGo wraps real URLs in uddg= parameter
            raw_urls = re.findall(r'uddg=(https?[^&">\s]+)', html)
            titles = re.findall(r'class="result__a"[^>]*>([^<]+)<', html)
            snippets = re.findall(r'class="result__snippet"[^>]*>([^<]+)<', html)

            for i in range(min(5, len(raw_urls), len(titles))):
                real_url = urllib.parse.unquote(raw_urls[i])
                # Skip duckduckgo internal links
                if 'duckduckgo.com' in real_url:
                    continue
                results.append({
                    "title": titles[i].strip(),
                    "url": real_url,
                    "snippet": snippets[i].strip() if i < len(snippets) else ""
                })

            return {"results": results[:5]}
    except Exception as e:
        return {"results": [], "error": str(e)}

@app.post("/chat")
async def chat(request: dict):
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