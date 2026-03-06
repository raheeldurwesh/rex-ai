import os
import random
import json
import re
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

            # Extract result blocks
            blocks = re.findall(r'<div class="result__body">(.*?)</div>\s*</div>', html, re.DOTALL)
            for block in blocks[:6]:
                # Extract URL
                url_match = re.search(r'href="(https?://[^"&]+)"', block)
                # Extract title
                title_match = re.search(r'<a[^>]+class="result__a"[^>]*>([^<]+)</a>', block)
                # Extract snippet
                snippet_match = re.search(r'<a[^>]+class="result__snippet"[^>]*>([^<]+)</a>', block)
                if not snippet_match:
                    snippet_match = re.search(r'class="result__snippet"[^>]*>(.*?)</a>', block, re.DOTALL)

                if url_match and title_match:
                    snippet = snippet_match.group(1).strip() if snippet_match else ""
                    snippet = re.sub(r'<[^>]+>', '', snippet)
                    results.append({
                        "title": title_match.group(1).strip(),
                        "url": url_match.group(1),
                        "snippet": snippet[:250]
                    })

            if not results:
                # Fallback: simpler extraction
                urls = re.findall(r'uddg=(https?[^&"]+)', html)
                titles = re.findall(r'class="result__a"[^>]*>([^<]+)<', html)
                snippets = re.findall(r'class="result__snippet"[^>]*>([^<]+)<', html)
                for i in range(min(5, len(urls), len(titles))):
                    import urllib.parse
                    results.append({
                        "title": titles[i].strip(),
                        "url": urllib.parse.unquote(urls[i]),
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