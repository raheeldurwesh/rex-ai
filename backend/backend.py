import os
import random
import json
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
        async with httpx.AsyncClient() as client:
            r = await client.get(
                "https://api.duckduckgo.com/",
                params={
                    "q": q,
                    "format": "json",
                    "no_html": "1",
                    "skip_disambig": "1",
                    "no_redirect": "1"
                },
                headers={"User-Agent": "RexAI/1.0"},
                timeout=8
            )
            data = r.json()
            results = []

            # Abstract (main answer)
            if data.get("AbstractText"):
                results.append({
                    "title": data.get("Heading", "Summary"),
                    "url": data.get("AbstractURL", "https://duckduckgo.com/?q=" + q),
                    "snippet": data["AbstractText"][:300]
                })

            # Related topics
            for topic in data.get("RelatedTopics", [])[:5]:
                if isinstance(topic, dict) and topic.get("Text"):
                    results.append({
                        "title": topic.get("Text", "")[:60],
                        "url": topic.get("FirstURL", "https://duckduckgo.com/?q=" + q),
                        "snippet": topic.get("Text", "")[:200]
                    })

            # If no results, do HTML scrape fallback via DuckDuckGo lite
            if not results:
                r2 = await client.get(
                    "https://lite.duckduckgo.com/lite/",
                    params={"q": q},
                    headers={"User-Agent": "Mozilla/5.0"},
                    timeout=8
                )
                import re
                links = re.findall(r'<a[^>]+href="(https?://[^"]+)"[^>]*>([^<]+)</a>', r2.text)
                snippets = re.findall(r'<td[^>]*class="result-snippet"[^>]*>([^<]+)</td>', r2.text)
                for i, (url, title) in enumerate(links[:5]):
                    if 'duckduckgo' not in url:
                        results.append({
                            "title": title.strip(),
                            "url": url,
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