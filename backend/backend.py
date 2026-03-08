from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from groq import Groq
from fastapi.responses import StreamingResponse
import json, os, httpx, re

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
if not GROQ_KEYS:
    GROQ_KEYS = []  # Set GROQ_API_KEY in Render environment variables

FALLBACK_MODELS = [
    "llama-3.3-70b-versatile",
    "llama-3.1-8b-instant",
    "meta-llama/llama-4-scout-17b-16e-instruct",
    "openai/gpt-oss-120b",
    "moonshotai/kimi-k2-instruct-0905",
]

class Message(BaseModel):
    role: str
    content: str

class ChatRequest(BaseModel):
    messages: list[Message]
    model: str = "llama-3.3-70b-versatile"

@app.get("/ping")
async def ping():
    return {"status": "ok"}

@app.post("/chat")
async def chat(req: ChatRequest):
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
async def search(q: str):
    try:
        results = []
        headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
        }

        async with httpx.AsyncClient(timeout=8, follow_redirects=True) as client:
            # DuckDuckGo HTML search
            resp = await client.get(
                "https://html.duckduckgo.com/html/",
                params={"q": q},
                headers=headers
            )
            html = resp.text

            # Parse result titles, urls, snippets
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

            # Fallback to DDG instant answer API
            if not results:
                ia = await client.get(
                    "https://api.duckduckgo.com/",
                    params={"q": q, "format": "json", "no_redirect": "1", "no_html": "1"}
                )
                data = ia.json()
                if data.get("AbstractText"):
                    results.append({
                        "title": data.get("Heading", q),
                        "snippet": data["AbstractText"],
                        "url": data.get("AbstractURL", "")
                    })
                for rt in data.get("RelatedTopics", [])[:4]:
                    if isinstance(rt, dict) and rt.get("Text"):
                        results.append({
                            "title": rt.get("Text", "")[:60],
                            "snippet": rt.get("Text", ""),
                            "url": rt.get("FirstURL", "")
                        })

        return {"results": results[:5], "query": q}

    except Exception as e:
        return {"results": [], "query": q, "error": str(e)}
