import os
import random
import json
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

# Load all API keys
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