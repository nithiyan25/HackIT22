from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from llm_pipeline import run_pipeline
from database import setup_database

app = FastAPI(title="LLM Security System")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

class ChatRequest(BaseModel):
    message: str

@app.post("/chat-vulnerable")
async def chat_vulnerable(req: ChatRequest):
    return {"response": run_pipeline(req.message, is_protected=False)}

@app.post("/chat-protected")
async def chat_protected(req: ChatRequest):
    return {"response": run_pipeline(req.message, is_protected=True)}

if __name__ == "__main__":
    import uvicorn
    setup_database() # Auto-creates DB & Tables on startup
    uvicorn.run(app, host="0.0.0.0", port=8000)