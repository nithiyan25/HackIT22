from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from llm_pipeline import run_pipeline, run_chat_pipeline, run_poison_test_pipeline
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
    customer_id: int

class LoginRequest(BaseModel):
    account_number: str

@app.post("/login")
async def login(req: LoginRequest):
    """
    Developer mode login: accepts only an account number and 
    returns the associated customer_id and name.
    """
    from database import get_db_connection
    try:
        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)
        cursor.execute("SELECT customer_id, name FROM customers WHERE account_number = %s", (req.account_number,))
        user = cursor.fetchone()
        cursor.close()
        conn.close()
        
        if user:
            return {"success": True, "user": user}
        return {"success": False, "error": "Account not found"}
    except Exception as e:
        return {"success": False, "error": str(e)}

@app.post("/chat-normal")
async def chat_normal(req: ChatRequest):
    """
    Normal LLM chat — conversational banking assistant.
    No SQL generation, no database access, no firewall protection.
    Demonstrates raw LLM behavior (vulnerable to prompt injection).
    """
    return {"response": run_chat_pipeline(req.message)}

@app.post("/chat-vulnerable")
async def chat_vulnerable(req: ChatRequest):
    return run_pipeline(req.message, req.customer_id, is_protected=False)

@app.post("/chat-protected")
async def chat_protected(req: ChatRequest):
    return run_pipeline(req.message, req.customer_id, is_protected=True)

@app.post("/chat-poison-test")
async def chat_poison_test(req: ChatRequest):
    """Poison Defense Lab — runs ONLY Layer 6 (Perplexity + Anomaly) on DB data."""
    return run_poison_test_pipeline(req.message, req.customer_id)

class TextRequest(BaseModel):
    text: str

@app.post("/analyze-text")
async def analyze_text(req: TextRequest):
    """
    General-purpose Layer 6 text analysis.
    Accepts ANY raw text and runs perplexity + anomaly detection.
    Not tied to database or banking — works for all test cases.
    """
    from firewall import analyze_text_layer6
    return analyze_text_layer6(req.text)

@app.post("/analyze-chunks")
async def analyze_chunks(req: TextRequest):
    """
    Layer 7 Chunk Analyzer.
    Splits bulk text into chunks, runs Layer 5 + Layer 6 + Semantic analysis
    on each chunk, and separates clean from malicious content.
    """
    from firewall import analyze_chunks_layer7
    return analyze_chunks_layer7(req.text)

if __name__ == "__main__":
    import uvicorn
    setup_database() # Auto-creates DB & Tables on startup
    uvicorn.run(app, host="0.0.0.0", port=8000)