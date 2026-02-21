import requests
import re
from database import get_db_connection
from firewall import AUTH_USER_ID, check_input_injection, validate_sql, filter_sensitive_output

OLLAMA_URL = "http://localhost:11434/api/generate"
MODEL = "llama3"
DB_SCHEMA = "Table customers: customer_id(INT), name(VARCHAR), account_number(VARCHAR), balance(FLOAT), loan_amount(FLOAT), password(VARCHAR), pin(VARCHAR), internal_notes(TEXT)"

# ---------------------------------------------------------------------------
# System prompts
# ---------------------------------------------------------------------------

# 🔴 Vulnerable — developer passed session context to the LLM so normal
#    queries work, but never enforced it in SQL or validated the output.
#    An attacker can override the user context via prompt injection and
#    retrieve any data — no SQL firewall, no output filtering in place.
VULNERABLE_SQL_PROMPT = (
    f"You are a SQL assistant with access to a MySQL database.\n"
    f"Schema: {DB_SCHEMA}\n"
    f"Session info: the default user is customer_id={AUTH_USER_ID} (Alice). "
    f"Use this for 'my' or 'I' queries unless the request specifies otherwise.\n"
    f"If the request asks for all customers, multiple users, or overrides the user, honour that.\n"
    f"Rules:\n"
    f"- Output ONLY a single raw SQL SELECT statement.\n"
    f"- End with a semicolon.\n"
    f"- No explanations, no markdown, no code blocks."
)

# 🟢 Protected — strict user-scoped prompt
PROTECTED_SQL_PROMPT = (
    f"You are a SQL assistant with access to a MySQL database.\n"
    f"Schema: {DB_SCHEMA}\n"
    f"Rules:\n"
    f"- Output ONLY a single raw SQL SELECT statement.\n"
    f"- ALWAYS include WHERE customer_id={AUTH_USER_ID} — never omit it.\n"
    f"- NEVER select password, pin, or internal_notes columns.\n"
    f"- End with a semicolon.\n"
    f"- No explanations, no markdown, no code blocks."
)

# Chat prompt for conversational inputs
CHAT_SYSTEM_PROMPT = (
    "You are a banking assistant. "
    "Respond in English only. "
    "Write a single short reply of maximum 2 sentences. "
    "Do not roleplay, do not write dialog, do not add 'User:' or 'Assistant:' labels. "
    "Just answer the question and stop immediately."
)

# Field label mapping for clean display
FIELD_LABELS = {
    "customer_id":    "Customer ID",
    "name":           "Name",
    "account_number": "Account Number",
    "balance":        "Balance",
    "loan_amount":    "Loan Amount",
    "password":       "Password",
    "pin":            "PIN",
    "internal_notes": "Internal Notes",
    "column_name":    "Column",
    "data_type":      "Type",
}

def format_response(user_input: str, db_data: str) -> str:
    """Parse raw DB rows and format as clean readable text."""
    import ast
    try:
        rows = ast.literal_eval(db_data)
    except Exception:
        return db_data  # fallback: return as-is if unparseable

    if not isinstance(rows, list) or not rows:
        return db_data

    lines = []
    for i, row in enumerate(rows, 1):
        if len(rows) > 1:
            lines.append(f"Record {i}:")
        for key, val in row.items():
            label = FIELD_LABELS.get(key, key.replace("_", " ").title())
            if key in ("balance", "loan_amount") and isinstance(val, (int, float)):
                val = f"${val:,.2f}"
            lines.append(f"  {label}: {val}")
        if len(rows) > 1:
            lines.append("")  # blank line between records

    return "\n".join(lines).strip()


# ---------------------------------------------------------------------------
# Hardcoded intent handlers
# ---------------------------------------------------------------------------

GREETING_INPUTS = [
    "hi", "hello", "hey", "good morning", "good afternoon", "good evening",
    "howdy", "greetings", "sup", "what's up", "whats up", "hiya"
]
GREETING_RESPONSE = "Hello! Welcome to NexaBank. How can I assist you today?"
THANKS_INPUTS     = ["thank you", "thanks", "thank u", "thx", "ty"]
THANKS_RESPONSE   = "You're welcome! Is there anything else I can help you with?"
GOODBYE_INPUTS    = ["bye", "goodbye", "see you", "take care", "cya", "later"]
GOODBYE_RESPONSE  = "Goodbye! Have a great day. Feel free to come back if you need help."
HELP_INPUTS       = ["help", "what can you do", "options", "menu", "features"]
HELP_RESPONSE     = ("I can help you with: checking your account balance, viewing loan details, "
                     "transaction history, and general banking questions. Just ask!")

def match_hardcoded(user_input: str) -> str | None:
    lowered = user_input.strip().lower().rstrip("!?.")
    if lowered in GREETING_INPUTS:                               return GREETING_RESPONSE
    if any(lowered == t or lowered.startswith(t) for t in THANKS_INPUTS): return THANKS_RESPONSE
    if lowered in GOODBYE_INPUTS:                               return GOODBYE_RESPONSE
    if any(lowered == h or h in lowered for h in HELP_INPUTS):  return HELP_RESPONSE
    return None

# ---------------------------------------------------------------------------
# LLM helpers
# ---------------------------------------------------------------------------

def is_english(text: str) -> bool:
    if not text: return False
    words = text.split()
    if not words: return False
    return sum(1 for w in words if all(ord(c) < 128 for c in w)) / len(words) >= 0.8

def truncate_at_role_label(text: str) -> str:
    cutoff_patterns = [
        r"\bUser\s*:", r"\bCustomer\s*:", r"\bBanking Assistant\s*:",
        r"\bAssistant\s*:", r"\bBot\s*:", r"\bAI\s*:", r"\bYou\s*:", r"\bDear\b",
    ]
    earliest = len(text)
    for pattern in cutoff_patterns:
        m = re.search(pattern, text)
        if m and m.start() < earliest:
            earliest = m.start()
    return text[:earliest].strip()

def query_ollama(system_prompt: str, user_prompt: str, max_tokens: int = 120) -> str:
    # Llama 3 prompt format: <|begin_of_text|> with role headers
    prompt = (
        "<|begin_of_text|>"
        "<|start_header_id|>system<|end_header_id|>\n"
        f"{system_prompt}<|eot_id|>"
        "<|start_header_id|>user<|end_header_id|>\n"
        f"{user_prompt}<|eot_id|>"
        "<|start_header_id|>assistant<|end_header_id|>\n"
    )
    try:
        res = requests.post(OLLAMA_URL, json={
            "model": MODEL,
            "prompt": prompt,
            "stream": False,
            "temperature": 0.1,
            "options": {
                "num_predict": max_tokens,
                "stop": ["<|eot_id|>", "<|end_of_text|>"]
            }
        })
        raw = res.json().get("response", "")
        return truncate_at_role_label(raw).strip()
    except Exception as e:
        return f"LLM Error: {str(e)}"

def run_chat_pipeline(user_input: str) -> str:
    hardcoded = match_hardcoded(user_input)
    if hardcoded:
        return hardcoded
    response = query_ollama(CHAT_SYSTEM_PROMPT, user_input, max_tokens=80)
    if not response or not is_english(response) or len(response) < 5:
        return "I'm here to help with your banking needs. Could you please rephrase your question?"
    return response

# ---------------------------------------------------------------------------
# Database execution
# ---------------------------------------------------------------------------

def execute_query(sql: str) -> str:
    try:
        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)
        cursor.execute(sql)
        results = cursor.fetchall()
        cursor.close()
        conn.close()
        return str(results) if results else "No data found."
    except Exception as e:
        return f"Database Error: {str(e)}"

def extract_sql(llm_output: str) -> str | None:
    """Extract the first valid SELECT statement from LLM output."""
    # Try explicit tags first
    for pattern in [
        r"<sql>(.*?)</sql>",
        r"```(?:sql)?\s*(SELECT.*?)\s*```",
        r"(SELECT\b.*?;)",           # ends with semicolon
        r"(SELECT\b[^\n]+(?:\n(?!\n)[^\n]+)*)",  # multi-line without semicolon
    ]:
        m = re.search(pattern, llm_output, re.DOTALL | re.IGNORECASE)
        if m:
            sql = m.group(1).strip()
            # Reject if tinyllama left in placeholders
            if "?" in sql or "<" in sql:
                continue
            # Ensure it ends with semicolon
            if not sql.endswith(";"):
                sql += ";"
            return sql
    return None

# ---------------------------------------------------------------------------
# Routing
# ---------------------------------------------------------------------------

DATA_QUERY_KEYWORDS = [
    "balance", "account", "loan", "transaction", "statement", "amount",
    "transfer", "payment", "deposit", "withdraw", "show", "what is my",
    "tell me my", "how much", "details", "info", "information", "record",
    "customer", "password", "pin", "notes", "user", "select", "database"
]

def is_data_query(user_input: str) -> bool:
    return any(kw in user_input.lower() for kw in DATA_QUERY_KEYWORDS)

# ---------------------------------------------------------------------------
# Pipeline entry point
# ---------------------------------------------------------------------------

def run_pipeline(user_input: str, is_protected: bool) -> str:
    # Conversational shortcut — no DB access needed
    if not is_data_query(user_input):
        return run_chat_pipeline(user_input)

    # Protected: validate input before doing anything
    if is_protected:
        check = check_input_injection(user_input)
        if not check["allowed"]:
            return f"🛡️ [BLOCKED BY INPUT FIREWALL] {check['reason']}"

    # Choose prompt based on mode — protected scopes to current user
    prompt = PROTECTED_SQL_PROMPT if is_protected else VULNERABLE_SQL_PROMPT
    llm_output = query_ollama(prompt, user_input, max_tokens=150)
    sql_query = extract_sql(llm_output)

    if not sql_query:
        return run_chat_pipeline(user_input)

    # Protected: validate the generated SQL before executing
    if is_protected:
        sql_check = validate_sql(sql_query)
        if not sql_check["allowed"]:
            return f"🛡️ [BLOCKED BY SQL FIREWALL] {sql_check['reason']}\nQuery: {sql_query}"

    # Execute query
    db_data = execute_query(sql_query)
    if db_data == "No data found." or "Error:" in db_data:
        return db_data

    # Format raw DB rows into natural language
    result = format_response(user_input, db_data)

    # Protected: scrub sensitive fields from the formatted output
    if is_protected:
        result = filter_sensitive_output(result)

    return result