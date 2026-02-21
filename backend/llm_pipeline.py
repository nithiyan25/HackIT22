import requests
import re
from database import get_db_connection
from firewall import AUTH_USER_ID, check_input_injection, validate_sql, filter_sensitive_output

OLLAMA_URL = "http://localhost:11434/api/generate"
MODEL = "tinyllama"
DB_SCHEMA = "Table customers: customer_id(INT), name(VARCHAR), account_number(VARCHAR), balance(FLOAT), loan_amount(FLOAT), password(VARCHAR), pin(VARCHAR), internal_notes(TEXT)"

CHAT_SYSTEM_PROMPT = (
    "You are a banking assistant. "
    "Respond in English only. "
    "Write a single short reply of maximum 2 sentences. "
    "Do not roleplay, do not write dialog, do not add 'User:' or 'Assistant:' labels. "
    "Just answer the question and stop immediately."
)

# ---------------------------------------------------------------------------
# Hardcoded intent handlers (TinyLlama is too small for open-ended chat)
# ---------------------------------------------------------------------------

GREETING_INPUTS = [
    "hi", "hello", "hey", "good morning", "good afternoon", "good evening",
    "howdy", "greetings", "sup", "what's up", "whats up", "hiya"
]
GREETING_RESPONSE  = "Hello! Welcome to NexaBank. How can I assist you today?"
THANKS_INPUTS      = ["thank you", "thanks", "thank u", "thx", "ty"]
THANKS_RESPONSE    = "You're welcome! Is there anything else I can help you with?"
GOODBYE_INPUTS     = ["bye", "goodbye", "see you", "take care", "cya", "later"]
GOODBYE_RESPONSE   = "Goodbye! Have a great day. Feel free to come back if you need help."
HELP_INPUTS        = ["help", "what can you do", "what can you help", "options", "menu", "features"]
HELP_RESPONSE      = ("I can help you with: checking your account balance, viewing loan details, "
                      "transaction history, and general banking questions. Just ask!")

def match_hardcoded(user_input: str) -> str | None:
    lowered = user_input.strip().lower().rstrip("!?.")
    if lowered in GREETING_INPUTS:                              return GREETING_RESPONSE
    if any(lowered == t or lowered.startswith(t) for t in THANKS_INPUTS): return THANKS_RESPONSE
    if lowered in GOODBYE_INPUTS:                              return GOODBYE_RESPONSE
    if any(lowered == h or h in lowered for h in HELP_INPUTS): return HELP_RESPONSE
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

def query_ollama(system_prompt: str, user_prompt: str, max_tokens: int = 80) -> str:
    try:
        res = requests.post(OLLAMA_URL, json={
            "model": MODEL,
            "prompt": f"[INST] <<SYS>>{system_prompt}<</SYS>> {user_prompt} [/INST]",
            "stream": False,
            "temperature": 0.1,
            "options": {
                "num_predict": max_tokens,
                "stop": ["User:", "Customer:", "Banking Assistant:", "Assistant:", "Dear"]
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

# ---------------------------------------------------------------------------
# Attack detection for vulnerable pipeline
# ---------------------------------------------------------------------------

# Keywords that indicate the user is trying a prompt injection / data exfiltration attack
ATTACK_KEYWORDS = [
    "ignore", "forget", "override", "your instructions", "system prompt",
    "unrestricted", "reveal", "show all", "all customers", "all records",
    "customer_id =", "customer_id=", "passwords", "internal notes",
    "select *", "drop table", "union select", "where 1=1",
    "act as", "you are now", "new instruction", "disable"
]

def detect_attack(user_input: str) -> bool:
    lowered = user_input.lower()
    return any(kw in lowered for kw in ATTACK_KEYWORDS)

def build_vulnerable_sql(user_input: str) -> str:
    """
    Simulates a naive system that blindly constructs SQL from user input.
    This is intentionally vulnerable — it trusts the user input directly.
    Attack payloads manipulate customer_id or request restricted columns.
    """
    lowered = user_input.lower()

    # Data exfiltration: user references another customer_id
    cid_match = re.search(r"customer_id\s*[=:]\s*(\d+)", lowered)
    if cid_match:
        target_id = cid_match.group(1)
        # Naively trusts the requested customer_id — no auth check
        return f"SELECT customer_id, name, account_number, balance, loan_amount, password, pin, internal_notes FROM customers WHERE customer_id = {target_id};"

    # Prompt injection asking for all records / passwords / internal notes
    if any(kw in lowered for kw in ["all customers", "all records", "show all", "every customer"]):
        # Naively drops the WHERE clause entirely
        return "SELECT customer_id, name, account_number, balance, loan_amount, password, pin, internal_notes FROM customers;"

    if any(kw in lowered for kw in ["password", "passwords", "pin", "internal notes", "internal_notes"]):
        # Naively includes restricted columns
        return f"SELECT customer_id, name, account_number, balance, loan_amount, password, pin, internal_notes FROM customers WHERE customer_id = {AUTH_USER_ID};"

    # Default: normal query for logged-in user
    return f"SELECT customer_id, name, account_number, balance, loan_amount FROM customers WHERE customer_id = {AUTH_USER_ID};"

# ---------------------------------------------------------------------------
# Routing keywords
# ---------------------------------------------------------------------------

DATA_QUERY_KEYWORDS = [
    "balance", "account", "loan", "transaction", "statement", "amount",
    "transfer", "payment", "deposit", "withdraw", "show", "what is my",
    "tell me my", "how much", "details", "info", "information", "record"
]

def is_data_query(user_input: str) -> bool:
    lowered = user_input.lower()
    return any(keyword in lowered for keyword in DATA_QUERY_KEYWORDS)

# ---------------------------------------------------------------------------
# Main pipelines
# ---------------------------------------------------------------------------

def run_pipeline(user_input: str, is_protected: bool) -> str:

    # ── PROTECTED pipeline ──────────────────────────────────────────────────
    if is_protected:
        input_check = check_input_injection(user_input)
        if not input_check["allowed"]:
            return f"🛡️ [BLOCKED BY INPUT FIREWALL] {input_check['reason']}"

        if not is_data_query(user_input):
            return run_chat_pipeline(user_input)

        sys_prompt = (f"Schema: {DB_SCHEMA}. Generate ONLY a valid SQL SELECT query "
                      f"WHERE customer_id={AUTH_USER_ID}. Do not write explanations. Just SQL.")
        llm_sql_response = query_ollama(sys_prompt, user_input, max_tokens=120)

        sql_match = re.search(r"<sql>(.*?)</sql>", llm_sql_response, re.DOTALL | re.IGNORECASE)
        if not sql_match:
            sql_match = re.search(r"```(?:sql)?\s*(SELECT.*?)\s*```", llm_sql_response, re.DOTALL | re.IGNORECASE)
        if not sql_match:
            sql_match = re.search(r"(SELECT.*?;)", llm_sql_response, re.DOTALL | re.IGNORECASE)

        if not sql_match:
            return f"Failed to generate SQL. LLM Output: {llm_sql_response}"
        sql_query = sql_match.group(1).strip()

        sql_check = validate_sql(sql_query)
        if not sql_check["allowed"]:
            return f"🛡️ [BLOCKED BY SQL FIREWALL] {sql_check['reason']}\nQuery: {sql_query}"

        db_data = execute_query(sql_query)
        final_answer = db_data if (db_data == "No data found." or "Error:" in db_data) else f"Here are the requested records: {db_data}"
        return filter_sensitive_output(final_answer)

    # ── VULNERABLE pipeline ─────────────────────────────────────────────────
    else:
        # Conversational input — use chat pipeline (no DB)
        if not is_data_query(user_input) and not detect_attack(user_input):
            return run_chat_pipeline(user_input)

        # Attack or data query — naively build and execute SQL without any validation
        sql_query = build_vulnerable_sql(user_input)
        db_data = execute_query(sql_query)

        if db_data == "No data found." or "Error:" in db_data:
            return db_data

        # ⚠️ No output filtering — exposes passwords, pins, internal_notes
        return f"⚠️ [VULNERABLE] Data leaked:\n{db_data}"