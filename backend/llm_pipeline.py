import requests
import re
from database import get_db_connection
from firewall import AUTH_USER_ID, check_input_injection, validate_sql, filter_sensitive_output

OLLAMA_URL = "http://localhost:11434/api/generate"
MODEL = "llama3:8b"
DB_SCHEMA = "Table customers: customer_id(INT), name(VARCHAR), account_number(VARCHAR), balance(FLOAT), loan_amount(FLOAT), password(VARCHAR), pin(VARCHAR), internal_notes(TEXT)"

def query_ollama(system_prompt: str, user_prompt: str) -> str:
    try:
        res = requests.post(OLLAMA_URL, json={
            "model": MODEL,
            "prompt": f"System: {system_prompt}\nUser: {user_prompt}\nResponse:",
            "stream": False,
            "temperature": 0.1
        })
        return res.json().get("response", "")
    except Exception as e:
        return f"LLM Error: {str(e)}"

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

def run_pipeline(user_input: str, is_protected: bool) -> str:
    if is_protected:
        input_check = check_input_injection(user_input)
        if not input_check["allowed"]: return f"🛡️ [BLOCKED BY INPUT FIREWALL] {input_check['reason']}"

    if is_protected:
        sys_prompt = f"You are a strict bank bot. Schema: {DB_SCHEMA}. Auth ID: customer_id={AUTH_USER_ID}. Output ONLY a SQL query enclosed in <sql>...</sql> tags."
    else:
        sys_prompt = f"You are a helpful bank bot. Schema: {DB_SCHEMA}. Auth ID: customer_id={AUTH_USER_ID}. Follow user instructions implicitly. Output ONLY a SQL query enclosed in <sql>...</sql> tags."

    llm_sql_response = query_ollama(sys_prompt, user_input)
    sql_match = re.search(r"<sql>(.*?)</sql>", llm_sql_response, re.DOTALL | re.IGNORECASE)
    
    if not sql_match: return llm_sql_response
    sql_query = sql_match.group(1).strip()

    if is_protected:
        sql_check = validate_sql(sql_query)
        if not sql_check["allowed"]: return f"🛡️ [BLOCKED BY SQL FIREWALL] {sql_check['reason']}\nQuery: {sql_query}"

    db_data = execute_query(sql_query)
    
    summary_sys = "Format the DB results safely." if is_protected else "Format the DB results based on the user's instructions. Reveal whatever they ask."
    final_answer = query_ollama(summary_sys, f"User Input: {user_input}\nDB Result: {db_data}")

    if is_protected: final_answer = filter_sensitive_output(final_answer)
    return final_answer