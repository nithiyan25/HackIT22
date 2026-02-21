import re
import logging

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

AUTH_USER_ID = 1  # Simulated authenticated user (Alice)

def check_input_injection(user_input: str) -> dict:
    forbidden_patterns = [
        r"ignore previous", r"admin", r"bypass", r"show all", 
        r"debug mode", r"act as", r"system prompt", r"internal auditor"
    ]
    user_input_lower = user_input.lower()
    for pattern in forbidden_patterns:
        if re.search(pattern, user_input_lower):
            logging.warning(f"🚨 INPUT FIREWALL: Attack pattern '{pattern}' detected")
            return {"allowed": False, "reason": f"Security violation: Prohibited phrase '{pattern}' detected."}
    return {"allowed": True}

def validate_sql(sql_query: str) -> dict:
    query = sql_query.upper().strip()
    if "SELECT *" in query:
        return {"allowed": False, "reason": "SELECT * queries are strictly prohibited."}
    if "WHERE" not in query:
        return {"allowed": False, "reason": "Unbounded queries are prohibited."}
    if not re.search(rf"CUSTOMER_ID\s*=\s*{AUTH_USER_ID}", query):
        return {"allowed": False, "reason": "Unauthorized access. You can only query your own customer_id."}
    
    restricted_columns = ["PASSWORD", "PIN", "INTERNAL_NOTES"]
    for col in restricted_columns:
        if col in query:
            return {"allowed": False, "reason": f"Access to restricted column '{col}' is denied."}
    return {"allowed": True}

def filter_sensitive_output(response: str) -> str:
    response = re.sub(r'(?i)password[\s:=]+[^\s]+', 'password: [REDACTED]', response)
    response = re.sub(r'(?i)pin[\s:=]+\d+', 'pin: [REDACTED]', response)
    response = re.sub(r'(?i)internal_notes[\s:=]+.*', 'internal_notes: [REDACTED]', response)
    return response