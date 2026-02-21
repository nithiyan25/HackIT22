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

import sqlglot
from sqlglot import exp

def validate_sql(sql_query: str) -> dict:
    try:
        # Parse the query into an AST
        parsed = sqlglot.parse_one(sql_query, read="mysql")
        
        # Check if it's a SELECT statement
        if not isinstance(parsed, exp.Select):
            return {"allowed": False, "reason": "Only SELECT statements are allowed."}

        # Find all requested columns (projections)
        for proj in parsed.find_all(exp.Column):
            col_name = proj.name.upper()
            if col_name in ["PASSWORD", "PIN", "INTERNAL_NOTES"]:
                return {"allowed": False, "reason": f"Access to restricted column '{col_name}' is denied."}
            if isinstance(proj.parent, exp.Star):
                return {"allowed": False, "reason": "SELECT * queries are strictly prohibited."}
        
        # Check for WHERE clause
        where_clause = parsed.args.get("where")
        if not where_clause:
            return {"allowed": False, "reason": "Unbounded queries are prohibited. A WHERE clause is required."}

        # Check that the WHERE clause restricts to AUTH_USER_ID
        is_auth_restricted = False
        for eq in where_clause.find_all(exp.EQ):
            if isinstance(eq.left, exp.Column) and eq.left.name.upper() == "CUSTOMER_ID":
                if isinstance(eq.right, exp.Literal) and eq.right.this == str(AUTH_USER_ID):
                    is_auth_restricted = True
                    break
        
        if not is_auth_restricted:
            return {"allowed": False, "reason": "Unauthorized access. You can only query your own customer_id."}

        return {"allowed": True}

    except sqlglot.errors.ParseError as e:
        return {"allowed": False, "reason": f"Invalid SQL syntax: {str(e)}"}

def filter_sensitive_output(response: str) -> str:
    response = re.sub(r'(?i)password[\s:=]+[^\s]+', 'password: [REDACTED]', response)
    response = re.sub(r'(?i)pin[\s:=]+\d+', 'pin: [REDACTED]', response)
    response = re.sub(r'(?i)internal_notes[\s:=]+.*', 'internal_notes: [REDACTED]', response)
    return response