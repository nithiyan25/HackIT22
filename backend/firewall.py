import re
import logging

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

AUTH_USER_ID = 1  # Simulated authenticated user (Alice)

# ---------------------------------------------------------------------------
# Layer 1 — Input Firewall
# ---------------------------------------------------------------------------

FORBIDDEN_PATTERNS = [
    r"ignore\s+(previous|instructions|above|context)",
    r"forget\s+(previous|instructions|above|context|the)",
    r"\badmin\b",
    r"bypass",
    r"show\s+all",
    r"display\s+all",
    r"list\s+all",
    r"all\s+(customers?|users?|records?|data|accounts?|passwords?)",
    r"every\s+(customer|user|record|account)",
    r"debug\s+mode",
    r"act\s+as",
    r"system\s+prompt",
    r"internal\s+auditor",
    r"override",
    r"pretend",
    r"you\s+are\s+now",
    r"new\s+instructions?",
    r"disregard",
    r"reveal\s+(all|every|password|pin|credential)",
    r"dump\s+(the|all|database|table|data)?",
    r"(all|every|each)\s+.*(password|pin|credential|secret)",
    r"(password|pin|credential)s?\s+(for|of)\s+(all|every|each)",
    r"show\s+me\s+(bob|carol|david|eve|frank|grace|henry|isabel|admin)",
    r"(bob|carol|david|eve|frank|grace|henry|isabel|admin).*(password|pin|balance|details|account|notes)",
    r"information_schema",
    r"--",
    r"/\*",
]

def check_input_injection(user_input: str) -> dict:
    lowered = user_input.lower()
    for pattern in FORBIDDEN_PATTERNS:
        if re.search(pattern, lowered):
            logging.warning(f"INPUT FIREWALL: Pattern '{pattern}' matched on: {user_input!r}")
            return {
                "allowed": False,
                "reason": f"Security violation: Prohibited phrase detected — request blocked."
            }
    return {"allowed": True}


# ---------------------------------------------------------------------------
# Layer 2 — SQL Firewall
# ---------------------------------------------------------------------------

import sqlglot
from sqlglot import exp

RESTRICTED_COLUMNS = {"PASSWORD", "PIN", "INTERNAL_NOTES"}

def validate_sql(sql_query: str) -> dict:
    try:
        parsed = sqlglot.parse_one(sql_query, read="mysql")

        # Only SELECT is allowed
        if not isinstance(parsed, exp.Select):
            return {"allowed": False, "reason": "Only SELECT statements are allowed."}

        # Block SELECT *
        for star in parsed.find_all(exp.Star):
            return {"allowed": False, "reason": "SELECT * queries are strictly prohibited."}

        # Block restricted columns
        for col in parsed.find_all(exp.Column):
            if col.name.upper() in RESTRICTED_COLUMNS:
                return {"allowed": False, "reason": f"Access to restricted column '{col.name.upper()}' is denied."}

        # Require a WHERE clause
        where_clause = parsed.args.get("where")
        if not where_clause:
            return {"allowed": False, "reason": "Unbounded queries are prohibited. A WHERE clause is required."}

        # WHERE must scope to the authenticated user
        is_auth_restricted = False
        for eq in where_clause.find_all(exp.EQ):
            left, right = eq.left, eq.right
            if isinstance(left, exp.Column) and left.name.upper() == "CUSTOMER_ID":
                if isinstance(right, exp.Literal) and right.this == str(AUTH_USER_ID):
                    is_auth_restricted = True
                    break

        if not is_auth_restricted:
            return {"allowed": False, "reason": "Unauthorized access. You can only query your own account."}

        return {"allowed": True}

    except sqlglot.errors.ParseError as e:
        return {"allowed": False, "reason": f"Invalid SQL syntax: {str(e)}"}


# ---------------------------------------------------------------------------
# Layer 3 — Output Filter
# ---------------------------------------------------------------------------

# Covers both raw dict format ('password': 'val') and formatted (Password: val)
SENSITIVE_PATTERNS = [
    (r"(?i)['\"]?password['\"]?\s*[:=]+\s*['\"]?[^\s,'\"\}]+['\"]?", "Password: [REDACTED]"),
    (r"(?i)['\"]?pin['\"]?\s*[:=]+\s*['\"]?\d+['\"]?",               "PIN: [REDACTED]"),
    (r"(?i)['\"]?internal_notes['\"]?\s*[:=]+\s*['\"]?[^,\}\n]+",    "Internal Notes: [REDACTED]"),
]

def filter_sensitive_output(response: str) -> str:
    for pattern, replacement in SENSITIVE_PATTERNS:
        response = re.sub(pattern, replacement, response)
    return response