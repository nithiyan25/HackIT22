import re
import logging

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

AUTH_USER_ID = 1  # Simulated authenticated user (Alice)

# ---------------------------------------------------------------------------
# Layer 1 — Input Firewall (Regex + ML)
# Stage A: Fast regex pattern matching for known attack signatures
# Stage B: ML-based classification for novel/obfuscated attacks
# ---------------------------------------------------------------------------

from ml_guard import classify_prompt

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

ML_CONFIDENCE_THRESHOLD = 0.85  # Only block if ML model is ≥85% confident

BENIGN_BANKING_PATTERNS = [
    r"^(what is |show |give |tell |check |get ).*(balance|loan|account|statement|amount|details|info)",
    r"^(my |the )?(balance|loan|account|statement|details|info|information)",
    r"^how much .*(balance|loan|owe|have|left|remaining)",
    r"^(do i have|what do i owe|when is my)",
    r"^(transfer|deposit|withdraw|payment)\b",
    r"^(help|hello|hi|hey|thanks|bye|goodbye)\b",
]

def _is_benign_banking_query(text: str) -> bool:
    """Check if text matches a known benign banking query pattern."""
    lowered = text.strip().lower()
    return any(re.search(p, lowered) for p in BENIGN_BANKING_PATTERNS)

def check_input_injection(user_input: str) -> dict:
    lowered = user_input.lower()

    # ── Stage A: Regex pattern matching (fast, deterministic) ────────────
    for pattern in FORBIDDEN_PATTERNS:
        if re.search(pattern, lowered):
            logging.warning(f"INPUT FIREWALL [REGEX]: Pattern '{pattern}' matched on: {user_input!r}")
            return {
                "allowed": False,
                "reason": f"Security violation: Prohibited phrase detected — request blocked.",
                "blocked_by": "regex"
            }

    # ── Stage B: ML-based classification (catches novel attacks) ─────────
    # Skip ML check for clearly benign banking queries to avoid false positives
    if _is_benign_banking_query(user_input):
        return {"allowed": True}

    ml_result = classify_prompt(user_input)
    if ml_result["is_malicious"] and ml_result["confidence"] >= ML_CONFIDENCE_THRESHOLD:
        logging.warning(
            f"INPUT FIREWALL [ML]: Prompt classified as MALICIOUS "
            f"(confidence: {ml_result['confidence']:.2%}): {user_input!r}"
        )
        return {
            "allowed": False,
            "reason": (
                f"🤖 ML Guard detected a potential prompt injection attack "
                f"(confidence: {ml_result['confidence']:.1%})."
            ),
            "blocked_by": "ml_model",
            "ml_confidence": ml_result["confidence"]
        }

    return {"allowed": True}


# ---------------------------------------------------------------------------
# Layer 2 — SQL Firewall
# ---------------------------------------------------------------------------

import sqlglot
from sqlglot import exp

RESTRICTED_COLUMNS = {"PASSWORD", "PIN", "INTERNAL_NOTES"}

def validate_sql(sql_query: str, customer_id: int) -> dict:
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
                if isinstance(right, exp.Literal) and right.this == str(customer_id):
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
    redacted_fields = []
    for pattern, replacement in SENSITIVE_PATTERNS:
        new_response = re.sub(pattern, replacement, response)
        if new_response != response:
            field = replacement.split(":")[0].strip()
            redacted_fields.append(field)
            response = new_response
    if redacted_fields:
        logging.warning(f"🔒 LAYER 3 OUTPUT FILTER: Redacted fields — {redacted_fields}")
    return response


# ---------------------------------------------------------------------------
# Layer 4 — Output Re-Analyzer
# Semantically inspects the final response before it is shown to the user.
# Catches anything that slipped past Layers 1-3 — cross-user data, raw
# credentials, injected content, or suspicious multi-record dumps.
# ---------------------------------------------------------------------------

# Names of other customers — their data should never appear in a response
OTHER_CUSTOMER_NAMES = {
    "bob", "carol", "david", "eve", "frank", "grace", "henry", "isabel"
}

# Patterns that suggest raw credential values survived output filtering
CREDENTIAL_LEAK_PATTERNS = [
    r"(?i)password\s*:\s*(?!\[REDACTED\])\S+",   # Password: <anything except redacted>
    r"(?i)\bpin\s*:\s*(?!\[REDACTED\])\d+",       # PIN: <digits>
    r"(?i)internal\s+notes?\s*:\s*(?!\[REDACTED\])\S+",  # Internal Notes: <anything>
]

# Phrases that suggest the LLM was manipulated into responding as a different role
INJECTION_RESPONSE_PATTERNS = [
    r"(?i)as\s+(an?\s+)?(admin|administrator|system|root|auditor)",
    r"(?i)i\s+(am|will|can)\s+(now\s+)?(ignore|bypass|override|disregard)",
    r"(?i)new\s+(role|instructions?|persona|mode)",
    r"(?i)switching\s+to\s+(admin|debug|privileged)",
]

def analyze_output(response: str, user_input: str) -> dict:
    """
    Re-analyze the formatted response before returning it to the user.
    Returns {"safe": True} or {"safe": False, "reason": "..."}
    """
    lowered_response = response.lower()
    lowered_input    = user_input.lower()

    # ── Check 1: Cross-user data leak ────────────────────────────────────────
    # If the response mentions another customer's name and the input didn't
    # legitimately ask about them, it's a cross-user leak.
    for name in OTHER_CUSTOMER_NAMES:
        if name in lowered_response:
            # Allow only if the authenticated user happened to share a name
            # (not the case here — AUTH user is Alice)
            logging.warning(f"🚨 OUTPUT ANALYZER: Cross-user data detected — '{name}' in response")
            return {
                "safe": False,
                "reason": f"Response contained data belonging to another customer. Request blocked."
            }

    # ── Check 2: Multiple records in response ────────────────────────────────
    # A legitimate response for a single authenticated user should never
    # contain more than one Record block.
    record_count = len(re.findall(r"(?i)record\s+\d+", response))
    if record_count > 1:
        logging.warning(f"🚨 OUTPUT ANALYZER: Multi-record response detected ({record_count} records)")
        return {
            "safe": False,
            "reason": "Response contained multiple customer records. Request blocked."
        }

    # ── Check 3: Raw credential values survived output filtering ─────────────
    for pattern in CREDENTIAL_LEAK_PATTERNS:
        if re.search(pattern, response):
            logging.warning(f"🚨 OUTPUT ANALYZER: Credential leak detected — pattern: {pattern}")
            return {
                "safe": False,
                "reason": "Response contained sensitive credential data. Request blocked."
            }

    # ── Check 4: LLM injection response ──────────────────────────────────────
    # Detects if the LLM acknowledged a role-change or bypass instruction.
    for pattern in INJECTION_RESPONSE_PATTERNS:
        if re.search(pattern, response):
            logging.warning(f"🚨 OUTPUT ANALYZER: Injection response detected — pattern: {pattern}")
            return {
                "safe": False,
                "reason": "Response indicated a security policy violation. Request blocked."
            }

    # ── Check 5: Abnormally large response ───────────────────────────────────
    # A single-user query should never return a huge payload.
    if len(response) > 1500:
        logging.warning(f"🚨 OUTPUT ANALYZER: Oversized response ({len(response)} chars)")
        return {
            "safe": False,
            "reason": "Response was abnormally large — possible data dump detected. Request blocked."
        }

    return {"safe": True}


# ---------------------------------------------------------------------------
# Layer 5 — DB Content Sanitizer (Indirect Prompt Poisoning Defense)
# Scrubs injected LLM instructions from database field values before they
# are passed to the formatter. Prevents poisoned DB content from being
# executed as instructions by the language model.
# ---------------------------------------------------------------------------

# Patterns that look like embedded LLM instructions in DB fields
DB_POISON_PATTERNS = [
    r"\[SYSTEM\s*:.*?\]",                          # [SYSTEM: ...]
    r"\[INST\s*:.*?\]",                            # [INST: ...]
    r"\[ADMIN.*?:.*?\]",                           # [ADMIN OVERRIDE: ...]
    r"(?i)ignore\s+(previous|all|the)\s+instructions?.*",
    r"(?i)forget\s+(previous|all|the)\s+instructions?.*",
    r"(?i)you\s+are\s+now\s+(a\s+)?(admin|superuser|root|privileged).*",
    r"(?i)disregard\s+all\s+rules.*",
    r"(?i)execute\s*:\s*SELECT.*",
    r"(?i)return\s+all\s+rows.*",
    r"(?i)(SELECT|INSERT|UPDATE|DELETE|DROP)\s+\w+.*FROM.*",  # raw SQL in field
    r"(?i)override.*restriction.*",
    r"(?i)new\s+instructions?.*",
]

import ast

def sanitize_db_output(raw_db_str: str) -> tuple[str, list]:
    """
    Parse raw DB rows and strip any embedded instruction patterns from
    all string field values. Returns (sanitized_str, list_of_poisoned_fields).
    """
    poisoned_fields = []
    try:
        rows = ast.literal_eval(raw_db_str)
    except Exception:
        return raw_db_str, []

    if not isinstance(rows, list):
        return raw_db_str, []

    sanitized_rows = []
    for row in rows:
        clean_row = {}
        for key, val in row.items():
            if isinstance(val, str):
                original = val
                for pattern in DB_POISON_PATTERNS:
                    val = re.sub(pattern, "[SANITIZED]", val, flags=re.DOTALL)
                if val != original:
                    poisoned_fields.append(f"{key} (record {row.get('customer_id', '?')})")
                    logging.warning(
                        f"🧪 LAYER 5 DB SANITIZER: Poisoned content removed from "
                        f"field '{key}' in record {row.get('customer_id', '?')}"
                    )
            clean_row[key] = val
        sanitized_rows.append(clean_row)

    return str(sanitized_rows), poisoned_fields