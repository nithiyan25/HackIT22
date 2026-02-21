"""
Session-based Metrics Tracker
Accumulates stats across all requests and calculates 
accuracy, detection rate, and confidence dynamically.
"""

import threading

_lock = threading.Lock()

# Session-wide accumulators
_stats = {
    # Attack & Defense tab (protected pipeline)
    "protected": {
        "total_requests": 0,
        "blocked_requests": 0,
        "passed_requests": 0,
        "blocked_by_regex": 0,
        "blocked_by_ml": 0,
        "blocked_by_sql_firewall": 0,
        "blocked_by_output_analyzer": 0,
        "ml_scores": [],          # all ML confidence scores
        "avg_response_time_ms": 0,
        "total_time_ms": 0,
    },
    # Attack & Defense tab (vulnerable pipeline)
    "vulnerable": {
        "total_requests": 0,
        "poison_injections_succeeded": 0,
        "avg_response_time_ms": 0,
        "total_time_ms": 0,
    },
    # Poison Defense Lab tab
    "layer6": {
        "total_analyzed": 0,
        "flagged_poisoned": 0,
        "flagged_clean": 0,
        "ml_scores": [],
        "entropy_scores": [],
        "avg_response_time_ms": 0,
        "total_time_ms": 0,
    }
}


def record_protected(time_ms: float, blocked_at: str = None, blocked_by: str = None, ml_confidence: float = None):
    """Record a protected pipeline request."""
    with _lock:
        s = _stats["protected"]
        s["total_requests"] += 1
        s["total_time_ms"] += time_ms
        s["avg_response_time_ms"] = round(s["total_time_ms"] / s["total_requests"], 1)

        if ml_confidence is not None:
            s["ml_scores"].append(ml_confidence)

        if blocked_at:
            s["blocked_requests"] += 1
            if blocked_by == "regex":
                s["blocked_by_regex"] += 1
            elif blocked_by == "ml_model":
                s["blocked_by_ml"] += 1
            elif "SQL" in (blocked_at or ""):
                s["blocked_by_sql_firewall"] += 1
            elif "Layer 4" in (blocked_at or ""):
                s["blocked_by_output_analyzer"] += 1
        else:
            s["passed_requests"] += 1


def record_vulnerable(time_ms: float, poison_succeeded: bool = False):
    """Record a vulnerable pipeline request."""
    with _lock:
        s = _stats["vulnerable"]
        s["total_requests"] += 1
        s["total_time_ms"] += time_ms
        s["avg_response_time_ms"] = round(s["total_time_ms"] / s["total_requests"], 1)
        if poison_succeeded:
            s["poison_injections_succeeded"] += 1


def record_layer6(time_ms: float, is_poisoned: bool, ml_score: float = None, entropy: float = None):
    """Record a Layer 6 analysis."""
    with _lock:
        s = _stats["layer6"]
        s["total_analyzed"] += 1
        s["total_time_ms"] += time_ms
        s["avg_response_time_ms"] = round(s["total_time_ms"] / s["total_analyzed"], 1)

        if is_poisoned:
            s["flagged_poisoned"] += 1
        else:
            s["flagged_clean"] += 1

        if ml_score is not None:
            s["ml_scores"].append(ml_score)
        if entropy is not None:
            s["entropy_scores"].append(entropy)


def get_session_metrics() -> dict:
    """Calculate and return all dynamic session metrics."""
    with _lock:
        p = _stats["protected"]
        v = _stats["vulnerable"]
        l6 = _stats["layer6"]

        # Protected pipeline accuracy
        prot_detection_rate = round((p["blocked_requests"] / p["total_requests"] * 100), 1) if p["total_requests"] > 0 else 0
        prot_pass_rate = round((p["passed_requests"] / p["total_requests"] * 100), 1) if p["total_requests"] > 0 else 0
        prot_avg_ml = round(sum(p["ml_scores"]) / len(p["ml_scores"]) * 100, 1) if p["ml_scores"] else 0

        # Vulnerable pipeline
        vuln_poison_rate = round((v["poison_injections_succeeded"] / v["total_requests"] * 100), 1) if v["total_requests"] > 0 else 0

        # Layer 6
        l6_detection_rate = round((l6["flagged_poisoned"] / l6["total_analyzed"] * 100), 1) if l6["total_analyzed"] > 0 else 0
        l6_clean_rate = round((l6["flagged_clean"] / l6["total_analyzed"] * 100), 1) if l6["total_analyzed"] > 0 else 0
        l6_avg_ml = round(sum(l6["ml_scores"]) / len(l6["ml_scores"]) * 100, 1) if l6["ml_scores"] else 0
        l6_avg_entropy = round(sum(l6["entropy_scores"]) / len(l6["entropy_scores"]), 3) if l6["entropy_scores"] else 0

        return {
            "protected": {
                "total_requests": p["total_requests"],
                "detection_rate": prot_detection_rate,
                "pass_rate": prot_pass_rate,
                "blocked_by_regex": p["blocked_by_regex"],
                "blocked_by_ml": p["blocked_by_ml"],
                "blocked_by_sql": p["blocked_by_sql_firewall"],
                "blocked_by_output": p["blocked_by_output_analyzer"],
                "avg_ml_confidence": prot_avg_ml,
                "avg_response_time_ms": p["avg_response_time_ms"],
            },
            "vulnerable": {
                "total_requests": v["total_requests"],
                "poison_success_rate": vuln_poison_rate,
                "avg_response_time_ms": v["avg_response_time_ms"],
            },
            "layer6": {
                "total_analyzed": l6["total_analyzed"],
                "detection_rate": l6_detection_rate,
                "clean_rate": l6_clean_rate,
                "avg_ml_confidence": l6_avg_ml,
                "avg_entropy": l6_avg_entropy,
                "avg_response_time_ms": l6["avg_response_time_ms"],
            }
        }


def reset_stats():
    """Reset all session stats."""
    with _lock:
        for key in _stats:
            for k, v in _stats[key].items():
                if isinstance(v, list):
                    _stats[key][k] = []
                elif isinstance(v, (int, float)):
                    _stats[key][k] = 0
