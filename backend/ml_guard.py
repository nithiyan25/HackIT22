"""
ML-based Prompt Injection Detector
Uses arkaean/promptguard-distilbert — a fine-tuned DistilBERT model
that classifies prompts as Benign (0) or Malicious (1).

The model is loaded LAZILY on first classify_prompt() call to avoid
blocking server startup. After first load, it's cached in memory.
"""

import logging

MODEL_NAME = "arkaean/promptguard-distilbert"

# Lazy-loaded globals
_tokenizer = None
_model = None
_model_loaded = None  # None = not yet attempted, True/False = result


def _load_model():
    """Load the model on first use (lazy initialization)."""
    global _tokenizer, _model, _model_loaded

    if _model_loaded is not None:
        return  # Already attempted

    logging.info(f"🔄 Loading PromptGuard model: {MODEL_NAME} ...")
    try:
        import torch
        from transformers import AutoTokenizer, AutoModelForSequenceClassification

        _tokenizer = AutoTokenizer.from_pretrained(MODEL_NAME)
        _model = AutoModelForSequenceClassification.from_pretrained(MODEL_NAME)
        _model.eval()
        _model_loaded = True
        logging.info("✅ PromptGuard model loaded successfully.")
    except Exception as e:
        logging.error(f"❌ Failed to load PromptGuard model: {e}")
        _model_loaded = False


def classify_prompt(text: str) -> dict:
    """
    Classify a user prompt as benign or malicious using the ML model.

    Returns:
        {
            "is_malicious": bool,
            "confidence": float,  # 0.0 to 1.0
            "label": str          # "BENIGN" or "MALICIOUS"
        }
    """
    _load_model()

    if not _model_loaded:
        logging.warning("⚠️ PromptGuard model not loaded — skipping ML check.")
        return {"is_malicious": False, "confidence": 0.0, "label": "SKIPPED"}

    try:
        import torch

        inputs = _tokenizer(text, return_tensors="pt", truncation=True, padding=True, max_length=512)

        with torch.no_grad():
            outputs = _model(**inputs)

        probs = torch.softmax(outputs.logits, dim=-1)
        prediction = torch.argmax(probs).item()
        confidence = probs[0][prediction].item()

        label = "MALICIOUS" if prediction == 1 else "BENIGN"

        if prediction == 1:
            logging.warning(
                f"🤖 ML GUARD: Prompt classified as MALICIOUS "
                f"(confidence: {confidence:.2%}): {text[:80]!r}..."
            )

        return {
            "is_malicious": prediction == 1,
            "confidence": confidence,
            "label": label
        }

    except Exception as e:
        logging.error(f"❌ ML Guard inference error: {e}")
        return {"is_malicious": False, "confidence": 0.0, "label": "ERROR"}
