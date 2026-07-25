import re
import json
import urllib.request
import urllib.error
from typing import Optional

from detector import detect_sensitive_info

OLLAMA_URL = "http://localhost:11434/api/chat"
MODEL = "llama3.2"

SYSTEM_INSTRUCTION = """You are Aegis Shield, a privacy-safe AI assistant. Your job is to help users while protecting their sensitive personal data.

## How placeholders work

The user's message has been sanitized before reaching you. Sensitive data has been replaced with placeholder tokens:

- **placeholder_person_1** -- a person's name
- **placeholder_org_1** -- an organization/company name
- **placeholder_email_1** -- an email address
- **placeholder_phone_1** -- a phone number
- **placeholder_secret_1** -- an API key, token, or password
- **placeholder_money_1[N]** -- a monetary amount. The number in brackets [N] is the raw numeric value (no currency symbols, no commas). Use this value for calculations.

## Rules

1. Do NOT modify, rephrase, or remove any placeholder token unless it is a money placeholder and you are performing a calculation.
2. For money calculations: Use the numeric value in the brackets. When you produce a result, express it as a plain number -- do NOT add currency symbols or commas. Example: if asked "what is the profit" and you see placeholder_money_1[5000000] and placeholder_money_2[3000000], respond with "2000000".
3. Preserve all other placeholders exactly as-is in your response.
4. Be helpful: Answer questions, provide analysis, and assist the user just like a normal assistant -- you just can't see or reveal their real personal data.
5. If a user asks you to reveal what is behind a placeholder, politely decline and explain that the data is protected for their privacy."""


def _extract_numeric(value):
    cleaned = value.replace(",", "").strip()
    multipliers = {"thousand": 1000, "k": 1000, "million": 1000000, "m": 1000000,
                   "billion": 1000000000, "bn": 1000000000}
    for word, mult in multipliers.items():
        if word in cleaned.lower():
            num_str = re.sub(r"[^\d.]", "", cleaned.lower().split(word)[0])
            if num_str:
                return float(num_str) * mult
            return float(mult)
    num_str = re.sub(r"[^\d.]", "", cleaned)
    if num_str:
        return float(num_str)
    return None


def sanitize(text):
    detections = detect_sensitive_info(text)
    if not detections:
        return text, {}

    result = text
    placeholder_map = {}
    counters = {}

    for det in reversed(detections):
        det_type = det["type"]
        key = det_type.lower()
        counters[key] = counters.get(key, 0) + 1

        if det_type == "MONEY":
            numeric = _extract_numeric(det["value"])
            if numeric is not None:
                placeholder = "placeholder_{}_{}[{}]".format(key, counters[key], int(numeric))
            else:
                placeholder = "placeholder_{}_{}".format(key, counters[key])
        else:
            placeholder = "placeholder_{}_{}".format(key, counters[key])

        placeholder_map[placeholder] = det["value"]
        result = result[: det["start"]] + placeholder + result[det["end"]:]

    return result, placeholder_map


def call_llm(sanitized_text):
    """Send sanitized prompt to Ollama and return the raw response text."""
    payload = json.dumps({
        "model": MODEL,
        "messages": [
            {"role": "system", "content": SYSTEM_INSTRUCTION},
            {"role": "user", "content": sanitized_text},
        ],
        "stream": False,
    }).encode("utf-8")

    req = urllib.request.Request(
        OLLAMA_URL,
        data=payload,
        headers={"Content-Type": "application/json"},
        method="POST",
    )

    try:
        with urllib.request.urlopen(req, timeout=120) as resp:
            data = json.loads(resp.read().decode("utf-8"))
            return data["message"]["content"]
    except urllib.error.URLError as e:
        raise RuntimeError("Ollama is not running. Start the Ollama app and try again.") from e
    except Exception as e:
        raise RuntimeError("LLM error: {}".format(e)) from e


def desanitize(response, placeholder_map):
    """Replace placeholders back with original values."""
    for placeholder in sorted(placeholder_map, key=len, reverse=True):
        original = placeholder_map[placeholder]
        response = response.replace(placeholder, original)
    return response


def process_prompt(user_prompt):
    """Full pipeline: detect -> sanitize -> LLM -> desanitize."""
    detections = detect_sensitive_info(user_prompt)
    sanitized, placeholder_map = sanitize(user_prompt)
    llm_raw = call_llm(sanitized)
    final = desanitize(llm_raw, placeholder_map)

    return {
        "sanitized_prompt": sanitized,
        "llm_response": llm_raw,
        "final_response": final,
        "detections": detections,
    }


if __name__ == "__main__":
    sample = (
        "John Smith works at Acme Corp. Revenue was $5,000,000. "
        "Email john@gmail.com. API key: sk-1234567890abcdef. Phone: +1-555-123-4567"
    )

    print("=== Input ===")
    print(sample)
    print()

    result = process_prompt(sample)

    print("=== Sanitized (sent to LLM) ===")
    print(result["sanitized_prompt"])
    print()
    print("=== Detections ===")
    print(json.dumps(result["detections"], indent=2))
    print()
    print("=== LLM Raw Response ===")
    print(result["llm_response"])
    print()
    print("=== Final Response (placeholders restored) ===")
    print(result["final_response"])
