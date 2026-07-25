import re
from typing import Optional

from google import genai

from detector import detect_sensitive_info

SYSTEM_INSTRUCTION = """You are Aegis Shield, a privacy-safe AI assistant. Your job is to help users while protecting their sensitive personal data.

## How placeholders work

The user's message has been sanitized before reaching you. Sensitive data has been replaced with placeholder tokens:

- **placeholder_person_1** — a person's name
- **placeholder_org_1** — an organization/company name
- **placeholder_email_1** — an email address
- **placeholder_phone_1** — a phone number
- **placeholder_secret_1** — an API key, token, or password
- **placeholder_money_1[N]** — a monetary amount. The number in brackets [N] is the raw numeric value (no currency symbols, no commas). Use this value for calculations.

## Rules

1. **Do NOT modify, rephrase, or remove any placeholder token** unless it is a money placeholder and you are performing a calculation.
2. **For money calculations**: Use the numeric value in the brackets. When you produce a result, express it as a plain number — do NOT add currency symbols or commas. Example: if asked "what is the profit" and you see placeholder_money_1[5000000] and placeholder_money_2[3000000], respond with "2000000".
3. **Preserve all other placeholders exactly as-is** in your response.
4. **Be helpful**: Answer questions, provide analysis, and assist the user just like a normal assistant — you just can't see or reveal their real personal data.
5. If a user asks you to reveal what is behind a placeholder, politely decline and explain that the data is protected for their privacy."""


def _extract_numeric(value: str) -> Optional[float]:
    """Extract a numeric value from a money string like '$5,000,000' or '3 billion'."""
    cleaned = value.replace(",", "").strip()
    multipliers = {"thousand": 1_000, "k": 1_000, "million": 1_000_000, "m": 1_000_000,
                   "billion": 1_000_000_000, "bn": 1_000_000_000}
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


def sanitize(text: str) -> tuple:
    """Detect sensitive info and replace with descriptive placeholders.

    For MONEY detections, embeds the raw numeric value in brackets:
        placeholder_money_1[5000000]

    Returns (sanitized_text, placeholder_map) where placeholder_map
    maps each placeholder string back to its original formatted value.
    """
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
                placeholder = f"placeholder_{key}_{counters[key]}[{int(numeric)}]"
            else:
                placeholder = f"placeholder_{key}_{counters[key]}"
        else:
            placeholder = f"placeholder_{key}_{counters[key]}"

        placeholder_map[placeholder] = det["value"]
        result = result[: det["start"]] + placeholder + result[det["end"] :]

    return result, placeholder_map


def call_gemini(sanitized_text: str, api_key: str) -> str:
    """Send sanitized prompt to Gemini and return the raw response text."""
    client = genai.Client(api_key=api_key)
    response = client.models.generate_content(
        model="gemini-2.0-flash",
        contents=sanitized_text,
        config={"system_instruction": SYSTEM_INSTRUCTION},
    )
    return response.text


def desanitize(response: str, placeholder_map: dict) -> str:
    """Replace placeholders back with original values.

    Processes longest placeholder keys first to avoid partial-match
    collisions (e.g. placeholder_email_10 before placeholder_email_1).
    """
    for placeholder in sorted(placeholder_map, key=len, reverse=True):
        original = placeholder_map[placeholder]
        response = response.replace(placeholder, original)
    return response


def process_prompt(user_prompt: str, api_key: str) -> dict:
    """Full pipeline: detect -> sanitize -> gemini -> desanitize.

    Always calls Gemini regardless of whether detections were found.
    Returns a dict with sanitized_prompt, gemini_response, final_response,
    and detections.
    """
    detections = detect_sensitive_info(user_prompt)
    sanitized, placeholder_map = sanitize(user_prompt)
    gemini_raw = call_gemini(sanitized, api_key)
    final = desanitize(gemini_raw, placeholder_map)

    return {
        "sanitized_prompt": sanitized,
        "gemini_response": gemini_raw,
        "final_response": final,
        "detections": detections,
    }


if __name__ == "__main__":
    import json
    import os

    api_key = os.environ.get("GEMINI_API_KEY", "YOUR_API_KEY_HERE")

    sample = (
        "John Smith works at Acme Corp. Revenue was $5,000,000. "
        "Email john@gmail.com. API key: sk-1234567890abcdef. Phone: +1-555-123-4567"
    )

    print("=== Input ===")
    print(sample)
    print()

    result = process_prompt(sample, api_key)

    print("=== Sanitized (sent to Gemini) ===")
    print(result["sanitized_prompt"])
    print()
    print("=== Detections ===")
    print(json.dumps(result["detections"], indent=2))
    print()
    print("=== Gemini Raw Response ===")
    print(result["gemini_response"])
    print()
    print("=== Final Response (placeholders restored) ===")
    print(result["final_response"])
