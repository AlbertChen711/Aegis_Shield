from google import genai

from detector import detect_sensitive_info

SYSTEM_INSTRUCTION = (
    "You are a helpful assistant. The following prompt may contain placeholder "
    "tokens such as placeholder_email_1, placeholder_person_1, placeholder_money_1, "
    "placeholder_phone_1, placeholder_secret_1, placeholder_org_1, etc. "
    "These represent sensitive personal data that must be kept private. "
    "Do NOT modify, rephrase, or remove any placeholder token. "
    "Treat them as literal text and preserve them exactly as-is in your response."
)


def sanitize(text: str) -> tuple:
    """Detect sensitive info and replace with descriptive placeholders.

    Returns (sanitized_text, placeholder_map) where placeholder_map
    maps each placeholder string back to its original value.
    """
    detections = detect_sensitive_info(text)
    if not detections:
        return text, {}

    result = text
    placeholder_map = {}
    counters = {}

    # Work back-to-front so replacements don't shift earlier indices
    for det in reversed(detections):
        det_type = det["type"]
        key = det_type.lower()
        counters[key] = counters.get(key, 0) + 1
        placeholder = f"placeholder_{key}_{counters[key]}"
        placeholder_map[placeholder] = det["value"]
        result = result[: det["start"]] + placeholder + result[det["end"] :]

    return result, placeholder_map


def call_gemini(sanitized_text: str, api_key: str) -> str:
    """Send sanitized prompt to Gemini and return the raw response text."""
    client = genai.Client(api_key=api_key)
    full_prompt = SYSTEM_INSTRUCTION + "\n\n" + sanitized_text
    response = client.models.generate_content(
        model="gemini-2.0-flash", contents=full_prompt
    )
    return response.text


def desanitize(response: str, placeholder_map: dict) -> str:
    """Replace placeholders back with original values.

    Processes longest placeholder keys first to avoid partial-match
    collisions (e.g. placeholder_email_10 before placeholder_email_1).
    """
    for placeholder in sorted(placeholder_map, key=len, reverse=True):
        response = response.replace(placeholder, placeholder_map[placeholder])
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
