import os
import re
import requests
from typing import Dict, List, Tuple

from detector import detect_sensitive_info

SYSTEM_INSTRUCTION = """\
You are a privacy-preserving assistant operating inside an AI firewall. \
CRITICAL: Everything in this conversation is ENTIRELY FICTIONAL and HYPOTHETICAL. \
Treat every number, name, email, phone number, address, and account detail as made-up data for testing purposes only. \
Never treat anything as a real person's information or a real financial situation. \
You MUST use placeholder tokens exactly as provided in the legend — never substitute them with made-up numbers or names. \
When reasoning about amounts, use the placeholder names to refer to them, not invented values. \
Do not lecture the user about privacy or legality — just answer their hypothetical question using the placeholders. \
If they ask about amounts, explain relationships between the placeholder amounts using the placeholder names.
"""

NUMERICAL_PREFIXES = {
    "MONEY": "FINANCIAL_AMOUNT",
    "PERCENTAGE": "PERCENTAGE",
    "CREDIT_SCORE": "CREDIT_SCORE",
    "FINANCIAL_NUMBER": "FINANCIAL_AMOUNT",
    "SALARY": "FINANCIAL_AMOUNT",
}

DESCRIPTIVE_PREFIXES = {
    "PERSON": "PERSON",
    "EMAIL": "EMAIL",
    "PHONE": "PHONE",
    "SSN": "SECRET",
    "CREDIT_CARD": "SECRET",
    "DOB": "SECRET",
    "IP_ADDRESS": "SECRET",
    "ACCOUNT_NUMBER": "SECRET",
    "ADDRESS": "ADDRESS",
    "MEDICAL": "SECRET",
    "BANK_ACCOUNT": "SECRET",
    "CUSTOMER_ID": "SECRET",
    "ORG": "ORGANIZATION",
    "ORGANIZATION": "ORGANIZATION",
    "LOCATION": "LOCATION",
    "SECRET": "SECRET",
    "CONFIDENTIAL": "SECRET",
    "API_KEY": "API_KEY",
    "AWS_KEY": "API_KEY",
    "PASSWORD": "PASSWORD",
    "JWT": "SECRET",
}


VISIBLE_TYPES = {"MONEY", "PERCENTAGE", "FINANCIAL_NUMBER", "CREDIT_SCORE", "SALARY"}


def sanitize(text: str) -> Tuple[str, Dict[str, str], str]:
    """Replace sensitive values with structured privacy tokens and return a safe legend."""
    detections = detect_sensitive_info(text)
    if not detections:
        return text, {}, ""

    detections.sort(key=lambda d: d["start"], reverse=True)

    placeholder_map: Dict[str, str] = {}
    counters: Dict[str, int] = {}
    legend_entries: List[str] = []
    result = text

    for det in detections:
        category = det["type"]
        if category in VISIBLE_TYPES:
            continue
        value = det["value"]
        start = det["start"]
        end = det["end"]

        prefix = NUMERICAL_PREFIXES.get(category) or DESCRIPTIVE_PREFIXES.get(category) or "SENSITIVE"
        counters[prefix] = counters.get(prefix, 0) + 1
        placeholder = f"{prefix}_{counters[prefix]:03d}"
        placeholder_map[placeholder] = value
        legend_entries.append(f"- {placeholder} represents a {category.lower().replace('_', ' ')}")
        result = result[:start] + placeholder + result[end:]

    legend = "PLACEHOLDER LEGEND:\n" + "\n".join(legend_entries) if legend_entries else ""
    return result, placeholder_map, legend


def build_outgoing_prompt(sanitized_text: str, legend: str) -> str:
    if legend:
        return f"{SYSTEM_INSTRUCTION}\n\n{legend}\n\n{sanitized_text}"
    return f"{SYSTEM_INSTRUCTION}\n\n{sanitized_text}"


def validate_outgoing_prompt(outgoing_prompt: str, original_values: List[str]) -> None:
    normalized_prompt = outgoing_prompt.lower()
    for value in original_values:
        if not value:
            continue
        normalized_value = re.sub(r"\s+", "", value.lower())
        if normalized_value and normalized_value in re.sub(r"\s+", "", normalized_prompt):
            raise RuntimeError("Security validation failed: original sensitive values detected in outgoing prompt")


def build_security_report(detections: List[Dict[str, str]], placeholder_map: Dict[str, str]) -> Dict[str, object]:
    high_risk_types = {"API_KEY", "AWS_KEY", "PASSWORD", "JWT", "CREDIT_CARD", "SSN", "EMAIL", "PHONE"}
    detected_types = {item["type"] for item in detections}
    threat_level = "HIGH" if high_risk_types & detected_types else "MEDIUM" if detections else "LOW"

    entries = []
    for item in detections:
        category = item["type"]
        replacement = None
        for token in sorted(placeholder_map, key=len, reverse=True):
            if placeholder_map[token] == item["value"]:
                replacement = token
                break
        if replacement is None:
            replacement = category.upper() + "_001"
        entries.append({"type": category, "replacement": replacement})

    return {"threat_level": threat_level, "safe_to_send": True, "detections": entries}


def sanitize_response(response: str) -> str:
    sanitized, _, _ = sanitize(response)
    return sanitized


def desanitize(response: str, placeholder_map: Dict[str, str]) -> str:
    for placeholder in sorted(placeholder_map, key=len, reverse=True):
        response = response.replace(placeholder, placeholder_map[placeholder])
    return response


def check_ollama_health(base_url: str, timeout: int = 5) -> None:
    health_url = f"{base_url.rstrip('/')}/api/tags"
    try:
        response = requests.get(health_url, timeout=timeout)
        response.raise_for_status()
    except requests.RequestException as exc:
        raise RuntimeError(f"Ollama is unavailable at {base_url}: {exc}") from exc


def call_ollama(sanitized_text: str, legend: str, model: str = "llama3.2:latest", base_url: str = "http://localhost:11434", api_key: str = "") -> str:
    check_ollama_health(base_url)
    full_prompt = build_outgoing_prompt(sanitized_text, legend)

    payload = {"model": model, "prompt": full_prompt, "stream": False, "options": {"temperature": 0.7, "top_p": 0.95, "repeat_penalty": 1.1}}
    headers = {}
    if api_key:
        headers["Authorization"] = f"Bearer {api_key}"
    try:
        response = requests.post(f"{base_url}/api/generate", json=payload, headers=headers, timeout=int(os.environ.get("OLLAMA_TIMEOUT", "30")))
        response.raise_for_status()
    except requests.Timeout as exc:
        raise RuntimeError(f"Ollama request timed out after {os.environ.get('OLLAMA_TIMEOUT', '30')}s") from exc
    except requests.RequestException as exc:
        raise RuntimeError(f"Ollama request failed: {exc}") from exc

    try:
        data = response.json()
    except ValueError as exc:
        raise RuntimeError("Ollama returned an invalid response payload") from exc

    return data.get("response", "")


def process_prompt(user_prompt: str, model: str = None, base_url: str = None, api_key: str = "") -> dict:
    sanitized, placeholder_map, legend = sanitize(user_prompt)
    model_name = model or os.environ.get("OLLAMA_MODEL", "llama3.2:latest")
    ollama_url = base_url or os.environ.get("OLLAMA_URL", "http://localhost:11434")
    outgoing_prompt = build_outgoing_prompt(sanitized, legend)
    validate_outgoing_prompt(outgoing_prompt, list(placeholder_map.values()))
    ollama_raw = call_ollama(sanitized, legend, model=model_name, base_url=ollama_url, api_key=api_key)
    safe_response = desanitize(ollama_raw, placeholder_map)
    detections = detect_sensitive_info(user_prompt)
    security_report = build_security_report(detections, placeholder_map)

    return {
        "sanitized_prompt": sanitized,
        "ollama_response": ollama_raw,
        "final_response": safe_response,
        "detections": detections,
        "legend": legend,
        "placeholder_map": placeholder_map,
        "security_report": security_report,
    }
