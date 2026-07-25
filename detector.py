import json
import re
import sys
from typing import Any, Dict, List, Optional

try:
    import spacy
except ImportError:  # pragma: no cover
    spacy = None


EMAIL_RE = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")

MONEY_RE = re.compile(
    r"""
    (?:
        \$\s?\d{1,3}(?:,\d{3})*(?:\.\d+)? |
        \$?\d+(?:,\d{3})*(?:\.\d+)?(?:\s*(?:million|billion|thousand|m|bn|k))?
    )
    """,
    re.IGNORECASE | re.VERBOSE,
)

SECRET_RE = re.compile(
    r"""
    (?:
        (?:api[_-]?key|access[_-]?token|client[_-]?secret|secret[_-]?key|token|password|auth[_-]?token)
        \s*[:=]\s*([A-Za-z0-9_\-]{6,})
        |
        \b(?:sk-[A-Za-z0-9]{16,}|ghp_[A-Za-z0-9]{16,}|AIza[0-9A-Za-z\-_]{35}|xox[baprs]-[A-Za-z0-9-]{10,})\b
    )
    """,
    re.IGNORECASE | re.VERBOSE,
)

PHONE_RE = re.compile(
    r"(?<![A-Za-z0-9-])(?:\+?\d{1,3}[-.\s]?)?(?:\(?\d{2,4}\)?[-.\s]?){1,2}\d{3,4}(?![A-Za-z0-9])"
)


def _load_nlp() -> Optional[Any]:
    if spacy is None:
        return None

    try:
        return spacy.load("en_core_web_sm")
    except OSError:
        try:
            return spacy.load("en_core_web_md")
        except OSError:
            try:
                return spacy.load("en_core_web_lg")
            except OSError:
                return None


NLP = _load_nlp()


def _add_result(results: List[Dict[str, Any]], entity_type: str, value: str, start: int, end: int) -> None:
    results.append(
        {
            "type": entity_type,
            "value": value,
            "start": start,
            "end": end,
        }
    )


def _detect_with_spacy(text: str, results: List[Dict[str, Any]]) -> None:
    if NLP is None:
        return

    doc = NLP(text)
    for ent in doc.ents:
        if ent.label_ in {"PERSON", "ORG", "ORGANIZATION"}:
            raw_value = ent.text.strip()
            if ent.label_ in {"ORG", "ORGANIZATION"}:
                cleaned_value = re.sub(r"\s+(?:Revenue|revenue|Email|email|API|Phone|phone).*$", "", raw_value)
                cleaned_value = re.sub(r"[\.,;:]+.*$", "", cleaned_value).strip()
                if not cleaned_value or cleaned_value.isupper() and len(cleaned_value) <= 3:
                    continue
                raw_value = cleaned_value

            _add_result(results, ent.label_ if ent.label_ != "ORGANIZATION" else "ORG", raw_value, ent.start_char, ent.end_char)


def _detect_emails(text: str, results: List[Dict[str, Any]]) -> None:
    for match in EMAIL_RE.finditer(text):
        _add_result(results, "EMAIL", match.group(0), match.start(), match.end())


def _detect_money(text: str, results: List[Dict[str, Any]]) -> None:
    for match in MONEY_RE.finditer(text):
        candidate = match.group(0).strip()
        if candidate.startswith("$") or any(token in candidate.lower() for token in ["million", "billion", "thousand", "m", "bn", "k"]):
            _add_result(results, "MONEY", candidate, match.start(), match.end())


def _detect_secrets(text: str, results: List[Dict[str, Any]]) -> None:
    for match in SECRET_RE.finditer(text):
        value = match.group(0).strip()
        _add_result(results, "SECRET", value, match.start(), match.end())


def _detect_phones(text: str, results: List[Dict[str, Any]]) -> None:
    for match in PHONE_RE.finditer(text):
        value = match.group(0).strip()
        _add_result(results, "PHONE", value, match.start(), match.end())


def detect_sensitive_info(text: str) -> List[Dict[str, Any]]:
    """Return structured sensitive-entity detections for the provided text."""
    if not text:
        return []

    results: List[Dict[str, Any]] = []
    _detect_with_spacy(text, results)
    _detect_emails(text, results)
    _detect_money(text, results)
    _detect_secrets(text, results)
    _detect_phones(text, results)

    results.sort(key=lambda item: (item["start"], item["end"], item["type"]))
    return results


if __name__ == "__main__":
    sample_text = (
        "John Williams works. Revenue was $5,000,000. "
        "Email john@gmail.com. API key: sk-1234567890abcdef. Phone: +1-555-123-4567"
    )

    if len(sys.argv) > 1:
        text = " ".join(sys.argv[1:])
    else:
        text = sample_text

    findings = detect_sensitive_info(text)

    print("===== ORIGINAL INPUT =====")
    print(text)

    print("\n===== DETECTED INFORMATION =====")
    print(json.dumps(findings, indent=2))
