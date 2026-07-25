import json
import math
import re
import sys
from typing import Any, Dict, List, Optional

try:
    import spacy
except ImportError:  # pragma: no cover
    spacy = None


# ---------------------------------------------------------------------------
# Regex patterns for sensitive data categories
# ---------------------------------------------------------------------------

EMAIL_RE = re.compile(r"\b[A-Za-z0-9._%+\u00C0-\u024F-]+@[A-Za-z0-9.\u00C0-\u024F-]+\.[A-Za-z]{2,}\b")

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
PERSON_RE = re.compile(r"\b(?:[A-Z][a-z]+(?:\s+[A-Z][a-z]+)+)\b")
ORG_RE = re.compile(
    r"\b(?:[A-Z][A-Za-z0-9&.-]+(?:\s+(?:Inc|LLC|Corp|Corporation|Ltd|Company|Group|University|Bank|Hospital|Institute|Systems|Labs|Technologies|Solutions|LLP|GmbH|Co\.))+)\b",
    re.IGNORECASE,
)
SSN_RE = re.compile(r"\b(?:\d{3}-\d{2}-\d{4}|\d{9})\b")
CREDIT_CARD_RE = re.compile(
    r"\b(?:4\d{3}[- ]?\d{4}[- ]?\d{4}[- ]?\d{4}|5\d{3}[- ]?\d{4}[- ]?\d{4}[- ]?\d{4}|3\d{3}[- ]?\d{6}[- ]?\d{5}|6\d{3}[- ]?\d{4}[- ]?\d{4}[- ]?\d{4})\b"
)
DOB_RE = re.compile(r"\b(?:\d{4}-\d{2}-\d{2}|\d{2}/\d{2}/\d{4}|\d{2}-\d{2}-\d{4})\b")
IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
ACCOUNT_RE = re.compile(
    r"\b(?:account(?:\s+number)?|acct(?:\s*#)?|routing\s+number)\s*[:#-]?\s*\d{3,}\b",
    re.IGNORECASE,
)

# --- New categories ---

ADDRESS_RE = re.compile(
    r"""
    \b\d{1,5}\s+(?:[A-Za-z0-9]+\s+){0,3}
    (?:Street|St|Avenue|Ave|Boulevard|Blvd|Drive|Dr|Court|Ct|Road|Rd|Lane|Ln|
       Way|Place|Pl|Circle|Cir|Trail|Trl|Parkway|Pkwy|Highway|Hwy|
       Apt|Apt\.|Unit|Suite|Ste\.|Ste|Floor|Fl)\b
    """,
    re.IGNORECASE | re.VERBOSE,
)

ADDRESS_NAME_RE = re.compile(
    r"\b\d{1,5}\s+(?:[A-Z][a-z]+(?:\s+[A-Z][a-z]+){0,3})\b"
)

MEDICAL_RE = re.compile(
    r"""
    (?:
        \b(?:MRN|Medical\s+Record\s+(?:Number|[#]))\s*[:#\[\]-]?\s*\d{6,12}\b |
        \b(?:ICD[- ]?(?:10|9))\s*[:#\[\]-]?\s*[A-Z]\d{2}(?:\.\d{1,2})?\b |
        \b(?:NPI)\s*[:#\[\]-]?\s*\d{10}\b |
        \b(?:Health\s+Insurance\s+(?:ID|Number|[#]))\s*[:#\[\]-]?\s*[A-Z0-9]{6,15}\b |
        \b(?:Policy\s+(?:Number|[#]))\s*[:#\[\]-]?\s*[A-Z0-9]{8,20}\b
    )
    """,
    re.IGNORECASE | re.VERBOSE,
)

BANK_ACCOUNT_RE = re.compile(
    r"""
    (?:
        \b(?:account(?:\s+number)?|acct(?:\s*[#])?|checking|savings)\s*[:#\[\]-]?\s*\d{8,17}\b |
        \brouting\s+(?:number|[#]|ABA)\s*[:#\[\]-]?\s*\d{9}\b |
        \b(?:ABA|routing)\s*[:#\[\]-]?\s*\d{9}\b
    )
    """,
    re.IGNORECASE | re.VERBOSE,
)

CREDIT_SCORE_RE = re.compile(
    r"""
    \b(?:credit\s+score|fico\s+score|score)\s*[:=]?\s*(?:is\s+)?(?:of\s+)?
    (\d{3})\b
    """,
    re.IGNORECASE | re.VERBOSE,
)

SALARY_RE = re.compile(
    r"""
    (?:
        (?:salary|wage|income|earnings|compensation|pay)\s*[:=]?\s*
        (?:of\s+|is\s+|was\s+|were\s+)?
        \$?\s?\d{1,3}(?:,\d{3})*(?:\.\d+)?(?:\s*(?:per\s+year|annually|\/yr|\/year|\/mo|per\s+month|hourly))?
        |
        \$\s?\d{1,3}(?:,\d{3})*(?:\.\d+)?\s*(?:per\s+year|annually|\/yr|\/year|\/mo|per\s+month|hourly|a\s+year|a\s+month)
    )
    """,
    re.IGNORECASE | re.VERBOSE,
)

CUSTOMER_ID_RE = re.compile(
    r"""
    \b(?:customer(?:\s+(?:id|number|code|no))?|client(?:\s+(?:id|number|code|no))?|member(?:\s+(?:id|number))?|subscriber(?:\s+(?:id|number))?|patient(?:\s+(?:id|number))?|user(?:\s+(?:id|number)))\s*[:#\[\]-]?\s*
    [A-Z]{0,4}[-]?\d{4,15}\b
    """,
    re.IGNORECASE | re.VERBOSE,
)

CONFIDENTIAL_RE = re.compile(
    r"""
    (?:
        \b(?:confidential|proprietary|trade\s+secret|internal\s+only|do\s+not\s+distribute|nda\s+required)\b
        \s*[:;.-]?\s*
        [^\n.]{5,80}
    )
    """,
    re.IGNORECASE | re.VERBOSE,
)

PERCENTAGE_RE = re.compile(
    r"(?<!\w)(\d{1,3}(?:\.\d+)?)\s*%",
)

# Context-aware: numbers near financial/credit keywords
FINANCIAL_NUMBER_RE = re.compile(
    r"""
    (?:
        (?:balance|savings|debt|loan|mortgage|credit\s+limit|available\s+credit|
           outstanding|owed|deposit|withdrawal|transfer|payment|refund|fee|
           charge|cost|price|budget|revenue|profit|loss|expense|invoice|billing|
           total|amount|value|worth|equity|asset|liability|net\s+worth)
        \s*[:=]?\s*(?:of\s+|is\s+|was\s+|were\s+|remaining\s+)?
        \$?\s?\d{1,3}(?:,\d{3})*(?:\.\d+)?
        |
        \$\s?\d{1,3}(?:,\d{3})*(?:\.\d+)?\s*(?:remaining|left|balance|owed|due|net|gross)
    )
    """,
    re.IGNORECASE | re.VERBOSE,
)


# ---------------------------------------------------------------------------
# NLP loader
# ---------------------------------------------------------------------------

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


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _add_result(results: List[Dict[str, Any]], entity_type: str, value: str, start: int, end: int) -> None:
    results.append(
        {
            "type": entity_type,
            "value": value,
            "start": start,
            "end": end,
        }
    )


def _looks_like_card(value: str) -> bool:
    return bool(CREDIT_CARD_RE.fullmatch(value.strip()))


def _overlaps(existing: List[Dict[str, Any]], start: int, end: int) -> bool:
    """Check if a new range overlaps with any already-detected range."""
    for det in existing:
        if start < det["end"] and end > det["start"]:
            return True
    return False


def _estimate_entropy(value: str) -> float:
    if not value:
        return 0.0
    freq = {}
    for ch in value:
        freq[ch] = freq.get(ch, 0) + 1
    length = len(value)
    entropy = 0.0
    for count in freq.values():
        p = count / length
        entropy -= p * math.log2(p)
    return entropy


# ---------------------------------------------------------------------------
# Individual detectors
# ---------------------------------------------------------------------------

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
                if "@" in cleaned_value or "@" in text[ent.start_char:ent.end_char]:
                    continue
                raw_value = cleaned_value

            _add_result(results, ent.label_ if ent.label_ != "ORGANIZATION" else "ORG", raw_value, ent.start_char, ent.end_char)

    for ent in doc.ents:
        if ent.label_ == "GPE" and not _overlaps(results, ent.start_char, ent.end_char):
            _add_result(results, "LOCATION", ent.text.strip(), ent.start_char, ent.end_char)


def _detect_emails(text: str, results: List[Dict[str, Any]]) -> None:
    for match in EMAIL_RE.finditer(text):
        if not _overlaps(results, match.start(), match.end()):
            _add_result(results, "EMAIL", match.group(0), match.start(), match.end())


def _detect_money(text: str, results: List[Dict[str, Any]]) -> None:
    for match in MONEY_RE.finditer(text):
        candidate = match.group(0).strip()
        if candidate.startswith("$") or "," in candidate or any(
            token in candidate.lower() for token in ["million", "billion", "thousand", "m", "bn", "k"]
        ):
            if not _overlaps(results, match.start(), match.end()):
                _add_result(results, "MONEY", candidate, match.start(), match.end())
    dollar_context = re.finditer(r"\$\s*(\d[\d,]*(?:\.\d+)?)", text)
    for match in dollar_context:
        candidate = "$" + match.group(1)
        if not _overlaps(results, match.start(), match.end()):
            _add_result(results, "MONEY", candidate, match.start(), match.end())
    bare_dollars = re.finditer(r"\b(\d[\d,]*(?:\.\d+)?)\s*(?:dollars?|bucks?|usd)\b", text, re.IGNORECASE)
    for match in bare_dollars:
        candidate = "$" + match.group(1)
        if not _overlaps(results, match.start(), match.end()):
            _add_result(results, "MONEY", candidate, match.start(), match.end())


def _detect_secrets(text: str, results: List[Dict[str, Any]]) -> None:
    for match in SECRET_RE.finditer(text):
        value = match.group(0).strip()
        if not _overlaps(results, match.start(), match.end()):
            _add_result(results, "SECRET", value, match.start(), match.end())


def _detect_phones(text: str, results: List[Dict[str, Any]]) -> None:
    for match in PHONE_RE.finditer(text):
        value = match.group(0).strip()
        if _looks_like_card(value):
            continue
        if not _overlaps(results, match.start(), match.end()):
            _add_result(results, "PHONE", value, match.start(), match.end())


def _detect_people(text: str, results: List[Dict[str, Any]]) -> None:
    for match in PERSON_RE.finditer(text):
        if not _overlaps(results, match.start(), match.end()):
            _add_result(results, "PERSON", match.group(0), match.start(), match.end())


def _detect_orgs(text: str, results: List[Dict[str, Any]]) -> None:
    for match in ORG_RE.finditer(text):
        if not _overlaps(results, match.start(), match.end()):
            _add_result(results, "ORG", match.group(0), match.start(), match.end())


def _detect_ssn(text: str, results: List[Dict[str, Any]]) -> None:
    for match in SSN_RE.finditer(text):
        if not _overlaps(results, match.start(), match.end()):
            _add_result(results, "SSN", match.group(0), match.start(), match.end())


def _detect_credit_cards(text: str, results: List[Dict[str, Any]]) -> None:
    for match in CREDIT_CARD_RE.finditer(text):
        if not _overlaps(results, match.start(), match.end()):
            _add_result(results, "CREDIT_CARD", match.group(0), match.start(), match.end())


def _detect_dob(text: str, results: List[Dict[str, Any]]) -> None:
    for match in DOB_RE.finditer(text):
        if not _overlaps(results, match.start(), match.end()):
            _add_result(results, "DOB", match.group(0), match.start(), match.end())


def _detect_ips(text: str, results: List[Dict[str, Any]]) -> None:
    for match in IP_RE.finditer(text):
        if not _overlaps(results, match.start(), match.end()):
            _add_result(results, "IP_ADDRESS", match.group(0), match.start(), match.end())


def _detect_accounts(text: str, results: List[Dict[str, Any]]) -> None:
    for match in ACCOUNT_RE.finditer(text):
        if not _overlaps(results, match.start(), match.end()):
            _add_result(results, "ACCOUNT_NUMBER", match.group(0), match.start(), match.end())


def _detect_addresses(text: str, results: List[Dict[str, Any]]) -> None:
    for match in ADDRESS_RE.finditer(text):
        if not _overlaps(results, match.start(), match.end()):
            _add_result(results, "ADDRESS", match.group(0), match.start(), match.end())
    for match in ADDRESS_NAME_RE.finditer(text):
        if not _overlaps(results, match.start(), match.end()):
            _add_result(results, "ADDRESS", match.group(0), match.start(), match.end())


def _detect_medical(text: str, results: List[Dict[str, Any]]) -> None:
    for match in MEDICAL_RE.finditer(text):
        if not _overlaps(results, match.start(), match.end()):
            _add_result(results, "MEDICAL", match.group(0), match.start(), match.end())


def _detect_bank_accounts(text: str, results: List[Dict[str, Any]]) -> None:
    for match in BANK_ACCOUNT_RE.finditer(text):
        if not _overlaps(results, match.start(), match.end()):
            _add_result(results, "BANK_ACCOUNT", match.group(0), match.start(), match.end())


def _detect_credit_scores(text: str, results: List[Dict[str, Any]]) -> None:
    for match in CREDIT_SCORE_RE.finditer(text):
        if not _overlaps(results, match.start(), match.end()):
            _add_result(results, "CREDIT_SCORE", match.group(0), match.start(), match.end())


def _detect_salary(text: str, results: List[Dict[str, Any]]) -> None:
    for match in SALARY_RE.finditer(text):
        if not _overlaps(results, match.start(), match.end()):
            _add_result(results, "SALARY", match.group(0), match.start(), match.end())


def _detect_customer_ids(text: str, results: List[Dict[str, Any]]) -> None:
    for match in CUSTOMER_ID_RE.finditer(text):
        if not _overlaps(results, match.start(), match.end()):
            _add_result(results, "CUSTOMER_ID", match.group(0), match.start(), match.end())


def _detect_confidential(text: str, results: List[Dict[str, Any]]) -> None:
    for match in CONFIDENTIAL_RE.finditer(text):
        if not _overlaps(results, match.start(), match.end()):
            _add_result(results, "CONFIDENTIAL", match.group(0), match.start(), match.end())


def _detect_contextual_secrets(text: str, results: List[Dict[str, Any]]) -> None:
    patterns = [
        (re.compile(r"\b(sk_(?:live|test)_[A-Za-z0-9]{16,})\b", re.IGNORECASE), "API_KEY"),
        (re.compile(r"\b(sk-[A-Za-z0-9]{16,})\b", re.IGNORECASE), "API_KEY"),
        (re.compile(r"\b(AKIA[0-9A-Z]{16})\b", re.IGNORECASE), "AWS_KEY"),
        (re.compile(r"\b((?:gh[pousr]_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,}))\b", re.IGNORECASE), "API_KEY"),
        (re.compile(r"\b(eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+)\b", re.IGNORECASE), "JWT"),
        (re.compile(r"\b(?:api[_-]?key|token|access[_-]?token|secret|password|passwd|credential|auth[_-]?token)\s*[:=]\s*([^\s,;]{4,})", re.IGNORECASE), "PASSWORD"),
        (re.compile(r"\b(?:password|passwd|secret|credential)\s+(?:is|was|=|:)?\s*([^\s,;]{4,})", re.IGNORECASE), "PASSWORD"),
    ]

    for pattern, kind in patterns:
        for match in pattern.finditer(text):
            value = match.group(1) if match.lastindex else match.group(0)
            if not value:
                continue
            if not _overlaps(results, match.start(), match.end()):
                _add_result(results, kind, value.strip(), match.start(), match.end())

    for match in re.finditer(r"\b([A-Za-z0-9!@#$%^&*()_+=\-.]{14,})\b", text):
        value = match.group(1)
        if len(value) < 16:
            continue
        if any(ch.isdigit() for ch in value) and any(ch.isalpha() for ch in value) and _estimate_entropy(value) >= 3.2:
            if not _overlaps(results, match.start(), match.end()):
                _add_result(results, "SECRET", value, match.start(), match.end())


def _detect_percentages(text: str, results: List[Dict[str, Any]]) -> None:
    for match in PERCENTAGE_RE.finditer(text):
        full = match.group(0).strip()
        if not _overlaps(results, match.start(), match.end()):
            _add_result(results, "PERCENTAGE", full, match.start(), match.end())


def _detect_financial_numbers(text: str, results: List[Dict[str, Any]]) -> None:
    """Detect bare numbers that appear in financial context (balance, loan, etc.)."""
    for match in FINANCIAL_NUMBER_RE.finditer(text):
        if not _overlaps(results, match.start(), match.end()):
            _add_result(results, "FINANCIAL_NUMBER", match.group(0).strip(), match.start(), match.end())


# ---------------------------------------------------------------------------
# Main entry point
# ---------------------------------------------------------------------------

def detect_sensitive_info(text: str) -> List[Dict[str, Any]]:
    """Return structured sensitive-entity detections for the provided text.

    Categories detected:
    - PERSON, ORG, LOCATION  (via spaCy NER)
    - EMAIL, PHONE, SSN, CREDIT_CARD, DOB, IP_ADDRESS, ACCOUNT_NUMBER
    - MONEY, SECRET
    - ADDRESS, MEDICAL, BANK_ACCOUNT, CREDIT_SCORE, SALARY
    - CUSTOMER_ID, CONFIDENTIAL, PERCENTAGE, FINANCIAL_NUMBER
    """
    if not text:
        return []

    results: List[Dict[str, Any]] = []

    # spaCy NER pass (people, orgs, locations)
    _detect_with_spacy(text, results)

    # Deterministic regex passes (high-confidence patterns first)
    _detect_credit_cards(text, results)
    _detect_emails(text, results)

    # Address detection BEFORE secrets to avoid overlap conflicts
    _detect_addresses(text, results)

    _detect_contextual_secrets(text, results)
    _detect_secrets(text, results)
    _detect_bank_accounts(text, results)
    _detect_medical(text, results)
    _detect_customer_ids(text, results)
    _detect_accounts(text, results)
    _detect_ips(text, results)
    _detect_credit_scores(text, results)
    _detect_ssn(text, results)

    # Context-aware passes (before generic MONEY so context overrides)
    _detect_salary(text, results)
    _detect_money(text, results)
    _detect_financial_numbers(text, results)
    _detect_percentages(text, results)

    # Lower-confidence passes
    _detect_phones(text, results)
    _detect_dob(text, results)
    _detect_confidential(text, results)

    # Fallback regex passes for orgs/names (only if spaCy didn't find them)
    has_org = any(r["type"] == "ORG" for r in results)
    has_person = any(r["type"] == "PERSON" for r in results)
    if not has_org:
        _detect_orgs(text, results)
    if not has_person:
        _detect_people(text, results)

    # Upgrade PERSON to ORG if the matched text also looks like an organization
    for det in results:
        if det["type"] == "PERSON" and ORG_RE.fullmatch(det["value"]):
            det["type"] = "ORG"

    results.sort(key=lambda item: (item["start"], item["end"], item["type"]))
    return results


if __name__ == "__main__":
    sample_text = (
        "John Williams works at Acme Corp. Revenue was $5,000,000. "
        "Email john@gmail.com. API key: sk-1234567890abcdef. "
        "Phone: +1-555-123-4567. SSN 123-45-6789. Card 4111-1111-1111-1111. "
        "Address: 123 Main Street. Credit score: 750. Salary: $85,000 annually. "
        "Account number: 123456789012. Customer ID: CUST-001234."
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
