"""
Risk Score Module for Aegis Shield

Calculates a privacy risk score (0-100) based on three categories:
  A) Sensitive Data Detection (max 40 points)
  B) Information Sensitivity Level (max 40 points)
  C) Context Risk (max 20 points)
"""

import re
from typing import Any, Dict, List, Tuple


# ---------------------------------------------------------------------------
# Category A: Entity -> point value mapping
# ---------------------------------------------------------------------------

ENTITY_POINTS: Dict[str, int] = {
    "PERSON": 5,
    "DOB": 5,
    "EMAIL": 10,
    "PHONE": 10,
    "SALARY": 20,
    "FINANCIAL_NUMBER": 25,
    "MONEY": 0,  # money is visible, low risk on its own
    "CREDIT_SCORE": 20,
    "API_KEY": 40,
    "AWS_KEY": 40,
    "PASSWORD": 40,
    "JWT": 40,
    "SECRET": 35,
    "MEDICAL": 30,
    "CUSTOMER_ID": 30,
    "CONFIDENTIAL": 25,
    "SSN": 40,
    "CREDIT_CARD": 40,
    "IP_ADDRESS": 15,
    "ACCOUNT_NUMBER": 25,
    "BANK_ACCOUNT": 25,
    "ORG": 15,
    "ADDRESS": 10,
    "LOCATION": 5,
    "PERCENTAGE": 0,
}

ENTITY_LABELS: Dict[str, Tuple[str, str]] = {
    "PERSON": ("Personal Identity", "Person name detected"),
    "DOB": ("Personal Identity", "Date of birth detected"),
    "EMAIL": ("Contact Information", "Email address detected"),
    "PHONE": ("Contact Information", "Phone number detected"),
    "SALARY": ("Financial Information", "Salary / compensation data detected"),
    "FINANCIAL_NUMBER": ("Financial Information", "Financial figure detected"),
    "MONEY": ("Financial Information", "Monetary amount detected"),
    "CREDIT_SCORE": ("Financial Information", "Credit score detected"),
    "CREDIT_CARD": ("Financial Information", "Credit card number detected"),
    "ACCOUNT_NUMBER": ("Financial Information", "Account number detected"),
    "BANK_ACCOUNT": ("Financial Information", "Bank account details detected"),
    "API_KEY": ("Authentication / Secrets", "API key detected"),
    "AWS_KEY": ("Authentication / Secrets", "AWS access key detected"),
    "PASSWORD": ("Authentication / Secrets", "Password or credential detected"),
    "JWT": ("Authentication / Secrets", "JWT token detected"),
    "SECRET": ("Authentication / Secrets", "Secret / high-entropy string detected"),
    "SSN": ("Government ID", "Social Security Number detected"),
    "MEDICAL": ("Medical Information", "Medical record data detected"),
    "CUSTOMER_ID": ("Personal Records", "Customer / user ID detected"),
    "CONFIDENTIAL": ("Confidential Material", "Confidential / restricted content detected"),
    "IP_ADDRESS": ("Network Information", "IP address detected"),
    "ORG": ("Business Information", "Company / organization name detected"),
    "ADDRESS": ("Location Information", "Physical address detected"),
    "LOCATION": ("Location Information", "Geographic location detected"),
    "PERCENTAGE": ("Financial Information", "Percentage figure detected"),
}


# ---------------------------------------------------------------------------
# Category B: Sensitivity keywords -> level
# ---------------------------------------------------------------------------

HIGHLY_CONFIDENTIAL_KEYWORDS = [
    "acquisition", "merger", "takeover", "unreleased", "embargo",
    "api.key", "secret.key", "password", "credential", "ssn",
    "social security", "credit card", "api_key", "private.key",
]

CONFIDENTIAL_KEYWORDS = [
    "salary", "payroll", "revenue", "profit", "budget",
    "financial", "earnings", "confidential", "nda", "internal",
    "proprietary", "contract", "agreement", "legal", "medical",
    "health", "patient", "customer", "employee", "compensation",
]

INTERNAL_KEYWORDS = [
    "internal", "team", "project", "roadmap", "sprint",
    "quarterly", "report", "forecast", "plan", "strategy",
    "meeting", "notes", "document", "draft", "review",
]


# ---------------------------------------------------------------------------
# Category C: Context patterns
# ---------------------------------------------------------------------------

LEGAL_FINANCIAL_CONTEXT = [
    "revenue", "profit", "loss", "earnings", "budget", "forecast",
    "contract", "agreement", "legal", "regulatory", "compliance",
    "audit", "tax", "filing", "lawsuit", "settlement",
    "acquisition", "merger", "ipo", "valuation",
]

SECURITY_CONTEXT = [
    "password", "api.key", "secret", "token", "credential",
    "auth", "encrypt", "decrypt", "certificate", "key",
    "vulnerability", "breach", "firewall", "access",
]

FUTURE_PLANS_CONTEXT = [
    "upcoming", "future", "next quarter", "next year", "roadmap",
    "planned", "launch", "release", "unreleased", "embargo",
    "announcement", "reveal", " unveil",
]


# ---------------------------------------------------------------------------
# Scoring helpers
# ---------------------------------------------------------------------------

def _score_entities(detections: List[Dict[str, Any]]) -> Tuple[int, List[Dict[str, Any]]]:
    """Category A: score detected entities, capped at 40."""
    total = 0
    items: List[Dict[str, Any]] = []
    seen_types: Dict[str, int] = {}

    for det in detections:
        dtype = det["type"]
        points = ENTITY_POINTS.get(dtype, 0)
        if points <= 0:
            continue

        # Count each type once but use highest points for that type
        if dtype not in seen_types:
            seen_types[dtype] = points
        else:
            seen_types[dtype] = max(seen_types[dtype], points)

    for dtype, points in seen_types.items():
        total += points
        label, desc = ENTITY_LABELS.get(dtype, (dtype, f"{dtype} detected"))
        items.append({
            "type": label,
            "description": f"{desc} (+{points})",
            "severity": "High" if points >= 25 else "Medium" if points >= 10 else "Low",
            "points": points,
        })

    return min(total, 40), items


def _score_sensitivity(text: str) -> Tuple[int, str]:
    """Category B: classify overall information sensitivity."""
    lower = text.lower()

    for kw in HIGHLY_CONFIDENTIAL_KEYWORDS:
        if kw in lower:
            return 40, "Highly Confidential"

    for kw in CONFIDENTIAL_KEYWORDS:
        if kw in lower:
            return 25, "Confidential"

    for kw in INTERNAL_KEYWORDS:
        if kw in lower:
            return 10, "Internal"

    return 0, "Public"


def _score_context(text: str) -> Tuple[int, str]:
    """Category C: analyze context risk."""
    lower = text.lower()

    legal_hits = sum(1 for kw in LEGAL_FINANCIAL_CONTEXT if kw in lower)
    security_hits = sum(1 for kw in SECURITY_CONTEXT if kw in lower)
    future_hits = sum(1 for kw in FUTURE_PLANS_CONTEXT if kw in lower)

    if legal_hits >= 2 or security_hits >= 2:
        return 20, "Legal / Financial / Security context"
    if future_hits >= 2:
        return 15, "Future plans / unreleased information"
    if legal_hits >= 1 or security_hits >= 1:
        return 10, "Internal company workflow"
    if future_hits >= 1:
        return 10, "Internal company workflow"

    return 0, "General request"


# ---------------------------------------------------------------------------
# Risk level helpers
# ---------------------------------------------------------------------------

def _risk_level(score: int) -> str:
    if score <= 25:
        return "LOW"
    if score <= 50:
        return "MEDIUM"
    if score <= 75:
        return "HIGH"
    return "CRITICAL"


def _risk_label(score: int) -> str:
    if score <= 25:
        return "Safe to send"
    if score <= 50:
        return "Review recommended"
    if score <= 75:
        return "Sensitive information detected"
    return "Should be blocked or heavily sanitized"


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def calculate_risk(text: str, detections: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Calculate the full risk assessment for a user prompt.

    Returns a dict with:
      risk_score, risk_level, risk_label,
      category_a (data points + items),
      category_b (sensitivity level + points),
      category_c (context label + points),
      detected_items, recommendation
    """
    entity_points, entity_items = _score_entities(detections)
    sensitivity_points, sensitivity_level = _score_sensitivity(text)
    context_points, context_label = _score_context(text)

    raw_score = entity_points + sensitivity_points + context_points
    risk_score = min(raw_score, 100)
    risk_level = _risk_level(risk_score)
    risk_label = _risk_label(risk_score)

    # Merge all detected items
    all_items = list(entity_items)

    if sensitivity_points > 0:
        all_items.append({
            "type": "Information Sensitivity",
            "description": f"Classified as {sensitivity_level} (+{sensitivity_points})",
            "severity": "High" if sensitivity_points >= 25 else "Medium",
            "points": sensitivity_points,
        })

    if context_points > 0:
        all_items.append({
            "type": "Context Risk",
            "description": f"{context_label} (+{context_points})",
            "severity": "High" if context_points >= 15 else "Medium",
            "points": context_points,
        })

    if risk_score <= 25:
        recommendation = "Safe to send as-is"
    elif risk_score <= 50:
        recommendation = "Review recommended before sending"
    elif risk_score <= 75:
        recommendation = "Sanitize before sending to AI"
    else:
        recommendation = "Block or heavily sanitize before sending"

    return {
        "risk_score": risk_score,
        "risk_level": risk_level,
        "risk_label": risk_label,
        "category_a": {"points": entity_points, "max": 40, "label": "Sensitive Data Detection"},
        "category_b": {"points": sensitivity_points, "max": 40, "label": f"Information Sensitivity: {sensitivity_level}"},
        "category_c": {"points": context_points, "max": 20, "label": f"Context Risk: {context_label}"},
        "detected_items": all_items,
        "recommendation": recommendation,
    }


def build_audit(original: str, sanitized: str, detections: List[Dict[str, Any]],
                placeholder_map: Dict[str, str], risk: Dict[str, Any]) -> Dict[str, Any]:
    """Build the View Privacy Audit payload."""
    protected = []
    for placeholder, value in sorted(placeholder_map.items(), key=lambda x: x[0]):
        dtype = None
        for det in detections:
            if det["value"] == value:
                dtype = det["type"]
                break
        label, _ = ENTITY_LABELS.get(dtype, (dtype or "Sensitive", "Sensitive data")) if dtype else ("Sensitive", "Sensitive data")
        protected.append({
            "original": value,
            "placeholder": placeholder,
            "category": label,
        })

    return {
        "original": original,
        "sent_to_ai": sanitized,
        "protected_items": protected,
        "risk": risk,
    }
