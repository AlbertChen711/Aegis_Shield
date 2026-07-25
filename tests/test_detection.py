import os
import sys

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from detector import detect_sensitive_info


def test_detects_common_pii_patterns():
    text = (
        "Contact John Doe at john.doe@example.com. "
        "His SSN is 123-45-6789 and card is 4111-1111-1111-1111. "
        "Phone +1-555-123-4567."
    )
    detections = detect_sensitive_info(text)
    types = {item["type"] for item in detections}
    assert "EMAIL" in types
    assert "PHONE" in types
    assert "SSN" in types
    assert "CREDIT_CARD" in types


def test_detects_names_and_orgs():
    text = "Alice Smith works at Acme Corp and lives in Seattle."
    detections = detect_sensitive_info(text)
    assert any(item["type"] in {"PERSON", "ORG"} for item in detections)
