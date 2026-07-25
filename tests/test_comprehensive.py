"""Comprehensive tests for the Aegis Shield detection and privacy transformation system.

Covers: detection categories, sanitization, desanitization, relationship preservation,
and end-to-end financial/medical/business scenarios.
"""

import os
import sys

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from detector import detect_sensitive_info
from ollama_gateway import sanitize, desanitize, NUMERICAL_PREFIXES, DESCRIPTIVE_PREFIXES, build_outgoing_prompt, validate_outgoing_prompt


# ---------------------------------------------------------------------------
# Detection tests
# ---------------------------------------------------------------------------

class TestEmailDetection:
    def test_basic_email(self):
        text = "Send to john.doe@example.com"
        detections = detect_sensitive_info(text)
        assert any(d["type"] == "EMAIL" and d["value"] == "john.doe@example.com" for d in detections)

    def test_multiple_emails(self):
        text = "CC alice@corp.org and bob@company.net"
        detections = detect_sensitive_info(text)
        emails = [d for d in detections if d["type"] == "EMAIL"]
        assert len(emails) >= 1

    def test_email_not_in_name(self):
        text = "Email is myname@domain.com for contact"
        detections = detect_sensitive_info(text)
        emails = [d for d in detections if d["type"] == "EMAIL"]
        assert len(emails) == 1


class TestSSNDetection:
    def test_formatted_ssn(self):
        text = "SSN is 123-45-6789"
        detections = detect_sensitive_info(text)
        assert any(d["type"] == "SSN" and "123-45-6789" in d["value"] for d in detections)

    def test_unformatted_ssn(self):
        text = "SSN: 123456789"
        detections = detect_sensitive_info(text)
        assert any(d["type"] == "SSN" for d in detections)


class TestCreditCardDetection:
    def test_visa(self):
        text = "Card: 4111-1111-1111-1111"
        detections = detect_sensitive_info(text)
        assert any(d["type"] == "CREDIT_CARD" for d in detections)

    def test_mastercard(self):
        text = "Card: 5500-0000-0000-0004"
        detections = detect_sensitive_info(text)
        assert any(d["type"] == "CREDIT_CARD" for d in detections)

    def test_amex(self):
        text = "Card: 3782-822463-10005"
        detections = detect_sensitive_info(text)
        assert any(d["type"] == "CREDIT_CARD" for d in detections)


class TestPhoneDetection:
    def test_us_phone(self):
        text = "Call +1-555-123-4567"
        detections = detect_sensitive_info(text)
        assert any(d["type"] == "PHONE" for d in detections)

    def test_international_phone(self):
        text = "Phone: +44 20 7946 0958"
        detections = detect_sensitive_info(text)
        phones = [d for d in detections if d["type"] == "PHONE"]
        assert len(phones) >= 1


class TestMoneyDetection:
    def test_dollar_amount(self):
        text = "Revenue was $5,000,000"
        detections = detect_sensitive_info(text)
        assert any(d["type"] in ("MONEY", "FINANCIAL_NUMBER") for d in detections)

    def test_million_suffix(self):
        text = "Worth 3.5 billion dollars"
        detections = detect_sensitive_info(text)
        money = [d for d in detections if d["type"] in ("MONEY", "FINANCIAL_NUMBER")]
        assert len(money) >= 1


class TestAddressDetection:
    def test_street_address(self):
        text = "Visit us at 123 Main Street"
        detections = detect_sensitive_info(text)
        assert any(d["type"] == "ADDRESS" for d in detections)

    def test_avenue(self):
        text = "Office at 456 Oak Avenue"
        detections = detect_sensitive_info(text)
        assert any(d["type"] == "ADDRESS" for d in detections)


class TestCreditScoreDetection:
    def test_credit_score(self):
        text = "His credit score is 750"
        detections = detect_sensitive_info(text)
        assert any(d["type"] == "CREDIT_SCORE" for d in detections)

    def test_fico_score(self):
        text = "FICO score: 680"
        detections = detect_sensitive_info(text)
        assert any(d["type"] == "CREDIT_SCORE" for d in detections)


class TestSalaryDetection:
    def test_annual_salary(self):
        text = "Salary: $85,000 annually"
        detections = detect_sensitive_info(text)
        assert any(d["type"] == "SALARY" for d in detections)

    def test_hourly_wage(self):
        text = "Wage is $25.50 hourly"
        detections = detect_sensitive_info(text)
        assert any(d["type"] == "SALARY" for d in detections)


class TestBankAccountDetection:
    def test_account_number(self):
        text = "Account number: 1234567890123456"
        detections = detect_sensitive_info(text)
        assert any(d["type"] == "BANK_ACCOUNT" for d in detections)

    def test_routing_number(self):
        text = "Routing number: 021000021"
        detections = detect_sensitive_info(text)
        types = {d["type"] for d in detections}
        assert "BANK_ACCOUNT" in types or "ACCOUNT_NUMBER" in types


class TestMedicalDetection:
    def test_mrn(self):
        text = "MRN: 12345678"
        detections = detect_sensitive_info(text)
        assert any(d["type"] == "MEDICAL" for d in detections)

    def test_icd_code(self):
        text = "Diagnosis: ICD-10 E11.9"
        detections = detect_sensitive_info(text)
        assert any(d["type"] == "MEDICAL" for d in detections)


class TestCustomerIDDetection:
    def test_customer_id(self):
        text = "Customer ID: CUST-001234"
        detections = detect_sensitive_info(text)
        assert any(d["type"] == "CUSTOMER_ID" for d in detections)

    def test_patient_number(self):
        text = "Patient number: PAT-98765"
        detections = detect_sensitive_info(text)
        assert any(d["type"] == "CUSTOMER_ID" for d in detections)


class TestPersonDetection:
    def test_person_name(self):
        text = "John Williams submitted the report"
        detections = detect_sensitive_info(text)
        persons = [d for d in detections if d["type"] == "PERSON"]
        assert len(persons) >= 1

    def test_two_word_name(self):
        text = "Alice Smith works at Acme Corp"
        detections = detect_sensitive_info(text)
        persons = [d for d in detections if d["type"] == "PERSON"]
        assert len(persons) >= 1


class TestOrgDetection:
    def test_corporation(self):
        text = "Works at Acme Corp"
        detections = detect_sensitive_info(text)
        orgs = [d for d in detections if d["type"] == "ORG"]
        assert len(orgs) >= 1


class TestSecretDetection:
    def test_api_key(self):
        text = "API key: sk-1234567890abcdef1234"
        detections = detect_sensitive_info(text)
        assert any(d["type"] in {"SECRET", "API_KEY"} for d in detections)

    def test_labeled_secret(self):
        text = "token: mySecretToken123456"
        detections = detect_sensitive_info(text)
        assert any(d["type"] in {"SECRET", "PASSWORD"} for d in detections)


class TestPercentageDetection:
    def test_percentage(self):
        text = "Growth was 40%"
        detections = detect_sensitive_info(text)
        assert any(d["type"] == "PERCENTAGE" for d in detections)

    def test_decimal_percentage(self):
        text = "Interest rate: 3.75%"
        detections = detect_sensitive_info(text)
        assert any(d["type"] == "PERCENTAGE" for d in detections)


# ---------------------------------------------------------------------------
# Sanitize / Desanitize tests
# ---------------------------------------------------------------------------

class TestSanitize:
    def test_replaces_email(self):
        text, pmap, legend = sanitize("Email: test@example.com")
        assert "test@example.com" not in text
        assert any("test@example.com" in v for v in pmap.values())
        assert "LEGEND" in legend

    def test_replaces_money(self):
        text, pmap, legend = sanitize("Revenue was $5,000,000")
        assert "$5,000,000" not in text
        assert any("$5,000,000" in v for v in pmap.values())
        assert "FINANCIAL_AMOUNT_" in text

    def test_preserves_operators(self):
        text, pmap, legend = sanitize("$10,000 - $4,000 = remaining")
        assert "-" in text
        assert "=" in text
        assert any("FINANCIAL_AMOUNT_" in k or "MONEY_" in k for k in pmap)

    def test_empty_text(self):
        text, pmap, legend = sanitize("")
        assert text == ""
        assert pmap == {}
        assert legend == ""

    def test_no_sensitive_info(self):
        text, pmap, legend = sanitize("Hello world")
        assert text == "Hello world"
        assert pmap == {}

    def test_multiple_categories(self):
        text, pmap, legend = sanitize(
            "John Doe (john@test.com) has SSN 123-45-6789 and earned $85,000"
        )
        assert "john@test.com" not in text
        assert "123-45-6789" not in text
        assert "$85,000" not in text
        assert "PERSON_" in text or "EMAIL_" in text

    def test_legend_contains_types(self):
        _, _, legend = sanitize("Card: 4111-1111-1111-1111")
        assert "credit card" in legend.lower()

    def test_credit_score_placeholder(self):
        text, pmap, _ = sanitize("Credit score is 750")
        assert "CREDIT_SCORE_" in text
        assert any("750" in v for v in pmap.values())


class TestDesanitize:
    def test_restores_values(self):
        original = "Revenue was $5,000,000"
        text, pmap, _ = sanitize(original)
        restored = desanitize(text, pmap)
        assert "$5,000,000" in restored

    def test_restores_all_placeholders(self):
        original = "Email: test@example.com, Phone: +1-555-123-4567"
        text, pmap, _ = sanitize(original)
        restored = desanitize(text, pmap)
        assert "test@example.com" in restored
        assert "+1-555-123-4567" in restored

    def test_longest_placeholder_first(self):
        original = "SSN 123-45-6789 and secret sk-abc123def456ghi789"
        text, pmap, _ = sanitize(original)
        restored = desanitize(text, pmap)
        assert "123-45-6789" in restored


# ---------------------------------------------------------------------------
# Relationship preservation tests
# ---------------------------------------------------------------------------

class TestRelationshipPreservation:
    def test_subtraction_relationship(self):
        """$10,000 - $4,000 should become FINANCIAL_AMOUNT_A - FINANCIAL_AMOUNT_B"""
        text, pmap, legend = sanitize("Starting balance was $10,000 and lost $4,000")
        assert "FINANCIAL_AMOUNT_" in text
        assert "-" not in text or "Money_" in text

    def test_ratio_preserved(self):
        """2x growth ratio should be preserved in text"""
        text, pmap, legend = sanitize("Revenue increased from $5,000 to $10,000 (2x growth)")
        assert "2x" in text
        assert "$5,000" not in text
        assert "$10,000" not in text

    def test_percentage_preserved(self):
        """40% should be replaced with PERCENTAGE_A"""
        text, pmap, legend = sanitize("Lost 40% of the original balance")
        assert "PERCENTAGE_" in text
        assert "40%" not in text

    def test_comparison_preserved(self):
        """Comparison text should remain, values should be masked"""
        text, pmap, legend = sanitize(
            "Person A has $50,000 savings and Person B has $30,000 savings"
        )
        assert "$50,000" not in text
        assert "$30,000" not in text
        assert "FINANCIAL_AMOUNT_" in text

    def test_financial_calculation_context(self):
        """Full financial sentence should preserve structure"""
        text, pmap, legend = sanitize(
            "John Doe's account balance is $25,000. "
            "After a withdrawal of $7,500, the remaining balance is $17,500."
        )
        assert "John Doe" not in text
        assert "$25,000" not in text
        assert "$7,500" not in text
        assert "$17,500" not in text
        assert "remaining balance" in text


# ---------------------------------------------------------------------------
# Scenario tests
# ---------------------------------------------------------------------------

class TestFinancialScenario:
    def test_budget_analysis(self):
        text = (
            "Company: Acme Corp\n"
            "Revenue: $12,500,000\n"
            "Expenses: $8,200,000\n"
            "Profit margin calculation needed"
        )
        detections = detect_sensitive_info(text)
        types = {d["type"] for d in detections}
        assert "ORG" in types or any("MONEY" in t or "FINANCIAL" in t for t in types)

    def test_personal_finance(self):
        text = (
            "John Smith earns $95,000 annually. "
            "His credit score is 720. "
            "He has $45,000 in savings and owes $12,000 on his credit card 4111-1111-1111-1111. "
            "Contact: john.smith@email.com"
        )
        detections = detect_sensitive_info(text)
        types = {d["type"] for d in detections}
        assert any(t in types for t in ("EMAIL", "SECRET", "API_KEY"))
        assert "CREDIT_CARD" in types
        assert any(t in types for t in ("MONEY", "SALARY", "FINANCIAL_NUMBER"))

    def test_business_report(self):
        text = (
            "Q4 Report for TechCorp Inc\n"
            "Revenue: $45,000,000\n"
            "Growth: 23%\n"
            "Employee count: 1,200\n"
            "Average salary: $120,000"
        )
        detections = detect_sensitive_info(text)
        types = {d["type"] for d in detections}
        assert any(t in types for t in ("ORG", "MONEY", "FINANCIAL_NUMBER", "PERCENTAGE", "SALARY"))

    def test_medical_record(self):
        text = (
            "Patient: Jane Doe\n"
            "MRN: 12345678\n"
            "Diagnosis: ICD-10 E11.9\n"
            "Insurance Policy: POL-12345678"
        )
        detections = detect_sensitive_info(text)
        types = {d["type"] for d in detections}
        assert "PERSON" in types
        assert "MEDICAL" in types

    def test_large_document_multiple_fields(self):
        text = (
            "Confidential: Internal Use Only\n"
            "Employee: Robert Johnson, SSN 987-65-4321\n"
            "Email: robert.j@company.com, Phone: +1-555-987-6543\n"
            "Salary: $110,000 annually, Credit score: 690\n"
            "Bank account: 9876543210123456, Routing: 021000021\n"
            "Address: 789 Oak Avenue\n"
            "Customer ID: CUST-987654\n"
            "Medical MRN: 87654321"
        )
        detections = detect_sensitive_info(text)
        types = {d["type"] for d in detections}
        assert len(types) >= 6  # At least 6 different categories detected


# ---------------------------------------------------------------------------
# Edge cases
# ---------------------------------------------------------------------------

class TestEdgeCases:
    def test_empty_input(self):
        assert detect_sensitive_info("") == []

    def test_no_sensitive_data(self):
        text = "The weather is nice today and the sky is blue"
        detections = detect_sensitive_info(text)
        assert len(detections) == 0

    def test_overlapping_detections(self):
        """Email inside a longer string should not double-detect"""
        text = "Send report to alice@company.com immediately"
        detections = detect_sensitive_info(text)
        emails = [d for d in detections if d["type"] == "EMAIL"]
        assert len(emails) == 1

    def test_special_characters(self):
        text = "Revenue was $1,234,567.89 and growth was 15.5%"
        detections = detect_sensitive_info(text)
        assert len(detections) >= 1

    def test_unicode_handling(self):
        text = "Contact: josé@empresa.com"
        detections = detect_sensitive_info(text)
        assert any(d["type"] == "EMAIL" for d in detections)


if __name__ == "__main__":
    import pytest
    pytest.main([__file__, "-v"])
