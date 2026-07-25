from typing import Any, Dict, List


def mask_text(text: str, detected_entities: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Replace detected entities in text with placeholders and return a vault mapping."""
    if not text:
        return {"masked_text": "", "vault": {}}

    masked_text = text
    vault: Dict[str, str] = {}
    placeholder_counts: Dict[str, int] = {}

    ordered_entities = sorted(
        detected_entities,
        key=lambda item: (item.get("start", 0), item.get("end", 0)),
        reverse=True,
    )

    for entity in ordered_entities:
        start = entity.get("start")
        end = entity.get("end")
        entity_type = str(entity.get("type", "ENTITY")).upper()
        value = entity.get("value")

        if start is None or end is None:
            continue
        if not isinstance(start, int) or not isinstance(end, int):
            continue
        if start < 0 or end <= start or end > len(text):
            continue
        if value is None:
            value = masked_text[start:end]

        placeholder_counts[entity_type] = placeholder_counts.get(entity_type, 0) + 1
        placeholder = f"{entity_type}_{placeholder_counts[entity_type]}"
        vault[placeholder] = value

        masked_text = masked_text[:start] + placeholder + masked_text[end:]

    return {"masked_text": masked_text, "vault": vault}


if __name__ == "__main__":
    sample_text = "John Smith works at Acme Corp. Revenue was $5,000,000."
    sample_entities = [
        {"type": "PERSON", "value": "John Smith", "start": 0, "end": 10},
        {"type": "ORG", "value": "Acme Corp", "start": 20, "end": 29},
        {"type": "MONEY", "value": "$5,000,000", "start": 43, "end": 53},
    ]

    result = mask_text(sample_text, sample_entities)
    expected = "PERSON_1 works at ORG_1. Revenue was MONEY_1."

    print("Masked text:", result["masked_text"])
    print("Vault:", result["vault"])
    print("Matches expected:", result["masked_text"] == expected)

    example_text = "Confidential report for Alice Chen at Microsoft. Revenue was $25,000,000. Contact alice@microsoft.com."
    example_entities = [
        {"type": "PERSON", "value": "Alice Chen", "start": 24, "end": 34},
        {"type": "ORG", "value": "Microsoft", "start": 38, "end": 47},
        {"type": "MONEY", "value": "$25,000,000", "start": 61, "end": 72},
        {"type": "EMAIL", "value": "alice@microsoft.com", "start": 82, "end": 101},
    ]

    example_result = mask_text(example_text, example_entities)
    print("Example masked text:", example_result["masked_text"])
    print("Example vault:", example_result["vault"])
