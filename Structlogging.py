# log_wrapper.py
import re

PII_FIELDS = {"email", "phone", "ssn", "dob", "password", "user_name"}

def mask_pii(_, __, event_dict):
    redacted = {}

    for key, value in event_dict.items():
        if key.lower() in PII_FIELDS:
            redacted[key] = "[REDACTED]"
        elif isinstance(value, str):
            # Optional: redact email addresses and phone numbers in free text
            value = re.sub(r"[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+", "[REDACTED_EMAIL]", value)
            value = re.sub(r"\b\d{10}\b", "[REDACTED_PHONE]", value)
            redacted[key] = value
        else:
            redacted[key] = value

    return redacted

