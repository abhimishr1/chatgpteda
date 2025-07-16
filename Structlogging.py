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

[
  "name",
  "first_name",
  "last_name",
  "full_name",
  "username",
  "user_name",
  "nickname",
  "email",
  "email_address",
  "phone",
  "mobile",
  "telephone",
  "contact_number",
  "fax",
  "address",
  "street",
  "city",
  "state",
  "zipcode",
  "zip",
  "postal_code",
  "country",
  "location",
  "coordinates",
  "ssn",
  "sin",
  "passport",
  "aadhaar",
  "pan",
  "voter_id",
  "driver_license",
  "national_id",
  "tax_id",
  "credit_card",
  "card_number",
  "cvv",
  "iban",
  "bic",
  "bank_account",
  "account_number",
  "routing_number",
  "dob",
  "birthdate",
  "expiration_date",
  "issue_date",
  "password",
  "passcode",
  "pin",
  "secret",
  "security_answer",
  "token",
  "access_token",
  "refresh_token",
  "api_key",
  "ip",
  "ip_address",
  "mac_address",
  "device_id",
  "session_id",
  "user_agent",
  "hostname",
  "cookie"
]
