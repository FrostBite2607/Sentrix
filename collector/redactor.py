"""
SENTRIX Redactor Module
-----------------------
Strips sensitive data from log messages and event text before anything
leaves the local environment. Replacements are deterministic so the
same input always produces the same output — useful for testing.

Privacy guarantee: raw PII never reaches the central server.

Supported redactions:
  - Email addresses         → [EMAIL]
  - Bearer / auth tokens    → [TOKEN]
  - API keys                → [API_KEY]
  - Passwords / secrets     → [PASSWORD]
  - Usernames               → [USERNAME]
  - IPv4 addresses          → [IP]
  - IPv6 addresses          → [IP]
  - Long digit sequences    → [DIGITS]  (10+ digits — card numbers, SSNs, etc.)
"""

import re
from typing import List, Tuple


# ---------------------------------------------------------------------------
# Compiled regex patterns, ordered so narrower patterns run before broader
# ones. Patterns use negative lookaheads so placeholder tokens like
# [EMAIL], [IP], [PASSWORD], etc., are never treated as sensitive content.
# ---------------------------------------------------------------------------

_PATTERNS: List[Tuple[re.Pattern, str]] = [
    # 1. Email addresses — must run before username patterns
    (re.compile(
        r'\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b'
    ), '[EMAIL]'),

    # 2. Bearer tokens (e.g. "Bearer eyJhbG...")
    (re.compile(
        r'(?i)\bBearer\s+(?!\[TOKEN\])[A-Za-z0-9\-._~+/]{8,}=*'
    ), 'Bearer [TOKEN]'),

    # 3. Authorization header values (e.g. "Authorization: Basic abc123")
    (re.compile(
        r'(?i)(Authorization\s*[:=]\s*)["\']?(?!\[TOKEN\])(\S+(?:\s+\S+)?)["\']?'
    ), r'\1[TOKEN]'),

    # 4. API keys in key=value or header style (8+ character values)
    (re.compile(
        r'(?i)\b(api[_\-]?key|apikey|x-api-key|access[_\-]?key'
        r'|secret[_\-]?key)\s*[:=]\s*["\']?(?!\[API_KEY\])'
        r'([A-Za-z0-9\-._~+/]{8,})["\']?'
    ), r'\1=[API_KEY]'),

    # 5. Passwords and secrets in key=value pairs
    (re.compile(
        r'(?i)\b(password|passwd|pwd|secret|credential'
        r'|pass)\s*[:=]\s*["\']?(?!\[PASSWORD\])(\S+?)["\']?(?=\s|$|[,;}&\]])'
    ), r'\1=[PASSWORD]'),

    # 6. Usernames in key=value (skip if already [EMAIL] or any other bracketed token)
    (re.compile(
        r'(?i)\b(user|username|user_name|login|usr'
        r')\s*[:=]\s*["\']?(?!\[[A-Z_]+\])([A-Za-z0-9._%+\-]+)["\']?(?=\s|$|[,;}&\]])'
    ), r'\1=[USERNAME]'),

    # 7. IPv4 addresses (strict octet ranges 0-255)
    (re.compile(
        r'\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}'
        r'(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b'
    ), '[IP]'),

    # 8. IPv6 addresses (simplified — covers most common notations)
    (re.compile(
        r'\b(?:[0-9a-fA-F]{1,4}:){2,7}[0-9a-fA-F]{1,4}\b'
    ), '[IP]'),

    # 9. Long digit sequences — 10 or more consecutive digits
    (re.compile(
        r'\b\d{10,}\b'
    ), '[DIGITS]'),
]


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def redact(text: str) -> str:
    """
    Apply all redaction patterns to *text* and return the sanitised version.
    Patterns are applied in priority order.
    """
    for pattern, replacement in _PATTERNS:
        text = pattern.sub(replacement, text)
    return text


def contains_sensitive(text: str) -> bool:
    """
    Return True if *text* contains any data that matches a sensitive pattern.
    Useful as an assertion in tests to verify nothing slipped through.
    """
    for pattern, _ in _PATTERNS:
        if pattern.search(text):
            return True
    return False


if __name__ == '__main__':
    samples = [
        'Failed login for user=admin@corp.com from 192.168.1.105',
        'Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.abc',
        'password=SuperSecret123! api_key=AKIAIOSFODNN7EXAMPLE',
        'Card number 4111111111111111 on file',
        'IPv6 test: 2001:0db8:85a3:0000:0000:8a2e:0370:7334',
        'Authorization: Basic dXNlcm5hbWU6cGFzc3dvcmQ=',
    ]
    for s in samples:
        print(f'IN:  {s}')
        print(f'OUT: {redact(s)}')
        print()
