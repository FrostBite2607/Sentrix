"""
SENTRIX Redactor — Unit Tests
------------------------------
At least 15 test cases covering all redaction categories, edge cases,
and a "server safety" test that asserts no raw email or IP can reach
the server payload.

Run with:  python -m pytest tests/test_redactor.py -v
"""

import sys
import os

# Add project root to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from collector.redactor import redact, contains_sensitive


# ===================================================================
# 1–3: EMAIL REDACTION
# ===================================================================

def test_simple_email():
    """Basic email address is replaced with [EMAIL]."""
    result = redact('Contact alice@example.com for details')
    assert '[EMAIL]' in result
    assert 'alice@example.com' not in result


def test_email_with_plus_and_dots():
    """Complex email with + addressing and dots in local part."""
    result = redact('Send to john.doe+alerts@company.co.uk now')
    assert '[EMAIL]' in result
    assert 'john.doe+alerts@company.co.uk' not in result


def test_multiple_emails():
    """Multiple emails in one string are all redacted."""
    text = 'From a@b.com to c@d.org cc e@f.net'
    result = redact(text)
    assert result.count('[EMAIL]') == 3
    assert 'a@b.com' not in result


# ===================================================================
# 4–5: IPv4 REDACTION
# ===================================================================

def test_ipv4_address():
    """Standard IPv4 address is replaced with [IP]."""
    result = redact('Connection from 192.168.1.105 refused')
    assert '[IP]' in result
    assert '192.168.1.105' not in result


def test_ipv4_with_port():
    """IPv4 followed by a port number — IP is redacted, port remains."""
    result = redact('Listening on 10.0.0.42:8080')
    assert '[IP]' in result
    assert '10.0.0.42' not in result
    assert '8080' in result  # port should stay


# ===================================================================
# 6: IPv6 REDACTION
# ===================================================================

def test_ipv6_address():
    """Full IPv6 address is replaced with [IP]."""
    result = redact('Source: 2001:0db8:85a3:0000:0000:8a2e:0370:7334')
    assert '[IP]' in result
    assert '2001:0db8' not in result


# ===================================================================
# 7–8: BEARER TOKEN AND AUTH HEADER
# ===================================================================

def test_bearer_token():
    """Bearer token value is replaced with [TOKEN]."""
    text = 'Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.abc'
    result = redact(text)
    assert 'Bearer [TOKEN]' in result
    assert 'eyJhbGci' not in result


def test_authorization_header():
    """Authorization header value is redacted."""
    result = redact('Authorization: Basic dXNlcm5hbWU6cGFzc3dvcmQ=')
    assert '[TOKEN]' in result
    assert 'dXNlcm5hbWU6cGFzc3dvcmQ' not in result


# ===================================================================
# 9–10: API KEYS
# ===================================================================

def test_api_key_equals():
    """API key in key=value format is redacted."""
    result = redact('api_key=AKIAIOSFODNN7EXAMPLE')
    assert '[API_KEY]' in result
    assert 'AKIAIOSFODNN7EXAMPLE' not in result


def test_x_api_key_header():
    """x-api-key header style is redacted."""
    result = redact('x-api-key: sk_live_abcdef1234567890')
    assert '[API_KEY]' in result
    assert 'sk_live_abcdef1234567890' not in result


# ===================================================================
# 11–12: PASSWORDS AND SECRETS
# ===================================================================

def test_password_in_key_value():
    """password=... is redacted."""
    result = redact('Login failed: password=SuperSecret123!')
    assert '[PASSWORD]' in result
    assert 'SuperSecret123!' not in result


def test_secret_key():
    """secret_key=... is redacted."""
    result = redact('Config: secret_key=my_very_secret_value_here')
    assert '[API_KEY]' in result or '[PASSWORD]' in result
    assert 'my_very_secret_value_here' not in result


# ===================================================================
# 13: USERNAME
# ===================================================================

def test_username_key_value():
    """user=... is replaced with [USERNAME] (after emails are caught)."""
    result = redact('Failed for user=admin from server')
    assert '[USERNAME]' in result
    assert 'user=admin' not in result


# ===================================================================
# 14: LONG DIGIT SEQUENCES (card numbers, etc.)
# ===================================================================

def test_long_digit_sequence():
    """10+ digit number (like a credit card) is replaced with [DIGITS]."""
    result = redact('Card number 4111111111111111 on file')
    assert '[DIGITS]' in result
    assert '4111111111111111' not in result


# ===================================================================
# 15: CLEAN TEXT IS UNCHANGED
# ===================================================================

def test_no_sensitive_data_unchanged():
    """Text without any sensitive data passes through unmodified."""
    text = 'CPU usage is at 87% and memory at 2.1 GB'
    assert redact(text) == text


# ===================================================================
# 16–18: TRICKY EDGE CASES
# ===================================================================

def test_multiple_types_in_one_line():
    """Line with email, IP, and password — all three are redacted."""
    text = 'user=admin@corp.com from 192.168.1.1 password=abc123'
    result = redact(text)
    assert 'admin@corp.com' not in result
    assert '192.168.1.1' not in result
    assert 'abc123' not in result
    # The sensitive data is gone — redacted via email or username placeholder
    assert '[EMAIL]' in result or '[USERNAME]' in result
    assert '[IP]' in result
    assert '[PASSWORD]' in result


def test_already_redacted_text_stable():
    """Already-redacted text should not be re-mangled by a second pass."""
    text = 'Failed for user=[USERNAME] from [IP] password=[PASSWORD]'
    result = redact(text)
    # The placeholders themselves should survive unchanged
    assert '[USERNAME]' in result
    assert '[IP]' in result
    assert '[PASSWORD]' in result


def test_email_in_user_field():
    """user=someone@domain.com — email is redacted before username pattern
    can grab it, so the raw email must be gone regardless of which
    placeholder wins."""
    text = 'Failed for user=admin@corp.com from server'
    result = redact(text)
    # The raw email must be gone
    assert 'admin@corp.com' not in result
    assert '[EMAIL]' in result or '[USERNAME]' in result


# ===================================================================
# 19: CONTAINS_SENSITIVE HELPER
# ===================================================================

def test_contains_sensitive_true():
    """contains_sensitive correctly detects raw PII."""
    assert contains_sensitive('admin@corp.com')
    assert contains_sensitive('from 10.0.0.1')
    assert contains_sensitive('Bearer eyJhbGciOiJIUzI1NiJ9.test1234')


def test_contains_sensitive_false_on_clean():
    """contains_sensitive returns False for clean text."""
    assert not contains_sensitive('CPU at 42%')
    assert not contains_sensitive('[EMAIL] was redacted')


# ===================================================================
# 20: SERVER SAFETY — the critical privacy assertion
# ===================================================================

def test_server_payload_has_no_raw_pii():
    """
    Simulate what the agent sends to the server: redact a batch of
    realistic log lines and assert that NO raw email or IP address
    survives in the output.  This test MUST pass for the privacy
    guarantee to hold.
    """
    raw_lines = [
        'Failed login for user=admin@corp.com from 192.168.1.105',
        'Error on 10.0.0.42: api_key=AKIAIOSFODNN7EXAMPLE',
        'SMTP to alice@example.org via 172.16.0.5',
        'Bearer eyJhbGciOiJIUzI1NiJ9.test session for bob@test.io',
        'password=hunter2 for user=operator from 203.0.113.42',
        'IPv6 source 2001:0db8:85a3:0000:0000:8a2e:0370:7334',
        'Card 4111111111111111 for user=finance@bigcorp.com',
    ]

    for raw in raw_lines:
        sanitised = redact(raw)
        # No raw email should survive
        assert '@corp.com' not in sanitised, f'Email leaked: {sanitised}'
        assert '@example.org' not in sanitised, f'Email leaked: {sanitised}'
        assert '@test.io' not in sanitised, f'Email leaked: {sanitised}'
        assert '@bigcorp.com' not in sanitised, f'Email leaked: {sanitised}'
        # No raw IPv4 should survive
        assert '192.168.1.105' not in sanitised, f'IP leaked: {sanitised}'
        assert '10.0.0.42' not in sanitised, f'IP leaked: {sanitised}'
        assert '172.16.0.5' not in sanitised, f'IP leaked: {sanitised}'
        assert '203.0.113.42' not in sanitised, f'IP leaked: {sanitised}'
        # The result should be clean
        assert not contains_sensitive(sanitised), \
            f'Sensitive data survived redaction: {sanitised}'
