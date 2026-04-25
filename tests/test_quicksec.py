import sys
import datetime
from unittest.mock import patch, MagicMock

import pytest

sys.path.insert(0, "src")
from quicksec import get_cn, parse_ssl_date, fetch, check_https_redirect


# ── get_cn ────────────────────────────────────────────────────────────────────

def test_get_cn_returns_common_name():
    name = [(("commonName", "example.com"),)]
    assert get_cn(name) == "example.com"

def test_get_cn_multiple_fields():
    name = [
        (("countryName", "US"),),
        (("organizationName", "Example Inc"),),
        (("commonName", "example.com"),),
    ]
    assert get_cn(name) == "example.com"

def test_get_cn_missing_returns_unknown():
    assert get_cn([]) == "unknown"
    assert get_cn([(("countryName", "US"),)]) == "unknown"


# ── parse_ssl_date ────────────────────────────────────────────────────────────

def test_parse_ssl_date_returns_utc_aware():
    dt = parse_ssl_date("Jun  3 00:00:00 2026 GMT")
    assert dt.tzinfo == datetime.timezone.utc
    assert dt.year == 2026
    assert dt.month == 6
    assert dt.day == 3

def test_parse_ssl_date_single_digit_day():
    dt = parse_ssl_date("Jan  1 12:00:00 2025 GMT")
    assert dt.day == 1
    assert dt.month == 1


# ── fetch ─────────────────────────────────────────────────────────────────────

def test_fetch_returns_response_on_success():
    mock_resp = MagicMock()
    with patch("quicksec.requests.get", return_value=mock_resp):
        resp, err = fetch("https://example.com")
    assert resp is mock_resp
    assert err is None

def test_fetch_returns_error_on_exception():
    import requests as req
    with patch("quicksec.requests.get", side_effect=req.exceptions.ConnectionError("timeout")):
        resp, err = fetch("https://example.com")
    assert resp is None
    assert "timeout" in err


# ── check_https_redirect ──────────────────────────────────────────────────────

def test_check_https_redirect_true_when_final_url_is_https():
    mock_resp = MagicMock()
    mock_resp.url = "https://example.com/"
    with patch("quicksec.requests.get", return_value=mock_resp):
        assert check_https_redirect("example.com") is True

def test_check_https_redirect_false_when_stays_on_http():
    mock_resp = MagicMock()
    mock_resp.url = "http://example.com/"
    with patch("quicksec.requests.get", return_value=mock_resp):
        assert check_https_redirect("example.com") is False

def test_check_https_redirect_false_on_connection_error():
    import requests as req
    with patch("quicksec.requests.get", side_effect=req.exceptions.ConnectionError):
        assert check_https_redirect("example.com") is False
