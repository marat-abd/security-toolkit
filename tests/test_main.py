from unittest.mock import patch

from security_toolkit.__main__ import run_assessment


@patch("security_toolkit.__main__.calculate_security_score")
@patch("security_toolkit.__main__.lookup_dns")
@patch("security_toolkit.__main__.check_tls_certificate")
@patch("security_toolkit.__main__.check_security_headers")
@patch("security_toolkit.__main__.resolve_public_ips")
def test_run_assessment(
    mock_resolve,
    mock_headers,
    mock_tls,
    mock_dns,
    mock_score,
):
    mock_resolve.return_value = ["93.184.216.34"]
    mock_headers.return_value = {"status_code": 200}
    mock_tls.return_value = {"tls_version": "TLSv1.3"}
    mock_dns.return_value = {
        "hostname": "example.com",
        "ipv4": ["93.184.216.34"],
        "ipv6": [],
    }
    mock_score.return_value = {"score": 100}

    result = run_assessment("example.com")

    assert "headers" in result
    assert "tls" in result
    assert "dns" in result

    mock_resolve.assert_called_once_with("example.com")
    mock_headers.assert_called_once_with(
        "https://example.com",
        ["93.184.216.34"],
    )
