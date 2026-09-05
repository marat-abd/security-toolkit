from security_toolkit.headers import check_security_headers


def test_check_security_headers():
    result = check_security_headers("https://example.com")

    assert result["url"] == "https://example.com"
    assert "status_code" in result
    assert "headers" in result

    assert "Strict-Transport-Security" in result["headers"]
    assert "Content-Security-Policy" in result["headers"]
