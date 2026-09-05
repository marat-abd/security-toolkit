from security_toolkit.tls import check_tls_certificate


def test_check_tls_certificate():
    result = check_tls_certificate("https://example.com")

    assert result["hostname"] == "example.com"
    assert result["tls_version"].startswith("TLS")
    assert result["cipher"]
    assert result["not_before"]
    assert result["not_after"]
