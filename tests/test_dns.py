from security_toolkit.dns import lookup_dns


def test_lookup_dns():
    result = lookup_dns("example.com")

    assert result["hostname"] == "example.com"
    assert "ipv4" in result
    assert "ipv6" in result
    assert isinstance(result["ipv4"], list)
    assert isinstance(result["ipv6"], list)
