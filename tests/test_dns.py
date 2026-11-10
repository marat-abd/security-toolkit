
from security_toolkit.dns import lookup_dns


def test_lookup_dns():
    result = lookup_dns(
        "example.com",
        ["93.184.216.34", "2606:2800:220:1:248:1893:25c8:1946"],
    )

    assert result["hostname"] == "example.com"
    assert result["ipv4"] == ["93.184.216.34"]
    assert result["ipv6"] == ["2606:2800:220:1:248:1893:25c8:1946"]
