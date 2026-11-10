
def lookup_dns(hostname: str, addresses: list[str] | None = None) -> dict:
    """Get DNS information from supplied, pre-resolved addresses."""

    hostname = hostname.strip()

    if not hostname:
        return {"hostname": hostname, "error": "Hostname is empty"}

    if addresses is None:
        return {
            "hostname": hostname,
            "error": "Resolved IP addresses are required",
        }

    ipv4_addresses = sorted({
        ip for ip in addresses if "." in ip
    })

    ipv6_addresses = sorted({
        ip for ip in addresses if ":" in ip
    })

    return {
        "hostname": hostname,
        "ipv4": ipv4_addresses,
        "ipv6": ipv6_addresses,
    }
