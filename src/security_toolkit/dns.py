import socket


def lookup_dns(hostname: str) -> dict:
    """Get basic DNS information for a hostname."""

    hostname = hostname.strip()

    if not hostname:
        return {"hostname": hostname, "error": "Hostname is empty"}

    try:
        addresses = socket.getaddrinfo(
            hostname,
            None,
            type=socket.SOCK_STREAM,
        )

        ipv4_addresses = sorted(
            {
                address[4][0]
                for address in addresses
                if "." in address[4][0]
            }
        )

        ipv6_addresses = sorted(
            {
                address[4][0]
                for address in addresses
                if ":" in address[4][0]
            }
        )

        return {
            "hostname": hostname,
            "ipv4": ipv4_addresses,
            "ipv6": ipv6_addresses,
        }

    except socket.gaierror as error:
        return {
            "hostname": hostname,
            "error": f"DNS lookup failed: {error}",
        }
