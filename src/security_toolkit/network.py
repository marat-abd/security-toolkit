import ipaddress
import socket


def resolve_public_ips(hostname: str) -> list[str]:
    """Resolve hostname once and reject non-public IP addresses."""

    try:
        addresses = socket.getaddrinfo(
            hostname,
            None,
            type=socket.SOCK_STREAM,
        )

        if not addresses:
            raise ValueError("No IP addresses found")

        ips = sorted({
            str(ipaddress.ip_address(address[4][0]))
            for address in addresses
        })

        if not ips:
            raise ValueError("No IP addresses found")

        for ip in ips:
            if not ipaddress.ip_address(ip).is_global:
                raise ValueError("Non-public IP address detected")

        return ips

    except (socket.gaierror, ValueError, OSError) as error:
        raise ValueError(
            f"Host validation failed: {error}"
        ) from error
