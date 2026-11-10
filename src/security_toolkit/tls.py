
import socket
import ssl
import ipaddress
from urllib.parse import urlparse


def check_tls_certificate(url: str, ips: list[str] | None = None) -> dict:
    """Get TLS certificate information using pre-validated IP addresses."""

    if not url.startswith(("http://", "https://")):
        url = "https://" + url

    parsed = urlparse(url)
    hostname = parsed.hostname
    port = parsed.port or 443

    if not hostname:
        return {"url": url, "error": "Invalid URL"}

    if ips is None:
        return {
            "hostname": hostname,
            "error": "Validated IP addresses are required",
        }

    if not ips:
        return {
            "hostname": hostname,
            "error": "No validated IP addresses provided",
        }

    context = ssl.create_default_context()
    errors = []

    for ip in ips:
        try:
            address = ipaddress.ip_address(ip)
            if not address.is_global:
                raise ValueError("Non-public IP address")

            with socket.create_connection((str(address), port), timeout=10) as sock:
                with context.wrap_socket(
                    sock,
                    server_hostname=hostname,
                ) as secure_sock:
                    certificate = secure_sock.getpeercert()

                    return {
                        "hostname": hostname,
                        "tls_version": secure_sock.version(),
                        "cipher": secure_sock.cipher()[0],
                        "issuer": certificate.get("issuer"),
                        "subject": certificate.get("subject"),
                        "not_before": certificate.get("notBefore"),
                        "not_after": certificate.get("notAfter"),
                    }

        except (socket.timeout, socket.error, ssl.SSLError, ValueError) as error:
            errors.append(f"{ip}: {error}")

    return {
        "hostname": hostname,
        "error": "; ".join(errors),
    }
