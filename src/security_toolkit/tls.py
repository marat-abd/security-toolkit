import socket
import ssl
from urllib.parse import urlparse


def check_tls_certificate(url: str) -> dict:
    """Get basic TLS certificate information."""

    if not url.startswith(("http://", "https://")):
        url = "https://" + url

    parsed = urlparse(url)
    hostname = parsed.hostname

    if not hostname:
        return {"url": url, "error": "Invalid URL"}

    context = ssl.create_default_context()

    try:
        with socket.create_connection((hostname, 443), timeout=10) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as secure_sock:
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

    except (socket.timeout, socket.error, ssl.SSLError) as error:
        return {
            "hostname": hostname,
            "error": str(error),
        }
