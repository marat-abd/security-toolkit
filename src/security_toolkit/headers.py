import http.client
import ipaddress
import socket
import ssl
from urllib.parse import urlparse


SECURITY_HEADERS = {
    "Strict-Transport-Security": "HSTS",
    "Content-Security-Policy": "CSP",
    "X-Content-Type-Options": "X-Content-Type-Options",
    "X-Frame-Options": "X-Frame-Options",
    "Referrer-Policy": "Referrer-Policy",
    "Permissions-Policy": "Permissions-Policy",
}


class PinnedHTTPConnection(http.client.HTTPConnection):
    """HTTP connection that connects directly to a validated IP."""

    def __init__(self, hostname, ip, port, timeout=10):
        super().__init__(hostname, port=port, timeout=timeout)
        self.ip = ip

    def connect(self):
        self.sock = socket.create_connection(
            (self.ip, self.port),
            self.timeout,
        )


class PinnedHTTPSConnection(http.client.HTTPSConnection):
    """HTTPS connection that connects to a validated IP using the original hostname."""

    def __init__(self, hostname, ip, port, timeout=10):
        super().__init__(
            hostname,
            port=port,
            timeout=timeout,
            context=ssl.create_default_context(),
        )
        self.ip = ip

    def connect(self):
        sock = socket.create_connection(
            (self.ip, self.port),
            self.timeout,
        )
        self.sock = self._context.wrap_socket(
            sock,
            server_hostname=self.host,
        )


def check_security_headers(url: str, ips: list[str] | None = None) -> dict:
    """Check HTTP security headers using pre-validated IP addresses."""

    if not url.startswith(("http://", "https://")):
        url = "https://" + url

    parsed = urlparse(url)
    hostname = parsed.hostname

    if parsed.scheme not in ("http", "https") or not hostname:
        return {"url": url, "error": "Invalid URL"}

    if parsed.username or parsed.password:
        return {"url": url, "error": "Credentials in URL are not allowed"}

    if not ips:
        return {
            "url": url,
            "error": "Validated IP addresses are required",
        }

    try:
        port = parsed.port or (443 if parsed.scheme == "https" else 80)

        for ip in ips:
            address = ipaddress.ip_address(ip)
            if not address.is_global:
                return {
                    "url": url,
                    "error": "Non-public IP address rejected",
                }

        path = parsed.path or "/"
        if parsed.query:
            path += "?" + parsed.query

        host_header = f"[{hostname}]" if ":" in hostname else hostname
        default_port = 443 if parsed.scheme == "https" else 80

        if port != default_port:
            host_header += f":{port}"

    except ValueError as error:
        return {"url": url, "error": f"Invalid URL or IP: {error}"}

    errors = []

    for ip in ips:
        connection = None

        try:
            if parsed.scheme == "https":
                connection = PinnedHTTPSConnection(hostname, ip, port)
            else:
                connection = PinnedHTTPConnection(hostname, ip, port)

            connection.request(
                "GET",
                path,
                headers={
                    "Host": host_header,
                    "User-Agent": "SecurityToolkit/1.0",
                },
            )

            response = connection.getresponse()
            headers = response.headers

            result = {
                name: {
                    "present": name in headers,
                    "value": headers.get(name),
                }
                for name in SECURITY_HEADERS
            }

            return {
                "url": url,
                "status_code": response.status,
                "headers": result,
            }

        except (OSError, ssl.SSLError, http.client.HTTPException) as error:
            errors.append(f"{ip}: {error}")

        finally:
            if connection is not None:
                connection.close()

    return {
        "url": url,
        "error": "Connection failed: " + "; ".join(errors),
    }


if __name__ == "__main__":
    target = input("Enter URL: ").strip()
    print("Run this module through the main assessment so IP validation is performed.")
