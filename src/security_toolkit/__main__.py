import sys

from security_toolkit.headers import check_security_headers
from security_toolkit.tls import check_tls_certificate
from security_toolkit.dns import lookup_dns


def main():
    if len(sys.argv) != 2:
        print("Usage: python -m security_toolkit <URL>")
        sys.exit(1)

    url = sys.argv[1]
    hostname = url.replace("https://", "").replace("http://", "").split("/")[0]
    dns_result = lookup_dns(hostname)

    headers_result = check_security_headers(url)
    tls_result = check_tls_certificate(url)

    print("\nSecurity Headers Report")
    print("=" * 40)

    if "error" in headers_result:
        print(headers_result["error"])
    else:
        print(f"URL: {headers_result['url']}")
        print(f"Status: {headers_result['status_code']}\n")

        for header, data in headers_result["headers"].items():
            status = "PRESENT" if data["present"] else "MISSING"
            print(f"[{status}] {header}")

    print("\nTLS Certificate Report")
    print("=" * 40)

    if "error" in tls_result:
        print(tls_result["error"])
    else:
        print(f"Hostname: {tls_result['hostname']}")
        print(f"TLS Version: {tls_result['tls_version']}")
        print(f"Cipher: {tls_result['cipher']}")
        print(f"Valid from: {tls_result['not_before']}")
        print(f"Valid until: {tls_result['not_after']}")

    print("\nDNS Report")
    print("=" * 40)

    if "error" in dns_result:
        print(dns_result["error"])
    else:
        print(f"Hostname: {dns_result['hostname']}")
        print(f"IPv4: {', '.join(dns_result['ipv4']) or 'None'}")
        print(f"IPv6: {', '.join(dns_result['ipv6']) or 'None'}")

if __name__ == "__main__":
    main()
