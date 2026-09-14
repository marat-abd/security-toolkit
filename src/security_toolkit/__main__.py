import argparse
import json
from urllib.parse import urlparse

from security_toolkit.headers import check_security_headers
from security_toolkit.tls import check_tls_certificate
from security_toolkit.dns import lookup_dns

def save_json_report(result: dict, filename: str) -> None:
    with open(filename, "w", encoding="utf-8") as file:
        json.dump(result, file, indent=2, ensure_ascii=False)

def run_assessment(url: str) -> dict:
    headers_result = check_security_headers(url)
    tls_result = check_tls_certificate(url)

    hostname = urlparse(url if "://" in url else f"https://{url}").hostname
    dns_result = lookup_dns(hostname)

    return {
        "headers": headers_result,
        "tls": tls_result,
        "dns": dns_result,
    }

def main():
    parser = argparse.ArgumentParser(
        description="Basic security assessment toolkit"
    )

    parser.add_argument(
        "url",
        help="Target URL or hostname"
    )

    parser.add_argument(
        "--json",
        default="security_report.json",
        help="JSON report filename"
    )

    parser.add_argument(
        "--version",
        action="version",
        version="security-toolkit 0.1.0"
    )

    args = parser.parse_args()

    url = args.url

    report = run_assessment(url)

    headers_result = report["headers"]
    tls_result = report["tls"]
    dns_result = report["dns"]

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

    save_json_report(report, args.json)
    print(f"\nJSON report saved to {args.json}")

if __name__ == "__main__":
    main()
