import sys

from security_toolkit.headers import check_security_headers


def main():
    if len(sys.argv) != 2:
        print("Usage: python -m security_toolkit <URL>")
        sys.exit(1)

    url = sys.argv[1]
    result = check_security_headers(url)

    print("\nSecurity Headers Report")
    print("=" * 40)

    if "error" in result:
        print(result["error"])
        sys.exit(1)

    print(f"URL: {result['url']}")
    print(f"Status: {result['status_code']}\n")

    for header, data in result["headers"].items():
        status = "PRESENT" if data["present"] else "MISSING"
        print(f"[{status}] {header}")


if __name__ == "__main__":
    main()
