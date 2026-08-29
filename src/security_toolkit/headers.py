from urllib.request import Request, urlopen
from urllib.error import URLError, HTTPError

SECURITY_HEADERS = {
"Strict-Transport-Security": "HSTS",
"Content-Security-Policy": "CSP",
"X-Content-Type-Options": "X-Content-Type-Options",
"X-Frame-Options": "X-Frame-Options",
"Referrer-Policy": "Referrer-Policy",
"Permissions-Policy": "Permissions-Policy",
}

def check_security_headers(url: str) -> dict:
"""Check whether common HTTP security headers are present."""

```
if not url.startswith(("http://", "https://")):
    url = "https://" + url

request = Request(
    url,
    headers={"User-Agent": "SecurityToolkit/1.0"},
    method="GET",
)

try:
    with urlopen(request, timeout=10) as response:
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

except HTTPError as error:
    return {
        "url": url,
        "error": f"HTTP error: {error.code}",
    }

except URLError as error:
    return {
        "url": url,
        "error": f"Connection error: {error.reason}",
    }
```

if **name** == "**main**":
target = input("Enter URL: ").strip()

```
result = check_security_headers(target)

print("\nSecurity Headers Report")
print("=" * 40)

if "error" in result:
    print(result["error"])
else:
    print(f"URL: {result['url']}")
    print(f"Status: {result['status_code']}\n")

    for header, data in result["headers"].items():
        status = "PRESENT" if data["present"] else "MISSING"
        print(f"[{status}] {header}")

        if data["value"]:
            print(f"  Value: {data['value']}")
```
