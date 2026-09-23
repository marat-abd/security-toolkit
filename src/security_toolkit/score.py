def calculate_security_score(headers_result: dict) -> dict:
    """Calculate a simple security score based on HTTP security headers."""

    if "error" in headers_result:
        return {
            "score": 0,
            "max_score": 0,
            "percentage": 0,
            "level": "UNKNOWN",
        }

    headers = headers_result.get("headers", {})

    score = sum(
        1
        for data in headers.values()
        if data.get("present") is True
    )

    max_score = len(headers)
    percentage = round((score / max_score) * 100) if max_score else 0

    if percentage <= 33:
        level = "LOW"
    elif percentage <= 66:
        level = "MEDIUM"
    else:
        level = "HIGH"

    return {
        "score": score,
        "max_score": max_score,
        "percentage": percentage,
        "level": level,
    }
