from security_toolkit.score import calculate_security_score


def test_calculate_security_score():
    headers_result = {
        "headers": {
            "Strict-Transport-Security": {"present": True},
            "Content-Security-Policy": {"present": True},
            "X-Content-Type-Options": {"present": False},
            "X-Frame-Options": {"present": True},
            "Referrer-Policy": {"present": False},
            "Permissions-Policy": {"present": True},
        }
    }

    result = calculate_security_score(headers_result)

    assert result["score"] == 4
    assert result["max_score"] == 6
    assert result["percentage"] == 67
