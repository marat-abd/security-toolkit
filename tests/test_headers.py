from unittest.mock import MagicMock, patch

from security_toolkit.headers import check_security_headers


def test_check_security_headers():
    mock_response = MagicMock()
    mock_response.status = 200
    mock_response.headers = {
        "Strict-Transport-Security": "max-age=31536000",
        "Content-Security-Policy": "default-src 'self'",
    }

    with patch(
        "security_toolkit.headers.PinnedHTTPSConnection"
    ) as mock_connection:

        mock_connection.return_value.getresponse.return_value = mock_response

        result = check_security_headers(
            "https://example.com",
            ["93.184.216.34"],
        )

    assert result["url"] == "https://example.com"
    assert result["status_code"] == 200
    assert result["headers"]["Strict-Transport-Security"]["present"]
    assert result["headers"]["Content-Security-Policy"]["present"]
    assert not result["headers"]["X-Frame-Options"]["present"]
