from unittest.mock import MagicMock, patch

from security_toolkit.headers import (
    PinnedHTTPConnection,
    PinnedHTTPSConnection,
    check_security_headers,
)

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


def test_http_connection_uses_validated_ip():
    fake_socket = MagicMock()

    with patch(
        "security_toolkit.headers.socket.create_connection",
        return_value=fake_socket,
    ) as mock_connect:

        connection = PinnedHTTPConnection(
            "example.com",
            "93.184.216.34",
            80,
        )
        connection.connect()

    mock_connect.assert_called_once_with(
        ("93.184.216.34", 80),
        10,
    )
    assert connection.sock is fake_socket


def test_https_connection_uses_validated_ip_and_hostname_for_sni():
    fake_socket = MagicMock()
    fake_tls_socket = MagicMock()

    with (
        patch(
            "security_toolkit.headers.socket.create_connection",
            return_value=fake_socket,
        ) as mock_connect,
        patch(
            "security_toolkit.headers.ssl.create_default_context"
        ) as mock_context,
    ):
        mock_context.return_value.wrap_socket.return_value = fake_tls_socket

        connection = PinnedHTTPSConnection(
            "example.com",
            "93.184.216.34",
            443,
        )
        connection.connect()

    mock_connect.assert_called_once_with(
        ("93.184.216.34", 443),
        10,
    )

    mock_context.return_value.wrap_socket.assert_called_once_with(
        fake_socket,
        server_hostname="example.com",
    )

    assert connection.sock is fake_tls_socket


def test_check_security_headers_rejects_private_ip():
    result = check_security_headers(
        "https://example.com",
        ["127.0.0.1"],
    )

    assert result["error"] == "Non-public IP address rejected"
