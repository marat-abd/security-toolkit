
from unittest.mock import MagicMock, patch

from security_toolkit.tls import check_tls_certificate


def test_check_tls_certificate():
    certificate = {
        "issuer": ((("commonName", "Example CA"),),),
        "subject": ((("commonName", "example.com"),),),
        "notBefore": "Jan  1 00:00:00 2026 GMT",
        "notAfter": "Jan  1 00:00:00 2027 GMT",
    }

    mock_secure_socket = MagicMock()
    mock_secure_socket.getpeercert.return_value = certificate
    mock_secure_socket.version.return_value = "TLSv1.3"
    mock_secure_socket.cipher.return_value = ("TLS_AES_256_GCM_SHA384", "TLSv1.3", 256)

    mock_context = MagicMock()
    mock_context.wrap_socket.return_value.__enter__.return_value = mock_secure_socket

    with patch("security_toolkit.tls.ssl.create_default_context", return_value=mock_context), \
         patch("security_toolkit.tls.socket.create_connection") as mock_connection:

        mock_connection.return_value.__enter__.return_value = MagicMock()

        result = check_tls_certificate(
            "https://example.com",
            ["93.184.216.34"],
        )

    assert result["hostname"] == "example.com"
    assert result["tls_version"] == "TLSv1.3"
    assert result["cipher"] == "TLS_AES_256_GCM_SHA384"
    assert result["not_before"]
    assert result["not_after"]

    mock_connection.assert_called_once_with(("93.184.216.34", 443), timeout=10)
