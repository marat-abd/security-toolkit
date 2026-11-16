import socket
import pytest

from bot import is_public_host
from security_toolkit.network import resolve_public_ips

def test_blocks_localhost():
    assert is_public_host("127.0.0.1") is False


def test_blocks_unresolvable_hostname(monkeypatch):
    def fake_getaddrinfo(*args, **kwargs):
        raise socket.gaierror("Name resolution failed")

    monkeypatch.setattr(socket, "getaddrinfo", fake_getaddrinfo)

    assert is_public_host("nonexistent.invalid") is False


def test_blocks_private_ip(monkeypatch):
    def fake_getaddrinfo(*args, **kwargs):
        return [
            (socket.AF_INET, socket.SOCK_STREAM, 6, "",
             ("192.168.1.1", 0))
        ]

    monkeypatch.setattr(socket, "getaddrinfo", fake_getaddrinfo)

    assert is_public_host("internal.example") is False


def test_blocks_invalid_ip_response(monkeypatch):
    def fake_getaddrinfo(*args, **kwargs):
        return [
            (socket.AF_INET, socket.SOCK_STREAM, 6, "",
             ("invalid-ip", 0))
        ]

    monkeypatch.setattr(socket, "getaddrinfo", fake_getaddrinfo)

    assert is_public_host("example.com") is False


def test_blocks_empty_dns_response(monkeypatch):
    monkeypatch.setattr(socket, "getaddrinfo", lambda *args, **kwargs: [])

    assert is_public_host("example.com") is False


def test_accepts_public_ip(monkeypatch):
    def fake_getaddrinfo(*args, **kwargs):
        return [
            (socket.AF_INET, socket.SOCK_STREAM, 6, "",
             ("8.8.8.8", 0))
        ]

    monkeypatch.setattr(socket, "getaddrinfo", fake_getaddrinfo)

    assert resolve_public_ips("example.com") == ["8.8.8.8"]


def test_rejects_private_ip(monkeypatch):
    def fake_getaddrinfo(*args, **kwargs):
        return [
            (socket.AF_INET, socket.SOCK_STREAM, 6, "",
             ("192.168.1.1", 0))
        ]

    monkeypatch.setattr(socket, "getaddrinfo", fake_getaddrinfo)

    with pytest.raises(ValueError):
        resolve_public_ips("internal.example")


def test_rejects_empty_dns_response(monkeypatch):
    monkeypatch.setattr(socket, "getaddrinfo", lambda *args, **kwargs: [])

    with pytest.raises(ValueError):
        resolve_public_ips("example.com")


def test_accepts_multiple_public_ips(monkeypatch):
    def fake_getaddrinfo(*args, **kwargs):
        return [
            (socket.AF_INET, socket.SOCK_STREAM, 6, "",
             ("8.8.8.8", 0)),
            (socket.AF_INET, socket.SOCK_STREAM, 6, "",
             ("1.1.1.1", 0)),
        ]

    monkeypatch.setattr(socket, "getaddrinfo", fake_getaddrinfo)

    assert resolve_public_ips("example.com") == [
        "1.1.1.1",
        "8.8.8.8",
    ]


def test_rejects_mixed_public_and_private_ips(monkeypatch):
    def fake_getaddrinfo(*args, **kwargs):
        return [
            (socket.AF_INET, socket.SOCK_STREAM, 6, "",
             ("8.8.8.8", 0)),
            (socket.AF_INET, socket.SOCK_STREAM, 6, "",
             ("192.168.1.1", 0)),
        ]

    monkeypatch.setattr(socket, "getaddrinfo", fake_getaddrinfo)

    with pytest.raises(ValueError):
        resolve_public_ips("example.com")
