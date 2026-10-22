
import socket

from bot import is_public_host


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
