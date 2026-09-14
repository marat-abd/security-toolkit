from security_toolkit.__main__ import run_assessment


def test_run_assessment():
    result = run_assessment("example.com")

    assert "headers" in result
    assert "tls" in result
    assert "dns" in result
