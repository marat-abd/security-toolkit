
# Security Toolkit

[![Tests](https://github.com/marat-abd/security-toolkit/actions/workflows/tests.yml/badge.svg?branch=main)](https://github.com/marat-abd/security-toolkit/actions/workflows/tests.yml)

A lightweight Python toolkit for basic security assessment and network diagnostics.

Designed for authorized security testing, defensive security assessment, and cybersecurity learning.

## Features

- HTTP security headers analysis
- TLS/HTTPS certificate and configuration checks
- DNS resolution and IP address validation
- Basic security scoring based on HTTP security headers
- JSON security report generation
- Command-line interface
- Telegram bot for remote security checks
- SSRF protection through public IP validation and pinned-IP connections
- Automated unit tests
- Continuous integration with GitHub Actions

## Security

The toolkit includes basic SSRF protections:

- Rejects private and non-public IP addresses
- Validates DNS resolution results
- Rejects mixed public and private DNS responses
- Connects directly to validated IP addresses
- Preserves the original hostname for TLS SNI and certificate validation

HTTP redirects are not followed automatically.

## Use Cases

- Initial security assessment of systems you own or are authorized to test
- Security learning and experimentation
- Basic HTTPS and TLS diagnostics
- HTTP security headers auditing
- Automating repetitive security checks

## Tech Stack

- Python 3.10+
- Standard Python libraries
- `python-telegram-bot`
- HTTP / TLS / DNS
- pytest
- GitHub Actions
- Linux

## Installation

Clone the repository:

```bash
git clone https://github.com/marat-abd/security-toolkit.git
cd security-toolkit
```

Create and activate a virtual environment:

```bash
python3 -m venv .venv
source .venv/bin/activate
```

Install the project:

```bash
pip install -e .
```

Install test dependencies:

```bash
pip install pytest
```

## Usage

Run a security assessment:

```bash
python -m security_toolkit example.com
```

The toolkit performs:

1. DNS resolution and public IP validation
2. HTTP security headers analysis
3. TLS certificate checks
4. Security score calculation

A JSON report is saved as:

```text
security_report.json
```

## Telegram Bot

Install the Telegram bot dependency:

```bash
pip install python-telegram-bot
```

Set your Telegram bot token as an environment variable:

```bash
export TELEGRAM_BOT_TOKEN="your_bot_token"
```

Start the bot:

```bash
python bot.py
```

Keep your bot token private. Do not commit it to the repository.

## Running Tests

Run the test suite:

```bash
pytest -q
```

The project uses pytest for automated testing.

GitHub Actions automatically runs the tests on pushes and pull requests targeting the `main` branch.

## Project Status

The project is under active development.

Current focus:

- Improving security and SSRF protection
- Expanding automated test coverage
- Improving documentation
- Preparing the first release

## Roadmap

- [x] HTTP security headers checker
- [x] TLS certificate checks
- [x] DNS resolution and IP validation
- [x] CLI interface
- [x] JSON report output
- [x] Unit tests
- [x] Telegram bot
- [x] GitHub Actions CI
- [ ] Safe redirect handling with per-hop validation
- [ ] TCP connectivity checker
- [ ] Docker support
- [ ] First stable release

## Responsible Use

This tool is intended for authorized security testing and defensive purposes only.

Only use it against systems that you own or have explicit permission to assess.

The results provide a basic security assessment and should not be considered a comprehensive penetration test or security audit.

## Author

**Marat Abd**

Cybersecurity | Python | Automation

GitHub: [marat-abd](https://github.com/marat-abd)
