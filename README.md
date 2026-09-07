# Security Toolkit

A lightweight Python toolkit for basic security assessment and network diagnostics.

The project is designed for authorized security testing, learning and defensive security assessment.

## Features

* HTTP security headers analysis
* TLS/HTTPS configuration checks
* DNS information lookup
* Basic TCP port connectivity checks
* CLI interface
* Human-readable security reports

## Use Cases

The toolkit can be used for:

* Initial security assessment of systems you own or are authorized to test
* Security learning and experimentation
* Quick diagnostic checks
* Automating repetitive security tasks

## Tech Stack

* Python 3
* Standard Python libraries
* HTTP / TLS / DNS
* Linux
* Git

## Installation

Clone the repository:

    git clone git@github-marat:marat-abd/security-toolkit.git
    cd security-toolkit

Create a virtual environment:

    python3 -m venv .venv
    source .venv/bin/activate

Install the project:

    pip install -e .

## Usage

Run a security assessment:

    python -m security_toolkit example.com

The toolkit checks:

- HTTP security headers
- TLS certificate information
- DNS records

A JSON report is saved as:

    security_report.json

## Project Status

🚧 Work in progress

The project is being developed incrementally as part of my cybersecurity portfolio.

## Roadmap

* [ ] HTTP security headers checker
* [ ] TLS certificate information
* [ ] DNS information
* [ ] TCP connectivity checker
* [ ] CLI interface
* [ ] JSON report output
* [ ] Unit tests
* [ ] Docker support

## Responsible Use

This tool is intended for authorized security testing and defensive purposes only.

Only use it against systems that you own or have explicit permission to assess.

## Author

**Marat Abd**

Cybersecurity | Python | Automation

GitHub: [marat-abd](https://github.com/marat-abd)
