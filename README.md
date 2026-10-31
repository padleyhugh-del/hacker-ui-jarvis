# J.A.R.V.I.S. — Security Dashboard

A local Flask-based security research dashboard designed for Kali Linux and WSL.
J.A.R.V.I.S. brings supported security tools and lookup workflows into one browser interface.

## Features

The dashboard includes pages for supported workflows such as:

- Shodan search and host lookups
- Sherlock
- SpiderFoot
- Nuclei
- SQLMap
- BBOT
- Recon-ng
- PhoneInfoga
- Evilginx configuration checks
- Domain and related dashboard utilities

Availability of each feature depends on its required external tool, configuration, and credentials.

## Requirements

- Kali Linux or a compatible Linux distribution
- Python 3.10 or newer
- pip
- The external tools you want to use
- API credentials for services that require them

Some integrations may require additional setup and may not work until their external tools are installed.

## Installation

Clone the repository:

```bash
git clone https://github.com/padleyhugh-del/hacker-ui-jarvis.git
cd hacker-ui-jarvis
```

Create and activate a virtual environment:

```bash
python3 -m venv .venv
source .venv/bin/activate
```

Install Python dependencies:

```bash
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
```

Start the dashboard:

```bash
python app.py
```

Open the local dashboard in your browser:

http://127.0.0.1:5050

Stop the server with `Ctrl+C`.

## Shodan configuration

The Shodan integration supports the `SHODAN_API_KEY` environment variable or the key stored by the Shodan CLI in `~/.shodan/api_key`.

To configure the Shodan CLI, install the Shodan package and run:

```bash
shodan init YOUR_OWN_SHODAN_API_KEY
```

Replace the placeholder with your own key locally. Never commit API keys or share them in screenshots, issues, or chat messages.

## Security notes

- The dashboard is intended for local use. Keep the server bound to `127.0.0.1`.
- Do not expose the dashboard directly to the public internet.
- External tools and services may have their own authentication, permissions, usage limits, and installation requirements.
- Only use security tools against systems you own or are explicitly authorized to assess.
- Review configuration and tool behavior before enabling integrations.

## Disclaimer

This project is provided for educational, authorized security research, and defensive testing. You are responsible for complying with applicable laws, service terms, and authorization requirements.

## Contributing

Issues and pull requests are welcome. Please do not include API keys, passwords, personal data, scan results, or other sensitive information in contributions.
