OSINT Pro

Professional public-source intelligence toolkit for authorized username, email, and phone investigations.

Features

Username checks across supported platforms

Email validation, disposable detection, MX/DNS checks

Phone validation, region, carrier, line type, and timezone

Optional Sherlock, Maigret, Holehe, and PhoneInfoga integration

Console, JSON, and CSV output

Concurrent requests with retries and configurable timeouts

YAML configuration

Evidence-oriented results with confidence levels

Requirements

Python 3.10+

Internet access

Install dependencies:

python -m pip install aiohttp phonenumbers dnspython rich tenacity pyyaml colorama requests

Optional tools:

python -m pip install sherlock-project maigret holehe

Installation

git clone <repository-url>
cd osint-pro

python -m venv osint-env

Windows:

osint-env\Scripts\activate

Linux/macOS:

source osint-env/bin/activate

Usage

Username:

python osint_pro.py -u johndoe

Email:

python osint_pro.py -e target@example.com

Phone:

python osint_pro.py -p +14155552671 --region US

Combined:

python osint_pro.py -u johndoe -e target@example.com -p +14155552671 --external -o json,csv

Options

Option

Description

-u

Username

-e

Email

-p

Phone number

--region

Phone region, such as US

--external

Enable external tools

-o

Output formats: json,csv

-c

YAML config file

-v

Verbose output

Configuration

Example config.yaml:

timeout: 12
max_concurrent: 15
retries: 3
output_dir: osint_results

sherlock_path: sherlock
maigret_path: maigret
holehe_path: holehe
phoneinfoga_path: phoneinfoga

Run with a config file:

python osint_pro.py -u johndoe -c config.yaml

Supported Platforms

Instagram, Snapchat, TikTok, X, Reddit, GitHub, YouTube, Twitch, Pinterest, Steam, LinkedIn, and other configured sources.

Results

Results may include:

FOUND

NOT FOUND

UNCERTAIN

Confidence: HIGH, MEDIUM, or LOW

Supporting evidence

Automated findings are leads. Verify important results manually.

Output

Default results are displayed in the console.

Reports can be exported as:

osint_results/
├── results.json
└── results.csv

Troubleshooting

Use:

python -m pip --version
python -m pip list

Windows:

where python
where pip

Linux/macOS:

which python
which pip

For phone lookups, use international E.164 format when possible:

+14155552671

If requests fail or sites rate-limit you, reduce max_concurrent and respect the target service's limits.

Extending

Add or modify username platforms in the project's platform configuration.

The toolkit is designed to support additional modules, external tools, output formats, and data sources without changing the core workflow.

Security and Legal

Use OSINT Pro only for lawful, authorized public-source research.

Do not use it to:

Bypass authentication or access controls

Obtain private information

Perform credential attacks

Abuse services or evade rate limits

Violate applicable laws or terms of service

Do not store credentials or API tokens in the project. Protect generated reports because they may contain sensitive research data.

Roadmap

More platform modules

Batch investigations

HTML reports

Graph/export support

Expanded external-tool integrations

License

MIT

Disclaimer

OSINT Pro is intended for authorized public-source intelligence and research. You are responsible for how you use the software and for complying with applicable laws and service terms.
