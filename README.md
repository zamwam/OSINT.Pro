**Professional-grade public reconnaissance toolkit for username, email, and phone investigations.**

OSINT Pro is a modular, concurrent, and evidence-oriented Python framework designed for cybersecurity professionals, red team operators, threat intelligence analysts, and authorized investigators. It focuses on reliable public-source intelligence collection while remaining extensible, auditable, and operationally practical.

> **⚠ LEGAL & ETHICAL NOTICE — READ BEFORE USE**  
>  
> This tool is intended **exclusively** for:  
> - Authorized penetration tests and red-team engagements (with written permission)  
> - Defensive digital footprint analysis of your own accounts or assets  
> - Threat intelligence research on publicly available data  
> - Educational and training purposes in controlled environments  
>  
> **Unauthorized use** against individuals or organizations without proper authorization may violate:  
> - Computer Fraud and Abuse Act (CFAA) and similar laws  
> - GDPR, CCPA, and other privacy regulations  
> - Platform Terms of Service  
>  
> The authors and contributors accept **no liability** for misuse. Always obtain explicit authorization before investigating any target.

---

## Table of Contents

1. [Features](#features)
2. [Architecture Overview](#architecture-overview)
3. [Requirements](#requirements)
4. [Installation](#installation)
5. [Quick Start](#quick-start)
6. [Command-Line Usage](#command-line-usage)
7. [Configuration](#configuration)
8. [Understanding Results](#understanding-results)
9. [Output Formats](#output-formats)
10. [External Tool Integration](#external-tool-integration)
11. [Platform Coverage](#platform-coverage)
12. [Best Practices for Professional Use](#best-practices-for-professional-use)
13. [Performance & Tuning](#performance--tuning)
14. [Troubleshooting](#troubleshooting)
15. [Extending the Tool](#extending-the-tool)
16. [Security Considerations](#security-considerations)
17. [Limitations & Known Issues](#limitations--known-issues)
18. [Roadmap](#roadmap)
19. [Contributing](#contributing)
20. [License](#license)
21. [Disclaimer](#disclaimer)

---

## Features

### Core Capabilities

| Category              | Description                                                                 |
|-----------------------|-----------------------------------------------------------------------------|
| **Username Enumeration** | Concurrent public profile existence checks across major platforms with confidence scoring and evidence |
| **Email Analysis**       | Format validation, disposable email detection, MX record verification       |
| **Phone Intelligence**   | Full validation, carrier lookup, line type, country/region, timezones using Google’s libphonenumber |
| **External Engine Support** | Seamless integration with Sherlock, Maigret, Holehe, and PhoneInfoga when installed |
| **Structured Reporting** | Rich console tables, JSON, and CSV export                                   |
| **Resilient Networking** | Async HTTP with retries, exponential backoff, configurable timeouts, and user-agent rotation |
| **Evidence-Oriented Design** | Every result includes a confidence level and supporting evidence string   |
| **Configurable**         | YAML configuration for proxies, concurrency, paths, and timeouts            |
| **Batch-Friendly**       | Designed for both interactive use and pipeline integration                  |

### Design Principles

- **Public data only** — No authentication bypass, no private profile scraping, no credential stuffing
- **Fail gracefully** — Missing external tools do not break the run
- **Auditable** — Timestamps, confidence scores, and evidence for every finding
- **Extensible** — Clear separation between built-in checkers and external tool wrappers
- **Operational** — Suitable for real investigations, not just demos

---

## Architecture Overview
osint_pro.py
├── Configuration Layer # Defaults + optional YAML override
├── Data Models
│ ├── CheckResult # Single platform/check outcome
│ └── TargetReport # Full investigation report
├── UsernameChecker (async) # Built-in concurrent profile checks
├── Email Analyzer # Validation + DNS
├── Phone Analyzer # phonenumbers library
├── External Tool Wrappers
│ ├── run_sherlock()
│ ├── run_maigret()
│ ├── run_holehe()
│ └── run_phoneinfoga()
├── Reporting Engine
│ ├── Rich console tables
│ ├── JSON export
│ └── CSV export
└── CLI Orchestrator # Argument parsing + execution flow

text

All network activity for built-in checks uses aiohttp with controlled concurrency. External tools are invoked via subprocess only when --external is specified and the binaries are available on PATH.

---

## Requirements

### Mandatory

- **Python 3.10 or higher** (3.11+ recommended)
- Internet connectivity for public checks

### Python Dependencies

bash
aiohttp
phonenumbers
dnspython
rich
tenacity
pyyaml
colorama
requests
Optional but Strongly Recommended External Tools
Tool	Purpose	Installation	Notes
Sherlock	Username search across 400+ sites	pip install sherlock-project	Mature, widely used
Maigret	Deep username profiling (2000+ sites)	pip install maigret	Richer profile extraction
Holehe	Email → registered accounts	pip install holehe	Does not alert the target
PhoneInfoga	Advanced phone number OSINT	Download binary from GitHub Releases	Place binary on PATH
Installation
1. Obtain the Script
Save the main script as osint_pro.py (or clone your repository containing it).

2. Create a Virtual Environment (Recommended)
Bash

# Linux / macOS
python3 -m venv osint-env
source osint-env/bin/activate

# Windows (Command Prompt)
python -m venv osint-env
osint-env\Scripts\activate.bat

# Windows (PowerShell)
python -m venv osint-env
osint-env\Scripts\Activate.ps1
3. Install Dependencies
Always prefer python -m pip to avoid interpreter mismatches (especially on Windows with Microsoft Store Python):

Bash

python -m pip install --upgrade pip
python -m pip install aiohttp phonenumbers dnspython rich tenacity pyyaml colorama requests
4. Install External Engines (Optional)
Bash

python -m pip install sherlock-project maigret holehe
For PhoneInfoga:

Download the latest release for your OS from the official repository.

Extract the binary.

Add it to your system PATH or place it in a directory already on PATH.

Verify: phoneinfoga version

5. Verify Installation
Bash

python -c "import aiohttp, phonenumbers, dns.resolver, rich, tenacity, yaml; print('All core dependencies OK')"
python osint_pro.py -h
Quick Start
Bash

# Simple username check
python osint_pro.py -u johndoe

# Full username investigation with external engines
python osint_pro.py -u johndoe --external -o json,csv

# Email investigation
python osint_pro.py -e target@example.com --external

# Phone investigation
python osint_pro.py -p +14155552671 --region US --external

# Combined investigation
python osint_pro.py -u johndoe -e target@example.com -p +14155552671 --external -o json,csv -v
Command-Line Usage
text

usage: osint_pro.py [-h] [-u USERNAME] [-e EMAIL] [-p PHONE] [--region REGION]
                    [--external] [-o OUTPUT] [-c CONFIG] [-v]
Argument	Description	Default
-u, --username	Username to investigate	—
-e, --email	Email address to analyze	—
-p, --phone	Phone number (E.164 preferred, e.g. +15551234567)	—
--region	Default region for phone parsing when country code is missing	US
--external	Also run Sherlock / Maigret / Holehe / PhoneInfoga if available	False
-o, --output	Output formats: console, json, csv (comma-separated)	console
-c, --config	Path to custom YAML configuration file	—
-v, --verbose	Enable debug logging	False
You can combine multiple target types in a single run.

Configuration
Create a config.yaml file to override defaults:

YAML

# Network
timeout: 12                    # Seconds per request
max_concurrent: 15             # Concurrent built-in checks
retries: 3                     # Retry attempts with backoff

# Output
output_dir: osint_results

# User-Agent rotation
user_agents:
  - "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
  - "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Safari/605.1.15"
  - "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36"

# Proxies (optional)
proxies: []
  # - "http://user:pass@proxy.example.com:8080"
  # - "socks5://127.0.0.1:9050"

# External tool paths (override if not on PATH)
sherlock_path: sherlock
maigret_path: maigret
holehe_path: holehe
phoneinfoga_path: phoneinfoga
Load it with:

Bash

python osint_pro.py -u target --external -c config.yaml
Understanding Results
Status Values
Status	Meaning	Typical Confidence
FOUND	Strong indication the account/profile exists	high / medium
NOT FOUND	Strong indication the account does not exist	high / medium
UNCERTAIN	Ambiguous response, rate limiting, blocking, or login wall	low
Confidence Levels
high — Multiple strong signals (correct HTTP status + absence of negative markers, or known reliable detection pattern)

medium — Reasonable signals but some ambiguity possible

low — Weak or conflicting signals; treat as requiring manual verification

Evidence Field
Every result includes an evidence string explaining why the tool reached its conclusion (e.g., "HTTP 200 + no negative markers", "marker: page not found", "HTTP 404/410").

Always manually verify high-value findings. Platforms change their page structure and anti-bot measures frequently.

Output Formats
Console (default)
Rich-formatted tables with color-coded status, confidence, and truncated evidence/URL.

JSON
Complete machine-readable report including:

Target and type

UTC timestamp

Full list of CheckResult objects

Raw output from external tools (when used)

Summary metadata

Ideal for pipelines, SIEM ingestion, or further processing.

CSV
Flat tabular export suitable for spreadsheets or databases:

text

platform,exists,confidence,url,evidence,error
File Naming
Reports are saved under ./osint_results/ (or the configured directory) with the pattern:

text

{target_type}_{sanitized_target}_{unix_timestamp}.{ext}
External Tool Integration
When --external is supplied, OSINT Pro attempts to call:

Tool	Triggered by	What it adds
Sherlock	Username	Broad coverage across hundreds of sites
Maigret	Username	Deeper profile data and recursive discovery
Holehe	Email	List of services where the email is registered
PhoneInfoga	Phone	Carrier enrichment, footprinting, reputation data
If a tool is not found on PATH, the corresponding section simply records an error and the rest of the investigation continues.

You can override binary locations in the configuration file.

Platform Coverage (Built-in)
Current built-in username checkers:

Platform	Detection Quality	Notes
Instagram	High	Negative marker detection
Snapchat	Medium	Public profile page
TikTok	High	Negative marker detection
X (Twitter)	High	Negative marker detection
Reddit	High	Reliable 404 behavior
GitHub	High	Clean existence signals
YouTube	Medium	Channel handle checks
Twitch	High	Clear not-found pages
Pinterest	Medium	

Steam	High	

LinkedIn	Low	Frequently blocked / login wall
Additional platforms can be added by extending the USERNAME_SITES dictionary.

Best Practices for Professional Use
Authorization first — Never run against a target without proper authorization.

Start narrow — Begin with built-in checks, then enable --external only when needed.

Verify everything — Treat automated results as leads, not ground truth.

Document your process — Keep the generated JSON/CSV reports as part of your case notes.

Respect rate limits — Aggressive scanning can trigger blocks and may violate ToS.

Use proxies responsibly — When operational security requires it, configure proxies in config.yaml.

Combine with manual analysis — Profile pictures, bios, post history, and linked accounts provide far more value than a simple “exists” flag.

Separate environments — Run investigative tools in isolated VMs or containers when possible.

Performance & Tuning
Setting	Effect	Recommendation
max_concurrent	Number of simultaneous built-in checks	10–20 for most connections
timeout	Per-request timeout	10–15 seconds
retries	Retry attempts on transient failures	2–3
--external	Adds significant runtime	Use selectively
For large username lists, consider wrapping the tool in a simple loop or integrating it into a larger orchestration framework rather than modifying the core script.

Troubleshooting
Symptom	Likely Cause	Solution
ModuleNotFoundError: aiohttp	Wrong Python interpreter	Use python -m pip install ...
External tools report “not found”	Binary not on PATH	Verify with where sherlock / which holehe
Many UNCERTAIN results	Anti-bot blocking or page changes	Lower concurrency, add proxies, update markers
Slow performance	High concurrency + external tools	Reduce max_concurrent or skip --external
SSL / certificate errors	Corporate proxy or old Python	Update certificates or configure proxy correctly
Phone parsing fails	Missing country code	Provide number in E.164 format or set --region
Windows-specific notes
Microsoft Store Python frequently causes path mismatches between pip and python. Always prefer:

cmd

python -m pip install <packages>
python osint_pro.py ...
Extending the Tool
Adding a New Platform
Edit the USERNAME_SITES dictionary:

Python

"NewPlatform": {
    "url": "https://example.com/user/{}",
    "not_found": ["user not found", "page does not exist"],
    "confidence": "medium",
},
Adding a New Checker Module
Follow the existing pattern:

Create a function or class that returns a list of CheckResult objects.

Integrate it into the appropriate run_* function.

Update the CLI and reporting as needed.

Calling External Tools Programmatically
The wrapper functions (run_sherlock, run_holehe, etc.) can be imported and reused in larger automation scripts.

Security Considerations
The tool makes outbound HTTP requests. Run it from a controlled network when operational security matters.

Proxy support is available but must be configured manually.

No credentials or session tokens are stored or transmitted by the core tool.

Generated reports may contain sensitive findings — handle and store them according to your organization’s data handling policies.

Avoid running the tool from production or sensitive systems.

Limitations & Known Issues
Built-in username checks are heuristic. Platforms frequently change HTML structure and anti-bot defenses.

LinkedIn and similar sites often return low-confidence or blocked results.

External tools have their own rate limits, detection methods, and failure modes.

No recursive pivoting or automatic correlation between username → email → phone is performed in the current version.

Phone carrier data reflects the original allocation and may not reflect number portability in all countries.

Disposable email list is not exhaustive.

Roadmap
Planned or suggested improvements:

Native plugin system (checkers/ directory)

Direct Python API usage for Maigret and Holehe (instead of CLI)

Optional Have I Been Pwned / breach integration (API key required)

Proxy rotation and request fingerprinting improvements

Graph export (NetworkX / Neo4j)

Docker image with all external tools pre-installed

Batch mode for file-based target lists

Improved LinkedIn and other high-friction platforms

Contributing
Contributions that improve reliability, coverage, documentation, or operational safety are welcome — provided they remain within the scope of authorized, public-source intelligence.

Please:

Keep changes focused and well-documented.

Preserve the legal/ethical warnings.

Avoid adding any functionality that bypasses authentication or accesses private data.

Test on multiple platforms before submitting.

License
MIT License

Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the “Software”), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED “AS IS”, WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED.

Disclaimer
OSINT Pro is provided for legitimate cybersecurity research, authorized testing, and educational purposes only. The authors and contributors disclaim all liability for any damages or legal consequences arising from the use or misuse of this software. Users are solely responsible for ensuring their activities comply with all applicable laws and regulations.

Use responsibly. Verify everything. Obtain authorization first.

text

Save the content above as `README.md` next to `osint_pro.py`. This version is significantly mo
Close


Analyzed
Done. I rebuilt it into a single professional Markdown/text file with:

Clean Markdown formatting

Proper tables and code blocks

Reorganized professional structure

Improved CLI documentation

Better installation instructions

More detailed configuration guidance

Professional investigation workflow

Clearer security and privacy considerations

Expanded troubleshooting

Cleaner architecture documentation

More polished roadmap and contribution sections

Corrected and standardized terminology

 



make it wayyyyyyyyyyy shorter

Yeah. The previous version was still way too long.

I’d cut it down to a compact GitHub-style README, keeping only what someone actually needs to understand, install, and run OSINT Pro.




Ad

do it


Analyzed
Done. I cut it down substantially while keeping the important installation, usage, configuration, features, security, and troubleshooting sections.

 


You're on the free plan
ChatGPT gets less accurate and may forget details in long conversations. Upgrade to chat longer with better memory.

Get Plus

New chat


OSINT_Pro_README_SHORT.md


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
Option	Description
-u	Username
-e	Email
-p	Phone number
--region	Phone region, such as US
--external	Enable external tools
-o	Output formats: json,csv
-c	YAML config file
-v	Verbose output
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
