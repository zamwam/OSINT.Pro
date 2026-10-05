# OSINT.Pro

**Professional public reconnaissance toolkit for username, email, and phone investigations.**

Built for cybersecurity practitioners, red-teamers, and investigators who need reliable, auditable, and extensible OSINT capabilities. Performs only public, non-authenticated checks.

> **Legal & Ethical Notice**  
> Use **only** on targets you are authorized to investigate.  
> Unauthorized use may violate laws (CFAA, GDPR, CCPA, etc.) and platform Terms of Service.  
> This tool does **not** bypass authentication, scrape private data, or perform any intrusive actions.

---

## Features

- **Username enumeration** – Concurrent checks across major platforms (Instagram, Snapchat, TikTok, X, Reddit, GitHub, YouTube, Twitch, etc.) with confidence scoring
- **Email analysis** – Format validation, disposable detection, MX record lookup
- **Phone intelligence** – Validation, carrier, line type, country/region, timezones (via `phonenumbers`)
- **External tool integration** – Automatically calls Sherlock, Maigret, Holehe, and PhoneInfoga when available
- **Structured output** – Console (Rich), JSON, and CSV
- **Resilient networking** – Async requests, retries with exponential backoff, configurable timeouts
- **Configurable** – YAML config support for proxies, user-agents, paths, concurrency
- **Evidence-oriented** – Every result includes confidence level and evidence string

---

## Requirements

- Python 3.10+
- Recommended external tools (optional but strongly recommended for production use):

| Tool        | Purpose                  | Install command / notes                     |
|-------------|--------------------------|---------------------------------------------|
| Sherlock    | Username (400+ sites)    | `pip install sherlock-project`              |
| Maigret     | Username (deep profiles) | `pip install maigret`                       |
| Holehe      | Email → registered accounts | `pip install holehe`                     |
| PhoneInfoga | Advanced phone OSINT     | Download binary from [releases](https://github.com/sundowndev/phoneinfoga/releases) and add to PATH |

---

## Installation

### 1. Clone or download the script

```bash
# If you have the file as osint_pro.py
