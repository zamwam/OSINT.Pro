#!/usr/bin/env python3
"""
OSINT Pro – Professional username / email / phone reconnaissance toolkit
For authorized cybersecurity investigations and defensive research only.

Legal notice:
  Use only on targets you are authorized to investigate.
  Respect all applicable laws (CFAA, GDPR, CCPA, etc.) and platform Terms of Service.
  This tool performs only public, non-authenticated checks.
"""

from __future__ import annotations

import argparse
import asyncio
import csv
import json
import logging
import os
import re
import shutil
import subprocess
import sys
import time
from dataclasses import dataclass, asdict, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple
from concurrent.futures import ThreadPoolExecutor

import aiohttp
import phonenumbers
from phonenumbers import geocoder, carrier, timezone as pn_timezone, number_type, PhoneNumberType
import dns.resolver
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn
from tenacity import retry, stop_after_attempt, wait_exponential, retry_if_exception_type
from colorama import init

init(autoreset=True)
console = Console()

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

DEFAULT_CONFIG = {
    "timeout": 12,
    "max_concurrent": 15,
    "retries": 3,
    "user_agents": [
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Safari/605.1.15",
        "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36",
    ],
    "proxies": [],          # list of "http://user:pass@host:port"
    "output_dir": "osint_results",
    "sherlock_path": "sherlock",
    "maigret_path": "maigret",
    "holehe_path": "holehe",
    "phoneinfoga_path": "phoneinfoga",
}

# ---------------------------------------------------------------------------
# Data models
# ---------------------------------------------------------------------------

@dataclass
class CheckResult:
    platform: str
    exists: Optional[bool]          # True / False / None (uncertain)
    url: Optional[str] = None
    confidence: str = "medium"      # high / medium / low
    evidence: str = ""
    extra: Dict[str, Any] = field(default_factory=dict)
    error: Optional[str] = None

@dataclass
class TargetReport:
    target: str
    target_type: str                # username | email | phone
    timestamp: str
    results: List[CheckResult] = field(default_factory=list)
    summary: Dict[str, Any] = field(default_factory=dict)
    raw_external: Dict[str, Any] = field(default_factory=dict)

# ---------------------------------------------------------------------------
# Utilities
# ---------------------------------------------------------------------------

def setup_logging(verbose: bool = False) -> None:
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(
        level=level,
        format="%(asctime)s [%(levelname)s] %(message)s",
        datefmt="%H:%M:%S",
    )

def load_config(path: Optional[str] = None) -> dict:
    cfg = DEFAULT_CONFIG.copy()
    if path and Path(path).exists():
        import yaml
        with open(path) as f:
            user = yaml.safe_load(f) or {}
        cfg.update(user)
    return cfg

def which(cmd: str) -> Optional[str]:
    return shutil.which(cmd)

# ---------------------------------------------------------------------------
# Username checkers
# ---------------------------------------------------------------------------

USERNAME_SITES = {
    "Instagram": {
        "url": "https://www.instagram.com/{}/",
        "not_found": ["sorry, this page isn't available", "page not found"],
        "confidence": "high",
    },
    "Snapchat": {
        "url": "https://www.snapchat.com/add/{}",
        "not_found": ["page not found", "content not found"],
        "confidence": "medium",
    },
    "TikTok": {
        "url": "https://www.tiktok.com/@{}",
        "not_found": ["couldn't find this account", "user not found"],
        "confidence": "high",
    },
    "X": {
        "url": "https://x.com/{}",
        "not_found": ["this account doesn’t exist", "account suspended"],
        "confidence": "high",
    },
    "Reddit": {
        "url": "https://www.reddit.com/user/{}",
        "not_found": ["page not found", "nobody on reddit goes by that name"],
        "confidence": "high",
    },
    "GitHub": {
        "url": "https://github.com/{}",
        "not_found": ["not found", "404"],
        "confidence": "high",
    },
    "YouTube": {
        "url": "https://www.youtube.com/@{}",
        "not_found": ["this channel does not exist", "404"],
        "confidence": "medium",
    },
    "Twitch": {
        "url": "https://www.twitch.tv/{}",
        "not_found": ["sorry. unless you’ve got a time machine", "404"],
        "confidence": "high",
    },
    "Pinterest": {
        "url": "https://www.pinterest.com/{}/",
        "not_found": ["page not found"],
        "confidence": "medium",
    },
    "Steam": {
        "url": "https://steamcommunity.com/id/{}",
        "not_found": ["the specified profile could not be found"],
        "confidence": "high",
    },
    "LinkedIn": {
        "url": "https://www.linkedin.com/in/{}",
        "not_found": ["page not found", "this page doesn’t exist"],
        "confidence": "low",   # often blocked / login wall
    },
}

class UsernameChecker:
    def __init__(self, config: dict):
        self.config = config
        self.session: Optional[aiohttp.ClientSession] = None

    async def __aenter__(self):
        timeout = aiohttp.ClientTimeout(total=self.config["timeout"])
        self.session = aiohttp.ClientSession(timeout=timeout)
        return self

    async def __aexit__(self, *args):
        if self.session:
            await self.session.close()

    @retry(
        stop=stop_after_attempt(3),
        wait=wait_exponential(multiplier=1, min=1, max=8),
        retry=retry_if_exception_type((aiohttp.ClientError, asyncio.TimeoutError)),
    )
    async def _fetch(self, url: str, headers: dict) -> Tuple[int, str]:
        assert self.session
        async with self.session.get(url, headers=headers, allow_redirects=True, ssl=False) as resp:
            text = await resp.text()
            return resp.status, text.lower()

    async def check_one(self, username: str, platform: str, meta: dict) -> CheckResult:
        url = meta["url"].format(username)
        headers = {"User-Agent": self.config["user_agents"][hash(platform) % len(self.config["user_agents"])]}
        try:
            status, text = await self._fetch(url, headers)
            if status == 404 or status == 410:
                return CheckResult(platform, False, url, meta["confidence"], "HTTP 404/410")
            if status == 200:
                for marker in meta.get("not_found", []):
                    if marker in text:
                        return CheckResult(platform, False, url, meta["confidence"], f"marker: {marker}")
                return CheckResult(platform, True, url, meta["confidence"], "HTTP 200 + no negative markers")
            return CheckResult(platform, None, url, "low", f"HTTP {status}")
        except Exception as e:
            return CheckResult(platform, None, url, "low", error=str(e))

    async def check(self, username: str) -> List[CheckResult]:
        tasks = [self.check_one(username, p, m) for p, m in USERNAME_SITES.items()]
        return await asyncio.gather(*tasks)

# ---------------------------------------------------------------------------
# External tool wrappers
# ---------------------------------------------------------------------------

def run_sherlock(username: str, config: dict) -> Dict[str, Any]:
    path = which(config["sherlock_path"])
    if not path:
        return {"error": "sherlock not found on PATH"}
    try:
        cmd = [path, username, "--print-found", "--no-color", "--timeout", "10"]
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=180)
        found = []
        for line in proc.stdout.splitlines():
            if line.startswith("[+]"):
                found.append(line.strip())
        return {"found": found, "raw": proc.stdout}
    except Exception as e:
        return {"error": str(e)}

def run_maigret(username: str, config: dict) -> Dict[str, Any]:
    path = which(config["maigret_path"])
    if not path:
        return {"error": "maigret not found on PATH"}
    try:
        out_dir = Path(config["output_dir"]) / "maigret"
        out_dir.mkdir(parents=True, exist_ok=True)
        cmd = [path, username, "--json", "simple", "-fo", str(out_dir), "--timeout", "10"]
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
        return {"stdout": proc.stdout, "stderr": proc.stderr, "out_dir": str(out_dir)}
    except Exception as e:
        return {"error": str(e)}

def run_holehe(email: str, config: dict) -> Dict[str, Any]:
    path = which(config["holehe_path"])
    if not path:
        return {"error": "holehe not found on PATH"}
    try:
        cmd = [path, email, "--only-used", "--no-color"]
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
        return {"raw": proc.stdout}
    except Exception as e:
        return {"error": str(e)}

def run_phoneinfoga(number: str, config: dict) -> Dict[str, Any]:
    path = which(config["phoneinfoga_path"])
    if not path:
        return {"error": "phoneinfoga binary not found on PATH"}
    try:
        cmd = [path, "scan", "-n", number]
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=90)
        return {"raw": proc.stdout}
    except Exception as e:
        return {"error": str(e)}

# ---------------------------------------------------------------------------
# Email & Phone
# ---------------------------------------------------------------------------

DISPOSABLE = {
    "tempmail.com", "guerrillamail.com", "10minutemail.com", "mailinator.com",
    "yopmail.com", "throwaway.email", "temp-mail.org", "fakeinbox.com",
    "getnada.com", "mohmal.com", "sharklasers.com",
}

def analyze_email(email: str) -> List[CheckResult]:
    results = []
    email = email.strip().lower()
    results.append(CheckResult("Format", bool(re.match(r"^[^@]+@[^@]+\.[^@]+$", email)), evidence="regex"))

    domain = email.split("@")[-1]
    results.append(CheckResult("Disposable", domain in DISPOSABLE, evidence=domain))

    try:
        answers = dns.resolver.resolve(domain, "MX")
        hosts = [str(r.exchange).rstrip(".") for r in answers]
        results.append(CheckResult("MX", True, evidence=", ".join(hosts[:4])))
    except Exception as e:
        results.append(CheckResult("MX", False, error=str(e)))

    return results

def analyze_phone(number: str, default_region: str = "US") -> List[CheckResult]:
    results = []
    try:
        parsed = phonenumbers.parse(number, default_region)
        valid = phonenumbers.is_valid_number(parsed)
        possible = phonenumbers.is_possible_number(parsed)

        results.append(CheckResult("Valid", valid))
        results.append(CheckResult("Possible", possible))
        results.append(CheckResult(
            "E164", True,
            evidence=phonenumbers.format_number(parsed, phonenumbers.PhoneNumberFormat.E164)
        ))
        results.append(CheckResult(
            "International", True,
            evidence=phonenumbers.format_number(parsed, phonenumbers.PhoneNumberFormat.INTERNATIONAL)
        ))
        results.append(CheckResult("Country", True, evidence=geocoder.description_for_number(parsed, "en") or "Unknown"))
        results.append(CheckResult("Carrier", True, evidence=carrier.name_for_number(parsed, "en") or "Unknown"))
        results.append(CheckResult(
            "Timezones", True,
            evidence=", ".join(pn_timezone.time_zones_for_number(parsed))
        ))

        ntype = number_type(parsed)
        type_map = {
            PhoneNumberType.MOBILE: "Mobile",
            PhoneNumberType.FIXED_LINE: "Fixed line",
            PhoneNumberType.FIXED_LINE_OR_MOBILE: "Fixed/Mobile",
            PhoneNumberType.TOLL_FREE: "Toll-free",
            PhoneNumberType.VOIP: "VoIP",
            PhoneNumberType.PREMIUM_RATE: "Premium",
        }
        results.append(CheckResult("LineType", True, evidence=type_map.get(ntype, "Other")))
    except phonenumbers.NumberParseException as e:
        results.append(CheckResult("Parse", False, error=str(e)))
    return results

# ---------------------------------------------------------------------------
# Reporting
# ---------------------------------------------------------------------------

def print_report(report: TargetReport) -> None:
    console.print(Panel(f"[bold]{report.target_type.upper()}: {report.target}[/bold]\n{report.timestamp}", title="OSINT Pro"))

    table = Table(show_header=True, header_style="bold magenta")
    table.add_column("Platform / Check")
    table.add_column("Status")
    table.add_column("Confidence")
    table.add_column("Evidence / URL")

    for r in report.results:
        status = "FOUND" if r.exists is True else ("NOT FOUND" if r.exists is False else "UNCERTAIN")
        color = "green" if r.exists is True else ("red" if r.exists is False else "yellow")
        table.add_row(
            r.platform,
            f"[{color}]{status}[/{color}]",
            r.confidence,
            (r.url or r.evidence or r.error or "")[:80]
        )
    console.print(table)

    if report.raw_external:
        console.print("\n[bold]External tool output (abbreviated):[/bold]")
        for tool, data in report.raw_external.items():
            console.print(f"  {tool}: {str(data)[:200]}...")

def save_report(report: TargetReport, config: dict, formats: List[str]) -> None:
    out_dir = Path(config["output_dir"])
    out_dir.mkdir(parents=True, exist_ok=True)
    base = out_dir / f"{report.target_type}_{report.target.replace('@','_').replace('+','')}_{int(time.time())}"

    if "json" in formats:
        with open(f"{base}.json", "w") as f:
            json.dump(asdict(report), f, indent=2, default=str)
        console.print(f"[green]JSON → {base}.json[/green]")

    if "csv" in formats:
        with open(f"{base}.csv", "w", newline="") as f:
            writer = csv.writer(f)
            writer.writerow(["platform", "exists", "confidence", "url", "evidence", "error"])
            for r in report.results:
                writer.writerow([r.platform, r.exists, r.confidence, r.url, r.evidence, r.error])
        console.print(f"[green]CSV  → {base}.csv[/green]")

# ---------------------------------------------------------------------------
# Main orchestration
# ---------------------------------------------------------------------------

async def run_username(target: str, config: dict, use_external: bool) -> TargetReport:
    report = TargetReport(
        target=target,
        target_type="username",
        timestamp=datetime.now(timezone.utc).isoformat(),
    )

    async with UsernameChecker(config) as checker:
        with Progress(SpinnerColumn(), TextColumn("[progress.description]{task.description}"), console=console) as progress:
            task = progress.add_task("Built-in username checks...", total=None)
            report.results = await checker.check(target)
            progress.update(task, completed=1)

    if use_external:
        console.print("[cyan]Running external tools (Sherlock / Maigret)...[/cyan]")
        report.raw_external["sherlock"] = run_sherlock(target, config)
        report.raw_external["maigret"] = run_maigret(target, config)

    return report

def run_email(target: str, config: dict, use_external: bool) -> TargetReport:
    report = TargetReport(
        target=target,
        target_type="email",
        timestamp=datetime.now(timezone.utc).isoformat(),
        results=analyze_email(target),
    )
    if use_external:
        console.print("[cyan]Running Holehe...[/cyan]")
        report.raw_external["holehe"] = run_holehe(target, config)
    return report

def run_phone(target: str, config: dict, use_external: bool, region: str) -> TargetReport:
    report = TargetReport(
        target=target,
        target_type="phone",
        timestamp=datetime.now(timezone.utc).isoformat(),
        results=analyze_phone(target, region),
    )
    if use_external:
        console.print("[cyan]Running PhoneInfoga...[/cyan]")
        report.raw_external["phoneinfoga"] = run_phoneinfoga(target, config)
    return report

def main() -> None:
    parser = argparse.ArgumentParser(
        description="OSINT Pro – Professional public reconnaissance toolkit (authorized use only)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python osint_pro.py -u johndoe --external
  python osint_pro.py -e target@domain.com --external -o json,csv
  python osint_pro.py -p +15551234567 --region US --external
  python osint_pro.py -u user -e email@x.com -p +1... --external -o json
        """,
    )
    parser.add_argument("-u", "--username", help="Username to investigate")
    parser.add_argument("-e", "--email", help="Email address")
    parser.add_argument("-p", "--phone", help="Phone number (preferably E.164)")
    parser.add_argument("--region", default="US", help="Default region for phone parsing")
    parser.add_argument("--external", action="store_true", help="Also run Sherlock/Maigret/Holehe/PhoneInfoga if installed")
    parser.add_argument("-o", "--output", default="console", help="Output formats: console,json,csv (comma-separated)")
    parser.add_argument("-c", "--config", help="Path to YAML config file")
    parser.add_argument("-v", "--verbose", action="store_true")
    args = parser.parse_args()

    if not any([args.username, args.email, args.phone]):
        parser.print_help()
        sys.exit(1)

    setup_logging(args.verbose)
    config = load_config(args.config)
    formats = [f.strip() for f in args.output.split(",")]

    console.print(Panel(
        "[bold red]AUTHORIZED USE ONLY[/bold red]\n"
        "This tool is for legitimate cybersecurity investigations, red-team engagements with permission, "
        "and defensive digital footprint analysis. Misuse may violate laws and platform ToS.",
        title="Legal Notice",
    ))

    reports: List[TargetReport] = []

    if args.username:
        report = asyncio.run(run_username(args.username.strip(), config, args.external))
        print_report(report)
        reports.append(report)

    if args.email:
        report = run_email(args.email.strip().lower(), config, args.external)
        print_report(report)
        reports.append(report)

    if args.phone:
        report = run_phone(args.phone.strip(), config, args.external, args.region)
        print_report(report)
        reports.append(report)

    for r in reports:
        if any(f in formats for f in ("json", "csv")):
            save_report(r, config, formats)

    console.print("\n[bold green]Done.[/bold green] Review results carefully – existence checks are probabilistic.")

if __name__ == "__main__":
    main()
