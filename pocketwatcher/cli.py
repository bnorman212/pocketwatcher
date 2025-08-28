from __future__ import annotations

import json
from pathlib import Path
from typing import Optional, Set

import click

from .detectors import detect_bruteforce, detect_spray, detect_country_block, detect_asn_burst
from .linux import parse_auth_log
from .reporting import print_findings, write_csv, write_jsonl
from .utils import FailureEvent, parse_window
from .windows import parse_security_evtx
from .enrichment import Enricher

@click.group()
def main() -> None:
    """Pocketwatcher CLI."""

@main.command()
@click.argument("platform", type=click.Choice(["linux", "windows"], case_sensitive=False))
@click.option("--path", "path_", type=click.Path(exists=True, dir_okay=False), required=True, help="Path to log file (auth.log or Security.evtx)")
@click.option("--threshold", type=int, default=10, show_default=True, help="Threshold for brute-force detection (per IP)")
@click.option("--spray-threshold", type=int, default=12, show_default=True, help="Unique-IP count for spray detection (per user)")
@click.option("--asn-threshold", type=int, default=25, show_default=True, help="Failures from same ASN within window to trigger asn_burst")
@click.option("--window", type=str, default="5m", show_default=True, help="Rolling time window e.g. 5m, 30s, 1h")
@click.option("--csv", "csv_path", type=str, default=None, help="Write CSV report here")
@click.option("--jsonl", "jsonl_path", type=str, default=None, help="Write JSONL report here")
@click.option("--geoip-mmdb", type=click.Path(exists=True, dir_okay=False), default=None, help="Path to MaxMind GeoLite2-Country.mmdb (optional)")
@click.option("--asn-db", type=click.Path(exists=True, dir_okay=False), default=None, help="Path to pyasn database (e.g., rib.x.yz.dat). Optional")
@click.option("--allow-country", multiple=True, help="Only allow these ISO country codes; flag all others (can repeat)")
@click.option("--deny-country", multiple=True, help="Flag these ISO country codes explicitly (can repeat)")
def scan(platform: str, path_: str, threshold: int, spray_threshold: int, asn_threshold: int, window: str, csv_path: Optional[str], jsonl_path: Optional[str], geoip_mmdb: Optional[str], asn_db: Optional[str], allow_country: tuple[str, ...], deny_country: tuple[str, ...]) -> None:
    """Scan logs (linux|windows) for failed logins/lockouts."""
    events: list[FailureEvent] = []
    if platform.lower() == "linux":
        text = Path(path_).read_text(encoding="utf-8", errors="ignore")
        events = list(parse_auth_log(text))
    else:
        events = list(parse_security_evtx(path_))

    win = parse_window(window)

    enricher = Enricher(geoip_mmdb=geoip_mmdb, asn_db=asn_db)
    allow: Set[str] = {c.upper() for c in allow_country} if allow_country else set()
    deny: Set[str] = {c.upper() for c in deny_country} if deny_country else set()

    findings = []
    findings += list(detect_bruteforce(events, threshold=threshold, window=win))
    findings += list(detect_spray(events, threshold=spray_threshold, window=win))

    # Optional detections if enrichment available / flags set
    if allow or deny:
        findings += list(detect_country_block(events, window=win, deny=deny or None, allow=allow or None, ip_to_country=lambda ip: enricher.enrich_ip(ip).country))
    if asn_db:
        findings += list(detect_asn_burst(events, threshold=asn_threshold, window=win, ip_to_asn=lambda ip: enricher.enrich_ip(ip).asn))

    print_findings(findings)

    if csv_path:
        Path(csv_path).parent.mkdir(parents=True, exist_ok=True)
        write_csv(findings, csv_path)
    if jsonl_path:
        Path(jsonl_path).parent.mkdir(parents=True, exist_ok=True)
        write_jsonl(findings, jsonl_path)

@main.command()
def explain() -> None:
    """Show detection thresholds and configuration keys."""
    click.echo(json.dumps({
        "thresholds": {
            "brute_force_per_ip": 10,
            "spray_per_user_unique_ips": 12,
            "asn_burst": 25
        },
        "window": "5m",
        "enrichment": {
            "geoip_mmdb": "GeoLite2-Country.mmdb (optional)",
            "asn_db": "pyasn *.dat (optional)"
        },
        "notes": "Use --allow-country/--deny-country to gate by ISO country codes."
    }, indent=2))

if __name__ == "__main__":
    main()
