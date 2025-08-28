<p align="center">
  <img src="assets/banner.svg" alt="Pocketwatcher banner" width="100%"/>
</p>

<p align="center">
  <a href="https://github.com/"><img alt="CI" src="https://img.shields.io/github/actions/workflow/status/yourname/pocketwatcher/ci.yml?label=CI"></a>
  <a href="https://pypi.org/project/pocketwatcher/"><img alt="PyPI" src="https://img.shields.io/pypi/v/pocketwatcher.svg"></a>
  <img alt="License" src="https://img.shields.io/badge/license-MIT-green.svg">
</p>


# Pocketwatcher

**Pocketwatcher** is a small-but-mighty log analysis CLI that spots **brute‑force** and **password‑spray** activity and summarizes **account lockouts** across Linux (`/var/log/auth.log`) and Windows (Security.evtx). Built for blue teams, IR, and SOC analysts who want fast answers.

- ✅ Parses Linux `auth.log` (sshd, su, sudo, PAM)
- 🪟 Parses Windows Security logs (4625/4624/4740) when `python-evtx` is available
- 🔎 Detects **brute-force** (per‑IP) and **spray** (per‑user unique IPs) with configurable thresholds
- 📈 Terminal tables + **CSV** and **JSONL** reports
- 🧹 Ruff + GitHub Actions CI
- 🧪 Samples + tests included

> Defensive-only: Pocketwatcher **reads logs** and **reports**—no offensive actions.

## Quickstart

```bash
python -m venv .venv && source .venv/bin/activate  # Windows: .venv\Scripts\activate
pip install -e .
pocketwatcher scan linux --path samples/linux/auth.log --csv reports/linux_report.csv
```

### Windows example (optional dependency on Windows)
```powershell
pocketwatcher scan windows --path C:\Path\To\Security.evtx --jsonl reports\win_findings.jsonl
```

## CLI

```
Usage: pocketwatcher [OPTIONS] COMMAND [ARGS]...

Options:
  --help  Show this message and exit.

Commands:
  scan     Scan logs (linux|windows) for failed logins/lockouts
  explain  Show detection thresholds and config
```

### Examples

**Detect ssh brute-force** (>10 failures in 5 minutes from one IP):
```bash
pocketwatcher scan linux --path /var/log/auth.log --window 5m --threshold 10
```

**Export JSONL for SIEM ingest**
```bash
pocketwatcher scan linux --path /var/log/auth.log --jsonl reports/findings.jsonl
```

## Detection logic

- **Brute force (per‑IP)**: N failures from the same IP within a rolling window.
- **Spray (per‑user)**: N **unique IPs** failing against the same username within a window.
- **Lockouts** (Windows): Event ID **4740**.

Tune everything via CLI flags or `pocketwatcher.yml`.

## Configuration

```yaml
thresholds:
  brute_force_per_ip: 10
  spray_per_user: 12
window: "5m"
ignore_users:
  - root
ignore_ips:
  - 127.0.0.1
```

## Output

- **Terminal**: Rich tables
- **CSV**: Flat report
- **JSONL**: Line-delimited, SIEM‑friendly

## Development

```bash
pipx install ruff
ruff check --fix
pytest -q
```

## Samples

See `samples/linux/auth.log` for common sshd failure patterns.

---

### LinkedIn Launch Post — Ready to Copy

⏱️🔒 **Pocketwatcher** — a tiny, defensive log watcher for blue teams.  
It scans Linux `auth.log` and Windows Security logs to surface **brute‑force** and **password‑spray** attempts, with clean CSV/JSONL output.

- Linux & Windows (Evtx) support
- Configurable thresholds & time windows
- MIT‑licensed, simple CLI
- Perfect for SOC, IR, and homelabs

Built by Brittany Norman — August 28, 2025  
#BlueTeam #CyberSecurity #DFIR #SIEM #Python #OpenSource

## New in 0.2.0
- Optional **GeoIP** (country) and **ASN** enrichment
- New detections: `country_block` and `asn_burst`
- Ready-to-go **PyPI publish** workflow (tag with `v0.2.0` to release)

### Geo/ASN usage
```bash
# Install extras
pip install .[geo,asn]
# Use MaxMind & pyasn databases
pocketwatcher scan linux --path /var/log/auth.log --geoip-mmdb GeoLite2-Country.mmdb --asn-db rib.dat --allow-country US --deny-country CN --asn-threshold 40
```
