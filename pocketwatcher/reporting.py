from __future__ import annotations

import csv, json
from typing import Iterable

from rich.console import Console
from rich.table import Table

from .detectors import Finding

console = Console()

def print_findings(findings: Iterable[Finding]) -> None:
    table = Table(title="Pocketwatcher Findings")
    table.add_column("Kind")
    table.add_column("Key")
    table.add_column("Count", justify="right")
    table.add_column("Window (min)", justify="right")
    table.add_column("Sample")
    for f in findings:
        sample_lines = "\n".join(f"[{e.when.isoformat()}] {e.username}@{e.ip}" for e in f.sample[:5])
        table.add_row(f.kind, f.key, str(f.count), f"{f.window_minutes:g}", sample_lines)
    console.print(table)

def write_csv(findings: Iterable[Finding], path: str) -> None:
    rows = [
        {"kind": f.kind, "key": f.key, "count": f.count, "window_minutes": f.window_minutes}
        for f in findings
    ]
    with open(path, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=list(rows[0].keys()) if rows else ["kind","key","count","window_minutes"])
        w.writeheader()
        w.writerows(rows)

def write_jsonl(findings: Iterable[Finding], path: str) -> None:
    with open(path, "w", encoding="utf-8") as f:
        for fnd in findings:
            f.write(json.dumps(fnd.__dict__) + "\n")
