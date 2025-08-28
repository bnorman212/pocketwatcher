from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass
from datetime import timedelta
from typing import Iterable, Iterator, Optional, Set

from .utils import FailureEvent, rolling_window

@dataclass
class Finding:
    kind: str               # 'bruteforce' | 'spray' | 'country_block' | 'asn_burst'
    key: str                # ip | username | country | asn
    count: int
    window_minutes: float
    sample: list[FailureEvent]

def detect_bruteforce(events: Iterable[FailureEvent], threshold: int, window: timedelta) -> Iterator[Finding]:
    events = sorted(events, key=lambda e: e.when)
    by_ip = defaultdict(list)
    for ev in events:
        by_ip[ev.ip].append(ev)
    for ip, evs in by_ip.items():
        for win in rolling_window(evs, window):
            if len(win) >= threshold:
                yield Finding("bruteforce", ip, len(win), window.total_seconds()/60, win[-min(len(win),20):])
                break

def detect_spray(events: Iterable[FailureEvent], threshold: int, window: timedelta) -> Iterator[Finding]:
    events = sorted(events, key=lambda e: e.when)
    by_user = defaultdict(list)
    for ev in events:
        by_user[ev.username].append(ev)
    for user, evs in by_user.items():
        for win in rolling_window(evs, window):
            unique_ips = {e.ip for e in win}
            if len(unique_ips) >= threshold:
                yield Finding("spray", user, len(unique_ips), window.total_seconds()/60, win[-min(len(win),20):])
                break

def detect_country_block(events: Iterable[FailureEvent], window: timedelta, deny: Optional[Set[str]] = None, allow: Optional[Set[str]] = None, ip_to_country=lambda ip: None) -> Iterator[Finding]:
    """Flag failures coming from denied countries or outside allowed list."""
    if not deny and not allow:
        return
    events = sorted(events, key=lambda e: e.when)
    by_country = defaultdict(list)
    for ev in events:
        c = ip_to_country(ev.ip)
        if not c:
            continue
        if (deny and c in deny) or (allow and c not in allow):
            by_country[c].append(ev)
    for c, evs in by_country.items():
        # summarize over entire set; window used only for consistency in Finding
        yield Finding("country_block", c, len(evs), window.total_seconds()/60, evs[-min(len(evs),20):])

def detect_asn_burst(events: Iterable[FailureEvent], threshold: int, window: timedelta, ip_to_asn=lambda ip: None) -> Iterator[Finding]:
    """Flag many failures sourced from the same ASN within a window."""
    events = sorted(events, key=lambda e: e.when)
    by_asn = defaultdict(list)
    for ev in events:
        asn = ip_to_asn(ev.ip)
        if asn is None:
            continue
        by_asn[asn].append(ev)
    for asn, evs in by_asn.items():
        for win in rolling_window(evs, window):
            if len(win) >= threshold:
                yield Finding("asn_burst", str(asn), len(win), window.total_seconds()/60, win[-min(len(win),20):])
                break
