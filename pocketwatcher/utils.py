from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta
from dateutil import parser as dateparser
from typing import Iterable, Iterator

def parse_window(s: str) -> timedelta:
    s = s.strip().lower()
    if s.endswith("ms"):
        return timedelta(milliseconds=int(s[:-2]))
    if s.endswith("s"):
        return timedelta(seconds=int(s[:-1]))
    if s.endswith("m"):
        return timedelta(minutes=int(s[:-1]))
    if s.endswith("h"):
        return timedelta(hours=int(s[:-1]))
    if s.endswith("d"):
        return timedelta(days=int(s[:-1]))
    raise ValueError(f"Unsupported window format: {s}")

def parse_dt(s: str) -> datetime:
    return dateparser.parse(s)

@dataclass(frozen=True)
class FailureEvent:
    when: datetime
    ip: str
    username: str
    source: str  # 'linux' | 'windows'
    raw: str

def rolling_window(events: Iterable['FailureEvent'], window: timedelta) -> Iterator[list['FailureEvent']]:
    buf: list[FailureEvent] = []
    for ev in sorted(events, key=lambda e: e.when):
        buf.append(ev)
        min_time = ev.when - window
        while buf and buf[0].when < min_time:
            buf.pop(0)
        yield list(buf)
