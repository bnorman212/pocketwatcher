from __future__ import annotations

import re
from datetime import datetime
from typing import Iterator

from .utils import FailureEvent

SSH_FAIL_RE = re.compile(
    r"^(?P<ts>\w{3}\s+\d+\s+\d{2}:\d{2}:\d{2}).*sshd\[\d+\]:\s+Failed password for (?:invalid user )?(?P<user>[\w\-\.]+) from (?P<ip>[\d\.]+)"
)

def parse_auth_log(text: str, year: int | None = None) -> Iterator[FailureEvent]:
    for line in text.splitlines():
        m = SSH_FAIL_RE.search(line)
        if not m:
            continue
        ts = m.group("ts")
        when = datetime.strptime(f"{ts} {year or datetime.now().year}", "%b %d %H:%M:%S %Y")
        yield FailureEvent(when=when, ip=m.group("ip"), username=m.group("user"), source="linux", raw=line)
