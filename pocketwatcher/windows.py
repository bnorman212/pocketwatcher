from __future__ import annotations

from typing import Iterator

try:
    from Evtx.Evtx import Evtx  # type: ignore
    HAVE_EVTX = True
except Exception:  # pragma: no cover
    HAVE_EVTX = False

from .utils import FailureEvent, parse_dt

def parse_security_evtx(path: str) -> Iterator[FailureEvent]:
    if not HAVE_EVTX:
        raise RuntimeError("python-evtx not available. Install on Windows to parse .evtx files.")
    with Evtx(path) as log:
        for record in log.records():
            xml = record.xml()
            if "<EventID>4625</EventID>" not in xml:
                continue
            def get(tag: str) -> str:
                start = xml.find(f"<Data Name='{tag}'>")
                if start == -1: 
                    return ""
                start += len(f"<Data Name='{tag}'>")
                end = xml.find("</Data>", start)
                return xml[start:end]
            ip = get("IpAddress") or "-"
            user = get("TargetUserName") or "-"
            created_start = xml.find("<TimeCreated SystemTime="")
            if created_start != -1:
                created_start += len("<TimeCreated SystemTime="")
                created_end = xml.find(""", created_start)
                when = parse_dt(xml[created_start:created_end])
            else:
                continue
            yield FailureEvent(when=when, ip=ip, username=user, source="windows", raw=xml)
