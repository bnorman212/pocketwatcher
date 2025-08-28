from __future__ import annotations

from dataclasses import dataclass
from typing import Optional

@dataclass
class Enriched:
    ip: str
    country: Optional[str] = None
    asn: Optional[int] = None
    asn_name: Optional[str] = None

class Enricher:
    def __init__(self, geoip_mmdb: Optional[str] = None, asn_db: Optional[str] = None) -> None:
        self.geo_reader = None
        self.asn = None
        # Lazy imports so base install stays slim
        if geoip_mmdb:
            try:
                import geoip2.database  # type: ignore
                self.geo_reader = geoip2.database.Reader(geoip_mmdb)
            except Exception:
                self.geo_reader = None
        if asn_db:
            try:
                import pyasn  # type: ignore
                self.asn = pyasn.pyasn(asn_db)
            except Exception:
                self.asn = None

    def enrich_ip(self, ip: str) -> Enriched:
        country = None
        if self.geo_reader:
            try:
                r = self.geo_reader.country(ip)
                country = (r.country.iso_code or None)
            except Exception:
                country = None
        asn_num = None
        asn_name = None
        if self.asn:
            try:
                res = self.asn.lookup(ip)
                if isinstance(res, tuple):
                    asn_num = res[0]
            except Exception:
                asn_num = None
        return Enriched(ip=ip, country=country, asn=asn_num, asn_name=asn_name)
