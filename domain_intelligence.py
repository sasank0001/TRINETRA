"""
TRINETRA - Domain Intelligence Engine
======================================

Fetches real-world domain metadata without connecting to or executing anything on the target site:
  1. DNS Records: A, MX, NS, TXT via dnspython
  2. WHOIS Information: Registrar, creation date, expiration date, age via python-whois
  3. Age Heuristics: Flags newly registered domains (< 30 days or < 90 days)

Graceful Fallback:
  If a domain is not reachable, has WHOIS privacy, or query fails, it explicitly returns
  'Information Unavailable' rather than fabricating fake data.
"""

from __future__ import annotations

import datetime
import socket
from urllib.parse import urlsplit

import dns.resolver
import whois
from feature_extraction import registered_domain


def get_domain_intelligence(hostname: str) -> dict:
    """
    Performs passive DNS and WHOIS lookups for the given host.
    Returns:
      {
        "status": "available" | "partial" | "unavailable",
        "domain": str,
        "registrar": str,
        "creation_date": str,
        "expiration_date": str,
        "domain_age_days": int | None,
        "is_newly_registered": bool,
        "nameservers": list[str],
        "dns_records": {
            "a": list[str],
            "mx": list[str],
            "ns": list[str]
        },
        "indicators": list[dict]
      }
    """
    host = (hostname or "").lower().rstrip(".")
    reg_domain, tld, subdomains = registered_domain(host)
    target_domain = reg_domain if reg_domain else host

    data = {
        "status": "unavailable",
        "domain": target_domain,
        "registrar": "Information Unavailable",
        "creation_date": "Information Unavailable",
        "expiration_date": "Information Unavailable",
        "domain_age_days": None,
        "is_newly_registered": False,
        "nameservers": [],
        "dns_records": {"a": [], "mx": [], "ns": []},
        "indicators": [],
    }

    # 1. Passive DNS Lookup (A, MX, NS) with strict 2-second timeout
    resolver = dns.resolver.Resolver()
    resolver.timeout = 2.0
    resolver.lifetime = 2.5

    try:
        a_answers = resolver.resolve(target_domain, "A")
        data["dns_records"]["a"] = [r.to_text() for r in a_answers][:4]
        data["status"] = "partial"
    except Exception:
        pass

    try:
        ns_answers = resolver.resolve(target_domain, "NS")
        data["dns_records"]["ns"] = [r.to_text().rstrip(".") for r in ns_answers][:4]
        data["nameservers"] = data["dns_records"]["ns"]
        data["status"] = "partial"
    except Exception:
        pass

    try:
        mx_answers = resolver.resolve(target_domain, "MX")
        data["dns_records"]["mx"] = [r.exchange.to_text().rstrip(".") for r in mx_answers][:4]
    except Exception:
        pass

    # 2. WHOIS Information
    try:
        w = whois.whois(target_domain)
        if w:
            if w.registrar:
                data["registrar"] = str(w.registrar)
                data["status"] = "available"

            # Parse Creation Date
            cdate = w.creation_date
            if isinstance(cdate, list) and cdate:
                cdate = cdate[0]
            if isinstance(cdate, datetime.datetime):
                data["creation_date"] = cdate.strftime("%Y-%m-%d")
                now = datetime.datetime.now()
                # Remove tzinfo if present for safe subtraction
                if cdate.tzinfo is not None:
                    cdate = cdate.replace(tzinfo=None)
                age = (now - cdate).days
                data["domain_age_days"] = age
                data["status"] = "available"

                if age < 30:
                    data["is_newly_registered"] = True
                    data["indicators"].append({
                        "severity": "high",
                        "title": "Extremely Young Domain (< 30 days)",
                        "detail": f"Domain was registered only {age} days ago ({data['creation_date']}). Phishing campaigns frequently rely on disposable domains.",
                    })
                elif age < 90:
                    data["is_newly_registered"] = True
                    data["indicators"].append({
                        "severity": "medium",
                        "title": "Recently Registered Domain (< 90 days)",
                        "detail": f"Domain is {age} days old. Young domains carry higher statistical risk.",
                    })

            # Parse Expiration Date
            edate = w.expiration_date
            if isinstance(edate, list) and edate:
                edate = edate[0]
            if isinstance(edate, datetime.datetime):
                data["expiration_date"] = edate.strftime("%Y-%m-%d")

            # Nameservers from WHOIS if DNS didn't catch them
            if not data["nameservers"] and w.name_servers:
                ns_list = w.name_servers if isinstance(w.name_servers, list) else [w.name_servers]
                data["nameservers"] = [str(n).lower().rstrip(".") for n in ns_list][:4]
                data["dns_records"]["ns"] = data["nameservers"]
    except Exception:
        pass

    # If DNS found no records, add an indicator
    if not data["dns_records"]["a"] and not data["dns_records"]["ns"]:
        data["indicators"].append({
            "severity": "low",
            "title": "No Public DNS Records Found",
            "detail": "Domain could not be resolved to active A or NS records.",
        })

    return data
