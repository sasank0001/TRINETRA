"""
TRINETRA - Safe URL Redirect & Chain Analysis Engine
===================================================

Analyzes URL shorteners and redirect behaviors safely:
  - Uses HTTP HEAD requests with strict timeout (2.5s) and `allow_redirects=False`.
  - Follows up to 4 hops manually to inspect destination headers (`Location`).
  - NEVER downloads response bodies, executes Javascript, or renders DOM.
  - Rejects private/loopback destination IPs to prevent SSRF (Server-Side Request Forgery).
  - Highlights unexpected domain hops (e.g. shortening service -> deceptive domain).

If network analysis fails or times out, it gracefully marks status as "unverified"
with an explanatory message without breaking the scan.
"""

from __future__ import annotations

import ipaddress
import socket
from urllib.parse import urlsplit, urljoin
import requests
from feature_extraction import URL_SHORTENERS, parse_url, registered_domain

MAX_HOPS = 4
REQUEST_TIMEOUT = 2.5


def _is_private_or_loopback(host: str) -> bool:
    """SSRF guard: checks if hostname resolves to private/loopback/link-local address."""
    try:
        ip = socket.gethostbyname(host)
        addr = ipaddress.ip_address(ip)
        return addr.is_private or addr.is_loopback or addr.is_link_local or addr.is_reserved
    except Exception:
        return False


def analyze_redirects(url: str) -> dict:
    """
    Safely inspects redirect headers without downloading content or executing scripts.
    Returns:
      {
        "is_shortener": bool,
        "has_redirects": bool,
        "redirect_count": int,
        "chain": list[dict],
        "final_url": str,
        "domain_changed": bool,
        "status": "success" | "unverified" | "none",
        "message": str,
        "indicators": list[dict]
      }
    """
    parsed = parse_url(url)
    host = parsed["host"]
    is_shortener = host in URL_SHORTENERS or any(s in host for s in ("bit.ly", "tinyurl", "t.co", "shorturl"))

    result = {
        "is_shortener": is_shortener,
        "has_redirects": False,
        "redirect_count": 0,
        "chain": [{"step": 0, "url": url, "status_code": 200, "domain": host}],
        "final_url": url,
        "domain_changed": False,
        "status": "none",
        "message": "Direct link (no redirection detected).",
        "indicators": [],
    }

    # SSRF Check
    if _is_private_or_loopback(host):
        result["status"] = "unverified"
        result["message"] = "Analysis skipped: Target host resolves to private/loopback address (SSRF Protection)."
        return result

    current_url = url
    session = requests.Session()
    session.headers.update({
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 TRINETRA-RedirectBot/2.0",
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    })

    try:
        for hop in range(1, MAX_HOPS + 1):
            p = parse_url(current_url)
            if _is_private_or_loopback(p["host"]):
                break

            # HEAD request only: never downloads body
            resp = session.head(
                current_url,
                allow_redirects=False,
                timeout=REQUEST_TIMEOUT,
                verify=False,  # Don't crash on self-signed certs during passive analysis
            )

            if resp.is_redirect or resp.status_code in (301, 302, 303, 307, 308):
                location = resp.headers.get("Location")
                if not location:
                    break
                next_url = urljoin(current_url, location)
                next_host = parse_url(next_url)["host"]

                result["has_redirects"] = True
                result["redirect_count"] += 1
                result["chain"].append({
                    "step": hop,
                    "url": next_url,
                    "status_code": resp.status_code,
                    "domain": next_host,
                })
                current_url = next_url
            else:
                break

        result["final_url"] = current_url
        final_host = parse_url(current_url)["host"]
        if final_host != host:
            result["domain_changed"] = True

        if result["redirect_count"] > 0:
            result["status"] = "success"
            result["message"] = f"Link redirects {result['redirect_count']} time(s) to destination domain '{final_host}'."
            if result["domain_changed"]:
                result["indicators"].append({
                    "severity": "medium",
                    "title": "Cross-Domain Redirect",
                    "detail": f"Submitted link on '{host}' redirects users to an entirely different domain '{final_host}'.",
                })
            if result["redirect_count"] >= 3:
                result["indicators"].append({
                    "severity": "medium",
                    "title": "Extended Redirect Chain",
                    "detail": f"Encountered {result['redirect_count']} redirect hops, often utilized to evade automated security crawlers.",
                })
        else:
            result["status"] = "success"
            result["message"] = "URL resolves directly without redirection."

    except requests.exceptions.Timeout:
        result["status"] = "unverified"
        result["message"] = "Redirect check timed out. Link status could not be verified remotely."
    except Exception as e:
        result["status"] = "unverified"
        result["message"] = "Redirect analysis unavailable for this link."

    return result
