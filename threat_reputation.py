"""
TRINETRA - Threat Reputation Engine (VirusTotal API Integration)
===============================================================

Optional external threat-intelligence integration:
  - Queries VirusTotal API v3 for URL or domain reputation.
  - Securely reads API key from environment variable `VIRUSTOTAL_API_KEY`.
  - Gracefully handles missing key, invalid key, rate limits (HTTP 429), and network failures.
  - Never leaks API keys to the frontend or clients.
  - Never lets a missing key penalize or reward a URL's risk score.
"""

from __future__ import annotations

import base64
import datetime
import os
import requests


def get_threat_reputation(url: str) -> dict:
    """
    Checks URL against VirusTotal API v3 if `VIRUSTOTAL_API_KEY` is configured.
    Returns:
      {
        "status": "configured" | "not_configured" | "rate_limited" | "error" | "not_found",
        "service": "VirusTotal",
        "positives": int,
        "total_scanners": int,
        "malicious_count": int,
        "suspicious_count": int,
        "harmless_count": int,
        "undetected_count": int,
        "reputation_score": int | None,
        "last_analysis_date": str | None,
        "details_url": str | None,
        "message": str
      }
    """
    api_key = os.environ.get("VIRUSTOTAL_API_KEY", "").strip()

    result = {
        "status": "not_configured",
        "service": "VirusTotal",
        "positives": 0,
        "total_scanners": 0,
        "malicious_count": 0,
        "suspicious_count": 0,
        "harmless_count": 0,
        "undetected_count": 0,
        "reputation_score": None,
        "last_analysis_date": None,
        "details_url": None,
        "message": "VirusTotal API key not configured (Set VIRUSTOTAL_API_KEY in .env).",
    }

    if not api_key:
        return result

    try:
        # VirusTotal v3 requires base64url-encoded URL without padding
        url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
        endpoint = f"https://www.virustotal.com/api/v3/urls/{url_id}"
        headers = {
            "x-apikey": api_key,
            "Accept": "application/json",
            "User-Agent": "TRINETRA-Cyber-Threat-Scanner/2.0",
        }

        resp = requests.get(endpoint, headers=headers, timeout=4.0)

        if resp.status_code == 200:
            data = resp.json().get("data", {}).get("attributes", {})
            stats = data.get("last_analysis_stats", {})
            mal = stats.get("malicious", 0)
            susp = stats.get("suspicious", 0)
            harmless = stats.get("harmless", 0)
            undetected = stats.get("undetected", 0)
            total = mal + susp + harmless + undetected

            last_epoch = data.get("last_analysis_date")
            last_date_str = None
            if last_epoch:
                last_date_str = datetime.datetime.fromtimestamp(last_epoch).strftime("%Y-%m-%d %H:%M:%S")

            result.update({
                "status": "configured",
                "positives": mal + susp,
                "total_scanners": total,
                "malicious_count": mal,
                "suspicious_count": susp,
                "harmless_count": harmless,
                "undetected_count": undetected,
                "reputation_score": data.get("reputation", 0),
                "last_analysis_date": last_date_str,
                "details_url": f"https://www.virustotal.com/gui/url/{url_id}",
                "message": f"{mal} of {total} security vendors flagged this URL as malicious.",
            })
            return result

        elif resp.status_code == 404:
            result["status"] = "not_found"
            result["message"] = "URL not yet analyzed in VirusTotal global database."
            return result

        elif resp.status_code == 429:
            result["status"] = "rate_limited"
            result["message"] = "VirusTotal API rate limit reached (4 requests/min on free tier)."
            return result

        elif resp.status_code == 401:
            result["status"] = "error"
            result["message"] = "Invalid or expired VirusTotal API key."
            return result

        else:
            result["status"] = "error"
            result["message"] = f"VirusTotal returned HTTP status {resp.status_code}."
            return result

    except requests.exceptions.Timeout:
        result["status"] = "error"
        result["message"] = "VirusTotal API connection timed out."
        return result
    except Exception as e:
        result["status"] = "error"
        result["message"] = "Unable to connect to threat reputation service."
        return result
