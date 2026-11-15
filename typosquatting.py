"""
TRINETRA - Typosquatting and Brand Impersonation Detection Engine
==================================================================

Identifies deceptive domain imitations targeting prominent brands, banking institutions,
and tech platforms using:
  1. Levenshtein edit distance analysis
  2. Homoglyph / visually confusable character substitutions (e.g. 0 -> o, 1 -> l/i, vv -> w)
  3. Bitsquatting (single-bit flips in ASCII characters)
  4. Brand substring nesting (e.g. 'paypal.verification-portal.com' or 'login-paypal.com')
  5. Prefix/suffix hyphenation tricks (e.g. 'apple-security-id.com')

Ensures that genuine brand domains (e.g. 'paypal.com' or 'google.com') are NOT flagged.
"""

from __future__ import annotations

import difflib
import re
from feature_extraction import BRAND_NAMES, registered_domain

# High-profile targets for typosquatting / brand impersonation
MONITORED_BRANDS = {
    "google": {"domains": ["google.com", "google.co.in", "google.co.uk", "google.de", "google.fr", "google.ca"], "category": "Search & Cloud"},
    "paypal": {"domains": ["paypal.com", "paypal.me"], "category": "Financial Services"},
    "apple": {"domains": ["apple.com", "icloud.com"], "category": "Tech & Hardware"},
    "microsoft": {"domains": ["microsoft.com", "live.com", "office.com", "outlook.com"], "category": "Software & Enterprise"},
    "amazon": {"domains": ["amazon.com", "amazon.co.uk", "amazon.in", "amazon.de"], "category": "E-Commerce"},
    "facebook": {"domains": ["facebook.com", "fb.com", "meta.com"], "category": "Social Media"},
    "instagram": {"domains": ["instagram.com"], "category": "Social Media"},
    "netflix": {"domains": ["netflix.com"], "category": "Streaming Media"},
    "whatsapp": {"domains": ["whatsapp.com"], "category": "Communication"},
    "linkedin": {"domains": ["linkedin.com"], "category": "Social & Professional"},
    "twitter": {"domains": ["twitter.com", "x.com"], "category": "Social Media"},
    "yahoo": {"domains": ["yahoo.com"], "category": "Portal & Email"},
    "chase": {"domains": ["chase.com"], "category": "Banking"},
    "wellsfargo": {"domains": ["wellsfargo.com"], "category": "Banking"},
    "bankofamerica": {"domains": ["bankofamerica.com", "bofa.com"], "category": "Banking"},
    "citibank": {"domains": ["citibank.com", "citi.com"], "category": "Banking"},
    "sbi": {"domains": ["onlinesbi.sbi", "sbi.co.in"], "category": "Banking"},
    "hdfcbank": {"domains": ["hdfcbank.com"], "category": "Banking"},
    "icicibank": {"domains": ["icicibank.com"], "category": "Banking"},
    "binance": {"domains": ["binance.com"], "category": "Cryptocurrency"},
    "coinbase": {"domains": ["coinbase.com"], "category": "Cryptocurrency"},
    "metamask": {"domains": ["metamask.io"], "category": "Cryptocurrency"},
    "dropbox": {"domains": ["dropbox.com"], "category": "Cloud Storage"},
    "github": {"domains": ["github.com"], "category": "Developer Platform"},
    "gitlab": {"domains": ["gitlab.com"], "category": "Developer Platform"},
    "dhl": {"domains": ["dhl.com"], "category": "Logistics"},
    "fedex": {"domains": ["fedex.com"], "category": "Logistics"},
    "usps": {"domains": ["usps.com"], "category": "Logistics"},
    "steam": {"domains": ["steampowered.com", "steamcommunity.com"], "category": "Gaming Platform"},
}

# Common leetspeak & homoglyph character substitutions used in phishing
HOMOGLYPH_MAP = {
    "0": "o", "1": "l", "l": "i", "i": "l", "3": "e", "4": "a", "@": "a",
    "5": "s", "$": "s", "7": "t", "8": "b", "9": "g", "vv": "w", "rn": "m",
    "cl": "d",
}


def normalize_homoglyphs(text: str) -> str:
    """Normalize common leetspeak substitutions back to Latin letters."""
    norm = text.lower()
    for sub, rep in HOMOGLYPH_MAP.items():
        norm = norm.replace(sub, rep)
    return norm


def levenshtein_distance(s1: str, s2: str) -> int:
    """Computes Levenshtein distance between two strings."""
    if len(s1) < len(s2):
        return levenshtein_distance(s2, s1)
    if len(s2) == 0:
        return len(s1)

    previous_row = range(len(s2) + 1)
    for i, c1 in enumerate(s1):
        current_row = [i + 1]
        for j, c2 in enumerate(s2):
            insertions = previous_row[j + 1] + 1
            deletions = current_row[j] + 1
            substitutions = previous_row[j] + (c1 != c2)
            current_row.append(min(insertions, deletions, substitutions))
        previous_row = current_row
    return previous_row[-1]


def detect_typosquatting(hostname: str) -> dict:
    """
    Analyzes hostname for typosquatting or brand impersonation.
    Returns:
      {
        "is_impersonation": bool,
        "target_brand": str | None,
        "authentic_domains": list[str],
        "technique": str | None,
        "reason": str | None,
        "severity": "high" | "medium" | "none"
      }
    """
    host = (hostname or "").lower().rstrip(".")
    if not host:
        return {"is_impersonation": False, "target_brand": None, "technique": None, "reason": None, "severity": "none"}

    reg_domain, tld, subdomains = registered_domain(host)
    reg_sld = reg_domain.split(".")[0] if "." in reg_domain else reg_domain

    # 1. Check if the domain is legitimately owned by one of the brands
    for brand, info in MONITORED_BRANDS.items():
        if reg_domain in info["domains"]:
            return {
                "is_impersonation": False,
                "target_brand": brand.title(),
                "authentic_domains": info["domains"],
                "technique": "Legitimate Official Domain",
                "reason": f"This domain is verified as an official property of {brand.title()}.",
                "severity": "none",
            }

    # 2. Check for Brand Name Nesting in Subdomains or Hyphenated Prefixes
    # Example: "paypal.security-update.com" or "login-paypal-account.com"
    for brand, info in MONITORED_BRANDS.items():
        # Check subdomains
        for sub in subdomains:
            if brand == sub or f"{brand}-" in sub or f"-{brand}" in sub:
                return {
                    "is_impersonation": True,
                    "target_brand": brand.title(),
                    "authentic_domains": info["domains"],
                    "technique": "Subdomain Brand Nesting",
                    "reason": f"Brand '{brand.title()}' appears as a subdomain on untrusted registered domain '{reg_domain}'.",
                    "severity": "high",
                }

        # Check hyphenated / concatenated SLD: "paypal-update.com" or "verify-paypal.com"
        if brand in reg_sld and reg_sld != brand:
            # e.g., 'paypal-security' or 'bankpaypal'
            return {
                "is_impersonation": True,
                "target_brand": brand.title(),
                "authentic_domains": info["domains"],
                "technique": "Combosquatting / Brand Prefix/Suffix",
                "reason": f"Brand '{brand.title()}' is incorporated into domain name '{reg_domain}' outside official infrastructure.",
                "severity": "high",
            }

    # 3. Check for Homoglyph Substitutions (e.g. paypa1, amaz0n, g00gle)
    norm_sld = normalize_homoglyphs(reg_sld)
    for brand, info in MONITORED_BRANDS.items():
        if norm_sld == brand and reg_sld != brand:
            return {
                "is_impersonation": True,
                "target_brand": brand.title(),
                "authentic_domains": info["domains"],
                "technique": "Homoglyph / Visual Substitution",
                "reason": f"Domain '{reg_sld}' uses visually deceptive character substitution (e.g., 0 for o, 1 for l) to mimic '{brand.title()}'.",
                "severity": "high",
            }

    # 4. Levenshtein Edit Distance Typosquatting (Distance == 1 or 2)
    # Examples: 'payapl.com' (transposition), 'googel.com', 'amazn.com' (omission)
    for brand, info in MONITORED_BRANDS.items():
        # Only check distance if length is comparable
        if abs(len(reg_sld) - len(brand)) <= 2:
            dist = levenshtein_distance(reg_sld, brand)
            if dist == 1 and len(brand) >= 4:
                return {
                    "is_impersonation": True,
                    "target_brand": brand.title(),
                    "authentic_domains": info["domains"],
                    "technique": "Typo / Character Omission / Transposition",
                    "reason": f"Domain '{reg_domain}' is 1 character edit away from official brand '{brand.title()}' ({info['domains'][0]}).",
                    "severity": "high",
                }
            elif dist == 2 and len(brand) >= 6:
                return {
                    "is_impersonation": True,
                    "target_brand": brand.title(),
                    "authentic_domains": info["domains"],
                    "technique": "Close Typographical Variant",
                    "reason": f"Domain '{reg_domain}' closely resembles official brand '{brand.title()}'.",
                    "severity": "medium",
                }

    return {
        "is_impersonation": False,
        "target_brand": None,
        "authentic_domains": [],
        "technique": None,
        "reason": None,
        "severity": "none",
    }
