"""
TRINETRA - URL Feature Extraction
=================================

Purely *lexical* feature extraction for URLs. The submitted URL is NEVER
fetched, resolved, opened or downloaded - every feature is computed from the
URL string itself. This makes scanning safe and deterministic.

The SAME function (`extract_features`) and the SAME ordered feature list
(`FEATURE_NAMES`) are used by both `train_model.py` and `scanner.py`, which
guarantees the training and prediction pipelines are identical.
"""

from __future__ import annotations

import ipaddress
import math
import re
from collections import Counter
from urllib.parse import urlsplit, unquote

# ---------------------------------------------------------------------------
# Reference lists
# ---------------------------------------------------------------------------

SUSPICIOUS_KEYWORDS = (
    "login", "log-in", "signin", "sign-in", "verify", "verification", "update",
    "secure", "security", "account", "banking", "bank", "confirm", "password",
    "webscr", "ebayisapi", "wallet", "suspend", "unlock", "billing", "invoice",
    "authenticate", "auth", "recover", "validation", "support", "alert",
    "free", "bonus", "lucky", "gift", "prize", "claim", "kyc", "otp",
)

BRAND_NAMES = (
    "paypal", "apple", "icloud", "microsoft", "office365", "outlook", "google",
    "gmail", "facebook", "instagram", "whatsapp", "amazon", "netflix", "ebay",
    "linkedin", "dropbox", "adobe", "chase", "wellsfargo", "bankofamerica",
    "citibank", "hsbc", "barclays", "sbi", "hdfc", "icici", "axisbank",
    "paytm", "phonepe", "dhl", "fedex", "usps", "coinbase", "binance",
    "metamask", "steam", "yahoo", "twitter", "telegram", "irs", "docusign",
)

URL_SHORTENERS = (
    "bit.ly", "goo.gl", "tinyurl.com", "t.co", "ow.ly", "is.gd", "buff.ly",
    "adf.ly", "bit.do", "cutt.ly", "shorturl.at", "rb.gy", "tiny.cc", "t.ly",
    "rebrand.ly", "s.id", "v.gd", "qr.co", "lnkd.in", "trib.al", "shorte.st",
)

# TLDs that are statistically over-represented in abuse reports
# (Spamhaus / Interisle "most abused TLD" lists).
SUSPICIOUS_TLDS = (
    "tk", "ml", "ga", "cf", "gq", "xyz", "top", "work", "click", "link",
    "zip", "mov", "country", "kim", "loan", "men", "gdn", "racing", "review",
    "rest", "bar", "buzz", "cam", "icu", "monster", "sbs", "cfd", "quest",
    "support", "live", "online", "site", "fit", "best", "beauty", "hair",
)

# Common multi-label public suffixes (small offline approximation of the PSL)
MULTI_LABEL_SUFFIXES = (
    "co.uk", "org.uk", "ac.uk", "gov.uk", "co.in", "org.in", "gov.in", "ac.in",
    "net.in", "edu.in", "nic.in", "res.in", "com.au", "net.au", "org.au",
    "edu.au", "gov.au", "co.jp", "ne.jp", "or.jp", "ac.jp", "co.kr", "co.nz",
    "com.br", "com.cn", "com.mx", "com.tr", "com.sg", "com.my", "com.pk",
    "com.ng", "co.za", "com.ar", "com.co", "com.hk", "com.tw", "co.id",
    "com.ph", "com.vn", "com.ua", "com.eg", "com.sa", "co.il", "com.bd",
)

# ---------------------------------------------------------------------------
# Ordered feature list (the model is trained on exactly these columns)
# ---------------------------------------------------------------------------

FEATURE_NAMES = [
    "url_length",
    "hostname_length",
    "path_length",
    "query_length",
    "num_dots",
    "num_dots_host",
    "num_hyphens",
    "num_hyphens_host",
    "num_underscores",
    "num_slashes",
    "num_at",
    "num_question",
    "num_equals",
    "num_ampersand",
    "num_percent",
    "num_tilde",
    "num_digits",
    "num_digits_host",
    "digit_ratio",
    "letter_ratio",
    "special_char_ratio",
    "has_https",
    "has_ip",
    "has_port",
    "has_at_symbol",
    "num_subdomains",
    "tld_length",
    "suspicious_tld",
    "suspicious_keyword_count",
    "brand_in_subdomain_or_path",
    "is_shortener",
    "has_punycode",
    "has_double_slash_redirect",
    "has_hex_encoding",
    "host_entropy",
    "url_entropy",
    "path_depth",
    "longest_token_length",
    "has_http_in_path",
    "has_file_extension",
    "consecutive_char_repeat",
]

_IPV4_HEX_RE = re.compile(r"^(0x[0-9a-f]+\.?){1,4}$", re.I)
_SCHEME_RE = re.compile(r"^[a-zA-Z][a-zA-Z0-9+.\-]*://")
_FILE_EXT_RE = re.compile(
    r"\.(exe|zip|rar|apk|scr|js|bat|cmd|msi|jar|vbs|ps1|php|html?|asp|aspx|cgi)$",
    re.I,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def normalize_url(url: str) -> str:
    """Trim whitespace and ensure the URL has a scheme so it can be parsed.

    URLs without an explicit scheme are given ``http://`` purely so the parser
    can locate the hostname. This is applied identically during training and
    prediction.
    """
    url = (url or "").strip()
    if not _SCHEME_RE.match(url):
        url = "http://" + url
    return url


def _shannon_entropy(text: str) -> float:
    if not text:
        return 0.0
    counts = Counter(text)
    length = len(text)
    return -sum((c / length) * math.log2(c / length) for c in counts.values())


def _is_ip(host: str) -> bool:
    host = host.strip("[]")
    if not host:
        return False
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        pass
    # Hex / octal / integer-encoded IPv4 obfuscation (e.g. 0x7f.0x0.0x0.0x1)
    if _IPV4_HEX_RE.match(host):
        return True
    if host.isdigit() and len(host) >= 8:  # dword IP like http://3232235777
        return True
    return False


def registered_domain(host: str) -> tuple[str, str, list[str]]:
    """Return (registered_domain, tld, subdomain_labels) using an offline
    approximation of the Public Suffix List."""
    labels = [l for l in host.split(".") if l]
    if len(labels) < 2:
        return host, (labels[-1] if labels else ""), []
    last_two = ".".join(labels[-2:])
    if last_two in MULTI_LABEL_SUFFIXES and len(labels) >= 3:
        reg = ".".join(labels[-3:])
        subs = labels[:-3]
        tld = last_two
    else:
        reg = last_two
        subs = labels[:-2]
        tld = labels[-1]
    return reg, tld, subs


def parse_url(url: str) -> dict:
    """Split a URL into components without any network access."""
    norm = normalize_url(url)
    parts = urlsplit(norm)
    host = (parts.hostname or "").lower().rstrip(".")
    invalid_port = False
    try:
        port = parts.port
    except ValueError:
        port, invalid_port = None, True
    return {
        "normalized": norm,
        "scheme": parts.scheme.lower(),
        "netloc": parts.netloc,
        "host": host,
        "port": port,
        "has_explicit_port": port is not None or invalid_port,
        "path": parts.path or "",
        "query": parts.query or "",
        "fragment": parts.fragment or "",
    }


# ---------------------------------------------------------------------------
# Main extraction function
# ---------------------------------------------------------------------------

def extract_features(url: str) -> dict:
    """Extract the lexical feature vector for one URL.

    Returns a dict keyed by every name in ``FEATURE_NAMES``.
    """
    raw = (url or "").strip()
    p = parse_url(raw)
    full = p["normalized"]
    host = p["host"]
    path = p["path"]
    query = p["query"]
    lower_full = full.lower()
    # Everything after the scheme - so 'https://' does not inflate counts.
    body = full.split("://", 1)[1] if "://" in full else full
    body_lower = body.lower()

    reg_domain, tld, subdomains = registered_domain(host)
    is_ip = _is_ip(host)

    letters = sum(ch.isalpha() for ch in body)
    digits = sum(ch.isdigit() for ch in body)
    specials = sum((not ch.isalnum()) for ch in body)
    blen = max(len(body), 1)

    # Keyword / brand analysis is done on everything except the registered
    # domain itself, so 'paypal.com' is not penalised but 'paypal.evil.com'
    # or 'evil.com/paypal/login' is.
    non_reg_part = (".".join(subdomains) + " " + unquote(path) + " " + unquote(query)).lower()
    kw_count = sum(1 for kw in SUSPICIOUS_KEYWORDS if kw in body_lower)
    brand_flag = int(
        any(b in non_reg_part for b in BRAND_NAMES)
        or (not is_ip and any(b in reg_domain.split(".")[0] and b != reg_domain.split(".")[0] for b in BRAND_NAMES))
    )

    tokens = [t for t in re.split(r"[/\.\?\=\-_&:@~%+]", body) if t]
    longest_token = max((len(t) for t in tokens), default=0)
    path_segments = [s for s in path.split("/") if s]

    feats = {
        "url_length": len(body),
        "hostname_length": len(host),
        "path_length": len(path),
        "query_length": len(query),
        "num_dots": body.count("."),
        "num_dots_host": host.count("."),
        "num_hyphens": body.count("-"),
        "num_hyphens_host": host.count("-"),
        "num_underscores": body.count("_"),
        "num_slashes": body.count("/"),
        "num_at": body.count("@"),
        "num_question": body.count("?"),
        "num_equals": body.count("="),
        "num_ampersand": body.count("&"),
        "num_percent": body.count("%"),
        "num_tilde": body.count("~"),
        "num_digits": digits,
        "num_digits_host": sum(ch.isdigit() for ch in host),
        "digit_ratio": round(digits / blen, 4),
        "letter_ratio": round(letters / blen, 4),
        "special_char_ratio": round(specials / blen, 4),
        "has_https": int(p["scheme"] == "https"),
        "has_ip": int(is_ip),
        "has_port": int(p["has_explicit_port"]),
        "has_at_symbol": int("@" in body),
        "num_subdomains": 0 if is_ip else len(subdomains),
        "tld_length": 0 if is_ip else len(tld),
        "suspicious_tld": int((not is_ip) and tld.split(".")[-1] in SUSPICIOUS_TLDS),
        "suspicious_keyword_count": kw_count,
        "brand_in_subdomain_or_path": brand_flag,
        "is_shortener": int(host in URL_SHORTENERS or reg_domain in URL_SHORTENERS),
        "has_punycode": int("xn--" in host),
        "has_double_slash_redirect": int("//" in body),
        "has_hex_encoding": int(bool(re.search(r"%[0-9a-fA-F]{2}", body))),
        "host_entropy": round(_shannon_entropy(host), 4),
        "url_entropy": round(_shannon_entropy(body_lower), 4),
        "path_depth": len(path_segments),
        "longest_token_length": longest_token,
        "has_http_in_path": int("http" in (path + query).lower()),
        "has_file_extension": int(bool(_FILE_EXT_RE.search(path))),
        "consecutive_char_repeat": max((len(m.group(0)) for m in re.finditer(r"(.)\1*", body)), default=0),
    }
    return feats


def features_to_vector(feats: dict) -> list:
    """Convert a feature dict into the ordered list expected by the model."""
    return [feats[name] for name in FEATURE_NAMES]


# ---------------------------------------------------------------------------
# Human-readable explanations (used by scanner.py / the UI)
# ---------------------------------------------------------------------------

FEATURE_LABELS = {
    "url_length": "URL length",
    "hostname_length": "Domain length",
    "path_length": "Path length",
    "query_length": "Query string length",
    "num_dots": "Number of dots",
    "num_dots_host": "Dots in domain",
    "num_hyphens": "Number of hyphens",
    "num_hyphens_host": "Hyphens in domain",
    "num_underscores": "Underscores",
    "num_slashes": "Number of slashes",
    "num_at": "'@' characters",
    "num_question": "'?' characters",
    "num_equals": "'=' characters",
    "num_ampersand": "'&' characters",
    "num_percent": "'%' characters",
    "num_tilde": "'~' characters",
    "num_digits": "Digits in URL",
    "num_digits_host": "Digits in domain",
    "digit_ratio": "Digit ratio",
    "letter_ratio": "Letter ratio",
    "special_char_ratio": "Special-character ratio",
    "has_https": "Uses HTTPS",
    "has_ip": "IP address as host",
    "has_port": "Explicit port number",
    "has_at_symbol": "Contains '@' symbol",
    "num_subdomains": "Number of subdomains",
    "tld_length": "TLD length",
    "suspicious_tld": "High-abuse TLD",
    "suspicious_keyword_count": "Suspicious keywords",
    "brand_in_subdomain_or_path": "Brand name outside registered domain",
    "is_shortener": "URL shortener",
    "has_punycode": "Punycode (IDN) domain",
    "has_double_slash_redirect": "'//' redirect in path",
    "has_hex_encoding": "Percent/hex encoding",
    "host_entropy": "Domain entropy",
    "url_entropy": "URL entropy",
    "path_depth": "Path depth",
    "longest_token_length": "Longest token length",
    "has_http_in_path": "'http' inside path/query",
    "has_file_extension": "Script/executable file extension",
    "consecutive_char_repeat": "Longest repeated character run",
}


def explain_indicators(url: str, feats: dict) -> list[dict]:
    """Return a list of rule-based indicators found in the URL.

    Each indicator: {"severity": "high|medium|low|info", "title": str, "detail": str}
    These explanations complement - and never replace - the ML prediction.
    """
    p = parse_url(url)
    host = p["host"]
    reg_domain, tld, subdomains = registered_domain(host)
    found: list[dict] = []

    def add(sev, title, detail):
        found.append({"severity": sev, "title": title, "detail": detail})

    if feats["has_ip"]:
        add("high", "IP address used instead of domain",
            f"The host '{host}' is a raw IP address. Legitimate services almost always use a domain name.")
    if feats["has_at_symbol"]:
        add("high", "'@' symbol in URL",
            "Browsers ignore everything before '@' in the authority part, a classic trick to disguise the real destination.")
    if feats["brand_in_subdomain_or_path"]:
        add("high", "Brand name outside the registered domain",
            f"A well-known brand name appears in the subdomain, path or a look-alike domain, but the registered domain is '{reg_domain}'.")
    if feats["has_punycode"]:
        add("high", "Punycode / internationalised domain",
            "The domain uses 'xn--' encoding, which can hide look-alike (homograph) characters.")
    if feats["has_double_slash_redirect"]:
        add("medium", "Embedded '//' redirect",
            "A '//' after the domain can indicate an open redirect to another site.")
    if feats["has_http_in_path"]:
        add("medium", "Another URL embedded in path/query",
            "The path or query contains 'http', which is often used to chain redirects.")
    if feats["has_port"]:
        add("medium", "Non-standard port specified",
            f"The URL explicitly specifies port {p['port']}. Public websites rarely require explicit ports.")
    if feats["is_shortener"]:
        add("medium", "URL shortening service",
            "Shortened links hide the final destination. Expand them with a trusted preview service before visiting.")
    if feats["suspicious_tld"]:
        add("medium", "High-abuse top-level domain",
            f"The '.{tld}' TLD is frequently reported in phishing and spam campaigns.")
    if feats["suspicious_keyword_count"] > 0:
        kws = [k for k in SUSPICIOUS_KEYWORDS if k in p["normalized"].lower().split("://", 1)[-1]]
        add("medium" if feats["suspicious_keyword_count"] >= 2 else "low",
            "Suspicious keywords present",
            "Contains: " + ", ".join(sorted(set(kws))[:8]))
    if feats["num_hyphens_host"] >= 2:
        add("medium", "Multiple hyphens in domain",
            f"The domain contains {feats['num_hyphens_host']} hyphens, common in look-alike domains such as 'secure-login-bank.com'.")
    elif feats["num_hyphens_host"] == 1:
        add("low", "Hyphen in domain", "A hyphen in the domain is common but also used by imitation domains.")
    if feats["num_subdomains"] >= 3:
        add("medium", "Excessive subdomains",
            f"{feats['num_subdomains']} subdomain levels detected; attackers stack subdomains to make a URL look trustworthy.")
    if feats["url_length"] >= 100:
        add("medium", "Very long URL", f"The URL is {feats['url_length']} characters long, which can hide the real destination.")
    elif feats["url_length"] >= 60:
        add("low", "Long URL", f"The URL is {feats['url_length']} characters long.")
    if feats["has_hex_encoding"]:
        add("low", "Percent-encoded characters", "Encoded characters can be used to obfuscate the URL content.")
    if feats["has_file_extension"] and re.search(r"\.(exe|zip|rar|apk|scr|bat|cmd|msi|jar|vbs|ps1)$", p["path"], re.I):
        add("high", "Executable / archive download link", "The URL points directly at a downloadable executable or archive file.")
    if feats["host_entropy"] >= 4.0 and not feats["has_ip"]:
        add("low", "Random-looking domain", "The domain name has high character randomness, typical of auto-generated domains.")
    if feats["num_digits_host"] >= 4 and not feats["has_ip"]:
        add("low", "Many digits in domain", f"The domain contains {feats['num_digits_host']} digits.")
    if not feats["has_https"]:
        add("low", "No HTTPS in submitted URL",
            "The URL does not use HTTPS (or no scheme was supplied). Data sent to it may not be encrypted.")
    else:
        add("info", "HTTPS present",
            "The URL uses HTTPS. Note: HTTPS only encrypts traffic - many phishing sites also use valid certificates, so it is NOT proof of legitimacy.")
    return found
