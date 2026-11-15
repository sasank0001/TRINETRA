"""
TRINETRA - URL Scanning & Intelligent Risk Assessment Engine
============================================================

Integrates:
  1. Lexical Feature Extraction (41 features, identical to training pipeline)
  2. Random Forest Model Inference & Tree Path Interpretation
  3. Typosquatting & Brand Impersonation Detection
  4. Domain Intelligence (WHOIS, DNS, Age calculation)
  5. Threat Reputation (VirusTotal API integration)
  6. URL Redirection & Chain Analysis
  7. Transparent Intelligent Risk Scoring (0–100 scale):
     - Low Risk: 0–30
     - Medium Risk: 31–60
     - High Risk: 61–100
"""

from __future__ import annotations

import json
import os
import re
import threading
from urllib.parse import urlsplit

import joblib
import numpy as np
import pandas as pd

from domain_intelligence import get_domain_intelligence
from feature_extraction import (
    FEATURE_LABELS,
    FEATURE_NAMES,
    explain_indicators,
    extract_features,
    features_to_vector,
    normalize_url,
    parse_url,
)
from redirect_analysis import analyze_redirects
from threat_reputation import get_threat_reputation
from typosquatting import detect_typosquatting

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
MODEL_PATH = os.path.join(BASE_DIR, "model", "trinetra_rf_model.joblib")
METRICS_PATH = os.path.join(BASE_DIR, "model", "metrics.json")

MAX_URL_LENGTH = 2048


class ModelNotAvailableError(RuntimeError):
    pass


class InvalidURLError(ValueError):
    pass


_HOST_LABEL_RE = re.compile(r"^(?!-)[a-z0-9\-_]{1,63}(?<!-)$", re.I)
_ALLOWED_SCHEMES = {"http", "https"}


def validate_url(raw: str) -> str:
    """Validate user URL input without executing or connecting to anything."""
    if raw is None:
        raise InvalidURLError("Please enter a URL to scan.")
    url = str(raw).strip()
    if not url:
        raise InvalidURLError("Please enter a URL to scan.")
    if len(url) > MAX_URL_LENGTH:
        raise InvalidURLError(f"URL is too long (maximum {MAX_URL_LENGTH} characters).")
    if any(ch.isspace() for ch in url):
        raise InvalidURLError("URLs cannot contain spaces or line breaks.")
    if any(ord(ch) < 32 or ord(ch) == 127 for ch in url):
        raise InvalidURLError("URL contains invalid control characters.")

    scheme_match = re.match(r"^([a-zA-Z][a-zA-Z0-9+.\-]*):", url)
    if scheme_match and "://" in url[: len(scheme_match.group(0)) + 2]:
        scheme = scheme_match.group(1).lower()
        if scheme not in _ALLOWED_SCHEMES:
            raise InvalidURLError(f"Only http:// and https:// URLs can be scanned (got '{scheme}://').")
    elif scheme_match and scheme_match.group(1).lower() in ("javascript", "data", "file", "vbscript", "mailto"):
        raise InvalidURLError("Only web (http/https) URLs can be scanned.")

    try:
        parts = urlsplit(normalize_url(url))
        host = parts.hostname
        _ = parts.port
    except ValueError:
        raise InvalidURLError("The URL is malformed (invalid host or port).")
    if not host:
        raise InvalidURLError("The URL does not contain a valid domain or IP address.")
    host = host.rstrip(".")
    if len(host) > 253:
        raise InvalidURLError("Domain name is too long.")
    if not re.match(r"^\[?[0-9a-f:.]+\]?$", host, re.I):
        labels = host.split(".")
        if len(labels) < 2:
            raise InvalidURLError("Please enter a complete domain such as 'example.com'.")
        try:
            ascii_host = host.encode("idna").decode("ascii")
        except UnicodeError:
            raise InvalidURLError("The domain name contains invalid characters.")
        for label in ascii_host.split("."):
            if not _HOST_LABEL_RE.match(label):
                raise InvalidURLError("The domain name contains invalid characters.")
    return url


class Scanner:
    def __init__(self, model_path: str = MODEL_PATH):
        self.model_path = model_path
        self._bundle = None
        self._lock = threading.Lock()

    def _load(self):
        if self._bundle is None:
            with self._lock:
                if self._bundle is None:
                    if not os.path.exists(self.model_path):
                        raise ModelNotAvailableError("Trained model not found. Retrain the model first.")
                    bundle = joblib.load(self.model_path)
                    if bundle.get("feature_names") != FEATURE_NAMES:
                        raise ModelNotAvailableError("Model feature mismatch. Retrain the model.")
                    self._bundle = bundle
        return self._bundle

    @property
    def available(self) -> bool:
        try:
            self._load()
            return True
        except ModelNotAvailableError:
            return False

    @staticmethod
    def _tree_contributions(model, x: np.ndarray, phishing_idx: int) -> np.ndarray:
        contrib = np.zeros(x.shape[1])
        for est in model.estimators_:
            tree = est.tree_
            values = tree.value[:, 0, :]
            probs = values / values.sum(axis=1, keepdims=True)
            node = 0
            while tree.children_left[node] != -1:
                feat = tree.feature[node]
                if x[0, feat] <= tree.threshold[node]:
                    nxt = tree.children_left[node]
                else:
                    nxt = tree.children_right[node]
                contrib[feat] += probs[nxt, phishing_idx] - probs[node, phishing_idx]
                node = nxt
        return contrib / len(model.estimators_)

    def scan(self, raw_url: str) -> dict:
        url = validate_url(raw_url)
        bundle = self._load()
        model = bundle["model"]
        phishing_label = bundle.get("phishing_label", 1)
        classes = list(model.classes_)
        phishing_idx = classes.index(phishing_label)

        # 1. Lexical feature extraction (Identical to training)
        feats = extract_features(url)
        vec = np.array([features_to_vector(feats)], dtype=float)
        X = pd.DataFrame(vec, columns=FEATURE_NAMES)
        rf_prob = float(model.predict_proba(X)[0][phishing_idx])

        # 2. Heuristic explanations
        indicators = explain_indicators(url, feats)

        # 3. Typosquatting & Brand Impersonation Check
        p = parse_url(url)
        host = p["host"]
        typo_res = detect_typosquatting(host)
        if typo_res.get("is_impersonation"):
            indicators.append({
                "severity": typo_res["severity"],
                "title": f"Suspected Brand Impersonation: {typo_res['target_brand']}",
                "detail": typo_res["reason"],
            })

        # 4. Domain Intelligence & WHOIS
        dom_intel = get_domain_intelligence(host)
        for ind in dom_intel.get("indicators", []):
            indicators.append(ind)

        # 5. Threat Reputation Check (VirusTotal API)
        reputation = get_threat_reputation(url)
        if reputation.get("malicious_count", 0) > 0:
            indicators.append({
                "severity": "high",
                "title": "Threat Intelligence Blacklist Match",
                "detail": reputation["message"],
            })

        # 6. Safe URL Redirect Analysis
        redirect_res = analyze_redirects(url)
        for ind in redirect_res.get("indicators", []):
            indicators.append(ind)

        # 7. Model-driven tree factors (Explainable AI)
        contrib = self._tree_contributions(model, vec, phishing_idx)
        order = np.argsort(-np.abs(contrib))
        factors = []
        for i in order[:8]:
            if abs(contrib[i]) < 0.005:
                continue
            name = FEATURE_NAMES[i]
            factors.append({
                "feature": name,
                "label": FEATURE_LABELS.get(name, name),
                "value": feats[name],
                "impact": round(float(contrib[i]) * 100, 1),
                "direction": "phishing" if contrib[i] > 0 else "legitimate",
            })

        # 8. Intelligent Risk Scoring (0–100) & Breakdown
        # ML Base: 0 to 65 points from pure Random Forest probability
        base_score = rf_prob * 65.0
        score_breakdown = [
            {"factor": "Machine Learning Baseline (Random Forest)", "points": round(base_score, 1), "description": f"Probability: {rf_prob*100:.1f}%"}
        ]
        additive_points = 0.0

        # Typosquatting impact
        if typo_res.get("is_impersonation"):
            pts = 20.0 if typo_res["severity"] == "high" else 10.0
            additive_points += pts
            score_breakdown.append({"factor": "Brand Impersonation / Typosquatting", "points": pts, "description": typo_res["technique"]})

        # Domain age impact
        if dom_intel.get("domain_age_days") is not None:
            if dom_intel["domain_age_days"] < 30:
                additive_points += 15.0
                score_breakdown.append({"factor": "Domain Age < 30 Days", "points": 15.0, "description": f"Registered {dom_intel['domain_age_days']} days ago"})
            elif dom_intel["domain_age_days"] < 90:
                additive_points += 8.0
                score_breakdown.append({"factor": "Domain Age < 90 Days", "points": 8.0, "description": f"Registered {dom_intel['domain_age_days']} days ago"})

        # Threat reputation impact (Only if configured and vendors flag it)
        if reputation.get("malicious_count", 0) > 0:
            mal_pts = min(20.0, reputation["malicious_count"] * 5.0)
            additive_points += mal_pts
            score_breakdown.append({"factor": "VirusTotal Vendor Detections", "points": mal_pts, "description": f"{reputation['malicious_count']} vendors flagged"})

        # Cross-domain redirect impact
        if redirect_res.get("domain_changed"):
            additive_points += 10.0
            score_breakdown.append({"factor": "Cross-Domain Redirect Chain", "points": 10.0, "description": f"Hops: {redirect_res['redirect_count']}"})

        # High heuristic indicators impact
        high_heuristics = sum(1 for ind in indicators if ind["severity"] == "high" and "Brand Impersonation" not in ind["title"] and "Blacklist" not in ind["title"])
        if high_heuristics > 0:
            h_pts = min(15.0, high_heuristics * 8.0)
            additive_points += h_pts
            score_breakdown.append({"factor": "High-Severity Heuristics (IP host, @ symbol, punycode)", "points": h_pts, "description": f"{high_heuristics} indicator(s)"})

        # Total combined score clamped to [0, 100]
        final_score = int(round(min(100.0, max(0.0, base_score + additive_points))))

        # Explicit Thresholds as required:
        # 0–30: Low Risk
        # 31–60: Medium Risk
        # 61–100: High Risk
        if final_score <= 30:
            risk_level = "LOW"
            prediction = "Legitimate"
        elif final_score <= 60:
            risk_level = "MEDIUM"
            prediction = "Suspicious"
        else:
            risk_level = "HIGH"
            prediction = "Potentially Phishing"

        return {
            "url": url,
            "normalized_url": p["normalized"],
            "domain": host,
            "scheme_supplied": "://" in url,
            "prediction": prediction,
            "risk_level": risk_level,
            "phishing_probability": round(rf_prob, 4),
            "risk_score": final_score,
            "score_breakdown": score_breakdown,
            "features": feats,
            "indicators": indicators,
            "model_factors": factors,
            "typosquatting": typo_res,
            "domain_intelligence": dom_intel,
            "threat_reputation": reputation,
            "redirect_analysis": redirect_res,
            "model_version": bundle.get("version", "1.0.0"),
        }

    @staticmethod
    def load_metrics() -> dict | None:
        if not os.path.exists(METRICS_PATH):
            return None
        try:
            with open(METRICS_PATH, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception:
            return None


scanner = Scanner()
