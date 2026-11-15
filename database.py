"""
TRINETRA - SQLite database layer (Upgraded).

All queries use parameter binding ('?' placeholders) to prevent SQL injection.
Stores full scan records along with advanced modular telemetry:
  - Explainable AI factors
  - Typosquatting & brand findings
  - Domain intelligence & WHOIS data
  - Threat reputation (VirusTotal) results
  - URL redirect analysis results
"""

from __future__ import annotations

import json
import os
import sqlite3
from contextlib import contextmanager
from datetime import datetime, timedelta

BASE_DIR = os.path.dirname(os.path.abspath(__file__))


def _resolve_db_path() -> str:
    """
    Resolve database path with fallback for serverless read-only environments (e.g. Vercel, AWS Lambda).
    """
    env_path = os.environ.get("TRINETRA_DB_PATH")
    if env_path:
        return env_path

    # If running on Vercel or other serverless platforms, default directly to /tmp
    if os.environ.get("VERCEL") or os.environ.get("AWS_LAMBDA_FUNCTION_NAME"):
        return "/tmp/trinetra.db"

    default_dir = os.path.join(BASE_DIR, "instance")
    try:
        os.makedirs(default_dir, exist_ok=True)
        # Test write permission
        test_file = os.path.join(default_dir, ".write_test")
        with open(test_file, "w") as f:
            f.write("ok")
        if os.path.exists(test_file):
            os.remove(test_file)
        return os.path.join(default_dir, "trinetra.db")
    except (OSError, IOError, PermissionError):
        # Fallback to /tmp on read-only filesystem
        return "/tmp/trinetra.db"


DB_PATH = _resolve_db_path()

SCHEMA = """
CREATE TABLE IF NOT EXISTS scans (
    id                   INTEGER PRIMARY KEY AUTOINCREMENT,
    url                  TEXT    NOT NULL,
    normalized_url       TEXT    NOT NULL,
    domain               TEXT,
    prediction           TEXT    NOT NULL,      -- Legitimate | Suspicious | Potentially Phishing
    risk_level           TEXT    NOT NULL,      -- LOW | MEDIUM | HIGH
    phishing_probability REAL    NOT NULL,      -- model probability of phishing class (0-1)
    risk_score           INTEGER NOT NULL,      -- 0-100 combined score (0-30: Low, 31-60: Medium, 61-100: High)
    features_json        TEXT    NOT NULL,
    indicators_json      TEXT    NOT NULL,
    score_breakdown_json TEXT,                  -- intelligent scoring factor contributions
    typosquatting_json   TEXT,                  -- brand impersonation telemetry
    domain_intel_json    TEXT,                  -- WHOIS & DNS intelligence
    threat_reputation_json TEXT,                -- VirusTotal API findings
    redirect_analysis_json TEXT,                -- safe redirect chain results
    model_version        TEXT,
    scanned_at           TEXT    NOT NULL       -- ISO-8601 local time
);
CREATE INDEX IF NOT EXISTS idx_scans_scanned_at ON scans(scanned_at);
CREATE INDEX IF NOT EXISTS idx_scans_risk ON scans(risk_level);
"""


@contextmanager
def get_conn():
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
    conn = sqlite3.connect(DB_PATH, timeout=10)
    conn.row_factory = sqlite3.Row
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


def init_db() -> None:
    with get_conn() as conn:
        conn.executescript(SCHEMA)
        # Migrate existing SQLite databases if columns are missing
        existing_cols = [c[1] for c in conn.execute("PRAGMA table_info(scans)").fetchall()]
        cols_to_add = [
            ("score_breakdown_json", "TEXT"),
            ("typosquatting_json", "TEXT"),
            ("domain_intel_json", "TEXT"),
            ("threat_reputation_json", "TEXT"),
            ("redirect_analysis_json", "TEXT"),
        ]
        for col_name, col_type in cols_to_add:
            if col_name not in existing_cols:
                conn.execute(f"ALTER TABLE scans ADD COLUMN {col_name} {col_type}")


def _row_to_dict(row: sqlite3.Row) -> dict:
    d = dict(row)
    d["features"] = json.loads(d.pop("features_json") or "{}")
    d["indicators"] = json.loads(d.pop("indicators_json") or "[]")
    d["score_breakdown"] = json.loads(d.pop("score_breakdown_json", None) or "[]")
    d["typosquatting"] = json.loads(d.pop("typosquatting_json", None) or "{}")
    d["domain_intelligence"] = json.loads(d.pop("domain_intel_json", None) or "{}")
    d["threat_reputation"] = json.loads(d.pop("threat_reputation_json", None) or "{}")
    d["redirect_analysis"] = json.loads(d.pop("redirect_analysis_json", None) or "{}")
    return d


def save_scan(result: dict) -> int:
    with get_conn() as conn:
        cur = conn.execute(
            """INSERT INTO scans (url, normalized_url, domain, prediction, risk_level,
                   phishing_probability, risk_score, features_json, indicators_json,
                   score_breakdown_json, typosquatting_json, domain_intel_json,
                   threat_reputation_json, redirect_analysis_json,
                   model_version, scanned_at)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                result["url"],
                result["normalized_url"],
                result.get("domain"),
                result["prediction"],
                result["risk_level"],
                float(result["phishing_probability"]),
                int(result["risk_score"]),
                json.dumps(result["features"]),
                json.dumps(result["indicators"]),
                json.dumps(result.get("score_breakdown", [])),
                json.dumps(result.get("typosquatting", {})),
                json.dumps(result.get("domain_intelligence", {})),
                json.dumps(result.get("threat_reputation", {})),
                json.dumps(result.get("redirect_analysis", {})),
                result.get("model_version"),
                datetime.now().isoformat(timespec="seconds"),
            ),
        )
        return cur.lastrowid


def get_scan(scan_id: int) -> dict | None:
    with get_conn() as conn:
        row = conn.execute("SELECT * FROM scans WHERE id = ?", (scan_id,)).fetchone()
        return _row_to_dict(row) if row else None


def list_scans(page: int = 1, per_page: int = 20, search: str = "", risk: str = "") -> tuple[list[dict], int]:
    where, params = [], []
    if search:
        where.append("url LIKE ? ESCAPE '\\'")
        esc = search.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
        params.append(f"%{esc}%")
    if risk in ("LOW", "MEDIUM", "HIGH"):
        where.append("risk_level = ?")
        params.append(risk)
    clause = ("WHERE " + " AND ".join(where)) if where else ""
    offset = max(page - 1, 0) * per_page
    with get_conn() as conn:
        total = conn.execute(f"SELECT COUNT(*) FROM scans {clause}", params).fetchone()[0]
        rows = conn.execute(
            f"SELECT * FROM scans {clause} ORDER BY id DESC LIMIT ? OFFSET ?",
            params + [per_page, offset],
        ).fetchall()
    return [_row_to_dict(r) for r in rows], total


def delete_scan(scan_id: int) -> bool:
    with get_conn() as conn:
        cur = conn.execute("DELETE FROM scans WHERE id = ?", (scan_id,))
        return cur.rowcount > 0


def clear_history() -> int:
    with get_conn() as conn:
        cur = conn.execute("DELETE FROM scans")
        conn.execute("DELETE FROM sqlite_sequence WHERE name = 'scans'")
        return cur.rowcount


def get_stats(days: int = 14) -> dict:
    """Aggregate enhanced dashboard statistics directly from the scans table."""
    with get_conn() as conn:
        total = conn.execute("SELECT COUNT(*) FROM scans").fetchone()[0]
        by_pred = {r[0]: r[1] for r in conn.execute(
            "SELECT prediction, COUNT(*) FROM scans GROUP BY prediction")}
        by_risk = {r[0]: r[1] for r in conn.execute(
            "SELECT risk_level, COUNT(*) FROM scans GROUP BY risk_level")}
        avg_score = conn.execute("SELECT AVG(risk_score) FROM scans").fetchone()[0]

        start = (datetime.now() - timedelta(days=days - 1)).date()
        daily_rows = conn.execute(
            """SELECT substr(scanned_at, 1, 10) AS day, risk_level, COUNT(*)
               FROM scans WHERE substr(scanned_at, 1, 10) >= ?
               GROUP BY day, risk_level""",
            (start.isoformat(),),
        ).fetchall()

        top_domains = [dict(domain=r[0], count=r[1]) for r in conn.execute(
            """SELECT domain, COUNT(*) c FROM scans
               WHERE risk_level = 'HIGH' AND domain IS NOT NULL AND domain != ''
               GROUP BY domain ORDER BY c DESC LIMIT 5""")]

        recent = [_row_to_dict(r) for r in conn.execute(
            "SELECT * FROM scans ORDER BY id DESC LIMIT 10").fetchall()]

        pattern_counts: dict[str, int] = {}
        typo_count = 0
        new_domain_count = 0
        redirect_count = 0

        for row in conn.execute("SELECT indicators_json, typosquatting_json, domain_intel_json, redirect_analysis_json FROM scans ORDER BY id DESC LIMIT 2000"):
            ind_json, typo_json, intel_json, red_json = row
            for ind in json.loads(ind_json or "[]"):
                t = ind.get("title", "")
                if t:
                    pattern_counts[t] = pattern_counts.get(t, 0) + 1

            typo_obj = json.loads(typo_json or "{}")
            if typo_obj.get("is_impersonation"):
                typo_count += 1

            intel_obj = json.loads(intel_json or "{}")
            if intel_obj.get("is_newly_registered"):
                new_domain_count += 1

            red_obj = json.loads(red_json or "{}")
            if red_obj.get("redirect_count", 0) > 0:
                redirect_count += 1

    labels = [(start + timedelta(days=i)).isoformat() for i in range(days)]
    series = {lvl: [0] * days for lvl in ("LOW", "MEDIUM", "HIGH")}
    idx = {d: i for i, d in enumerate(labels)}
    for day, lvl, cnt in daily_rows:
        if day in idx and lvl in series:
            series[lvl][idx[day]] = cnt

    top_patterns = sorted(pattern_counts.items(), key=lambda kv: kv[1], reverse=True)[:8]

    phishing_pct = round((by_pred.get("Potentially Phishing", 0) / total * 100), 1) if total > 0 else 0.0

    return {
        "total": total,
        "legitimate": by_pred.get("Legitimate", 0),
        "suspicious": by_pred.get("Suspicious", 0),
        "phishing": by_pred.get("Potentially Phishing", 0),
        "phishing_percentage": phishing_pct,
        "low": by_risk.get("LOW", 0),
        "medium": by_risk.get("MEDIUM", 0),
        "high": by_risk.get("HIGH", 0),
        "avg_risk_score": round(avg_score, 1) if avg_score is not None else 0,
        "daily": {"labels": labels, **series},
        "top_high_risk_domains": top_domains,
        "top_patterns": [{"pattern": t, "count": c} for t, c in top_patterns],
        "typosquatting_detected": typo_count,
        "newly_registered_domains": new_domain_count,
        "redirect_chains_detected": redirect_count,
        "recent": recent,
    }
