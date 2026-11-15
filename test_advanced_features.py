"""
TRINETRA - Comprehensive Verification Test Suite
================================================
Validates all 8 advanced features:
  1. Explainable AI (XAI)
  2. Typosquatting and Brand Impersonation Detection
  3. Domain Intelligence (DNS/WHOIS)
  4. Threat Reputation (VirusTotal integration & fallbacks)
  5. URL Redirection & Chain Analysis
  6. Intelligent Risk Scoring (0–100 Scale, Low: 0-30, Medium: 31-60, High: 61-100)
  7. PDF Security Reports
  8. Advanced Dashboard Analytics
"""

import io
import json
from app import app
from database import init_db, clear_history
from pdf_generator import generate_pdf_report
from typosquatting import detect_typosquatting
from domain_intelligence import get_domain_intelligence
from redirect_analysis import analyze_redirects
from threat_reputation import get_threat_reputation

def run_tests():
    init_db()
    clear_history()

    print("==================================================")
    print("  TRINETRA ADVANCED FEATURE VERIFICATION SUITE")
    print("==================================================")

    # 1. Test Typosquatting Engine
    print("\n[*] Feature 2: Testing Typosquatting & Brand Impersonation...")
    t1 = detect_typosquatting("paypa1.com")
    assert t1["is_impersonation"], "Failed to detect homoglyph paypa1.com"
    assert t1["target_brand"] == "Paypal"
    print("  [+] Homoglyph paypa1.com detected ->", t1["technique"])

    t2 = detect_typosquatting("google.com")
    assert not t2["is_impersonation"], "Incorrectly flagged authentic google.com"
    print("  [+] Authentic google.com passed without false positive.")

    t3 = detect_typosquatting("paypal.security-login.xyz")
    assert t3["is_impersonation"], "Failed to detect subdomain brand nesting"
    print("  [+] Subdomain brand nesting detected ->", t3["technique"])

    # 2. Test Domain Intelligence
    print("\n[*] Feature 3: Testing Domain Intelligence (DNS/WHOIS)...")
    d1 = get_domain_intelligence("google.com")
    assert d1["domain"] == "google.com"
    assert len(d1["dns_records"]["a"]) > 0
    print(f"  [+] DNS records resolved for google.com: {d1['dns_records']['a'][:2]}")
    print(f"  [+] Registrar: {d1['registrar']} | Age: {d1['domain_age_days']} days")

    # 3. Test Threat Reputation (VirusTotal fallback)
    print("\n[*] Feature 4: Testing Threat Reputation (VirusTotal Fallback)...")
    rep = get_threat_reputation("https://example.com")
    assert rep["service"] == "VirusTotal"
    assert rep["status"] in ("not_configured", "configured", "error")
    print("  [+] Graceful handling confirmed:", rep["message"])

    # 4. Test Safe Redirect Analysis
    print("\n[*] Feature 5: Testing Safe URL Redirect Analysis...")
    red = analyze_redirects("http://google.com")
    assert red["status"] == "success"
    print(f"  [+] Handled redirect: hops={red['redirect_count']}, final={red['final_url']}")

    with app.test_client() as client:
        # 5. Test Live Scan & Intelligent Risk Scoring (Feature 1, 6)
        print("\n[*] Features 1 & 6: Testing Scan API & Intelligent Scoring...")
        res = client.post("/api/scan", json={"url": "https://paypa1.com/login"})
        data = json.loads(res.data)
        assert data["success"]
        scan = data["data"]

        # Check score constraints
        score = scan["risk_score"]
        risk_lvl = scan["risk_level"]
        print(f"  [+] Scanned paypa1.com/login -> Score: {score}/100, Tier: {risk_lvl}")
        assert score >= 61, f"Expected HIGH risk score (>=61), got {score}"
        assert risk_lvl == "HIGH"
        assert len(scan["score_breakdown"]) > 0
        assert len(scan["model_factors"]) > 0
        print("  [+] Explainable AI factors:", len(scan["model_factors"]))
        print("  [+] Score breakdown:", scan["score_breakdown"])

        # Legitimate URL scan
        res_legit = client.post("/api/scan", json={"url": "https://google.com"})
        scan_legit = json.loads(res_legit.data)["data"]
        print(f"  [+] Scanned google.com -> Score: {scan_legit['risk_score']}/100, Tier: {scan_legit['risk_level']}")
        assert scan_legit["risk_score"] <= 30
        assert scan_legit["risk_level"] == "LOW"

        # 6. Test PDF Report Generation (Feature 7)
        print("\n[*] Feature 7: Testing PDF Report Generation...")
        scan_id = scan["id"]
        pdf_res = client.get(f"/report/{scan_id}.pdf")
        assert pdf_res.status_code == 200
        assert pdf_res.headers["Content-Type"] == "application/pdf"
        assert len(pdf_res.data) > 1000
        print(f"  [+] Generated PDF Report for Scan #{scan_id} ({len(pdf_res.data)} bytes)")

        # 7. Test Dashboard Analytics (Feature 8)
        print("\n[*] Feature 8: Testing Advanced Dashboard Telemetry...")
        dash_res = client.get("/dashboard")
        assert dash_res.status_code == 200
        assert b"Typosquatting &amp; Imitation" in dash_res.data
        assert b"Newly Registered Domains" in dash_res.data
        stats_api = client.get("/api/stats")
        stats_data = json.loads(stats_api.data)["data"]
        assert stats_data["total"] >= 2
        print(f"  [+] Telemetry verified: Total Scans={stats_data['total']}, Phishing %={stats_data['phishing_percentage']}%")

    print("\n==================================================")
    print("  [***] ALL 8 ADVANCED FEATURES VERIFIED! [***]")
    print("==================================================")

if __name__ == "__main__":
    run_tests()
