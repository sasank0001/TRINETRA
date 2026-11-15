"""
TRINETHRA - Professional PDF Security Report Generator
======================================================

Generates an executive, publication-grade cybersecurity evaluation PDF report
using ReportLab with custom vector graphics, brand-aligned Traditional Maroon (#7A263A),
Deep Navy (#111827), and Muted Teal (#527C78) palette, and a subtle central watermark.

Features:
  1. Header banner with vector TRINETHRA Shiva Tripundra emblem, metadata, and security tags.
  2. Balanced, translucent vector watermark centered on every page (background z-order).
  3. Running header bar and footer with dynamic page numbering and security markings.
  4. Executive Summary Card with prominent Risk Gauge (0-100) and ML confidence.
  5. Explainable AI (XAI) and Heuristic Threat Indicators Table.
  6. Brand Impersonation & Typosquatting Analysis.
  7. Domain Intelligence (WHOIS, DNS, Age) & VirusTotal Reputation.
  8. Safe URL Redirection Chain telemetry.
  9. Structured Defensive Remediation Recommendations.
 10. Institutional & Student Project Verification Block with SHA-256 Audit Digest.
"""

from __future__ import annotations

import hashlib
import io
import os
from datetime import datetime

from reportlab.lib import colors
from reportlab.lib.colors import Color, HexColor
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import inch
from reportlab.platypus import (
    Flowable,
    HRFlowable,
    KeepTogether,
    Paragraph,
    SimpleDocTemplate,
    Spacer,
    Table,
    TableStyle,
)
from reportlab.pdfgen import canvas

BASE_DIR = os.path.dirname(os.path.abspath(__file__))


# ---------------------------------------------------------------------------
# Vector Logo & Watermark Drawing Utilities
# ---------------------------------------------------------------------------

def _quad_to_cubic(x0: float, y0: float, x1: float, y1: float, x2: float, y2: float):
    """Convert quadratic bezier control points to cubic bezier control points."""
    cx1 = x0 + (2.0 / 3.0) * (x1 - x0)
    cy1 = y0 + (2.0 / 3.0) * (y1 - y0)
    cx2 = x2 + (2.0 / 3.0) * (x1 - x2)
    cy2 = y2 + (2.0 / 3.0) * (y1 - y2)
    return cx1, cy1, cx2, cy2, x2, y2


def _make_color(hex_str: str, alpha: float = 1.0) -> Color:
    """Create a ReportLab Color object with an explicit alpha channel."""
    h = hex_str.lstrip("#")
    r = int(h[0:2], 16) / 255.0
    g = int(h[2:4], 16) / 255.0
    b = int(h[4:6], 16) / 255.0
    return Color(r, g, b, alpha=alpha)


def draw_trinethra_logo(
    c: canvas.Canvas,
    x: float,
    y: float,
    size: float = 100,
    dark_outline: str = "#111827",
    accent: str = "#7A263A",
    alpha: float = 1.0,
):
    """
    Renders the vector TRINETHRA emblem onto a ReportLab canvas.
    Maps SVG viewBox (0 0 120 120) coordinates with crisp vector resolution.
    """
    c.saveState()
    scale = size / 120.0
    c.translate(x, y + size)
    c.scale(scale, -scale)

    is_watermark = alpha < 0.5
    accent_col = _make_color(accent, alpha=alpha)
    dark_col = _make_color(dark_outline, alpha=alpha)

    # 1. Classical Tripundra Curved Bars (3 left, 3 right)
    c.setStrokeColor(accent_col)
    c.setLineWidth(5.5 if is_watermark else 6.5)
    c.setLineCap(1)  # Round
    c.setLineJoin(1)
    if is_watermark:
        c.setStrokeAlpha(alpha)

    bars = [
        # Top bar
        (14, 45, 31, 39, 46, 37),
        (74, 37, 89, 39, 106, 45),
        # Middle bar
        (14, 60, 30, 55, 43, 54),
        (77, 54, 90, 55, 106, 60),
        # Bottom bar
        (14, 75, 31, 69, 46, 67),
        (74, 67, 89, 69, 106, 75),
    ]
    for x0, y0, qx, qy, x1, y1 in bars:
        p = c.beginPath()
        p.moveTo(x0, y0)
        c1x, c1y, c2x, c2y, fx, fy = _quad_to_cubic(x0, y0, qx, qy, x1, y1)
        p.curveTo(c1x, c1y, c2x, c2y, fx, fy)
        c.drawPath(p, stroke=1, fill=0)

    # 2. Vertical Third Eye Outer Contour
    c.setStrokeColor(dark_col)
    c.setLineWidth(4.0 if is_watermark else 5.0)
    if is_watermark:
        c.setStrokeAlpha(alpha)

    eye = c.beginPath()
    eye.moveTo(60, 18)
    eye.curveTo(77, 38, 77, 82, 60, 102)
    eye.curveTo(43, 82, 43, 38, 60, 18)
    eye.close()

    if is_watermark:
        c.drawPath(eye, stroke=1, fill=0)
    else:
        c.setFillColor(_make_color("#FFFFFF", alpha=1.0))
        c.drawPath(eye, stroke=1, fill=1)

    # 3. Iris (Traditional Maroon #7A263A)
    c.setFillColor(accent_col)
    c.setStrokeColor(accent_col)
    if is_watermark:
        c.setFillAlpha(alpha)
    c.circle(60, 60, 10.5, stroke=0, fill=1)

    # 4. Pupil Ring
    if is_watermark:
        c.setStrokeColor(dark_col)
        c.setStrokeAlpha(alpha)
        c.circle(60, 60, 4.5, stroke=1, fill=0)
    else:
        c.setFillColor(_make_color("#FFFFFF", alpha=1.0))
        c.circle(60, 60, 4.5, stroke=0, fill=1)

    # 5. Bindu Dot
    c.setFillColor(accent_col)
    if is_watermark:
        c.setFillAlpha(alpha)
    c.circle(60, 9, 3.4, stroke=0, fill=1)

    c.restoreState()


class TrinethraLogoFlowable(Flowable):
    """ReportLab Flowable for embedding the vector TRINETHRA emblem in layout tables."""

    def __init__(self, size: float = 46, dark_outline: str = "#111827", accent: str = "#7A263A"):
        super().__init__()
        self.size = size
        self.width = size
        self.height = size
        self.dark_outline = dark_outline
        self.accent = accent

    def wrap(self, availWidth, availHeight):
        return self.width, self.height

    def draw(self):
        draw_trinethra_logo(
            self.canv,
            0,
            0,
            size=self.size,
            dark_outline=self.dark_outline,
            accent=self.accent,
            alpha=1.0,
        )


def _draw_page_decorations(canvas_obj: canvas.Canvas, doc: SimpleDocTemplate):
    """
    Renders background decorations on every page BEFORE flowables are drawn:
      - Subtle watermark of the TRINETHRA emblem (size 260x260, alpha=0.10)
      - Running top security header bar
      - Running bottom footer with document classification and student credit
    """
    canvas_obj.saveState()
    page_w, page_h = doc.pagesize

    # 1. Center Watermark
    wm_size = 260.0
    wm_x = (page_w - wm_size) / 2.0
    wm_y = (page_h - wm_size) / 2.0
    draw_trinethra_logo(
        canvas_obj,
        wm_x,
        wm_y,
        size=wm_size,
        dark_outline="#374151",
        accent="#7A263A",
        alpha=0.10,
    )

    # 2. Running Top Header Bar (Subtle)
    canvas_obj.setStrokeColor(HexColor("#E5E7EB"))
    canvas_obj.setLineWidth(0.6)
    canvas_obj.line(36, page_h - 22, page_w - 36, page_h - 22)

    canvas_obj.setFont("Helvetica-Bold", 6.5)
    canvas_obj.setFillColor(HexColor("#4B5563"))
    canvas_obj.drawString(36, page_h - 18, "TRINETHRA // AUTOMATED THREAT INTELLIGENCE & CYBER AUDIT")
    canvas_obj.drawRightString(page_w - 36, page_h - 18, "CONFIDENTIAL \u2022 FOR AUTHORIZED USE ONLY")

    # 3. Running Bottom Footer Bar
    canvas_obj.setStrokeColor(HexColor("#E5E7EB"))
    canvas_obj.setLineWidth(0.6)
    canvas_obj.line(36, 26, page_w - 36, 26)

    canvas_obj.setFont("Helvetica", 7.0)
    canvas_obj.setFillColor(HexColor("#4B5563"))
    canvas_obj.drawString(36, 16, "Ancient Vision. Intelligent Protection. A Safer Digital Tomorrow.")
    canvas_obj.drawRightString(page_w - 36, 16, f"Page {canvas_obj._pageNumber}")

    canvas_obj.restoreState()


# ---------------------------------------------------------------------------
# Main PDF Report Generation Entry Point
# ---------------------------------------------------------------------------

def generate_pdf_report(scan_data: dict) -> bytes:
    """
    Builds an executive-grade cybersecurity report PDF and returns its raw bytes.
    """
    buffer = io.BytesIO()
    doc = SimpleDocTemplate(
        buffer,
        pagesize=letter,
        rightMargin=36,
        leftMargin=36,
        topMargin=32,
        bottomMargin=34,
    )

    # Bind decorations to beforeDrawPage so the watermark paints in the background
    doc.onFirstPage = _draw_page_decorations
    doc.onLaterPages = _draw_page_decorations

    # Brand Theme Colors
    navy_dark = HexColor("#111827")
    maroon = HexColor("#7A263A")
    teal = HexColor("#527C78")
    amber = HexColor("#B45309")
    slate = HexColor("#374151")
    text_muted = HexColor("#6B7280")
    border_color = HexColor("#E5E7EB")
    # Translucent label-cell shading so the background watermark stays visible
    card_bg = _make_color("#374151", alpha=0.035)

    # Typography styles
    title_style = ParagraphStyle(
        "DocTitle",
        fontName="Helvetica-Bold",
        fontSize=17,
        leading=21,
        textColor=navy_dark,
    )
    subtitle_style = ParagraphStyle(
        "DocSubtitle",
        fontName="Helvetica",
        fontSize=8.5,
        leading=11.5,
        textColor=text_muted,
    )
    meta_style = ParagraphStyle(
        "DocMeta",
        fontName="Helvetica",
        fontSize=8,
        leading=11.5,
        textColor=navy_dark,
        alignment=2,
    )
    heading_style = ParagraphStyle(
        "SectionHeading",
        fontName="Helvetica-Bold",
        fontSize=10.5,
        leading=14,
        textColor=navy_dark,
        spaceBefore=8,
        spaceAfter=5,
    )
    body_style = ParagraphStyle(
        "BodyDark",
        fontName="Helvetica",
        fontSize=8.5,
        leading=12,
        textColor=slate,
    )
    bold_style = ParagraphStyle(
        "BodyDarkBold",
        fontName="Helvetica-Bold",
        fontSize=8.5,
        leading=12,
        textColor=navy_dark,
    )
    mono_style = ParagraphStyle(
        "MonoStyle",
        fontName="Courier",
        fontSize=7.5,
        leading=10.5,
        textColor=navy_dark,
    )

    elements = []

    # 1. Header Banner with Vector Logo, Branding & Metadata
    logo_flowable = TrinethraLogoFlowable(size=44, dark_outline="#111827", accent="#7A263A")
    title_cell = [
        Paragraph("<b>TRINETHRA</b> &mdash; CYBER THREAT AUDIT REPORT", title_style),
        Paragraph("Intelligent Phishing URL Detection &amp; Autonomous Cyber Protection System", subtitle_style),
        Paragraph("<font color='#7A263A' size=7><b>PRE-EXECUTION THREAT INTELLIGENCE &bull; LEXICAL HEURISTICS &bull; ENSEMBLE ML</b></font>", subtitle_style),
    ]
    meta_cell = [
        Paragraph(f"<b>Generated:</b> {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", meta_style),
        Paragraph(f"<b>Audit ID:</b> #{scan_data.get('id', 'N/A')}", meta_style),
        Paragraph("<font color='#7A263A'><b>CLASSIFICATION: RESTRICTED</b></font>", meta_style),
    ]

    header_table = Table(
        [[logo_flowable, title_cell, meta_cell]],
        colWidths=[50, 4.4 * inch, 2.4 * inch],
    )
    header_table.setStyle(TableStyle([
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("LEFTPADDING", (0, 0), (-1, -1), 0),
        ("RIGHTPADDING", (0, 0), (-1, -1), 0),
        ("TOPPADDING", (0, 0), (-1, -1), 0),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 2),
    ]))
    elements.append(header_table)
    elements.append(Spacer(1, 4))
    elements.append(HRFlowable(width="100%", thickness=1.8, color=maroon, spaceAfter=10))

    # 2. Executive Summary & Verdict Box
    risk_lvl = scan_data.get("risk_level", "LOW")
    score = scan_data.get("risk_score", 0)
    pred = scan_data.get("prediction", "Legitimate")

    if risk_lvl == "HIGH":
        verdict_color = maroon
        verdict_bg = _make_color("#7A263A", alpha=0.09)
        badge_text = "CRITICAL THREAT &bull; PHISHING DETECTED"
    elif risk_lvl == "MEDIUM":
        verdict_color = amber
        verdict_bg = _make_color("#F59E0B", alpha=0.18)
        badge_text = "ELEVATED RISK &bull; SUSPICIOUS PATTERNS"
    else:
        verdict_color = teal
        verdict_bg = _make_color("#527C78", alpha=0.11)
        badge_text = "LOW RISK &bull; LEGITIMATE INFRASTRUCTURE"

    v_cell_score = Paragraph(
        f"<font size=28 color='{verdict_color.hexval()}'><b>{score}</b></font><br/>"
        f"<font size=7 color='#6B7280'>RISK INDEX (0-100)</font>",
        ParagraphStyle("ScoreStyle", alignment=1),
    )

    target_url = str(scan_data.get("url", ""))
    target_url_display = target_url[:80] + ("..." if len(target_url) > 80 else "")
    ml_prob = scan_data.get("phishing_probability", 0)

    v_cell_info = Paragraph(
        f"<font size=11 color='{verdict_color.hexval()}'><b>{badge_text}</b></font><br/><br/>"
        f"<b>Target URL:</b> <font face='Courier' size=7.5>{target_url_display}</font><br/>"
        f"<b>Domain:</b> {scan_data.get('domain', 'N/A')} &nbsp;&bull;&nbsp; "
        f"<b>ML Model Probability:</b> {ml_prob * 100:.1f}% &nbsp;&bull;&nbsp; "
        f"<b>Verdict:</b> {pred}",
        body_style,
    )

    verdict_table = Table([[v_cell_score, v_cell_info]], colWidths=[1.6 * inch, 5.7 * inch])
    verdict_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), verdict_bg),
        ("BOX", (0, 0), (-1, -1), 1.2, verdict_color),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("TOPPADDING", (0, 0), (-1, -1), 8),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 8),
        ("LEFTPADDING", (0, 0), (-1, -1), 10),
        ("RIGHTPADDING", (0, 0), (-1, -1), 10),
    ]))
    elements.append(verdict_table)
    elements.append(Spacer(1, 8))

    # 3. Explainable AI (XAI) & Suspicious Indicators Table
    elements.append(Paragraph("1. Explainable AI & Heuristic Findings", heading_style))
    indicators = scan_data.get("indicators", [])
    if indicators:
        ind_rows = [[
            Paragraph("<b>Severity</b>", bold_style),
            Paragraph("<b>Finding / Indicator</b>", bold_style),
            Paragraph("<b>Technical Analysis Detail</b>", bold_style),
        ]]
        for ind in indicators[:5]:
            sev = ind.get("severity", "info").upper()
            c = maroon if sev == "HIGH" else (amber if sev == "MEDIUM" else teal)
            ind_rows.append([
                Paragraph(f"<font color='{c.hexval()}'><b>{sev}</b></font>", bold_style),
                Paragraph(ind.get("title", ""), bold_style),
                Paragraph(ind.get("detail", ""), body_style),
            ])
        t_ind = Table(ind_rows, colWidths=[1.0 * inch, 2.3 * inch, 4.0 * inch])
        t_ind.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), card_bg),
            ("BOX", (0, 0), (-1, -1), 0.5, border_color),
            ("INNERGRID", (0, 0), (-1, -1), 0.5, border_color),
            ("TOPPADDING", (0, 0), (-1, -1), 3),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ]))
        elements.append(t_ind)
    else:
        elements.append(Paragraph("No anomalous heuristic indicators triggered for this URL (verified standard lexical structure).", body_style))

    elements.append(Spacer(1, 8))

    # 4. Typosquatting & Brand Impersonation
    typo = scan_data.get("typosquatting", {})
    elements.append(Paragraph("2. Typosquatting & Brand Impersonation Analysis", heading_style))
    if typo.get("is_impersonation"):
        typo_data = [
            [Paragraph("<b>Status:</b>", bold_style), Paragraph("<font color='#7A263A'><b>SUSPECTED BRAND IMPERSONATION DETECTED</b></font>", bold_style)],
            [Paragraph("<b>Target Brand:</b>", bold_style), Paragraph(str(typo.get("target_brand")), body_style)],
            [Paragraph("<b>Attack Technique:</b>", bold_style), Paragraph(str(typo.get("technique")), body_style)],
            [Paragraph("<b>Explanation:</b>", bold_style), Paragraph(str(typo.get("reason")), body_style)],
            [Paragraph("<b>Official Domain:</b>", bold_style), Paragraph(", ".join(typo.get("authentic_domains", [])[:3]), mono_style)],
        ]
    else:
        typo_data = [
            [Paragraph("<b>Status:</b>", bold_style), Paragraph("<font color='#527C78'><b>No Brand Imitation Identified</b></font>", bold_style)],
            [Paragraph("<b>Assessment:</b>", bold_style), Paragraph("Domain does not match known leetspeak, homoglyphs, or typo variants of monitored major brands.", body_style)],
        ]
    t_typo = Table(typo_data, colWidths=[1.5 * inch, 5.8 * inch])
    t_typo.setStyle(TableStyle([
        ("BOX", (0, 0), (-1, -1), 0.5, border_color),
        ("BACKGROUND", (0, 0), (0, -1), card_bg),
        ("INNERGRID", (0, 0), (-1, -1), 0.5, border_color),
        ("TOPPADDING", (0, 0), (-1, -1), 3),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
    ]))
    elements.append(t_typo)
    elements.append(Spacer(1, 8))

    # 5. Domain Intelligence & External Threat Intelligence
    dom_intel = scan_data.get("domain_intelligence", {})
    reputation = scan_data.get("threat_reputation", {})

    elements.append(Paragraph("3. Domain Intelligence & Threat Reputation", heading_style))
    intel_data = [
        [
            Paragraph("<b>WHOIS Registrar:</b>", bold_style),
            Paragraph(dom_intel.get("registrar", "Information Unavailable"), body_style),
            Paragraph("<b>VirusTotal Status:</b>", bold_style),
            Paragraph(reputation.get("status", "Not Configured").upper(), body_style),
        ],
        [
            Paragraph("<b>Creation Date:</b>", bold_style),
            Paragraph(dom_intel.get("creation_date", "Information Unavailable"), body_style),
            Paragraph("<b>Security Vendors:</b>", bold_style),
            Paragraph(f"{reputation.get('malicious_count', 0)} / {reputation.get('total_scanners', 0)} Flagged", body_style),
        ],
        [
            Paragraph("<b>Domain Age:</b>", bold_style),
            Paragraph(f"{dom_intel.get('domain_age_days')} days" if dom_intel.get("domain_age_days") is not None else "Information Unavailable", body_style),
            Paragraph("<b>Reputation Msg:</b>", bold_style),
            Paragraph(reputation.get("message", "N/A")[:40], body_style),
        ],
        [
            Paragraph("<b>DNS IP (A):</b>", bold_style),
            Paragraph(", ".join(dom_intel.get("dns_records", {}).get("a", [])[:2]) or "Unavailable", mono_style),
            Paragraph("<b>Nameservers:</b>", bold_style),
            Paragraph(", ".join(dom_intel.get("nameservers", [])[:2]) or "Unavailable", mono_style),
        ],
    ]
    t_intel = Table(intel_data, colWidths=[1.4 * inch, 2.25 * inch, 1.4 * inch, 2.25 * inch])
    t_intel.setStyle(TableStyle([
        ("BOX", (0, 0), (-1, -1), 0.5, border_color),
        ("INNERGRID", (0, 0), (-1, -1), 0.5, border_color),
        ("BACKGROUND", (0, 0), (0, -1), card_bg),
        ("BACKGROUND", (2, 0), (2, -1), card_bg),
        ("TOPPADDING", (0, 0), (-1, -1), 3),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
    ]))
    elements.append(t_intel)
    elements.append(Spacer(1, 8))

    # 6. Redirect Analysis
    redirects = scan_data.get("redirect_analysis", {})
    elements.append(Paragraph("4. URL Redirection & Safe Chain Analysis", heading_style))
    final_dest = str(redirects.get("final_url", "N/A"))
    final_dest_display = final_dest[:80] + ("..." if len(final_dest) > 80 else "")

    red_data = [
        [Paragraph("<b>Shortener Service:</b>", bold_style), Paragraph("YES" if redirects.get("is_shortener") else "NO", body_style)],
        [Paragraph("<b>Redirect Hops:</b>", bold_style), Paragraph(f"{redirects.get('redirect_count', 0)} hop(s) detected", body_style)],
        [Paragraph("<b>Final Landing URL:</b>", bold_style), Paragraph(final_dest_display, mono_style)],
        [Paragraph("<b>Status Note:</b>", bold_style), Paragraph(redirects.get("message", "Direct"), body_style)],
    ]
    t_red = Table(red_data, colWidths=[1.5 * inch, 5.8 * inch])
    t_red.setStyle(TableStyle([
        ("BOX", (0, 0), (-1, -1), 0.5, border_color),
        ("BACKGROUND", (0, 0), (0, -1), card_bg),
        ("INNERGRID", (0, 0), (-1, -1), 0.5, border_color),
        ("TOPPADDING", (0, 0), (-1, -1), 3),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
    ]))
    elements.append(t_red)
    elements.append(Spacer(1, 8))

    # 7. Security Guidance & Operational Recommendations
    elements.append(Paragraph("5. Recommended Security Mitigation Actions", heading_style))
    if risk_lvl == "HIGH":
        rec_text = (
            "<b>ACTION REQUIRED &bull; DO NOT ENGAGE:</b> Severe deceptive patterns or known brand impersonation "
            "attributes were detected. Immediately block this domain on perimeter firewalls, EDR agents, and DNS resolvers. "
            "Never input credentials, MFA tokens, or sensitive financial information."
        )
    elif risk_lvl == "MEDIUM":
        rec_text = (
            "<b>CAUTION ADVISED:</b> This URL exhibits anomalous structural traits or newly registered domain behavior. "
            "Perform sandbox execution or contact the sender through out-of-band verified channels before clicking."
        )
    else:
        rec_text = (
            "<b>STANDARD MONITORING:</b> The link displays standard lexical properties consistent with verified infrastructure. "
            "Follow standard web hygiene: ensure HTTPS encryption is active and never disclose private credentials."
        )
    elements.append(Paragraph(rec_text, body_style))
    elements.append(Spacer(1, 10))

    # 8. Cryptographic Audit Seal & Project Credit
    raw_hash_source = f"{scan_data.get('id', '')}-{target_url}-{datetime.now().strftime('%Y%m%d%H%M')}"
    sha_digest = hashlib.sha256(raw_hash_source.encode("utf-8")).hexdigest()[:24].upper()

    credit_data = [
        [
            Paragraph(
                f"<para align=left><b>Developed by CSE and IT Students &ndash; S7</b><br/>"
                f"<font size=7 color='#7A263A'>Ancient Vision. Intelligent Protection. A Safer Digital Tomorrow.</font></para>",
                body_style,
            ),
            Paragraph(
                f"<para align=right><font size=6.5 color='#6B7280'>AUDIT INTEGRITY SHA-256 DIGEST:<br/>"
                f"<font face='Courier' color='#111827'><b>{sha_digest}</b></font><br/>"
                f"TRINETHRA Machine Learning Defense System v2.4</font></para>",
                body_style,
            ),
        ]
    ]
    t_credit = Table(credit_data, colWidths=[4.2 * inch, 3.1 * inch])
    t_credit.setStyle(TableStyle([
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("LINEABOVE", (0, 0), (-1, -1), 0.8, border_color),
        ("TOPPADDING", (0, 0), (-1, -1), 6),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 0),
        ("LEFTPADDING", (0, 0), (-1, -1), 0),
        ("RIGHTPADDING", (0, 0), (-1, -1), 0),
    ]))
    elements.append(t_credit)

    # Build the document
    doc.build(elements)

    buffer.seek(0)
    return buffer.getvalue()
