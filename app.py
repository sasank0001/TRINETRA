"""
TRINETRA - Intelligent Phishing URL Detection and Cyber Protection System
========================================================================

Main Flask Web Application Server.
Exposes clean HTML routes and RESTful JSON endpoints.
Includes PDF report generation, threat intelligence, and analytics.
"""

from __future__ import annotations

import io
import os
import sys
import time
from urllib.parse import unquote

from flask import (
    Flask,
    Response,
    abort,
    jsonify,
    redirect,
    render_template,
    request,
    send_file,
    url_for,
)

from database import (
    clear_history,
    delete_scan,
    get_scan,
    get_stats,
    init_db,
    list_scans,
    save_scan,
)
from pdf_generator import generate_pdf_report
from scanner import (
    InvalidURLError,
    ModelNotAvailableError,
    scanner,
)

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

# Application Factory / Initialization
app = Flask(
    __name__,
    static_folder=os.path.join(BASE_DIR, "static"),
    template_folder=os.path.join(BASE_DIR, "templates"),
)
app.config["SECRET_KEY"] = os.environ.get("SECRET_KEY", "trinetra-cyber-protection-key-2026")
app.config["JSON_SORT_KEYS"] = False
app.config["SEND_FILE_MAX_AGE_DEFAULT"] = 0

# Ensure database tables exist and are migrated
init_db()


@app.context_processor
def inject_cache_bust():
    """Inject dynamic asset version timestamp to bypass aggressive browser cache."""
    return {"v": int(time.time())}


@app.after_request
def add_no_cache_headers(response):
    """Disable aggressive browser caching for development and real-time UI updates."""
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate, max-age=0"
    response.headers["Pragma"] = "no-cache"
    response.headers["Expires"] = "0"
    return response


# ---------------------------------------------------------------------------
# HTML Page Routes
# ---------------------------------------------------------------------------

@app.route("/")
def index():
    """Home Page - High-level overview, statistics overview, and CTA."""
    stats = get_stats()
    metrics = scanner.load_metrics()
    return render_template(
        "index.html",
        total_scanned=stats["total"],
        high_risk=stats["high"],
        legitimate_count=stats["legitimate"],
        model_metrics=metrics,
    )


@app.route("/scanner")
def scanner_page():
    """URL Scanner Page - Interactive URL analysis interface."""
    initial_url = request.args.get("url", "").strip()
    initial_result = None
    if initial_url:
        try:
            initial_result = scanner.scan(initial_url)
            scan_id = save_scan(initial_result)
            initial_result["id"] = scan_id
        except Exception:
            pass
    return render_template("scanner.html", initial_url=initial_url, initial_result=initial_result)


@app.route("/dashboard")
def dashboard_page():
    """Dashboard Page - Comprehensive analytics, distribution charts, and ML benchmarks."""
    stats = get_stats()
    metrics = scanner.load_metrics()
    return render_template("dashboard.html", stats=stats, metrics=metrics)


@app.route("/history")
def history_page():
    """Scan History Page - Searchable, paginated audit log of previous scans."""
    page = request.args.get("page", 1, type=int)
    search = request.args.get("q", "").strip()
    risk_filter = request.args.get("risk", "").strip()
    per_page = 15

    scans, total = list_scans(page=page, per_page=per_page, search=search, risk=risk_filter)
    total_pages = max(1, (total + per_page - 1) // per_page)

    return render_template(
        "history.html",
        scans=scans,
        total=total,
        page=page,
        total_pages=total_pages,
        search=search,
        risk_filter=risk_filter,
    )


@app.route("/about")
def about_page():
    """About Page - Architecture, brand philosophy, ML methodology, and student credits."""
    metrics = scanner.load_metrics()
    return render_template("about.html", metrics=metrics)


# ---------------------------------------------------------------------------
# PDF Report Generation Route
# ---------------------------------------------------------------------------

@app.route("/report/<int:scan_id>.pdf")
def download_scan_report(scan_id: int):
    """Generates and streams a professional PDF security report for a specific scan."""
    scan_data = get_scan(scan_id)
    if not scan_data:
        abort(404, description="Scan record not found.")

    try:
        pdf_bytes = generate_pdf_report(scan_data)
        filename = f"TRINETRA_Threat_Report_{scan_id}.pdf"
        return send_file(
            io.BytesIO(pdf_bytes),
            mimetype="application/pdf",
            as_attachment=True,
            download_name=filename,
        )
    except Exception as e:
        app.logger.error(f"Error generating PDF report for #{scan_id}: {e}")
        abort(500, description="Failed to generate PDF report.")


@app.route("/api/report/preview", methods=["POST"])
def api_report_preview():
    """Generates a PDF report from ad-hoc scan data without requiring a stored DB record."""
    data = request.get_json(silent=True) or {}
    if not data.get("url"):
        return jsonify({"success": False, "error": "Scan data is required."}), 400

    try:
        pdf_bytes = generate_pdf_report(data)
        return Response(
            pdf_bytes,
            mimetype="application/pdf",
            headers={"Content-Disposition": "attachment; filename=TRINETRA_Scan_Report.pdf"}
        )
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


# ---------------------------------------------------------------------------
# RESTful API Endpoints
# ---------------------------------------------------------------------------

@app.route("/api/scan", methods=["POST"])
def api_scan():
    """
    API: Analyze a URL.
    Payload: {"url": "https://example.com"}
    Returns: Complete multi-dimensional risk assessment JSON.
    """
    data = request.get_json(silent=True) or {}
    raw_url = data.get("url")

    if not raw_url:
        return jsonify({"success": False, "error": "URL parameter is required."}), 400

    try:
        result = scanner.scan(raw_url)
        scan_id = save_scan(result)
        result["id"] = scan_id
        return jsonify({"success": True, "data": result})

    except InvalidURLError as e:
        return jsonify({"success": False, "error": str(e)}), 422
    except ModelNotAvailableError as e:
        return jsonify({"success": False, "error": str(e)}), 503
    except Exception as e:
        app.logger.error(f"Error scanning URL: {e}")
        return jsonify({"success": False, "error": "An internal error occurred while processing the URL."}), 500


@app.route("/api/history/<int:scan_id>", methods=["DELETE"])
def api_delete_scan(scan_id: int):
    """API: Delete a specific scan record by ID."""
    success = delete_scan(scan_id)
    if success:
        return jsonify({"success": True, "message": f"Scan #{scan_id} deleted."})
    return jsonify({"success": False, "error": "Record not found."}), 404


@app.route("/api/history/clear", methods=["POST"])
def api_clear_history():
    """API: Purge all scan records from the database."""
    deleted_count = clear_history()
    return jsonify({"success": True, "deleted": deleted_count})


@app.route("/api/stats", methods=["GET"])
def api_stats():
    """API: Return current dashboard statistics."""
    stats = get_stats()
    return jsonify({"success": True, "data": stats})


# ---------------------------------------------------------------------------
# Global Error Handlers
# ---------------------------------------------------------------------------

@app.errorhandler(404)
def not_found_error(error):
    return render_template("base.html", content="<div class='card empty'><h2>404 Not Found</h2><p>The requested page does not exist.</p><a href='/' class='btn btn-primary'>Return Home</a></div>"), 404


@app.errorhandler(500)
def internal_error(error):
    return render_template("base.html", content="<div class='card empty'><h2>500 Internal Server Error</h2><p>Something went wrong on the server.</p><a href='/' class='btn btn-primary'>Return Home</a></div>"), 500


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    debug = os.environ.get("FLASK_DEBUG", "True").lower() in ("true", "1")
    print(f"[*] Starting TRINETRA Cyber Protection Server on http://127.0.0.1:{port}")
    app.run(host="0.0.0.0", port=port, debug=debug)
