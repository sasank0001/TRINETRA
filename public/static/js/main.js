// TRINETHRA Client Application JavaScript (Upgraded)
let currentScanData = null;

document.addEventListener("DOMContentLoaded", () => {
  // Mobile navigation toggle
  const navToggle = document.getElementById("navToggle");
  const navLinks = document.getElementById("navLinks");
  if (navToggle && navLinks) {
    navToggle.addEventListener("click", () => {
      navLinks.classList.toggle("open");
    });
  }

  // Auto-dismiss alerts after 5 seconds
  document.querySelectorAll(".alert .close").forEach((btn) => {
    btn.addEventListener("click", () => {
      const alert = btn.closest(".alert");
      if (alert) alert.remove();
    });
  });

  // Handle URL scanner interaction if present on page
  initScanner();

  // Handle Scan History actions if present
  initHistory();

  // Render initial Lucide icons
  if (window.lucide && typeof lucide.createIcons === "function") {
    lucide.createIcons();
  }
});

// Toast notification helper
function showToast(message, type = "info") {
  let wrap = document.querySelector(".toast-wrap");
  if (!wrap) {
    wrap = document.createElement("div");
    wrap.className = "toast-wrap";
    document.body.appendChild(wrap);
  }
  const el = document.createElement("div");
  el.className = `alert alert-${type}`;
  el.innerHTML = `
    <span>${escapeHtml(message)}</span>
    <button class="close" onclick="this.parentElement.remove()">&times;</button>
  `;
  wrap.appendChild(el);
  setTimeout(() => el.remove(), 5000);
}

// Icon helper functions (Consistent Lucide icon tokens)
function getSeverityIcon(severity) {
  const sev = String(severity || "").toLowerCase();
  if (sev === "high") {
    return '<i data-lucide="circle-x" style="color: var(--maroon);"></i>';
  }
  if (sev === "medium") {
    return '<i data-lucide="triangle-alert" style="color: var(--risk-med);"></i>';
  }
  return '<i data-lucide="circle-check" style="color: var(--teal);"></i>';
}

function getPdfButton(scanId, downloadUrl) {
  if (!scanId) return "";
  return `<a href="${downloadUrl}" class="btn btn-primary btn-sm" target="_blank" style="margin-left: auto;">
    <i data-lucide="file-text" class="lucide-sm"></i>
    <span>Download PDF Report</span>
  </a>`;
}

// -------------------------------------------------------------
// URL SCANNER LOGIC
// -------------------------------------------------------------
function initScanner() {
  const form = document.getElementById("scanForm");
  if (!form) return;

  const urlInput = document.getElementById("urlInput");
  const scanBtn = document.getElementById("scanBtn");
  const loader = document.getElementById("scanLoader");
  const resultCard = document.getElementById("scanResult");

  // Quick test chips click handler
  document.querySelectorAll(".chip[data-url]").forEach((chip) => {
    chip.addEventListener("click", () => {
      urlInput.value = chip.getAttribute("data-url");
      urlInput.focus();
    });
  });

  form.addEventListener("submit", async (e) => {
    e.preventDefault();
    const url = urlInput.value.trim();
    if (!url) {
      urlInput.classList.add("invalid");
      showToast("Please enter a valid website link or URL to scan.", "error");
      return;
    }
    urlInput.classList.remove("invalid");

    // UI State: Scanning
    scanBtn.disabled = true;
    scanBtn.innerHTML = `
      <span style="display:inline-block;width:14px;height:14px;border:2px solid #FFFFFF;border-top-color:transparent;border-radius:50%;animation:scanSpin 0.75s linear infinite;"></span>
      <span>Analyzing...</span>
    `;

    if (resultCard) resultCard.classList.remove("show");
    if (loader) {
      loader.classList.add("show");
    }

    try {
      const response = await fetch("/api/scan", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ url: url }),
      });

      const data = await response.json();

      if (!response.ok || !data.success) {
        throw new Error(data.error || "An error occurred while scanning the URL.");
      }

      currentScanData = data.data;

      // Render the result
      setTimeout(() => {
        if (loader) loader.classList.remove("show");
        renderScanResult(data.data);
        scanBtn.disabled = false;
        scanBtn.innerHTML = `
          <i data-lucide="scan-search"></i>
          <span>Scan URL</span>
        `;
        if (window.lucide) lucide.createIcons();
      }, 500);
    } catch (err) {
      if (loader) loader.classList.remove("show");
      scanBtn.disabled = false;
      scanBtn.innerHTML = `
        <i data-lucide="scan-search"></i>
        <span>Scan URL</span>
      `;
      if (window.lucide) lucide.createIcons();
      showToast(err.message, "error");
    }
  });
}

function renderScanResult(res) {
  const container = document.getElementById("scanResult");
  if (!container) return;

  currentScanData = res;
  const riskClass = res.risk_level; // LOW | MEDIUM | HIGH
  const riskTitle =
    riskClass === "HIGH"
      ? "POTENTIALLY PHISHING DETECTED"
      : riskClass === "MEDIUM"
        ? "SUSPICIOUS PATTERNS IDENTIFIED"
        : "LEGITIMATE LINK VERIFIED";

  const riskDesc =
    riskClass === "HIGH"
      ? "Strong deceptive patterns, brand impersonation, or malicious attributes detected. Interacting with this link poses a direct security risk."
      : riskClass === "MEDIUM"
        ? "Noticeable anomalies or suspicious attributes were detected. Exercise caution before providing credentials or personal data."
        : "No significant phishing anomalies detected by the AI model or security engines. Safe for standard interaction.";

  // 1. Indicators HTML
  let indicatorsHTML = "";
  if (res.indicators && res.indicators.length > 0) {
    indicatorsHTML = res.indicators
      .map(
        (ind) => `
      <div style="display: flex; gap: 12px; align-items: flex-start; padding: 10px 0; border-bottom: 1px solid var(--border);">
        <div style="margin-top: 2px;">${getSeverityIcon(ind.severity)}</div>
        <div style="flex: 1;">
          <b style="font-size: 0.885rem; color: var(--navy); display: block;">${escapeHtml(ind.title)}</b>
          <p class="small muted mb-0" style="margin-top: 2px;">${escapeHtml(ind.detail)}</p>
        </div>
      </div>
    `
      )
      .join("");
  } else {
    indicatorsHTML = `<p class="muted small mb-0">No heuristic suspicious indicators triggered for this URL.</p>`;
  }

  // 2. Model tree factors HTML
  let factorsHTML = "";
  if (res.model_factors && res.model_factors.length > 0) {
    factorsHTML = res.model_factors
      .map((f) => {
        const isPhish = f.direction === "phishing";
        const badgeColor = isPhish ? "var(--maroon)" : "var(--teal)";
        return `
        <div style="display: flex; justify-content: space-between; align-items: center; padding: 8px 0; border-bottom: 1px dashed var(--border);">
          <div>
            <span style="font-size: 0.85rem; font-weight: 500; color: var(--navy);">${escapeHtml(f.label)}</span>
            <span class="muted small" style="display: block;">Value: <code>${escapeHtml(String(f.value))}</code></span>
          </div>
          <span style="font-size: 0.825rem; font-weight: 600; color: ${badgeColor};">
            ${f.impact > 0 ? "+" : ""}${f.impact}% ${isPhish ? "Phish" : "Safe"}
          </span>
        </div>
      `;
      })
      .join("");
  } else {
    factorsHTML = `<p class="muted small mb-0">Model prediction derived from generalized baseline vector.</p>`;
  }

  // 3. Intelligent Score Breakdown HTML
  let breakdownHTML = "";
  if (res.score_breakdown && res.score_breakdown.length > 0) {
    breakdownHTML = res.score_breakdown
      .map(
        (b) => `
      <div style="display: flex; justify-content: space-between; align-items: center; padding: 8px 0; border-bottom: 1px dashed var(--border);">
        <div>
          <span style="font-size: 0.85rem; font-weight: 500; color: var(--navy);">${escapeHtml(b.factor)}</span>
          <span class="muted small" style="display: block;">${escapeHtml(b.description || "")}</span>
        </div>
        <span style="font-size: 0.885rem; font-weight: 700; color: ${b.points > 10 ? 'var(--maroon)' : (b.points > 0 ? 'var(--risk-med)' : 'var(--teal)')};">
          +${b.points} pts
        </span>
      </div>
    `
      )
      .join("");
  }

  // 4. Typosquatting Card HTML
  const typo = res.typosquatting || {};
  let typoHTML = "";
  if (typo.is_impersonation) {
    typoHTML = `
      <div style="background: var(--risk-high-bg); border: 1px solid var(--risk-high-border); padding: 12px; border-radius: var(--radius-sm); margin-bottom: 12px;">
        <b style="color: var(--maroon); font-size: 0.885rem; display: block; margin-bottom: 4px;">
          Suspected Brand Impersonation: ${escapeHtml(typo.target_brand)}
        </b>
        <p class="small mb-0" style="color: var(--slate);">${escapeHtml(typo.reason)}</p>
      </div>
      <div style="font-size: 0.85rem;">
        <div style="display: flex; justify-content: space-between; padding: 4px 0;"><span class="muted">Technique:</span> <b>${escapeHtml(typo.technique)}</b></div>
        <div style="display: flex; justify-content: space-between; padding: 4px 0;"><span class="muted">Authentic Host:</span> <code>${escapeHtml((typo.authentic_domains || [])[0] || 'N/A')}</code></div>
      </div>
    `;
  } else {
    typoHTML = `
      <div style="background: var(--risk-low-bg); border: 1px solid var(--risk-low-border); padding: 12px; border-radius: var(--radius-sm);">
        <b style="color: var(--teal); font-size: 0.885rem; display: block; margin-bottom: 2px;">
          No Brand Imitation Identified
        </b>
        <p class="small mb-0" style="color: var(--slate);">Domain does not match monitored typo variants or homoglyphs of protected institutions.</p>
      </div>
    `;
  }

  // 5. Domain Intelligence HTML
  const domIntel = res.domain_intelligence || {};
  const dnsA = (domIntel.dns_records && domIntel.dns_records.a) ? domIntel.dns_records.a.join(", ") : "Information Unavailable";
  const nameservers = (domIntel.nameservers && domIntel.nameservers.length > 0) ? domIntel.nameservers.slice(0, 2).join(", ") : "Information Unavailable";

  // 6. Threat Reputation HTML
  const rep = res.threat_reputation || {};
  let repHTML = "";
  if (rep.status === "configured") {
    repHTML = `
      <div style="font-size: 0.85rem;">
        <div style="display: flex; justify-content: space-between; padding: 4px 0;">
          <span class="muted">Security Vendors:</span>
          <b style="color: ${rep.malicious_count > 0 ? 'var(--maroon)' : 'var(--teal)'};">${rep.malicious_count} / ${rep.total_scanners} Flagged</b>
        </div>
        <div style="display: flex; justify-content: space-between; padding: 4px 0;">
          <span class="muted">Message:</span>
          <span>${escapeHtml(rep.message)}</span>
        </div>
      </div>
    `;
  } else {
    repHTML = `
      <p class="muted small mb-0">VirusTotal external threat intelligence not configured or skipped.</p>
    `;
  }

  // 7. Redirect Analysis HTML
  const red = res.redirect_analysis || {};
  let redHTML = `
    <div style="font-size: 0.85rem;">
      <div style="display: flex; justify-content: space-between; padding: 4px 0;"><span class="muted">Shortener Service:</span> <b>${red.is_shortener ? 'YES (Shortened)' : 'NO (Direct)'}</b></div>
      <div style="display: flex; justify-content: space-between; padding: 4px 0;"><span class="muted">Redirect Hops:</span> <b>${red.redirect_count} hop(s)</b></div>
      <div style="display: flex; justify-content: space-between; padding: 4px 0;"><span class="muted">Landing URL:</span> <code style="word-break: break-all;">${escapeHtml(red.final_url || 'N/A')}</code></div>
    </div>
  `;

  // Download PDF Report Link
  const pdfDownloadUrl = res.id ? `/report/${res.id}.pdf` : "#";

  container.innerHTML = `
    <!-- Top Executive Verdict Card -->
    <div class="verdict-card tier-${riskClass}">
      <div class="gauge-box tier-${riskClass}">
        <div class="gauge-val">${res.risk_score}</div>
        <div class="gauge-lbl">Risk Index (0–100)</div>
      </div>

      <div class="verdict-body">
        <div style="display: flex; gap: 8px; align-items: center; margin-bottom: 6px;">
          <span class="badge ${riskClass}">${riskClass} RISK</span>
          <span class="badge ${res.prediction}">${res.prediction}</span>
          <span class="badge plain">ML Confidence: ${(res.phishing_probability * 100).toFixed(1)}%</span>
        </div>
        <h2>${riskTitle}</h2>
        <div class="verdict-url">${escapeHtml(res.url)}</div>
        <p class="verdict-desc">${riskDesc}</p>
        <div style="margin-top: 10px; font-size: 0.8125rem; color: var(--slate-muted);">
          Host: <b>${escapeHtml(res.domain || "N/A")}</b> &bull; Scanned at ${new Date().toLocaleTimeString()}
        </div>
      </div>

      <div>
        ${getPdfButton(res.id, pdfDownloadUrl)}
      </div>
    </div>

    <!-- Structured 2-Column Findings -->
    <div class="grid grid-2 mt-3">
      <!-- 1. Explainable AI & Indicators -->
      <div class="card">
        <div class="card-title">
          <h3>
            <i data-lucide="shield-alert"></i>
            <span>Explainable AI &amp; Threat Indicators</span>
          </h3>
          <span class="badge plain">${res.indicators ? res.indicators.length : 0} Findings</span>
        </div>
        ${indicatorsHTML}
      </div>

      <!-- 2. Transparent Risk Score Breakdown -->
      <div class="card">
        <div class="card-title">
          <h3>
            <i data-lucide="chart-no-axes-combined"></i>
            <span>Intelligent Risk Scoring Breakdown</span>
          </h3>
          <span class="badge plain">Total: ${res.risk_score}/100</span>
        </div>
        ${breakdownHTML}
      </div>
    </div>

    <!-- Second 2-Column Row: Typosquatting & Domain Intel -->
    <div class="grid grid-2 mt-3">
      <!-- Typosquatting -->
      <div class="card">
        <div class="card-title">
          <h3>
            <i data-lucide="shield-check"></i>
            <span>Typosquatting &amp; Brand Impersonation</span>
          </h3>
          <span class="badge plain">Brand Defense</span>
        </div>
        ${typoHTML}
      </div>

      <!-- Domain Intelligence -->
      <div class="card">
        <div class="card-title">
          <h3>
            <i data-lucide="database"></i>
            <span>Domain Intelligence &amp; WHOIS</span>
          </h3>
          <span class="badge plain">Network Telemetry</span>
        </div>
        <div style="font-size: 0.85rem;">
          <div style="display: flex; justify-content: space-between; padding: 4px 0;"><span class="muted">Registrar:</span> <b>${escapeHtml(domIntel.registrar || 'Unavailable')}</b></div>
          <div style="display: flex; justify-content: space-between; padding: 4px 0;"><span class="muted">Creation Date:</span> <b>${escapeHtml(domIntel.creation_date || 'Unavailable')}</b></div>
          <div style="display: flex; justify-content: space-between; padding: 4px 0;"><span class="muted">Domain Age:</span> <b>${domIntel.domain_age_days !== null && domIntel.domain_age_days !== undefined ? escapeHtml(domIntel.domain_age_days + ' days old') : 'Unavailable'}</b></div>
          <div style="display: flex; justify-content: space-between; padding: 4px 0;"><span class="muted">DNS A-Record:</span> <code>${escapeHtml(dnsA)}</code></div>
          <div style="display: flex; justify-content: space-between; padding: 4px 0;"><span class="muted">Nameservers:</span> <code>${escapeHtml(nameservers)}</code></div>
        </div>
      </div>
    </div>

    <!-- Third Row: Redirection & ML Trees -->
    <div class="grid grid-2 mt-3">
      <!-- Safe Redirect Analysis -->
      <div class="card">
        <div class="card-title">
          <h3>
            <i data-lucide="network"></i>
            <span>URL Redirection &amp; Chain Analysis</span>
          </h3>
          <span class="badge plain">Passive Sandbox</span>
        </div>
        ${redHTML}
      </div>

      <!-- ML Tree Influences -->
      <div class="card">
        <div class="card-title">
          <h3>
            <i data-lucide="cpu"></i>
            <span>Random Forest Decision Factors</span>
          </h3>
          <span class="badge plain">XAI Tree Interpreter</span>
        </div>
        ${factorsHTML}
      </div>
    </div>

    <!-- Security Hygiene Notice -->
    <div style="background: #F3F4F6; padding: 12px 16px; border-radius: var(--radius-sm); border-left: 3px solid var(--teal); font-size: 0.8125rem; color: var(--slate); margin-top: 20px;">
      <b>Cybersecurity Advisory:</b> Machine Learning assessments evaluate structural features and deterministic lexical signals. Always verify unexpected links through trusted secondary channels.
    </div>
  `;

  container.classList.add("show");
  container.scrollIntoView({ behavior: "smooth", block: "start" });

  // Re-hydrate Lucide icons for all injected elements
  if (window.lucide && typeof lucide.createIcons === "function") {
    lucide.createIcons();
  }
}

// -------------------------------------------------------------
// SCAN HISTORY ACTIONS
// -------------------------------------------------------------
function initHistory() {
  const clearBtn = document.getElementById("clearHistoryBtn");
  const modal = document.getElementById("confirmModal");
  const cancelBtn = document.getElementById("cancelModalBtn");
  const confirmBtn = document.getElementById("confirmClearBtn");

  if (clearBtn && modal) {
    clearBtn.addEventListener("click", () => {
      modal.style.display = "flex";
    });
    if (cancelBtn) {
      cancelBtn.addEventListener("click", () => {
        modal.style.display = "none";
      });
    }
    if (confirmBtn) {
      confirmBtn.addEventListener("click", async () => {
        try {
          const res = await fetch("/api/history/clear", { method: "POST" });
          const data = await res.json();
          if (data.success) {
            window.location.reload();
          } else {
            showToast(data.error || "Failed to clear history.", "error");
          }
        } catch (err) {
          showToast("Network error.", "error");
        }
      });
    }
  }

  // Delete individual scan item
  document.querySelectorAll(".delete-scan-btn").forEach((btn) => {
    btn.addEventListener("click", async (e) => {
      e.stopPropagation();
      const id = btn.getAttribute("data-id");
      if (!confirm(`Delete scan record #${id}?`)) return;

      try {
        const res = await fetch(`/api/history/${id}`, { method: "DELETE" });
        const data = await res.json();
        if (data.success) {
          const row = btn.closest("tr");
          if (row) row.remove();
          showToast("Scan record deleted.", "success");
        } else {
          showToast(data.error || "Failed to delete record.", "error");
        }
      } catch (err) {
        showToast("Error deleting scan.", "error");
      }
    });
  });
}

function escapeHtml(str) {
  if (str === null || str === undefined) return "";
  return String(str)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#039;");
}
