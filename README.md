# TRINETRA – Intelligent Phishing URL Detection & Cyber Protection System

> **Tagline:** *Intelligent Protection Against Digital Threats*  
> **Academic Credit:** *Developed by CSE and IT Students – S7*

TRINETRA is an industry-grade AI/ML-powered phishing URL detection and cybersecurity defense application. It inspects submitted URLs at a granular lexical level, extracts 41 structural indicators, passes them through a high-accuracy Random Forest ensemble classifier, and delivers explainable risk verdicts without ever connecting to or executing code from the destination server.

---

## 🛡️ Key Features

- **Lexical Zero-Execution Sandbox:** Never makes outbound network requests or fetches HTML content. Safe against drive-by downloads and tracking pixels.
- **Ensemble Random Forest AI Model:** Trained on verified datasets including PhiUSIIL, Faizan research corpus, and Tranco Top 1M legitimate domains.
- **Authentic Evaluation Metrics:**
  - **Accuracy:** ~94.10%
  - **Precision:** ~93.94%
  - **Recall:** ~94.28%
  - **F1-Score:** ~94.11%
  - **ROC-AUC:** ~0.9866
- **Transparent Risk Scoring:** Explains *why* a URL was classified as Low, Medium, or High Risk, breaking down top feature contributions and triggered threat heuristics.
- **Dynamic Threat Analytics Dashboard:** Visualizes scanning activity trends over 14 days, risk ratios, and model confusion matrices using Chart.js.
- **Searchable Scan Audit History:** Powered by SQLite, allowing users to query, filter by risk level, inspect individual records, or clear history with confirmation.
- **Custom Cyber UI/UX:** Responsive dark-navy aesthetic featuring modern green/cyan accents, smooth animations, and a custom SVG brand logo inspired by the traditional Indian concept of *Trinetra* (the Three-Eyed Vision).

---

## 🗂️ Project Architecture

```
TRINETRA/
├── app.py                   # Main Flask application and REST API endpoints
├── feature_extraction.py    # 41-feature lexical extraction engine
├── scanner.py               # Model loader, probability scoring & tree interpreter
├── train_model.py           # Machine learning training & evaluation pipeline
├── prepare_dataset.py       # Balanced dataset curation & processing script
├── database.py              # SQLite database storage & query interface
├── requirements.txt         # Project Python dependencies
├── dataset/                 # Raw and processed datasets
│   ├── processed_urls.csv   # Balanced 25,000 URL training dataset
│   └── raw/                 # Downloaded source datasets
├── model/                   # Serialized ML artifacts
│   ├── trinetra_rf_model.joblib # Trained Random Forest model bundle
│   └── metrics.json         # Real test split evaluation metrics
├── static/
│   ├── css/style.css        # Premium custom cybersecurity styling
│   ├── js/main.js           # Client interactions and async scanning
│   ├── js/vendor/           # Local Chart.js bundle
│   └── images/logo.svg      # Custom Trinetra three-eyed vector emblem
└── templates/
    ├── base.html            # Main layout with navigation and student credit
    ├── index.html           # Landing page with system overview
    ├── scanner.html         # Interactive real-time URL scanner
    ├── dashboard.html       # Analytics telemetry and ML benchmark cards
    ├── history.html         # Searchable scan history and audit log
    └── about.html           # System architecture, brand concept & credits
```

---

## ⚙️ Installation & Setup Instructions

### Prerequisites
- Python 3.10+ (Python 3.11, 3.12, 3.13, 3.14 compatible)
- pip and virtualenv

### 1. Clone or Open Project
```bash
cd TRINETRA
```

### 2. Create and Activate Virtual Environment
On Windows (PowerShell):
```powershell
python -m venv venv
.\venv\Scripts\Activate.ps1
```
On Linux / macOS:
```bash
python3 -m venv venv
source venv/bin/activate
```

### 3. Install Dependencies
```bash
pip install -r requirements.txt
```

### 4. (Optional) Re-train the Machine Learning Model
The repository already includes the pre-trained, validated model (`model/trinetra_rf_model.joblib`) and metrics. If you wish to retrain from scratch:
```bash
# Prepares the balanced dataset from raw sources
python prepare_dataset.py 12500

# Trains the Random Forest model and outputs authentic metrics
python train_model.py
```

### 5. Launch the Application
```bash
python app.py
```
Open your browser and navigate to:
```
http://127.0.0.1:5000
```

---

## 🧪 Verification & Demonstration Guide

1. **Test Known Legitimate Links:**
   - `https://www.google.com` &rarr; Expected: **LOW RISK (Legitimate)**
   - `https://github.com` &rarr; Expected: **LOW RISK (Legitimate)**
   - `https://www.wikipedia.org` &rarr; Expected: **LOW RISK (Legitimate)**

2. **Test Phishing / Spoofed URLs:**
   - `http://paypal-security-verification.update-auth.xyz/login.php` &rarr; Expected: **HIGH RISK (Potentially Phishing)**
   - `http://192.168.1.100/admin/secure/banking/update.php` &rarr; Expected: **HIGH RISK (Potentially Phishing)**
   - `https://appleid.apple.com-verify-account.tk/signin` &rarr; Expected: **HIGH RISK (Potentially Phishing)**

3. **Check Dashboard & History:**
   - View updated statistics in the **Dashboard** tab.
   - Inspect individual feature breakdowns and tree decisions in **Scan History**.

---

## 🎓 Academic Attribution

**TRINETRA – Intelligent Phishing URL Detection and Cyber Protection System**  
*Final Year Major Project*  
**Developed by CSE and IT Students – S7**
