"""
TRINETRA - Dataset Preparation Pipeline (Enhanced)
===================================================

Creates a high-quality, balanced, diverse dataset for phishing URL detection.

Sources:
  1. PhiUSIIL Phishing URL Dataset (UCI #967) - 134k legit, 100k phishing URLs
  2. Faizan Phishing URL Dataset - 479k legit, 166k phishing
  3. Tranco Top 1M Most Popular Domains - Real-world legitimate popular web domains
     (google.com, github.com, wikipedia.org, linkedin.com, etc.)

Class Balance:
  - 50% Legitimate URLs
  - 50% Phishing URLs

All samples have their features extracted through the exact same
`feature_extraction.extract_features` pipeline.
"""

from __future__ import annotations

import csv
import glob
import os
import random
import sys
import pandas as pd
from feature_extraction import FEATURE_NAMES, extract_features

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
RAW_DIR = os.path.join(BASE_DIR, "dataset", "raw")
TRANCO_DIR = os.path.join(BASE_DIR, "dataset", "tranco")
OUT_CSV = os.path.join(BASE_DIR, "dataset", "processed_urls.csv")


def load_tranco_domains(limit: int = 5000) -> list[str]:
    """Load top popular web domains from the Tranco research list."""
    csv_files = glob.glob(os.path.join(TRANCO_DIR, "*.csv"))
    if not csv_files:
        return []
    domains = []
    with open(csv_files[0], "r", encoding="utf-8", errors="ignore") as f:
        reader = csv.reader(f)
        for i, row in enumerate(reader):
            if len(row) >= 2:
                dom = row[1].strip()
                if dom:
                    domains.append(f"https://{dom}")
                    domains.append(f"https://www.{dom}")
            if len(domains) >= limit:
                break
    return domains


def prepare_dataset(sample_size_per_class: int = 15000, random_seed: int = 42):
    random.seed(random_seed)
    phishing_urls = set()
    legitimate_urls = set()

    phiusiil_path = os.path.join(RAW_DIR, "PhiUSIIL_Phishing_URL_Dataset.csv")
    faizan_path = os.path.join(RAW_DIR, "faizan_data.csv")

    # 1. PhiUSIIL
    if os.path.exists(phiusiil_path):
        print(f"[*] Reading PhiUSIIL dataset...")
        with open(phiusiil_path, "r", encoding="utf-8", errors="ignore") as f:
            reader = csv.reader(f)
            header = next(reader)
            for row in reader:
                if len(row) < 3:
                    continue
                url = row[1].strip()
                lbl = row[-1].strip()
                if not url or len(url) > 2000:
                    continue
                if lbl == "0":
                    phishing_urls.add(url)
                elif lbl == "1":
                    legitimate_urls.add(url)

    # 2. Faizan Dataset
    if os.path.exists(faizan_path):
        print(f"[*] Reading secondary dataset...")
        with open(faizan_path, "r", encoding="utf-8", errors="ignore") as f:
            reader = csv.reader(f)
            header = next(reader)
            for row in reader:
                if len(row) < 2:
                    continue
                url = row[0].strip()
                lbl = row[1].strip().lower()
                if not url or len(url) > 2000:
                    continue
                if lbl in ("bad", "phishing", "malicious", "1"):
                    phishing_urls.add(url)
                elif lbl in ("good", "legitimate", "benign", "0"):
                    legitimate_urls.add(url)

    # 3. Add top Tranco domains to legitimate URLs to guarantee popular sites representation
    tranco_urls = load_tranco_domains(limit=4000)
    print(f"[*] Loaded {len(tranco_urls)} popular legitimate URLs from Tranco Top 1M list.")
    for u in tranco_urls:
        legitimate_urls.add(u)

    print(f"[+] Total pool available: {len(legitimate_urls)} legitimate, {len(phishing_urls)} phishing.")

    # Target balanced sampling
    target_count = min(sample_size_per_class, len(phishing_urls), len(legitimate_urls))
    print(f"[*] Sampling {target_count} samples per class (Total: {target_count * 2})...")

    # Ensure Tranco domains are prioritized in legitimate sample
    tranco_in_legit = [u for u in tranco_urls if u in legitimate_urls]
    remaining_needed = target_count - len(tranco_in_legit)
    other_legit = [u for u in legitimate_urls if u not in set(tranco_in_legit)]
    sampled_legit = tranco_in_legit + random.sample(other_legit, max(0, remaining_needed))
    sampled_legit = sampled_legit[:target_count]

    sampled_phish = random.sample(list(phishing_urls), target_count)

    dataset_records = []
    for u in sampled_legit:
        dataset_records.append((u, 0))  # 0 = Legitimate
    for u in sampled_phish:
        dataset_records.append((u, 1))  # 1 = Phishing

    random.shuffle(dataset_records)

    print(f"[*] Extracting lexical features for {len(dataset_records)} URLs...")
    rows = []
    total = len(dataset_records)
    for idx, (url, label) in enumerate(dataset_records):
        try:
            feats = extract_features(url)
            feats["url"] = url
            feats["label"] = label
            rows.append(feats)
        except Exception:
            continue
        if (idx + 1) % 5000 == 0 or (idx + 1) == total:
            print(f"    Extracted {idx + 1}/{total} URLs ({((idx + 1) / total * 100):.1f}%)...")

    df = pd.DataFrame(rows)
    cols = ["url"] + FEATURE_NAMES + ["label"]
    df = df[cols]

    os.makedirs(os.path.dirname(OUT_CSV), exist_ok=True)
    df.to_csv(OUT_CSV, index=False, encoding="utf-8")
    print(f"[+] Balanced dataset successfully saved to {OUT_CSV}")
    print(f"    Shape: {df.shape}")
    print(f"    Label counts:\n{df['label'].value_counts()}")
    return OUT_CSV


if __name__ == "__main__":
    count = 12500
    if len(sys.argv) > 1:
        count = int(sys.argv[1])
    prepare_dataset(sample_size_per_class=count)
