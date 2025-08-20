#!/usr/bin/env python3
import hashlib
import json
import re
from pathlib import Path
import pandas as pd

# ---- Configure paths ----
EXCEL_PATH = Path("jobs.xlsx")         # change if needed
OUTPUT_JSON = Path("jobs.json")        # this is what you upload to KV

# Column mapping tolerance
CANDIDATES = {
    "title":   ["title", "Title", "Job Title"],
    "company": ["company", "Company"],
    "city":    ["city", "City"],
    "country": ["country", "Country"],
    "job_id":  ["job_id", "JobID", "ID", "Job Id", "Job id"],
    "url":     ["url", "URL", "Link", "Job Link"],
}

def first_present(row, keys):
    for k in keys:
        if k in row and pd.notna(row[k]) and str(row[k]).strip() != "":
            return str(row[k]).strip()
    return ""

def normalize_key_piece(s: str) -> str:
    """Lowercase, trim, collapse spaces, strip non-alphanum (except -_)."""
    s = s.lower().strip()
    s = re.sub(r"\s+", " ", s)
    s = s.replace(" ", "-")
    s = re.sub(r"[^a-z0-9\-_]+", "", s)
    return s

def short_hash(*parts) -> str:
    data = "|".join([p or "" for p in parts]).encode("utf-8")
    return hashlib.sha1(data).hexdigest()[:10]

def build_key(company: str, job_id: str, title: str, url: str) -> str:
    c = normalize_key_piece(company)
    j = normalize_key_piece(job_id)
    if c and j:
        return f"{c}|{j}"
    # fallback if job_id missing: stable short hash of title+company+url
    return f"{c}|{short_hash(title, company, url)}"

def main():
    if not EXCEL_PATH.exists():
        raise SystemExit(f"Excel not found: {EXCEL_PATH.resolve()}")

    # Load Excel (auto-detect header row)
    df = pd.read_excel(EXCEL_PATH)

    # Build normalized records
    records = []
    for _, row in df.iterrows():
        row_dict = row.to_dict()

        title   = first_present(row_dict, CANDIDATES["title"])
        company = first_present(row_dict, CANDIDATES["company"])
        city    = first_present(row_dict, CANDIDATES["city"])
        country = first_present(row_dict, CANDIDATES["country"])
        job_id  = first_present(row_dict, CANDIDATES["job_id"])
        url     = first_present(row_dict, CANDIDATES["url"])

        # skip lines with no company+title
        if not (company or title):
            continue

        key = build_key(company, job_id, title, url)

        records.append({
            "company": company,
            "title": title,
            "city": city,
            "country": country,
            "job_id": job_id,
            "url": url,
            "key": key,
        })

    # De-duplicate by key (keep first)
    seen = set()
    dedup = []
    dups = []
    for r in records:
        if r["key"] in seen:
            dups.append(r)
            continue
        seen.add(r["key"])
        dedup.append(r)

    # Save JSON
    OUTPUT_JSON.write_text(json.dumps(dedup, ensure_ascii=False, indent=2))
    print(f"✅ Wrote {len(dedup)} jobs to {OUTPUT_JSON} ({len(dups)} duplicates removed)")

    if dups:
        print("\nDuplicate keys (ignored):")
        for r in dups[:20]:
            print(f"  {r['key']}  ←  {r['company']} | {r['title']} | {r['job_id']}")

if __name__ == "__main__":
    main()
