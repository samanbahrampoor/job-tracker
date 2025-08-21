# update_html.py
# Purpose: read jobs.xlsx and emit jobs.json including a stable 'id' per job.
# Requires: pandas, openpyxl
# Usage: python update_html.py
#
# Column flexibility:
#   - Company, Country, City, Title are required (case-insensitive).
#   - Link is detected via aliases: Link, URL, JobURL, PostingURL, ApplyURL, ApplicationURL (case-insensitive).
#   - If 'PersistKey' exists and is non-empty, it will be used as the job 'id' (preferred).
#   - Else if 'JobID' exists and is non-empty, it will be used for 'id'.
#   - Else we hash (company|title|country|city|link) to derive 'id'.

import pandas as pd
import hashlib
import json
import re
from pathlib import Path

SRC_XLSX = Path("jobs.xlsx")
OUT_JSON = Path("jobs.json")

def norm(s: str) -> str:
    return re.sub(r"[^a-z0-9]", "", str(s).lower())

ALIASES = {
    "company": ["company", "employer"],
    "title": ["title", "role", "position", "jobtitle"],
    "country": ["country"],
    "city": ["city", "location", "town"],
    "link": ["link", "url", "joburl", "postingurl", "applyurl", "applicationurl"],
    "jobid": ["jobid", "job_id", "id"],
    "persistkey": ["persistkey", "persist_key", "key", "slug", "uid"],
}

def find_col(columns, logical_name, required=False):
    """Return the ORIGINAL column name matching the logical name via aliases/normalization."""
    normalized_map = {norm(c): c for c in columns}
    for alias in ALIASES.get(logical_name, [logical_name]):
        alias_norm = norm(alias)
        if alias_norm in normalized_map:
            return normalized_map[alias_norm]
        # also try startswith match on normalized keys
        for k_norm, orig in normalized_map.items():
            if k_norm.startswith(alias_norm):
                return orig
    if required:
        raise KeyError(f"Missing column for '{logical_name}' in {list(columns)}")
    return None

def make_hash_id(company, title, country, city, link):
    base = f"{company}|{title}|{country}|{city}|{link}".lower().strip()
    return hashlib.sha1(base.encode("utf-8")).hexdigest()[:12]

def main():
    df = pd.read_excel(SRC_XLSX).fillna("")
    cols = df.columns

    company_col   = find_col(cols, "company", required=True)
    title_col     = find_col(cols, "title", required=True)
    country_col   = find_col(cols, "country", required=True)
    city_col      = find_col(cols, "city", required=True)
    link_col      = find_col(cols, "link", required=False)  # optional, used in hash + output
    jobid_col     = find_col(cols, "jobid", required=False)
    persist_col   = find_col(cols, "persistkey", required=False)

    out = []
    for _, row in df.iterrows():
        company = str(row[company_col]).strip()
        title   = str(row[title_col]).strip()
        country = str(row[country_col]).strip()
        city    = str(row[city_col]).strip()
        link    = str(row[link_col]).strip() if link_col else ""
        jobid   = str(row[jobid_col]).strip() if jobid_col else ""
        pkey    = str(row[persist_col]).strip() if persist_col else ""

        # Build stable id
        if pkey:
            jid = norm(pkey)[:40] or make_hash_id(company, title, country, city, link)
        elif jobid:
            jid = f"jobid-{norm(jobid)[:36]}"
        else:
            jid = make_hash_id(company, title, country, city, link)

        item = {
            "id": jid,
            "company": company,
            "title": title,
            "country": country,
            "city": city,
            "link": link,
        }

        # include any remaining columns as passthrough fields
        for c in df.columns:
            if c in [company_col, title_col, country_col, city_col, link_col, jobid_col, persist_col]:
                continue
            val = row[c]
            if pd.isna(val) or (isinstance(val, str) and not val.strip()):
                continue
            item[c] = val

        out.append(item)

    OUT_JSON.write_text(json.dumps(out, indent=2, ensure_ascii=False), encoding="utf-8")
    print(f"Wrote {OUT_JSON} with {len(out)} jobs")

if __name__ == "__main__":
    main()
