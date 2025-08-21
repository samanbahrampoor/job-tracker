# update_html.py
# Purpose: read jobs.xlsx and emit jobs.json including a stable 'id' per job.
# Requires: pandas, openpyxl
# Usage: python update_html.py

import pandas as pd
import hashlib
import json
from pathlib import Path

SRC_XLSX = Path("jobs.xlsx")
OUT_JSON = Path("jobs.json")

def make_job_id(company, title, country, city, link):
    base = f"{company}|{title}|{country}|{city}|{link}".lower().strip()
    return hashlib.sha1(base.encode("utf-8")).hexdigest()[:12]

def main():
    df = pd.read_excel(SRC_XLSX).fillna("")
    # Normalize expected columns; adapt names if your sheet differs
    cols = {c.lower().strip(): c for c in df.columns}

    def col(name):
        # try exact, else case-insensitive find
        if name in cols:
            return cols[name]
        for k,v in cols.items():
            if k.startswith(name):
                return v
        raise KeyError(f\"Missing column for '{name}' in {list(df.columns)}\")

    company_col = col("company")
    title_col   = col("title")
    country_col = col("country")
    city_col    = col("city")
    link_col    = col("link")

    out = []
    for _, row in df.iterrows():
        company = str(row[company_col]).strip()
        title   = str(row[title_col]).strip()
        country = str(row[country_col]).strip()
        city    = str(row[city_col]).strip()
        link    = str(row[link_col]).strip()

        jid = make_job_id(company, title, country, city, link)
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
            if c in [company_col, title_col, country_col, city_col, link_col]:
                continue
            val = row[c]
            if pd.isna(val):
                continue
            item[c] = val
        out.append(item)

    OUT_JSON.write_text(json.dumps(out, indent=2, ensure_ascii=False))
    print(f"Wrote {OUT_JSON} with {len(out)} jobs")

if __name__ == "__main__":
    main()
