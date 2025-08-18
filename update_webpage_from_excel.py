#!/usr/bin/env python3
import os, json, pandas as pd
EXCEL = os.path.join(os.path.dirname(__file__), "jobs.xlsx")
OUT_JSON = os.path.join(os.path.dirname(__file__), "jobs.json")
def main():
    if not os.path.exists(EXCEL): raise SystemExit("jobs.xlsx not found")
    df = pd.read_excel(EXCEL)
    for col in ["Company","Country","City","Title","JobID","URL","PersistKey"]:
        if col not in df.columns: raise SystemExit(f"Missing column in Excel: {col}")
    df = df.sort_values(["Company","Country","City","Title","JobID"], na_position="last").reset_index(drop=True)
    recs = [{
        "company": str(r["Company"] or ""),
        "country": str(r["Country"] or ""),
        "city": str(r["City"] or ""),
        "title": str(r["Title"] or ""),
        "job_id": str(r["JobID"] or ""),
        "url": str(r["URL"] or ""),
        "key": str(r["PersistKey"] or ""),
    } for _,r in df.iterrows()]
    with open(OUT_JSON,"w",encoding="utf-8") as f: json.dump(recs, f, ensure_ascii=False, indent=2)
    print(f"Wrote {OUT_JSON} ({len(recs)} records)")
if __name__ == "__main__": main()
