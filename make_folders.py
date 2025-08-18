#!/usr/bin/env python3
"""
Create a folder structure from jobs.xlsx:
- Top-level folder: Company name
- Subfolder per job: Title-Location-JobID (Location = City if available else Country, or 'Unknown')
- Each job folder contains copies of 'res.cls' and 'CV.tex' from the same directory as this script.

Usage:
    python make_folders.py
"""
import os, re, shutil, pandas as pd

BASE_DIR = os.path.dirname(__file__)
EXCEL_PATH = os.path.join(BASE_DIR, "jobs.xlsx")
RES_FILE = os.path.join(BASE_DIR, "res.cls")
CV_FILE = os.path.join(BASE_DIR, "CV.tex")

def safe_slug(s: str, maxlen=120) -> str:
    s = str(s)
    s = re.sub(r"[^\w\s\-]+", "", s, flags=re.UNICODE)
    s = re.sub(r"\s+", "-", s.strip())
    s = s.strip("-")
    if len(s) > maxlen:
        s = s[:maxlen].rstrip("-")
    return s

def main():
    if not os.path.exists(EXCEL_PATH):
        raise SystemExit("jobs.xlsx not found")
    if not os.path.exists(RES_FILE):
        raise SystemExit("res.cls not found in the same directory")
    if not os.path.exists(CV_FILE):
        raise SystemExit("CV.tex not found in the same directory")

    df = pd.read_excel(EXCEL_PATH)
    for _, row in df.iterrows():
        company = str(row.get("Company", "Company")).strip() or "Company"
        title = str(row.get("Title", "Title")).strip() or "Title"
        city = str(row.get("City", "")).strip()
        country = str(row.get("Country", "")).strip()
        jobid = str(row.get("JobID", "")).strip() or "ID"

        location = city if city else (country if country else "Unknown")
        company_dir = os.path.join(BASE_DIR, safe_slug(company, 80))
        job_folder_name = f"{safe_slug(title, 80)}-{safe_slug(location, 40)}-{safe_slug(jobid, 40)}"
        job_dir = os.path.join(company_dir, job_folder_name)

        os.makedirs(job_dir, exist_ok=True)

        # Copy files (overwrite if already exist)
        shutil.copy2(RES_FILE, os.path.join(job_dir, "res.cls"))
        shutil.copy2(CV_FILE, os.path.join(job_dir, "CV.tex"))

    print("Folder structure created/updated successfully.")

if __name__ == "__main__":
    main()
