import pandas as pd
from pathlib import Path

EXCEL_PATH = "jobs.xlsx"
HTML_PATH = "jobs.html"

def generate_html(df):
    companies = df.groupby("Company")

    html = """
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>Jobs Dashboard</title>
  <style>
    body { font-family: Arial, sans-serif; margin: 20px; background: #f9f9f9; }
    h1 { text-align: center; }
    .filters { margin: 20px 0; text-align: center; }
    .job { background: #fff; margin: 10px 0; padding: 15px; border-radius: 8px; 
           box-shadow: 0 2px 6px rgba(0,0,0,0.1); }
    .company { font-weight: bold; font-size: 18px; margin-top: 20px; }
    .title { font-size: 16px; font-weight: bold; }
    .location { color: #555; }
    .applied { margin-left: 10px; }
  </style>
</head>
<body>
  <h1>Jobs Dashboard</h1>
  <div class="filters">
    <label><input type="checkbox" id="filter-applied"> Show only applied</label>
    <select id="filter-location">
      <option value="">All locations</option>
    </select>
  </div>
  <div id="jobs">
"""

    for company, company_df in companies:
        html += f"<div class='company'>{company}</div>"
        for _, row in company_df.iterrows():
            job_id = str(row['JobID'])
            title = row['Title']
            loc = f"{row['Country']}, {row['City']}"
            link = row['URL']
            html += f"""
            <div class="job" data-location="{loc}" data-id="{job_id}">
              <div class="title"><a href="{link}" target="_blank">{title}</a></div>
              <div class="location">{loc}</div>
              <label class="applied">
                <input type="checkbox" class="apply-box" data-id="{job_id}"> Applied
              </label>
            </div>
            """

    html += """
  </div>
  <script>
    document.querySelectorAll(".apply-box").forEach(box => {
      const id = box.dataset.id;
      box.checked = localStorage.getItem("applied-" + id) === "true";
      box.addEventListener("change", () => {
        localStorage.setItem("applied-" + id, box.checked);
      });
    });

    const locations = [...new Set([...document.querySelectorAll(".job")]
      .map(j => j.dataset.location))].sort();
    const locSelect = document.getElementById("filter-location");
    locations.forEach(loc => {
      const opt = document.createElement("option");
      opt.value = loc;
      opt.textContent = loc;
      locSelect.appendChild(opt);
    });

    function applyFilters() {
      const appliedOnly = document.getElementById("filter-applied").checked;
      const selectedLoc = locSelect.value;
      document.querySelectorAll(".job").forEach(job => {
        const checked = job.querySelector(".apply-box").checked;
        const loc = job.dataset.location;
        let visible = true;
        if (appliedOnly && !checked) visible = false;
        if (selectedLoc && loc !== selectedLoc) visible = false;
        job.style.display = visible ? "" : "none";
      });
    }

    document.getElementById("filter-applied").addEventListener("change", applyFilters);
    locSelect.addEventListener("change", applyFilters);
  </script>
</body>
</html>
"""
    return html

def main():
    df = pd.read_excel(EXCEL_PATH)
    html = generate_html(df)
    Path(HTML_PATH).write_text(html, encoding="utf-8")
    print(f"✅ Updated {HTML_PATH} from {EXCEL_PATH}")

if __name__ == "__main__":
    main()
