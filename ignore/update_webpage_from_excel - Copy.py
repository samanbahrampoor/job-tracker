#!/usr/bin/env python3
"""
Regenerate jobs.html from jobs.xlsx with client‑side decryption + filters.

Security:
- The job data is AES‑GCM encrypted at build time using a passphrase you provide.
- The HTML embeds only ciphertext (plus salt/iv/params). No plaintext data ships.
- On load, the page asks for the passphrase and decrypts in the browser (Web Crypto).

Usage:
    pip install openpyxl cryptography
    # Either set a passphrase:
    #   (PowerShell)   $env:JOBS_SECRET="your passphrase"
    #   (bash/zsh)     export JOBS_SECRET="your passphrase"
    # Or just run and you'll be prompted.
    python update_webpage_from_excel.py
"""

import os, json, base64, getpass, pandas as pd
from pathlib import Path
from secrets import token_bytes
from typing import Dict, Any
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes

HERE = Path(__file__).resolve().parent
EXCEL_PATH = HERE / "jobs.xlsx"
HTML_PATH  = HERE / "jobs.html"

PBKDF2_ITERATIONS = 200_000  # balance of speed/security
SALT_BYTES = 16
IV_BYTES   = 12  # AES-GCM nonce length
KEY_BYTES  = 32  # 256-bit AES

def _records_from_excel(path: Path):
    df = pd.read_excel(path)
    df = df.sort_values(["Company","Country","City","Title","JobID"], na_position="last").reset_index(drop=True)
    recs = []
    for r in df.to_dict(orient="records"):
        recs.append({
            "company": r.get("Company","") or "",
            "country": r.get("Country","") or "",
            "city":    r.get("City","") or "",
            "title":   r.get("Title","") or "",
            "job_id":  r.get("JobID","") or "",
            "url":     r.get("URL","") or "",
            "key":     r.get("PersistKey","") or "",
        })
    return recs

def _derive_key(passphrase: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=KEY_BYTES, salt=salt, iterations=PBKDF2_ITERATIONS)
    return kdf.derive(passphrase.encode("utf-8"))

def _encrypt_json(obj: Any, passphrase: str) -> Dict[str,str]:
    plaintext = json.dumps(obj, ensure_ascii=False).encode("utf-8")
    salt = token_bytes(SALT_BYTES)
    iv   = token_bytes(IV_BYTES)
    key  = _derive_key(passphrase, salt)
    aesgcm = AESGCM(key)
    ct = aesgcm.encrypt(iv, plaintext, associated_data=None)
    return {
        "ciphertext_b64": base64.b64encode(ct).decode("ascii"),
        "salt_b64": base64.b64encode(salt).decode("ascii"),
        "iv_b64":   base64.b64encode(iv).decode("ascii"),
        "iterations": str(PBKDF2_ITERATIONS),
        "alg": "AES-GCM",
        "kdf": "PBKDF2-SHA256",
    }

HTML_TEMPLATE = r"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8"/>
<meta name="viewport" content="width=device-width, initial-scale=1"/>
<title>Jobs Dashboard</title>
<style>
:root {
  --bg: #0f172a; --card: #0b1223; --muted: #94a3b8; --text: #e2e8f0; --accent: #60a5fa; --border: #1f2a44;
}
* { box-sizing: border-box; }
body { margin:0; background: linear-gradient(135deg,#0b1020 0%, #0f172a 50%, #0a0f1f 100%); color: var(--text); font-family: ui-sans-serif, system-ui, -apple-system, Segoe UI, Roboto, Helvetica, Arial, sans-serif; }
header { position:sticky; top:0; z-index:10; backdrop-filter: blur(6px); background: rgba(10,15,31,.7); border-bottom:1px solid var(--border); }
.header-inner { max-width: 1100px; margin:0 auto; padding: 16px; display:flex; flex-wrap:wrap; align-items:center; gap:12px; }
h1 { margin:0; font-size: 22px; letter-spacing:.2px; }
.controls { display:flex; gap:10px; align-items:center; flex-wrap:wrap; margin-left:auto; }
input[type="search"], select { background: #0a1120; border:1px solid var(--border); color:var(--text); padding:10px 12px; border-radius:12px; min-width:220px; outline:none; }
input[type="search"]::placeholder { color: #7c8aa6; }
.badge { font-size:12px; padding:6px 10px; border-radius:999px; background:#0b1328; border:1px solid var(--border); color:#cbd5e1; }
.container { max-width: 1100px; margin: 0 auto; padding: 20px 16px 36px; }
.section { margin-top: 18px; }
.section h2 { margin: 22px 0 6px; font-size:18px; font-weight:700; color:#c7d2fe; }
.section h3 { margin: 12px 0 6px; font-size:14px; font-weight:700; color:#a5b4fc; opacity:.9; }
.section h4 { margin: 8px 0 10px; font-size:13px; font-weight:700; color:#93c5fd; opacity:.9; }
.grid { display:grid; grid-template-columns: repeat(auto-fill, minmax(320px, 1fr)); gap:12px; }
.card { background: linear-gradient(180deg, rgba(14,22,43,.9), rgba(12,17,33,.9)); border:1px solid var(--border); border-radius:16px; padding:14px; display:flex; flex-direction:column; gap:10px; box-shadow: 0 8px 24px rgba(0,0,0,.25); }
.card a { color: var(--accent); text-decoration:none; font-weight:600; }
.meta { font-size:12px; color: var(--muted); display:flex; gap:8px; flex-wrap:wrap; }
.tag { padding:2px 8px; border-radius:999px; background:#0d1731; border:1px solid var(--border); }
.toggle { display:inline-flex; align-items:center; gap:8px; user-select:none; cursor:pointer; width:fit-content; }
.toggle input { display:none; }
.switch { width:40px; height:22px; border-radius:999px; background:#0f1a35; border:1px solid var(--border); position:relative; transition:.2s; }
.knob { position:absolute; top:2px; left:2px; width:18px; height:18px; border-radius:50%; background:#7c8aa6; transition:.2s; }
input:checked + .switch { background: linear-gradient(90deg, #2563eb, #06b6d4); border-color: transparent; }
input:checked + .switch .knob { left:20px; background:white; }
.apply-line { display:flex; align-items:center; justify-content:space-between; gap:10px; }
footer { text-align:center; color:#8aa0c6; padding:24px; border-top:1px solid var(--border); background: rgba(10,15,31,.4); }
hr.sep { border:0; border-top:1px dashed var(--border); margin: 12px 0 18px; opacity:.6; }
.password-gate { max-width: 560px; margin: 80px auto; background: rgba(12,17,33,.75); border:1px solid var(--border); border-radius: 14px; padding: 18px; text-align:center; }
.password-gate input { width: 100%; }
.password-gate button { margin-top: 10px; padding: 10px 14px; border-radius: 10px; border:1px solid var(--border); background:#111827; color:white; cursor:pointer; }
.hidden { display:none !important; }
.filters { display:flex; gap:10px; flex-wrap:wrap; }
</style>
</head>
<body>
<header>
  <div class="header-inner">
    <h1>Jobs Dashboard</h1>
    <div class="controls">
      <input id="q" type="search" placeholder="Filter text… (title, city, country, company or id)"/>
      <select id="appliedFilter">
        <option value="all">All</option>
        <option value="applied">Applied</option>
        <option value="not">Not applied</option>
      </select>
      <select id="countryFilter"><option value="all">All countries</option></select>
      <select id="cityFilter"><option value="all">All cities</option></select>
      <span class="badge" id="count"></span>
    </div>
  </div>
</header>

<main class="container">
  <div id="gate" class="password-gate">
    <h2>Enter passphrase</h2>
    <p class="meta">This page only decrypts locally in your browser.</p>
    <input id="pw" type="password" placeholder="Passphrase"/>
    <button id="unlock">Unlock</button>
    <div id="err" class="meta" style="color:#fca5a5; margin-top:8px;"></div>
  </div>
  <div id="root" class="hidden"></div>
</main>

<footer>Checkbox status is saved locally (this device) via <code>localStorage</code>.</footer>

<script>
const ENCRYPTED = __ENCRYPTED_JSON__;
// ---- Decrypt helpers (Web Crypto) ----
async function deriveKey(passphrase, salt, iterations) {
  const enc = new TextEncoder();
  const baseKey = await crypto.subtle.importKey("raw", enc.encode(passphrase), "PBKDF2", false, ["deriveKey"]);
  return crypto.subtle.deriveKey(
    { name:"PBKDF2", salt, iterations, hash:"SHA-256" },
    baseKey,
    { name:"AES-GCM", length:256 },
    false, ["decrypt"]
  );
}
async function decryptToJson(passphrase) {
  const salt = Uint8Array.from(atob(ENCRYPTED.salt_b64), c=>c.charCodeAt(0));
  const iv   = Uint8Array.from(atob(ENCRYPTED.iv_b64),   c=>c.charCodeAt(0));
  const ct   = Uint8Array.from(atob(ENCRYPTED.ciphertext_b64), c=>c.charCodeAt(0));
  const key  = await deriveKey(passphrase, salt, parseInt(ENCRYPTED.iterations,10));
  const pt   = await crypto.subtle.decrypt({name:"AES-GCM", iv}, key, ct);
  const dec  = new TextDecoder().decode(pt);
  return JSON.parse(dec);
}
// ---- UI helpers + rendering ----
function storageKey(key){ return "applied::" + key; }
function el(tag, cls, html) {
  const e = document.createElement(tag);
  if (cls) e.className = cls;
  if (html !== undefined) e.innerHTML = html;
  return e;
}
function groupData(data) {
  const out = {};
  for (const r of data) {
    const c = r.company || '—'; const co = r.country || '—'; const ci = r.city || '—';
    (out[c] = out[c] || {}); (out[c][co] = out[c][co] || {}); (out[c][co][ci] = out[c][co][ci] || []);
    out[c][co][ci].push(r);
  }
  return out;
}
function buildFilters(data){
  const countries = Array.from(new Set(data.map(d => d.country || '—'))).sort((a,b)=>a.localeCompare(b));
  const countrySel = document.getElementById('countryFilter');
  const citySel    = document.getElementById('cityFilter');
  // Countries
  countrySel.innerHTML = '<option value="all">All countries</option>' + countries.map(c=>`<option>${c}</option>`).join('');
  // Cities (all at first)
  const allCities = Array.from(new Set(data.map(d => (d.city || '—') + '||' + (d.country || '—'))))
    .map(s => { const [city, country] = s.split('||'); return {city, country}; })
    .sort((a,b)=> a.city.localeCompare(b.city));
  citySel.innerHTML = '<option value="all">All cities</option>' + allCities.map(o=>`<option data-country="${o.country}">${o.city}</option>`).join('');
  // When country changes, filter city options
  countrySel.addEventListener('change', () => {
    const chosen = countrySel.value;
    const options = Array.from(citySel.querySelectorAll('option'));
    options.forEach((opt, idx) => {
      if (idx===0) { opt.hidden=false; return; } // keep "All cities"
      if (chosen==='all') opt.hidden=false;
      else opt.hidden = (opt.getAttribute('data-country') !== chosen);
    });
    citySel.value = 'all';
    window.__rerender && window.__rerender();
  });
  citySel.addEventListener('change', () => window.__rerender && window.__rerender());
}
function render(data) {
  const root = document.getElementById('root');
  const countEl = document.getElementById('count');
  root.innerHTML = '';
  const Q = (document.getElementById('q').value || '').toLowerCase();
  const appliedFilter = document.getElementById('appliedFilter').value; // all | applied | not
  const countryFilter = document.getElementById('countryFilter').value; // 'all' or country
  const cityFilter    = document.getElementById('cityFilter').value;    // 'all' or city
  const filtered = data.filter(d => {
    const matchesText = (d.title+d.city+d.country+d.company+d.job_id).toLowerCase().includes(Q);
    const applied = localStorage.getItem(storageKey(d.key || (d.company+'|'+d.job_id))) === '1';
    const matchesApplied = appliedFilter==='all' ? true : (appliedFilter==='applied' ? applied : !applied);
    const matchesCountry = (countryFilter==='all') || ((d.country||'—')===countryFilter);
    const matchesCity    = (cityFilter==='all')    || ((d.city||'—')===cityFilter);
    return matchesText && matchesApplied && matchesCountry && matchesCity;
  });
  const grouped = groupData(filtered);
  let total = 0;
  Object.keys(grouped).forEach(company => {
    const section = el('section', 'section');
    section.appendChild(el('h2', '', company));
    Object.keys(grouped[company]).forEach(country => {
      section.appendChild(el('h3', '', 'Country: ' + country));
      Object.keys(grouped[company][country]).forEach(city => {
        section.appendChild(el('h4', '', 'City: ' + city));
        const grid = el('div', 'grid');
        const jobs = grouped[company][country][city];
        jobs.forEach(job => {
          const card = el('div', 'card');
          const title = el('div', '', `<a href="${job.url}" target="_blank" rel="noopener">${job.title || 'Unknown Title'}</a>`);
          const meta = el('div', 'meta');
          meta.appendChild(el('span', 'tag', job.company));
          meta.appendChild(el('span', 'tag', job.city ? job.city + ', ' + (job.country || '') : (job.country || 'Location: —')));
          meta.appendChild(el('span', 'tag', 'ID: ' + (job.job_id || '—')));
          const toggleWrap = el('label', 'toggle apply-line');
          const cb = el('input'); cb.type = 'checkbox';
          const key = job.key || (job.company + '|' + job.job_id);
          cb.checked = localStorage.getItem(storageKey(key)) === '1';
          cb.addEventListener('change', () => {
            if (cb.checked) localStorage.setItem(storageKey(key), '1');
            else localStorage.removeItem(storageKey(key));
            render(data); // re-count / re-filter when toggled
          });
          const sw = el('span', 'switch'); const knob = el('span', 'knob'); sw.appendChild(knob);
          const label = el('span', '', 'Applied');
          toggleWrap.appendChild(cb); toggleWrap.appendChild(sw); toggleWrap.appendChild(label);
          card.appendChild(title); card.appendChild(meta); card.appendChild(toggleWrap);
          grid.appendChild(card); total += 1;
        });
        section.appendChild(grid);
        section.appendChild(el('hr', 'sep'));
      });
    });
    root.appendChild(section);
  });
  countEl.textContent = total + ' roles';
}
async function boot() {
  const gate = document.getElementById('gate');
  const root = document.getElementById('root');
  const err  = document.getElementById('err');
  const pw   = document.getElementById('pw');
  const unlock = document.getElementById('unlock');
  async function tryUnlock() {
    err.textContent = '';
    try {
      const DATA = await decryptToJson(pw.value);
      // show UI
      gate.classList.add('hidden'); root.classList.remove('hidden');
      // build filters & events
      buildFilters(DATA);
      document.getElementById('q').addEventListener('input', () => render(DATA));
      document.getElementById('appliedFilter').addEventListener('change', () => render(DATA));
      window.__rerender = () => render(DATA);
      render(DATA);
    } catch(e) {
      console.error(e);
      err.textContent = 'Could not decrypt. Check passphrase.';
    }
  }
  unlock.addEventListener('click', tryUnlock);
  pw.addEventListener('keydown', (ev)=>{ if(ev.key==='Enter') tryUnlock(); });
}
document.addEventListener('DOMContentLoaded', boot);
</script>
</body>
</html>
"""

def main():
    if not EXCEL_PATH.exists():
        raise SystemExit("jobs.xlsx not found next to this script.")
    secret = os.getenv("JOBS_SECRET") or getpass.getpass("Enter passphrase for encryption: ")
    data = _records_from_excel(EXCEL_PATH)
    enc = _encrypt_json(data, secret)
    html = HTML_TEMPLATE.replace("__ENCRYPTED_JSON__", json.dumps(enc))
    HTML_PATH.write_text(html, encoding="utf-8")
    print(f"Updated {HTML_PATH.name} from {EXCEL_PATH.name} (encrypted payload).")

if __name__ == "__main__":
    main()
