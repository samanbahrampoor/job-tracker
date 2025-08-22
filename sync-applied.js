// sync-applied.js (selector-agnostic + diagnostics badge)
(function () {
  // Set this before including the script if you like:
  // window.JOB_TRACKER_API_BASE = "https://<your>.workers.dev"
  const API_BASE = (window.JOB_TRACKER_API_BASE || "https://job-tracker-oauth.saman-bahrampoor.workers.dev").replace(/\/+$/, "");
  const TOGGLE_SEL = 'input.applied-toggle[type="checkbox"][data-job-id], [data-role="applied-toggle"][data-job-id]';

  // tiny status badge
  const badge = document.createElement("div");
  badge.style.cssText = "position:fixed;right:10px;bottom:10px;padding:6px 10px;border-radius:8px;font:12px system-ui;background:#eee;color:#333;box-shadow:0 2px 10px rgba(0,0,0,.12);z-index:99999";
  badge.textContent = "Sync: init";
  const setBadge = (t, ok=true)=>{ badge.textContent=t; badge.style.background=ok?"#e6ffe6":"#ffe6e6"; badge.style.color=ok?"#115511":"#661111"; };
  document.addEventListener("DOMContentLoaded", () => document.body.appendChild(badge));

  async function getJSON(p){ const r=await fetch(p,{credentials:"include"}); let j={}; try{ j=await r.json(); }catch{} return [r,j]; }

  async function loadAppliedMap() {
    try {
      const [whoRes, who] = await getJSON(`${API_BASE}/api/whoami`);
      if (!whoRes.ok || !who?.userId) { setBadge("Auth: not signed in", false); return {}; }
      const [res, data] = await getJSON(`${API_BASE}/api/state`);
      if (!res.ok) { setBadge(`GET ${res.status}`, false); return {}; }
      setBadge("Sync: ready"); return data.applied || {};
    } catch { setBadge("Sync: error", false); return {}; }
  }

  async function saveApplied(jobId, applied) {
    try {
      const r = await fetch(`${API_BASE}/api/state`, {
        method:"POST", credentials:"include",
        headers:{ "Content-Type":"application/json" },
        body: JSON.stringify({ jobId, applied })
      });
      if (!r.ok) setBadge(`Save ${r.status}`, false);
      else { setBadge("Saved"); setTimeout(()=>setBadge("Sync: ready"), 1000); }
    } catch { setBadge("Save error", false); }
  }

  function reflect(el, value) {
    if (el.matches('input[type="checkbox"]')) {
      el.checked = !!value;
    } else {
      el.classList.toggle("is-applied", !!value);
      el.setAttribute("aria-pressed", !!value);
      if (!el.dataset.labelBase) el.dataset.labelBase = el.textContent.trim() || "Applied";
      el.textContent = (!!value ? "✅ " : "⬜ ") + el.dataset.labelBase;
    }
  }

  function wire(el, appliedMap) {
    if (el.__wired) return;
    el.__wired = true;
    const id = el.getAttribute("data-job-id");
    reflect(el, appliedMap[id]?.applied);
    const handler = () => {
      const isOn = el.matches('input[type="checkbox"]') ? el.checked : el.classList.contains("is-applied");
      const next = !isOn;
      reflect(el, next);
      saveApplied(id, next);
    };
    if (el.matches('input[type="checkbox"]')) {
      el.addEventListener("change", handler);
    } else {
      el.addEventListener("click", handler);
      el.setAttribute("role", "button");
      el.setAttribute("tabindex", "0");
      el.addEventListener("keydown", (e)=>{ if (e.key === " " || e.key === "Enter") { e.preventDefault(); handler(); } });
    }
  }

  function scan(appliedMap) {
    document.querySelectorAll(TOGGLE_SEL).forEach(el => wire(el, appliedMap));
  }

  async function init() {
    const appliedMap = await loadAppliedMap();
    scan(appliedMap);
    new MutationObserver(() => scan(appliedMap)).observe(document.body, {childList:true, subtree:true});
  }

  document.readyState === "loading" ? document.addEventListener("DOMContentLoaded", init) : init();
})();
