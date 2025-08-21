// sync-applied.js
// Plug this into jobs.html AFTER your main rendering logic.
// Requirements:
//   - Each job's "Applied" checkbox must have: class="applied-toggle" and data-job-id="<job.id>"
//   - jobs.json MUST include an "id" field per job (update_html.py in this package does that).

(function () {
  const API_BASE = (window.JOB_TRACKER_API_BASE || "https://YOUR-WORKER-SUBDOMAIN.workers.dev").replace(/\/+$/, "")

  async function loadAppliedMap() {
    try {
      const resp = await fetch(`${API_BASE}/api/state`, { credentials: "include" })
      if (!resp.ok) return {}
      const data = await resp.json()
      return data.applied || {}
    } catch (e) {
      console.error("Failed to load applied map", e)
      return {}
    }
  }

  async function saveApplied(jobId, applied) {
    try {
      await fetch(`${API_BASE}/api/state`, {
        method: "POST",
        credentials: "include",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ jobId, applied }),
      })
    } catch (e) {
      console.error("Failed to save applied state", e)
    }
  }

  function applyToDOM(appliedMap) {
    document.querySelectorAll('input.applied-toggle[type="checkbox"][data-job-id]').forEach(chk => {
      const jobId = chk.getAttribute("data-job-id")
      if (!jobId) return
      const v = appliedMap[jobId]?.applied
      if (typeof v === "boolean") {
        chk.checked = v
      }
      // Ensure change handler is wired once
      if (!chk.__appliedSyncBound) {
        chk.addEventListener("change", (e) => {
          saveApplied(jobId, !!e.target.checked)
        })
        chk.__appliedSyncBound = true
      }
    })
  }

  async function init() {
    const map = await loadAppliedMap()
    applyToDOM(map)

    // If your app re-renders dynamically, observe mutations and re-apply mapping
    const mo = new MutationObserver(() => applyToDOM(map))
    mo.observe(document.body, { childList: true, subtree: true })
  }

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", init)
  } else {
    init()
  }
})();
