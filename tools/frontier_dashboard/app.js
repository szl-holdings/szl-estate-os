"use strict";
(() => {
  const data = JSON.parse(document.getElementById("inventory").textContent);
  const $ = (id) => document.getElementById(id);
  const set = (id, text) => { $(id).textContent = String(text); };
  const n = (value) => new Intl.NumberFormat("en-US").format(value);
  const time = (value) => { const d = new Date(value); return Number.isNaN(d.valueOf()) ? "Timestamp unavailable" : d.toISOString().replace("T", " ").replace(/\.\d+Z$/, " UTC"); };
  const c = data.counts; set("snapshot-day", time(data.snapshots.huggingface));
  set("github-count", n(c.github)); set("hf-count", n(c.huggingface)); set("local-count", n(c.local));
  set("github-sub", `${n(c.github - c.github_private)} public · ${n(c.github_private)} private observed`);
  set("hf-sub", `${c.models} models · ${c.datasets} datasets · ${c.spaces} Spaces`);
  set("local-sub", `${n(c.local)} of ${n(c.local_discovered)} discovered Git roots`);
  set("coverage-brief", `${c.workflow_unavailable} GitHub workflow inventories unavailable. ${c.local_dirty} sampled checkouts have tracked changes. Provider hosting states remain separate from application readiness.`);
  set("snapshot-range", `Hugging Face collection completed ${time(data.snapshots.huggingface)}`);
  set("github-coverage", `${c.github} repositories observed; consult the inventory coverage record for count reconciliation. ${c.github_private} are private. Workflow enumeration is unavailable for ${c.workflow_unavailable} repositories; consult source errors for the reason.`);
  set("hf-coverage", `${c.huggingface} credential-visible repositories and ${c.collections} collections enumerated. The registry table covers repository records; collections are counted separately. Inaccessible assets remain unknown.`);
  set("local-coverage", `${n(c.local)} of ${n(c.local_discovered)} discovered Git roots received metadata inspection. ${c.local_dirty} have tracked changes. These checkouts may duplicate remote repository records.`);
  for (const key of ["github", "hf", "local"]) set(key + "-time", "Snapshot: " + time(data.snapshots[key === "hf" ? "huggingface" : key]));
  for (const [name, hash] of Object.entries(data.digests)) { const dt = document.createElement("dt"), dd = document.createElement("dd"); dt.textContent = name; dd.textContent = hash; $("hashes").append(dt, dd); }
  let dark = window.matchMedia && window.matchMedia("(prefers-color-scheme: dark)").matches;
  function theme() { document.documentElement.dataset.theme = dark ? "dark" : "light"; $("theme").setAttribute("aria-pressed", String(dark)); set("theme", dark ? "Light mode" : "Dark mode"); }
  theme(); $("theme").addEventListener("click", () => { dark = !dark; theme(); });
  let page = 0; const pageSize = 20;
  const labels = {"OBSERVED_METADATA":"Observed metadata", "MEASURED_LOCAL_METADATA":"Local metadata", "UNAVAILABLE":"Unavailable", "NOT_APPLICABLE":"Not applicable", "UNVERIFIED":"Unverified", "RUNNING":"Provider running", "SLEEPING":"Provider sleeping"};
  function pill(value, kind) { const el = document.createElement("span"); el.className = "pill" + (kind === "evidence" ? " observed" : ["RUNNING", "SLEEPING"].includes(value) ? " attention" : ""); el.textContent = labels[value] || value; el.title = value; return el; }
  function factList(target, values) { target.replaceChildren(); for (const [key, value] of Object.entries(values)) { const dt = document.createElement("dt"), dd = document.createElement("dd"); dt.textContent = key; dd.textContent = value == null ? "UNAVAILABLE" : String(value); target.append(dt, dd); } }
  function sourceLink(value, label) { if (!value) return; let parsed; try { parsed = new URL(value); } catch { return; } if (parsed.protocol !== "https:" || !["github.com", "huggingface.co"].includes(parsed.hostname) || parsed.username || parsed.password) return; const a = document.createElement("a"); a.href = parsed.href; a.textContent = label + " ↗"; a.target = "_blank"; a.rel = "noopener noreferrer"; a.setAttribute("aria-label", label + " (opens a new tab)"); $("source-links").append(a); }
  function openDetails(asset) {
    set("detail-platform", asset.platform + " / " + asset.type);
    set("detail-title", asset.name);
    set("detail-note", `${asset.owner} · ${asset.visibility.toLowerCase()} · observed ${time(asset.timestamp)}`);
    $("detail-states").replaceChildren();
    for (const [title, field] of [["Evidence", "evidence"], ["Provider runtime", "runtime"], ["Authorization", "authorization"], ["Signer state", "signer"]]) {
      const cell = document.createElement("div"), label = document.createElement("span"); cell.className = "state-cell"; label.className = "small-label"; label.textContent = title; cell.append(label, pill(asset[field], field)); $("detail-states").append(cell);
    }
    factList($("identity-facts"), {"Canonical source": asset.source || "UNAVAILABLE", "Exact revision": asset.revision, "Branch / ref": asset.branch, "Application readiness": asset.readiness});
    $("source-links").replaceChildren(); sourceLink(asset.source, "Open canonical source"); sourceLink(asset.revisionSource, "Inspect exact revision");
    factList($("facts"), asset.facts); $("notices").replaceChildren();
    for (const notice of asset.notices.length ? asset.notices : ["No specific notice was recorded by this bounded collector. Unverified states still apply."]) { const li = document.createElement("li"); li.textContent = notice; $("notices").append(li); }
    set("detail-limit", asset.limit); $("detail").showModal(); $("detail").scrollTop = 0; $("close-detail").focus();
  }
  $("close-detail").addEventListener("click", () => $("detail").close());
  function match(asset) { const query = $("search").value.trim().toLowerCase(); if ($("platform").value && asset.platform !== $("platform").value) return false; if ($("type").value && asset.type !== $("type").value) return false; if (query && ![asset.name, asset.owner, asset.revision, asset.branch, asset.facts["Local path"] || ""].some(s => s.toLowerCase().includes(query))) return false; const a = $("attention").value; if (a === "notices" && !asset.notices.length) return false; if (a === "dirty" && !(asset.platform === "Local" && Number(asset.facts["Tracked changes"]) > 0)) return false; if (a === "runtime" && asset.runtime !== "RUNNING") return false; return true; }
  function render() {
    const filtered = data.assets.filter(match); const pages = Math.max(1, Math.ceil(filtered.length / pageSize)); page = Math.min(page, pages - 1); const shown = filtered.slice(page * pageSize, (page + 1) * pageSize); $("rows").replaceChildren();
    for (const asset of shown) {
      const tr = document.createElement("tr"), name = document.createElement("td"), button = document.createElement("button"), meta = document.createElement("div"), dot = document.createElement("span"), metaText = document.createElement("span");
      button.type = "button"; button.className = "asset-button"; button.textContent = asset.name; button.setAttribute("aria-haspopup", "dialog"); button.setAttribute("aria-label", `Inspect ${asset.name}, ${asset.platform} ${asset.type}`); button.addEventListener("click", () => openDetails(asset)); meta.className = "asset-meta"; dot.className = "source-dot " + asset.platform.toLowerCase().replaceAll(" ", ""); dot.setAttribute("aria-hidden", "true"); metaText.textContent = `${asset.platform} · ${asset.type}`; meta.append(dot, metaText); name.append(button, meta); tr.append(name);
      for (const field of ["evidence", "runtime", "authorization", "signer"]) { const td = document.createElement("td"); td.append(pill(asset[field], field)); tr.append(td); }
      const revision = document.createElement("td"), code = document.createElement("code"); code.className = "mono"; code.textContent = /^[a-f0-9]{40}$/.test(asset.revision) ? asset.revision.slice(0, 9) : asset.revision; code.title = asset.revision; revision.append(code); tr.append(revision); $("rows").append(tr);
    }
    set("results", `${n(filtered.length)} matching observations · ${n(data.assets.length)} total records across three sources`);
    set("page-label", filtered.length ? `Showing ${page * pageSize + 1}–${Math.min((page + 1) * pageSize, filtered.length)} of ${n(filtered.length)}` : "0 matching records");
    $("empty").hidden = filtered.length > 0; $("previous").disabled = page === 0; $("next").disabled = page >= pages - 1;
  }
  function reset() { for (const id of ["search", "platform", "type", "attention"]) $(id).value = ""; page = 0; render(); }
  for (const id of ["search", "platform", "type", "attention"]) $(id).addEventListener(id === "search" ? "input" : "change", () => { page = 0; render(); });
  $("reset").addEventListener("click", reset); $("empty-reset").addEventListener("click", () => { reset(); $("search").focus(); });
  $("previous").addEventListener("click", () => { page--; render(); }); $("next").addEventListener("click", () => { page++; render(); });
  for (const button of document.querySelectorAll("[data-platform]")) button.addEventListener("click", () => { reset(); $("platform").value = button.dataset.platform; render(); $("registry").scrollIntoView({block:"start"}); $("search").focus({preventScroll:true}); });
  render();
})();
