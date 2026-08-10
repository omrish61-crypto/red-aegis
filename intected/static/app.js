/* INTECTED SPA — read-only dashboard over the mission DB. */
"use strict";

const TOKEN = new URLSearchParams(location.search).get("token") || "";
let state = { missions: [], missionId: null, bundle: null };

const $ = (id) => document.getElementById(id);

async function api(path) {
  const res = await fetch(path + (TOKEN ? (path.includes("?") ? "&" : "?") + "token=" + TOKEN : ""), {
    headers: { "X-INTECTED-Token": TOKEN },
  });
  if (res.status === 401) throw new Error("unauthorized — bad token");
  if (!res.ok) throw new Error("HTTP " + res.status);
  return res.json();
}

function esc(s) {
  return String(s ?? "").replace(/[&<>"']/g, (c) =>
    ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
}

function badge(label) {
  return `<span class="badge ${esc(label)}">${esc(label)}</span>`;
}

async function loadMissions() {
  const missions = await api("/api/missions");
  state.missions = missions;
  const sel = $("mission-select");
  sel.innerHTML = missions.map((m) =>
    `<option value="${m.id}">#${m.id} ${esc(m.name)} (${esc(m.status)})</option>`).join("");
  if (!state.missionId && missions.length) state.missionId = missions[0].id;
  sel.value = state.missionId;
  sel.onchange = () => { state.missionId = Number(sel.value); refresh(); };
}

async function loadBundle() {
  if (!state.missionId) return;
  state.bundle = await api("/api/missions/" + state.missionId);
  render();
}

function renderTask(node, isRoot) {
  const cls = isRoot ? "node root" : "node";
  let html = `<div class="${cls}">${badge(node.status)} <strong>${esc(node.title)}</strong>
    <span style="color:var(--muted)">· ${esc(node.category)}</span></div>`;
  (node.children || []).forEach((c) => { html += renderTask(c, false); });
  return html;
}

function render() {
  const b = state.bundle;
  if (!b) return;
  $("conn").textContent = "connected";
  $("conn").className = "pill ok";

  // Process — task tree
  const byId = {};
  b.tasks.forEach((t) => { byId[t.id] = { ...t, children: [] }; });
  const roots = [];
  b.tasks.forEach((t) => {
    const node = byId[t.id];
    if (t.parent_id && byId[t.parent_id]) byId[t.parent_id].children.push(node);
    else roots.push(node);
  });
  $("task-tree").innerHTML = roots.map((r) => renderTask(r, true)).join("") ||
    '<div style="color:var(--muted)">no tasks yet</div>';
  $("task-count").textContent = `(${b.tasks.length})`;

  // Command queue
  $("cmd-table").querySelector("tbody").innerHTML = [...b.commands].reverse().map((c) =>
    `<tr><td>${c.id}</td><td>${badge(c.state)}</td>
     <td class="mono">${esc(c.cmd)}</td><td>${c.task_id ?? ""}</td></tr>`).join("") ||
    '<tr><td colspan="4" style="color:var(--muted)">no commands yet</td></tr>';

  // Timeline
  $("audit-list").innerHTML = b.audit.map((a) =>
    `<li><span class="ts">${esc(a.ts)}</span> <span class="act">${esc(a.action)}</span> ${esc(a.detail)}</li>`).join("");

  // Results — facts
  $("fact-count").textContent = `(${b.stats.facts_total})`;
  $("fact-table").querySelector("tbody").innerHTML = [...b.facts].reverse().map((f) =>
    `<tr><td>${f.id}</td><td>${esc(f.tool)}</td><td>${badge(f.fact_type)}</td>
     <td class="mono">${esc(JSON.stringify(f.value)).slice(0, 140)}</td>
     <td>${f.confidence}</td>
     <td><button class="btn" onclick="showEvidence(${f.id})">evidence</button></td></tr>`).join("") ||
    '<tr><td colspan="6" style="color:var(--muted)">no facts yet — paste tool output to start</td></tr>';

  // Mission
  const m = b.mission;
  let hosts = [];
  try { hosts = JSON.parse(m.allowed_hosts_json); } catch (e) {}
  renderTargets(hosts);
  renderScanAssignments(b.tasks, hosts);
  $("mission-dl").innerHTML =
    `<dt>id</dt><dd>${m.id}</dd><dt>name</dt><dd>${esc(m.name)}</dd>
     <dt>status</dt><dd>${esc(m.status)}</dd>
     <dt>auth ref</dt><dd>${esc(m.auth_ref || "—")}</dd>
     <dt>created</dt><dd>${esc(m.created_at)}</dd>`;
  const cards = [
    ["tasks", b.stats.tasks.completed || 0, "completed"],
    ["tasks", (b.stats.tasks.in_progress || 0), "in progress"],
    ["tasks", (b.stats.tasks.pending || 0), "pending"],
    ["tasks", (b.stats.tasks.failed || 0) + (b.stats.tasks.blocked || 0), "failed/blocked"],
    ["facts", b.stats.facts_total, "facts (evidence-linked)"],
    ["commands", (b.stats.commands.approved || 0) + (b.stats.commands.ran || 0), "approved/ran"],
    ["commands", b.stats.commands.rejected || 0, "rejected"],
  ];
  $("stat-cards").innerHTML = cards.map(([l, n, label]) =>
    `<div class="stat"><div class="n">${n}</div><div class="l">${label}</div></div>`).join("");
}

async function showEvidence(factId) {
  try {
    const ev = await api(`/api/missions/${state.missionId}/evidence/${factId}`);
    $("modal-title").textContent = `Evidence — fact #${ev.fact_id} (${ev.fact_type})`;
    $("modal-sha").textContent = `sha256 ${ev.sha256}  ·  ${ev.matches ? "✓ verified on disk" : "✗ HASH MISMATCH"}  ·  ${ev.evidence_path}`;
    $("modal-sha").style.color = ev.matches ? "var(--ok)" : "var(--err)";
    $("modal-content").textContent = ev.content;
    $("modal").classList.remove("hidden");
  } catch (e) { alert("evidence error: " + e.message); }
}

$("modal-close").onclick = () => $("modal").classList.add("hidden");
$("modal").onclick = (e) => { if (e.target === $("modal")) $("modal").classList.add("hidden"); };

document.querySelectorAll(".tab").forEach((t) => {
  t.onclick = () => {
    document.querySelectorAll(".tab").forEach((x) => x.classList.remove("active"));
    document.querySelectorAll(".view").forEach((x) => x.classList.remove("active"));
    t.classList.add("active");
    $("view-" + t.dataset.tab).classList.add("active");
    if (t.dataset.tab === "plan") loadPlan();
  };
});

document.addEventListener("DOMContentLoaded", () => {
  const form = document.getElementById("target-form");
  if (form) form.addEventListener("submit", addTarget);
  const start = document.getElementById("start-test");
  if (start) start.addEventListener("click", startTest);
});

function showAuthError() {
  $("conn").textContent = "auth error";
  $("conn").className = "pill err";
  const b = $("auth-banner");
  if (b) b.classList.remove("hidden");
}

function renderTargets(hosts) {
  $("scope-chips").innerHTML = (hosts && hosts.length)
    ? hosts.map((h) =>
        `<span class="scope-chip">${esc(h)}<button class="chip-x" title="remove ${esc(h)}" data-target="${esc(h)}">✕</button></span>`).join("")
    : '<span style="color:var(--muted)">no targets yet — add an IP, domain, or IP range</span>';
  const start = $("start-test");
  if (start) start.disabled = !(hosts && hosts.length);
  document.querySelectorAll(".chip-x").forEach((b) => {
    b.onclick = () => removeTarget(b.dataset.target);
  });
}

async function removeTarget(target) {
  const msg = $("target-msg");
  msg.textContent = "";
  const missionId = document.querySelector("#mission-select").value;
  if (!missionId) { msg.textContent = "select a mission first"; return; }
  const token = new URLSearchParams(window.location.search).get("token") || "";
  try {
    const res = await fetch(
      `/api/missions/${missionId}/targets?target=${encodeURIComponent(target)}`, {
        method: "DELETE",
        headers: { "X-INTECTED-Token": token },
      });
    const data = await res.json().catch(() => ({}));
    if (!res.ok) { msg.textContent = data.detail || `error ${res.status}`; return; }
    renderTargets(data.scope);
    msg.textContent = `removed ${data.target}`;
    msg.className = "target-msg ok";
  } catch (e) {
    msg.textContent = "request failed: " + e.message;
  }
}

function renderScanAssignments(tasks, hosts) {
  const PREFIX = "Run penetration test against ";
  const inScope = new Set(hosts || []);
  const rows = tasks
    .filter((t) => t.title && t.title.startsWith(PREFIX))
    .map((t) => ({ target: t.title.slice(PREFIX.length), task: t.title, status: t.status }))
    .filter((r) => inScope.has(r.target))  // only current-scope targets
    .sort((a, b) => a.target.localeCompare(b.target));
  const tbody = document.querySelector("#scan-assign tbody");
  if (!tbody) return;
  tbody.innerHTML = rows.length
    ? rows.map((r) =>
        `<tr><td class="mono">${esc(r.target)}</td><td>${esc(r.task)}</td><td>${badge(r.status)}</td></tr>`).join("")
    : '<tr><td colspan="3" style="color:var(--muted)">no scan tasks yet — add targets and click Start test</td></tr>';
}

async function startTest(ev) {
  ev.preventDefault();
  const msg = $("target-msg");
  msg.textContent = "";
  const missionId = document.querySelector("#mission-select").value;
  if (!missionId) { msg.textContent = "select a mission first"; return; }
  const token = new URLSearchParams(window.location.search).get("token") || "";
  try {
    const res = await fetch(`/api/missions/${missionId}/start`, {
      method: "POST",
      headers: { "X-INTECTED-Token": token },
    });
    const data = await res.json().catch(() => ({}));
    if (!res.ok) { msg.textContent = data.detail || `error ${res.status}`; return; }
    if (data.tasks_created > 0) {
      msg.textContent = `test started — ${data.tasks_created} scan task(s) created for ${data.targets.length} target(s) (see scan assignments below)`;
    } else {
      msg.textContent = `all ${data.targets.length} target(s) already have scan task(s) — see scan assignments below (${data.tasks_existing || 0} present)`;
    }
    msg.className = "target-msg ok";
    await loadBundle();
  } catch (e) {
    msg.textContent = "request failed: " + e.message;
  }
}

async function addTarget(ev) {
  ev.preventDefault();
  const input = $("target-input");
  const msg = $("target-msg");
  const value = input.value.trim();
  msg.textContent = "";
  if (!value) { msg.textContent = "enter a target first"; return; }
  const missionId = document.querySelector("#mission-select").value;
  if (!missionId) { msg.textContent = "select a mission first"; return; }
  // token lives in the page URL (?token=…) — GETs use the query param, POSTs
  // must forward it explicitly (never rely on Referer)
  const token = new URLSearchParams(window.location.search).get("token") || "";
  try {
    const res = await fetch(`/api/missions/${missionId}/targets`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "X-INTECTED-Token": token,
      },
      body: JSON.stringify({ target: value }),
    });
    const data = await res.json().catch(() => ({}));
    if (!res.ok) { msg.textContent = data.detail || `error ${res.status}`; return; }
    renderTargets(data.scope);
    msg.textContent = `added ${data.target}`;
    msg.className = "target-msg ok";
    input.value = "";
  } catch (e) {
    msg.textContent = "request failed: " + e.message;
  }
}

async function loadPlan() {
  const missionId = document.querySelector("#mission-select").value;
  if (!missionId) return;
  const token = new URLSearchParams(window.location.search).get("token") || "";
  try {
    const res = await fetch(`/api/missions/${missionId}/plan`, {
      headers: { "X-INTECTED-Token": token },
    });
    if (!res.ok) { $("plan-graph").textContent = "plan unavailable (" + res.status + ")"; return; }
    const data = await res.json();
    const g = data.graph, p = data.plan;
    const services = g.services.map((s) =>
      `<span class="scope-chip">${s.port}/${s.protocol}${s.banner ? " " + esc(s.banner.split(" ")[0]) : ""}</span>`).join("");
    const techs = g.technologies.map((t) =>
      `<span class="scope-chip">${esc(t.name)} ${(t.confidence * 100).toFixed(0)}%</span>`).join("");
    $("plan-graph").innerHTML =
      `<dl class="plan-dl">
        <dt>target</dt><dd class="mono">${esc(p.target)}</dd>
        <dt>branch</dt><dd>${esc(p.branch)}</dd>
        <dt>services</dt><dd>${services || "—"}</dd>
        <dt>technologies</dt><dd>${techs || "—"}</dd>
        <dt>waf</dt><dd>${g.waf.detected ? "detected (" + g.waf.confidence.toFixed(2) + ")" : "no indicators"}</dd>
        <dt>attack surface</dt><dd>${g.attack_surface.map((x) => `<span class="scope-chip">${esc(x)}</span>`).join("") || "—"}</dd>
       </dl>`;
    $("plan-items").innerHTML = p.plan.map((item) =>
      `<div class="plan-item">
        <div class="plan-rank">P${item.rank}</div>
        <div>
          <strong>${esc(item.area)}</strong>
          <div class="muted">${esc(item.hypothesis)}</div>
          ${item.commands.length ? `<div class="mono small">${esc(item.commands[0])}</div>` : ""}
        </div>
      </div>`).join("") || '<div style="color:var(--muted)">no plan yet — gather evidence first</div>';
  } catch (e) {
    $("plan-graph").textContent = "plan error: " + e.message;
  }
}

async function tick() {
  try {
    await loadBundle();
    if (document.querySelector("#view-plan").classList.contains("active")) await loadPlan();
  } catch (e) {
    $("conn").textContent = "error: " + e.message;
    $("conn").className = "pill err";
    if (/unauthorized/i.test(e.message || "")) showAuthError();
  }
}

(async function init() {
  try {
    await loadMissions();
  } catch (e) {
    showAuthError();
    return;
  }
  await tick();
  setInterval(tick, 3000);
})();
