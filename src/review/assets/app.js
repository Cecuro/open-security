(() => {
  "use strict";

  const snapshot = window.__OPENSEC_SNAPSHOT__ || null;
  const token = document.querySelector('meta[name="opensec-token"]')?.content || "";
  const state = {
    scans: [], detail: null, scanId: null, findingId: null,
    view: "runs", search: "", severity: "all", status: "all",
    runSearch: "", runStatus: "all", runRepo: "all", runSeverity: "all",
    filtersOpen: false, runFiltersOpen: false, drafts: {},
  };
  let loadSequence = 0;
  let toastTimer;
  const main = () => document.getElementById("main");
  const sidebar = () => document.getElementById("sidebar");

  if (document.readyState === "loading") document.addEventListener("DOMContentLoaded", init);
  else init();

  async function init() {
    bindGlobalEvents();
    try {
      const params = new URLSearchParams(location.search);
      const initialView = params.get("view") === "findings" ? "findings" : "runs";
      if (snapshot) {
        state.detail = snapshot;
        state.scanId = snapshot.scan.id;
        state.scans = [summaryFromDetail(snapshot)];
        state.view = initialView;
        state.findingId = firstVisibleFinding()?.id || snapshot.candidates[0]?.id || null;
        renderAll();
        return;
      }

      state.scans = await api("/api/scans");
      if (!state.scans.length) return renderNoScans();
      const requested = params.get("scan");
      const defaultScan = state.scans.find(scan => (scan.reviewable_count ?? scan.finding_count ?? 0) > 0) || state.scans[0];
      const scanId = state.scans.some(scan => scan.id === requested) ? requested : defaultScan.id;
      await openRun(scanId, initialView, false);
      replaceUrl();
    } catch (error) {
      renderError(error);
    }
  }

  function bindGlobalEvents() {
    document.addEventListener("click", async event => {
      const button = event.target.closest("button");
      if (!button) {
        if (!event.target.closest(".export-wrap")) closeExport();
        if (!event.target.closest(".select-menu")) closeSelectMenus();
        return;
      }

      const action = button.dataset.action;
      if (action === "view-runs") setView("runs");
      else if (action === "view-findings") setView("findings");
      else if (action === "mobile-back") document.body.classList.remove("detail-open");
      else if (action === "toggle-filters") toggleFilters(button);
      else if (action === "toggle-run-filters") toggleRunFilters(button);
      else if (action === "clear-filters") clearFindingFilters();
      else if (action === "clear-run-filters") clearRunFilters();
      else if (action === "toggle-export") toggleExport(button);
      else if (action === "toggle-select-menu") toggleSelectMenu(button);
      else if (action === "select-option") await chooseSelectOption(button);
      else if (action === "add-comment") await addComment();
      else if (action === "copy-threat-model") await copyText(state.detail?.threatModel || "", "Threat model copied");
      else if (action === "copy-finding-description") await copyText(currentFinding()?.description || "", "Finding description copied");
      else if (button.dataset.runId) {
        await openRun(button.dataset.runId, "runs");
        if (window.matchMedia("(max-width: 680px)").matches) document.body.classList.add("detail-open");
      } else if (button.dataset.findingId) selectFinding(button.dataset.findingId);
      else if (button.dataset.export) await exportData(button.dataset.export);

      if (!button.closest(".export-wrap") && action !== "toggle-export") closeExport();
      if (!button.closest(".select-menu") && action !== "toggle-select-menu") closeSelectMenus();
    });

    document.addEventListener("input", event => {
      const target = event.target;
      if (target.id === "run-search") { state.runSearch = target.value; renderRunResults(); }
      else if (target.id === "search") {
        state.search = target.value;
        ensureVisibleSelection();
        renderFindingResults();
        renderMain();
      } else if (target.id === "comment" && state.findingId) {
        state.drafts[state.findingId] = target.value;
      }
    });

    document.addEventListener("keydown", event => {
      const trigger = event.target.closest?.(".select-trigger");
      const option = event.target.closest?.(".select-option");
      if (trigger && (event.key === "ArrowDown" || event.key === "ArrowUp")) {
        event.preventDefault();
        openSelectMenu(trigger, event.key === "ArrowUp");
        return;
      }
      if (option && ["ArrowDown", "ArrowUp", "Home", "End"].includes(event.key)) {
        event.preventDefault();
        moveSelectFocus(option, event.key);
        return;
      }
      if ((event.metaKey || event.ctrlKey) && event.key === "k" && state.view === "findings") {
        event.preventDefault();
        document.getElementById("search")?.focus();
      }
      if (event.key === "Escape") {
        closeExport();
        const menu = event.target.closest?.(".select-menu");
        if (menu) menu.querySelector(".select-trigger")?.focus();
        closeSelectMenus();
        document.body.classList.remove("detail-open");
      }
    });
  }

  async function openRun(scanId, view = state.view, updateUrl = true) {
    const request = ++loadSequence;
    try {
      const detail = snapshot && snapshot.scan.id === scanId
        ? snapshot
        : await api(`/api/scans/${encodeURIComponent(scanId)}`);
      if (request !== loadSequence) return;

      const keepFinding = state.scanId === scanId && detail.candidates.some(candidate => candidate.id === state.findingId);
      state.scanId = scanId;
      state.detail = detail;
      state.view = view;
      state.findingId = keepFinding ? state.findingId : firstVisibleFinding()?.id || detail.candidates[0]?.id || null;
      const summaryIndex = state.scans.findIndex(scan => scan.id === scanId);
      if (summaryIndex >= 0) state.scans[summaryIndex] = summaryFromDetail(detail);
      document.body.classList.remove("detail-open");
      if (updateUrl && !snapshot) replaceUrl();
      renderAll();
    } catch (error) {
      if (request === loadSequence) renderError(error, false);
    }
  }

  function setView(view) {
    if (!state.detail) return;
    state.view = view;
    if (view === "findings") ensureVisibleSelection();
    document.body.classList.remove("detail-open");
    replaceUrl();
    renderAll();
  }

  function selectFinding(id) {
    state.findingId = id;
    document.body.classList.add("detail-open");
    renderFindingResults();
    renderMain();
    if (window.matchMedia("(max-width: 680px)").matches) main().querySelector("h1")?.focus?.();
  }

  function renderAll() {
    document.body.dataset.view = state.view;
    renderHeader();
    renderSidebar();
    renderMain();
  }

  function renderHeader() {
    document.querySelectorAll(".primary-nav button").forEach(button => {
      const active = button.dataset.action === `view-${state.view}`;
      button.classList.toggle("active", active);
      if (active) button.setAttribute("aria-current", "page");
      else button.removeAttribute("aria-current");
    });
    document.querySelector(".export-wrap").hidden = !state.detail || !!snapshot;
  }

  function renderSidebar() {
    if (!state.detail) return;
    if (state.view === "runs") renderRunsSidebar();
    else renderFindingsSidebar();
  }

  function renderRunsSidebar() {
    const repos = [...new Set(state.scans.map(scan => scan.repo_name))].sort((a, b) => a.localeCompare(b));
    sidebar().innerHTML = `<div class="sidebar-head"><strong>Recent runs</strong><span>${state.scans.length} on this machine</span></div>
      <div class="run-sidebar-tools">
        <label class="search"><span aria-hidden="true">⌕</span><input id="run-search" type="search" value="${esc(state.runSearch)}" placeholder="Search runs" aria-label="Search runs"></label>
        <button class="icon-button" data-action="toggle-run-filters" aria-expanded="${state.runFiltersOpen}" aria-controls="run-filters">Filter</button>
      </div>
      <div id="run-filters" class="filters" ${state.runFiltersOpen ? "" : "hidden"}>
        <div class="filter-field"><span>Repository</span>${selectMenu("run-repo-filter", "Repository", [["all", "All repositories"], ...repos.map(repo => [repo, repo])], state.runRepo)}</div>
        <div class="filter-field"><span>Severity</span>${selectMenu("run-severity-filter", "Severity", [["all", "Any severity"], ...["critical", "high", "medium", "low"].map(value => [value, label(value)])], state.runSeverity)}</div>
        <div class="filter-field"><span>Status</span>${selectMenu("run-status-filter", "Status", [["all", "Any status"], ["completed", "Completed"], ["running", "Running"], ["failed", "Failed"]], state.runStatus)}</div>
      </div>
      <div class="list-meta"><span id="run-count"></span><button data-action="clear-run-filters">Clear</button></div>
      <nav id="run-sidebar-list" class="run-sidebar-list" aria-label="Recent runs"></nav>`;
    renderRunResults();
  }

  function renderRunResults() {
    const container = document.getElementById("run-sidebar-list");
    if (!container) return;
    const runs = visibleRuns();
    document.getElementById("run-count").textContent = `${runs.length} ${runs.length === 1 ? "run" : "runs"}`;
    document.querySelector('[data-action="clear-run-filters"]').hidden = !hasRunFilters();
    container.innerHTML = runs.length ? runs.map(scan => {
      const status = displayRunStatus(scan);
      const result = compactSeveritySummary(scan.severity_counts || {});
      return `<button class="run-sidebar-row" data-run-id="${esc(scan.id)}" aria-current="${scan.id === state.scanId}">
        <span class="run-sidebar-title"><strong>${esc(scan.repo_name)}</strong><span class="status-label ${status.className}">${status.label}</span></span>
        <span class="run-sidebar-meta">${shortDateTime(scan.started_at)} · ${esc(shortHash(scan.revision))}</span>
        ${result ? `<span class="run-sidebar-result">${result}</span>` : ""}
      </button>`;
    }).join("") : `<div class="empty-list">No runs match this search.</div>`;
  }

  function renderFindingsSidebar() {
    sidebar().innerHTML = `<div class="sidebar-head"><strong>Findings</strong>
        ${selectMenu("run-picker", "Selected run", state.scans.map(scan => [scan.id, `${scan.repo_name} · ${shortDateTime(scan.started_at)}`]), state.scanId, "run-picker-menu")}
      </div>
      <div class="filter-bar"><label class="search"><span aria-hidden="true">⌕</span><input id="search" type="search" value="${esc(state.search)}" placeholder="Search findings" aria-label="Search findings"></label><button class="icon-button" data-action="toggle-filters" aria-expanded="${state.filtersOpen}" aria-controls="filters">Filter</button></div>
      <div id="filters" class="filters" ${state.filtersOpen ? "" : "hidden"}>
        <div class="filter-field"><span>Severity</span>${selectMenu("severity-filter", "Severity", [["all", "All severities"], ...["critical", "high", "medium", "low", "info"].map(value => [value, label(value)])], state.severity)}</div>
        <div class="filter-field"><span>State</span>${selectMenu("state-filter", "State", [["all", "All states"], ...["open", "confirmed", "needs_follow_up", "suppressed", "not_applicable", "duplicate"].map(value => [value, findingStateLabel(value)])], state.status)}</div>
      </div>
      <div class="list-meta"><span id="result-count"></span><button data-action="clear-filters">Clear</button></div>
      <nav id="finding-list" class="finding-list" aria-label="Findings"></nav>`;
    renderFindingResults();
  }

  function renderFindingResults() {
    const container = document.getElementById("finding-list");
    if (!container) return;
    const candidates = visibleFindings();
    document.getElementById("result-count").textContent = `${candidates.length} ${candidates.length === 1 ? "result" : "results"}`;
    document.querySelector('[data-action="clear-filters"]').hidden = !hasFindingFilters();
    container.innerHTML = candidates.length ? candidates.map(candidate => {
      const severity = severityOf(candidate);
      return `<button class="finding-row" data-finding-id="${esc(candidate.id)}" aria-current="${candidate.id === state.findingId}" style="--severity:${severityColor(severity)}">
        <span class="signal-rail" aria-hidden="true"></span>
        <span><span class="finding-row-title">${esc(candidate.title)}</span><span class="finding-row-meta"><span>${label(severity)}</span><span class="state-dot"></span><span>${findingStateLabel(candidate.status)}</span><code>${esc(candidate.id)}</code></span></span>
      </button>`;
    }).join("") : `<div class="empty-list">No findings match this view.${hasFindingFilters() ? `<button class="secondary-button" data-action="clear-filters">Clear filters</button>` : ""}</div>`;
  }

  function renderMain() {
    main().innerHTML = state.view === "runs" ? overviewView() : findingView(currentFinding());
  }

  function overviewView() {
    if (!state.detail) return "";
    const { scan, repo, coverage, threatModel, candidates } = state.detail;
    const stats = reviewStats(candidates);
    const status = displayRunStatus(scan);
    const model = scan.model_ref || scan.config?.modelRef || null;
    const duration = scan.completed_at ? formatDuration(new Date(scan.completed_at) - new Date(scan.started_at)) : null;
    const facts = [
      ["Repository", repo.name],
      model ? ["Model", model, true] : null,
      duration ? ["Duration", duration] : null,
      scan.cost_usd ? ["Cost", `$${scan.cost_usd.toFixed(2)}`] : null,
      coverage.files_in_scope ? ["Files read", `${coverage.files_touched} of ${coverage.files_in_scope}`] : null,
    ].filter(Boolean);
    return `<div class="page overview-page">
      <header class="overview-head"><div><h1>${esc(repo.name)}</h1><div class="overview-sub"><span class="status-label ${status.className}">${status.label}</span><span>·</span><span>${longDate(scan.started_at)}</span><span>·</span><code>${esc(shortHash(scan.revision))}</code></div></div><button class="primary-button" data-action="view-findings">View findings</button></header>
      <section class="run-result"><h2>Result</h2>${stats.reviewable ? `<div class="severity-line">${severityStrip(stats.counts, stats.reviewable)}</div><div class="severity-summary">${severityLabels(stats.counts)}</div>` : `<p>No reportable findings.</p>`}</section>
      <section class="run-facts"><h2>Run details</h2><dl>${facts.map(item => `<div><dt>${esc(item[0])}</dt><dd ${item[2] ? 'class="machine-value"' : ""}>${esc(item[1])}</dd></div>`).join("")}</dl></section>
      ${threatModel ? `<section class="threat-model-section"><div class="section-title"><h2>Threat model</h2><button class="copy-button" data-action="copy-threat-model" aria-label="Copy threat model" title="Copy threat model">${copyIcon()}</button></div><div class="markdown">${markdown(threatModel)}</div></section>` : ""}
    </div>`;
  }

  function findingView(candidate) {
    if (!candidate) return `<div class="main-inner"><button class="back-button" data-action="mobile-back">← Findings</button><div class="empty-list">Select a finding to review.</div></div>`;
    const severity = severityOf(candidate);
    const computed = candidate.computed;
    const locations = candidate.locations || [];
    const canChangeState = !snapshot && candidate.status !== "duplicate";
    const canComment = !snapshot;
    const activity = [...candidate.activities].reverse();
    return `<article class="main-inner" style="--severity:${severityColor(severity)}">
      <button class="back-button" data-action="mobile-back">← Findings</button>
      <header class="detail-head"><div class="eyebrow">Finding ${esc(candidate.id)}</div><h1 tabindex="-1">${esc(candidate.title)}</h1><div class="head-meta"><span class="severity-label"><span></span>${label(severity)}</span>${(candidate.cwe_ids || []).map(cwe => `<span class="chip">${esc(cwe)}</span>`).join("")}<div class="state-control"><span>State</span>${canChangeState ? stateSelect(candidate.status) : `<span class="chip">${findingStateLabel(candidate.status)}</span>`}</div></div></header>
      ${snapshot ? `<p class="status-note">This shared snapshot is read-only.</p>` : ""}
      <div class="reading"><div>
        <section class="prose-section"><div class="section-title"><h2>Summary</h2><button class="copy-button" data-action="copy-finding-description" aria-label="Copy finding description" title="Copy finding description">${copyIcon()}</button></div><div class="description">${paragraphs(candidate.description)}</div></section>
        <section class="prose-section"><h2>Locations</h2><div class="location-list">${locations.length ? locations.map(location => `<div class="location"><code>${esc(location.path)}:${location.start_line}${location.end_line !== location.start_line ? `–${location.end_line}` : ""}</code><span>${esc(label(location.role || "evidence"))}</span></div>`).join("") : `<span>No code locations recorded.</span>`}</div></section>
        ${computed?.rationale?.length ? `<section class="prose-section"><h2>Severity basis</h2><ul class="basis">${computed.rationale.map(item => `<li>${esc(item)}</li>`).join("")}</ul></section>` : ""}
        <section class="prose-section"><h2>Review history</h2><div class="activity">${activity.length ? activity.map(activityItem).join("") : `<div>No activity recorded.</div>`}</div></section>
        ${canComment ? `<div class="comment-form"><textarea id="comment" maxlength="10000" placeholder="Add review context…" aria-label="Review comment">${esc(state.drafts[candidate.id] || "")}</textarea><div class="comment-actions"><button class="primary-button" data-action="add-comment">Add comment</button></div></div>` : ""}
      </div><aside class="reading-aside">
        <section class="aside-section"><h2>Assessment</h2><dl class="fact-list"><div><dt>Confidence</dt><dd>${computed ? `${Math.round(computed.confidence * 100)}%` : "Not rated"}</dd></div><div><dt>Likelihood</dt><dd>${computed ? label(computed.likelihood) : "Not rated"}</dd></div>${computed?.proof_gap ? `<div><dt>Proof gap</dt><dd>${label(computed.proof_gap)}</dd></div>` : ""}${candidate.duplicate_of ? `<div><dt>Merged into</dt><dd><code>${esc(candidate.duplicate_of)}</code></dd></div>` : ""}</dl></section>
        <section class="aside-section"><h2>Source</h2><dl class="fact-list"><div><dt>Revision</dt><dd><code>${esc(shortHash(state.detail.scan.revision))}</code></dd></div><div><dt>Filed by</dt><dd><code>${esc(candidate.worker_id)}</code></dd></div><div><dt>Created</dt><dd>${longDate(candidate.created_at)}</dd></div></dl></section>
      </aside></div>
    </article>`;
  }

  function stateSelect(selected) {
    const options = ["open", "confirmed", "needs_follow_up", "suppressed", "not_applicable"];
    return selectMenu("state-select", "Finding state", options.map(value => [value, findingStateLabel(value)]), selected, "state-select-menu");
  }

  async function chooseSelectOption(button) {
    const id = button.dataset.selectId;
    const value = button.dataset.selectValue;
    closeSelectMenus();
    if (id === "run-picker") {
      if (value !== state.scanId) await openRun(value, "findings");
      return;
    }
    if (id === "run-status-filter") state.runStatus = value;
    else if (id === "run-repo-filter") state.runRepo = value;
    else if (id === "run-severity-filter") state.runSeverity = value;
    else if (id === "severity-filter") state.severity = value;
    else if (id === "state-filter") state.status = value;
    else if (id === "state-select") {
      await changeStatus(value);
      return;
    }
    if (id?.startsWith("run-")) renderRunsSidebar();
    else {
      ensureVisibleSelection();
      renderAll();
    }
  }

  async function changeStatus(status) {
    const candidate = currentFinding();
    if (candidate && candidate.status !== status) await saveReview({ status }, `State changed to ${findingStateLabel(status)}`);
  }

  async function saveReview(body, message) {
    const candidate = currentFinding();
    if (!candidate) return;
    try {
      const updated = await api(`/api/scans/${encodeURIComponent(state.scanId)}/candidates/${encodeURIComponent(candidate.id)}/review`, { method: "POST", body: JSON.stringify(body) });
      replaceCandidate(updated);
      ensureVisibleSelection();
      toast(message);
      renderAll();
    } catch (error) {
      renderError(error, false);
    }
  }

  async function addComment() {
    const candidate = currentFinding();
    const comment = state.drafts[candidate?.id] || document.getElementById("comment")?.value || "";
    if (!candidate || !comment.trim()) return;
    try {
      const updated = await api(`/api/scans/${encodeURIComponent(state.scanId)}/candidates/${encodeURIComponent(candidate.id)}/review`, { method: "POST", body: JSON.stringify({ comment: comment.trim() }) });
      replaceCandidate(updated);
      delete state.drafts[candidate.id];
      toast("Comment added");
      renderAll();
    } catch (error) {
      renderError(error, false);
    }
  }

  async function copyText(value, message) {
    if (!value) return;
    try {
      await navigator.clipboard.writeText(value);
    } catch {
      const textarea = document.createElement("textarea");
      textarea.value = value;
      textarea.setAttribute("readonly", "");
      textarea.style.position = "fixed";
      textarea.style.opacity = "0";
      document.body.append(textarea);
      textarea.select();
      document.execCommand("copy");
      textarea.remove();
    }
    toast(message);
  }

  function replaceCandidate(updated) {
    const index = state.detail.candidates.findIndex(candidate => candidate.id === updated.id);
    updated.computed = state.detail.candidates[index]?.computed || null;
    state.detail.candidates[index] = updated;
    const summaryIndex = state.scans.findIndex(scan => scan.id === state.scanId);
    if (summaryIndex >= 0) state.scans[summaryIndex] = summaryFromDetail(state.detail);
  }

  function visibleRuns() {
    const query = state.runSearch.trim().toLowerCase();
    return state.scans.filter(scan => {
      if (state.runStatus !== "all" && scan.status !== state.runStatus) return false;
      if (state.runRepo !== "all" && scan.repo_name !== state.runRepo) return false;
      if (state.runSeverity !== "all" && !(scan.severity_counts?.[state.runSeverity] > 0)) return false;
      return !query || `${scan.repo_name} ${scan.id} ${scan.revision || ""}`.toLowerCase().includes(query);
    });
  }

  function visibleFindings() {
    if (!state.detail) return [];
    const query = state.search.trim().toLowerCase();
    return state.detail.candidates.filter(candidate => {
      if (state.severity !== "all" && severityOf(candidate) !== state.severity) return false;
      if (state.status !== "all" && candidate.status !== state.status) return false;
      return !query || `${candidate.id} ${candidate.title} ${candidate.description} ${(candidate.cwe_ids || []).join(" ")} ${(candidate.locations || []).map(location => location.path).join(" ")}`.toLowerCase().includes(query);
    }).sort((a, b) => severityRank(severityOf(a)) - severityRank(severityOf(b)) || numericId(a.id) - numericId(b.id));
  }

  function reviewStats(candidates) {
    const reviewable = candidates.filter(isReviewable);
    const reviewed = reviewable.filter(isHumanReviewed).length;
    const counts = Object.fromEntries(["critical", "high", "medium", "low", "info"].map(severity => [severity, reviewable.filter(candidate => severityOf(candidate) === severity).length]));
    return {
      reviewable: reviewable.length,
      reviewed,
      remaining: reviewable.length - reviewed,
      duplicates: candidates.filter(candidate => candidate.status === "duplicate").length,
      dismissed: candidates.filter(candidate => !candidate.duplicate_of && !isReviewable(candidate)).length,
      counts,
    };
  }

  function isReviewable(candidate) {
    const assessed = [...candidate.activities].reverse().find(activity => (activity.kind === "assessment" || activity.kind === "validation") && activity.data?.disposition !== undefined)?.data?.disposition;
    return !candidate.duplicate_of && (assessed || candidate.status) === "confirmed" && candidate.computed?.reportable !== false;
  }
  function isHumanReviewed(candidate) { return candidate.activities.some(activity => activity.kind === "review"); }
  function severityOf(candidate) { return candidate.computed?.severity || "info"; }
  function currentFinding() { return state.detail?.candidates.find(candidate => candidate.id === state.findingId) || null; }
  function firstVisibleFinding() { return visibleFindings()[0] || null; }
  function ensureVisibleSelection() { if (!visibleFindings().some(candidate => candidate.id === state.findingId)) state.findingId = firstVisibleFinding()?.id || null; }
  function severityRank(value) { return ["critical", "high", "medium", "low", "info"].indexOf(value); }
  function numericId(value) { return Number(value.replace(/\D/g, "")) || 0; }

  function summaryFromDetail(detail) {
    const stats = reviewStats(detail.candidates);
    const pct = detail.coverage.bytes_in_scope ? Math.round(detail.coverage.bytes_read / detail.coverage.bytes_in_scope * 100) : 0;
    return {
      id: detail.scan.id, repo_name: detail.repo.name, status: detail.scan.status,
      started_at: detail.scan.started_at, completed_at: detail.scan.completed_at,
      revision: detail.scan.revision, cost_usd: detail.scan.cost_usd,
      finding_count: detail.candidates.length, reviewable_count: stats.reviewable,
      reviewed_count: stats.reviewed, open_count: stats.remaining,
      duplicate_count: stats.duplicates, severity_counts: stats.counts, coverage_percent: pct,
    };
  }

  function displayRunStatus(scan) {
    if (scan.status === "running" && Date.now() - new Date(scan.started_at).getTime() > 24 * 60 * 60 * 1000) return { label: "Possibly interrupted", className: "interrupted" };
    return { label: label(scan.status), className: scan.status };
  }

  function toggleFilters(button) {
    const filters = document.getElementById("filters");
    state.filtersOpen = !state.filtersOpen;
    filters.hidden = !state.filtersOpen;
    button.setAttribute("aria-expanded", String(state.filtersOpen));
  }
  function toggleSelectMenu(trigger) {
    const menu = document.getElementById(trigger.getAttribute("aria-controls"));
    if (!menu) return;
    const opening = menu.hidden;
    closeSelectMenus(menu.closest(".select-menu"));
    menu.hidden = !opening;
    trigger.setAttribute("aria-expanded", String(opening));
  }
  function openSelectMenu(trigger, focusLast = false) {
    const menu = document.getElementById(trigger.getAttribute("aria-controls"));
    if (!menu) return;
    closeSelectMenus(menu.closest(".select-menu"));
    menu.hidden = false;
    trigger.setAttribute("aria-expanded", "true");
    const options = [...menu.querySelectorAll(".select-option")];
    const selected = options.find(option => option.getAttribute("aria-selected") === "true");
    (focusLast ? options.at(-1) : selected || options[0])?.focus();
  }
  function closeSelectMenus(except = null) {
    document.querySelectorAll(".select-menu").forEach(select => {
      if (select === except) return;
      select.querySelector(".select-options")?.setAttribute("hidden", "");
      select.querySelector(".select-trigger")?.setAttribute("aria-expanded", "false");
    });
  }
  function moveSelectFocus(option, key) {
    const options = [...option.closest(".select-options").querySelectorAll(".select-option")];
    const index = options.indexOf(option);
    const next = key === "Home" ? 0 : key === "End" ? options.length - 1 : key === "ArrowUp" ? Math.max(0, index - 1) : Math.min(options.length - 1, index + 1);
    options[next]?.focus();
  }
  function toggleRunFilters(button) {
    const filters = document.getElementById("run-filters");
    state.runFiltersOpen = !state.runFiltersOpen;
    filters.hidden = !state.runFiltersOpen;
    button.setAttribute("aria-expanded", String(state.runFiltersOpen));
  }
  function toggleExport(button) {
    const menu = document.getElementById("export-menu");
    menu.hidden = !menu.hidden;
    button.setAttribute("aria-expanded", String(!menu.hidden));
    if (!menu.hidden) menu.querySelector("button")?.focus();
  }
  function closeExport() {
    const menu = document.getElementById("export-menu");
    if (menu) menu.hidden = true;
    document.querySelector('[data-action="toggle-export"]')?.setAttribute("aria-expanded", "false");
  }
  function hasFindingFilters() { return !!state.search || state.severity !== "all" || state.status !== "all"; }
  function clearFindingFilters() {
    state.search = "";
    state.severity = "all";
    state.status = "all";
    ensureVisibleSelection();
    renderAll();
  }
  function hasRunFilters() { return !!state.runSearch || state.runStatus !== "all" || state.runRepo !== "all" || state.runSeverity !== "all"; }
  function clearRunFilters() {
    state.runSearch = "";
    state.runStatus = "all";
    state.runRepo = "all";
    state.runSeverity = "all";
    renderAll();
  }

  async function exportData(format) {
    closeExport();
    try {
      const response = await fetch(`/api/scans/${encodeURIComponent(state.scanId)}/export?format=${encodeURIComponent(format)}`, { headers: { "X-OpenSec-Token": token } });
      if (!response.ok) throw new Error((await response.json()).error || `Export failed (${response.status})`);
      const blob = await response.blob();
      const link = document.createElement("a");
      link.href = URL.createObjectURL(blob);
      link.download = contentFilename(response.headers.get("Content-Disposition")) || `opensec.${format}`;
      link.click();
      URL.revokeObjectURL(link.href);
      toast(`${format.toUpperCase()} exported`);
    } catch (error) {
      renderError(error, false);
    }
  }

  async function api(path, options = {}) {
    const response = await fetch(path, { ...options, headers: { "Content-Type": "application/json", "X-OpenSec-Token": token, ...(options.headers || {}) } });
    const body = await response.json();
    if (!response.ok) throw new Error(body.error || `Request failed (${response.status})`);
    return body;
  }

  function replaceUrl() {
    if (snapshot || !state.scanId) return;
    history.replaceState(null, "", `?scan=${encodeURIComponent(state.scanId)}&view=${state.view}`);
  }
  function renderNoScans() {
    state.view = "runs";
    renderHeader();
    sidebar().innerHTML = `<div class="sidebar-head"><strong>Recent runs</strong><span>None on this machine</span></div>`;
    main().innerHTML = `<div class="page"><div class="error-box"><h2>No runs yet</h2><p>Run <code>opensec scan &lt;path&gt;</code>, then refresh this page.</p></div></div>`;
  }
  function renderError(error, replace = true) {
    if (!replace) return toast(error.message || String(error));
    main().innerHTML = `<div class="error-box"><h2>Could not load the review</h2><p>${esc(error.message || String(error))}</p></div>`;
  }
  function toast(message) {
    const element = document.getElementById("toast");
    element.textContent = message;
    element.classList.add("show");
    clearTimeout(toastTimer);
    toastTimer = setTimeout(() => element.classList.remove("show"), 2200);
  }

  function activityItem(item) { return `<div class="activity-item"><div class="activity-top"><span class="activity-kind">${esc(label(item.kind))}</span><span class="activity-time">${longDate(item.at)} · ${esc(item.worker_id)}</span></div>${item.body ? `<div class="activity-body markdown">${markdown(item.body)}</div>` : ""}</div>`; }
  function paragraphs(value) { return String(value || "").split(/\n\s*\n/).filter(Boolean).map(text => `<p>${esc(text).replaceAll("\n", "<br>")}</p>`).join("") || "<p>No description recorded.</p>"; }
  function selectMenu(id, ariaLabel, options, selectedValue, className = "") {
    const selected = options.find(([value]) => value === selectedValue) || options[0];
    return `<div class="select-menu ${className}" data-select-id="${esc(id)}">
      <button type="button" id="${esc(id)}-trigger" class="select-trigger" data-action="toggle-select-menu" aria-label="${esc(ariaLabel)}" aria-haspopup="listbox" aria-expanded="false" aria-controls="${esc(id)}-options"><span>${esc(selected?.[1] || "Select")}</span>${chevronIcon()}</button>
      <div id="${esc(id)}-options" class="select-options" role="listbox" aria-labelledby="${esc(id)}-trigger" hidden>${options.map(([value, copy]) => `<button type="button" class="select-option" data-action="select-option" data-select-id="${esc(id)}" data-select-value="${esc(value)}" role="option" aria-selected="${value === selectedValue}"><span>${esc(copy)}</span><i aria-hidden="true">✓</i></button>`).join("")}</div>
    </div>`;
  }
  function markdown(value) {
    const output = [];
    const paragraph = [];
    const listItems = [];
    let listTag = null;
    let inCode = false;
    let code = [];
    const flushParagraph = () => {
      if (paragraph.length) output.push(`<p>${inlineMarkdown(paragraph.join(" "))}</p>`);
      paragraph.length = 0;
    };
    const flushList = () => {
      if (listItems.length) output.push(`<${listTag}>${listItems.map(item => `<li>${inlineMarkdown(item)}</li>`).join("")}</${listTag}>`);
      listItems.length = 0;
      listTag = null;
    };

    for (const line of String(value || "").replaceAll("\r\n", "\n").split("\n")) {
      if (line.trim().startsWith("```")) {
        flushParagraph();
        flushList();
        if (inCode) {
          output.push(`<pre><code>${esc(code.join("\n"))}</code></pre>`);
          code = [];
        }
        inCode = !inCode;
        continue;
      }
      if (inCode) {
        code.push(line);
        continue;
      }
      if (!line.trim()) {
        flushParagraph();
        flushList();
        continue;
      }
      const heading = line.match(/^(#{1,4})\s+(.+)$/);
      if (heading) {
        flushParagraph();
        flushList();
        const level = Math.min(4, heading[1].length + 1);
        output.push(`<h${level}>${inlineMarkdown(heading[2])}</h${level}>`);
        continue;
      }
      const unordered = line.match(/^\s*[-*]\s+(.+)$/);
      const ordered = line.match(/^\s*\d+[.)]\s+(.+)$/);
      if (unordered || ordered) {
        flushParagraph();
        const nextTag = ordered ? "ol" : "ul";
        if (listTag && listTag !== nextTag) flushList();
        listTag = nextTag;
        listItems.push((unordered || ordered)[1]);
        continue;
      }
      flushList();
      paragraph.push(line.trim());
    }
    if (inCode && code.length) output.push(`<pre><code>${esc(code.join("\n"))}</code></pre>`);
    flushParagraph();
    flushList();
    return output.join("");
  }
  function inlineMarkdown(value) {
    return esc(value)
      .replace(/`([^`]+)`/g, "<code>$1</code>")
      .replace(/\*\*([^*]+)\*\*/g, "<strong>$1</strong>")
      .replace(/\*([^*]+)\*/g, "<em>$1</em>");
  }
  function copyIcon() { return `<svg viewBox="0 0 16 16" aria-hidden="true"><rect x="5" y="5" width="8" height="8" rx="1.5"></rect><path d="M3 10.5V4.25C3 3.56 3.56 3 4.25 3h6.25"></path></svg>`; }
  function chevronIcon() { return `<svg viewBox="0 0 16 16" aria-hidden="true"><path d="m4.5 6 3.5 3.5L11.5 6"></path></svg>`; }
  function compactSeveritySummary(counts) { return ["critical", "high", "medium", "low"].filter(level => counts[level]).slice(0, 3).map(level => `${counts[level]} ${label(level)}`).join(" · "); }
  function severityStrip(counts, total) { return total ? ["critical", "high", "medium", "low", "info"].map(level => counts[level] ? `<i style="width:${counts[level] / total * 100}%;background:${severityColor(level)}"></i>` : "").join("") : ""; }
  function severityLabels(counts) { return ["critical", "high", "medium", "low", "info"].filter(level => counts[level]).map(level => `<span class="severity-count" style="--severity:${severityColor(level)}"><i></i>${counts[level]} ${label(level)}</span>`).join(""); }
  function severityColor(value) { return `var(--${["critical", "high", "medium", "low", "info"].includes(value) ? value : "info"})`; }
  function findingStateLabel(value) { return ({ open: "Needs review", confirmed: "Confirmed", needs_follow_up: "Needs follow-up", suppressed: "Suppressed", not_applicable: "Not applicable", duplicate: "Duplicate" })[value] || label(value); }
  function label(value) { return String(value || "").replaceAll("_", " ").replace(/\b\w/g, char => char.toUpperCase()); }
  function shortHash(value) { return value ? String(value).slice(0, 10) : "No revision"; }
  function shortDateTime(value) { return new Intl.DateTimeFormat(undefined, { month: "short", day: "numeric", hour: "2-digit", minute: "2-digit" }).format(new Date(value)); }
  function longDate(value) { return new Intl.DateTimeFormat(undefined, { dateStyle: "medium", timeStyle: "short" }).format(new Date(value)); }
  function formatDuration(milliseconds) { const minutes = Math.max(1, Math.round(milliseconds / 60000)); return minutes < 60 ? `${minutes} min` : `${Math.floor(minutes / 60)} hr ${minutes % 60} min`; }
  function contentFilename(value) { return value?.match(/filename="([^"]+)"/)?.[1] || null; }
  function esc(value) { return String(value ?? "").replace(/[&<>'"]/g, char => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", "'": "&#39;", '"': "&quot;" })[char]); }
})();
