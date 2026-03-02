(() => {
  const state = {
    analysis: null,
    dot: "",
    graphTransform: { x: 20, y: 20, scale: 1 },
    panActive: false,
    panStart: { x: 0, y: 0 },
    selectedNodeId: null,
    roleIndex: {},
    serverViews: {},
    viewBackend: "unknown",
    viewShared: false,
  };

  const el = {
    source: document.getElementById("source"),
    namespaces: document.getElementById("namespaces"),
    layout: document.getElementById("layout"),
    page: document.getElementById("page"),
    pageSize: document.getElementById("pageSize"),
    maxSubjects: document.getElementById("maxSubjects"),
    manifest: document.getElementById("manifest"),
    viewName: document.getElementById("viewName"),
    saveViewBtn: document.getElementById("saveViewBtn"),
    savedViewsSelect: document.getElementById("savedViewsSelect"),
    loadViewBtn: document.getElementById("loadViewBtn"),
    deleteViewBtn: document.getElementById("deleteViewBtn"),
    copyLinkBtn: document.getElementById("copyLinkBtn"),
    sourceStatus: document.getElementById("sourceStatus"),
    pageStatus: document.getElementById("pageStatus"),
    analyzeBtn: document.getElementById("analyzeBtn"),
    dotBtn: document.getElementById("dotBtn"),
    downloadJsonBtn: document.getElementById("downloadJsonBtn"),
    fitGraphBtn: document.getElementById("fitGraphBtn"),
    tabs: Array.from(document.querySelectorAll(".tab")),
    panels: Array.from(document.querySelectorAll(".tab-panel")),
    graphNamespace: document.getElementById("graphNamespace"),
    graphSearch: document.getElementById("graphSearch"),
    graphRiskyOnly: document.getElementById("graphRiskyOnly"),
    graphEmptyState: document.getElementById("graphEmptyState"),
    graphSvg: document.getElementById("graphSvg"),
    graphPanZoom: document.getElementById("graphPanZoom"),
    inspectorBody: document.getElementById("inspectorBody"),
    riskTableBody: document.getElementById("riskTableBody"),
    blastWrap: document.getElementById("blastWrap"),
    jsonOutput: document.getElementById("jsonOutput"),
    dotOutput: document.getElementById("dotOutput"),
    mSubjects: document.getElementById("mSubjects"),
    mExecProd: document.getElementById("mExecProd"),
    mBindings: document.getElementById("mBindings"),
    mSAs: document.getElementById("mSAs"),
  };

  function setStatus(message, cls) {
    el.sourceStatus.classList.remove("ok", "warn");
    if (cls) el.sourceStatus.classList.add(cls);
    el.sourceStatus.textContent = message;
  }

  async function getJSON(url) {
    const res = await fetch(url);
    const data = await res.json();
    if (!res.ok) throw new Error(data.error || "Request failed");
    return data;
  }

  async function sendJSON(url, method, body) {
    const res = await fetch(url, {
      method,
      headers: { "Content-Type": "application/json" },
      body: body ? JSON.stringify(body) : undefined,
    });
    const data = await res.json();
    if (!res.ok) throw new Error(data.error || "Request failed");
    return data;
  }

  function parseIntInput(input, fallback, min, max) {
    const raw = Number.parseInt(String(input.value || ""), 10);
    if (!Number.isFinite(raw)) return fallback;
    return Math.max(min, Math.min(max, raw));
  }

  function buildPayload() {
    return {
      source: el.source.value,
      namespaces: el.namespaces.value,
      manifest: el.manifest.value,
      page: parseIntInput(el.page, 1, 1, 100000),
      page_size: parseIntInput(el.pageSize, 200, 1, 2000),
      max_subjects: parseIntInput(el.maxSubjects, 2000, 1, 10000),
    };
  }

  function switchTab(name) {
    for (const tab of el.tabs) tab.classList.toggle("active", tab.dataset.tab === name);
    for (const panel of el.panels) panel.classList.toggle("active", panel.id === `tab-${name}`);
  }

  function setMetrics(summary) {
    el.mSubjects.textContent = String(summary.subjects_analyzed ?? "-");
    el.mExecProd.textContent = String((summary.who_can_exec_prod || []).length);
    const rbac = summary.rbac_objects || {};
    el.mBindings.textContent = String((rbac.role_bindings || 0) + (rbac.cluster_role_bindings || 0));
    el.mSAs.textContent = String(rbac.service_accounts || 0);

    const p = summary.pagination || null;
    if (p) {
      let msg = `Page ${p.page}/${p.total_pages} | page size ${p.page_size} | showing ${p.page_subjects}/${p.subjects_after_limit} subjects after max_subjects=${p.max_subjects} (cluster total ${p.total_subjects})`;
      if (p.total_subjects === 0) {
        msg += " | no binding subjects found (check source, namespace filter, and RBAC bindings)";
      }
      el.pageStatus.textContent = msg;
    } else {
      el.pageStatus.textContent = "";
    }
  }

  function renderRiskTable(analysis) {
    const entries = Object.entries(analysis.effective_permissions || {}).map(([subject, info]) => ({
      subject,
      risks: info.risky_capabilities || [],
    }));

    entries.sort((a, b) => b.risks.length - a.risks.length || a.subject.localeCompare(b.subject));
    el.riskTableBody.innerHTML = "";

    if (!entries.length) {
      const tr = document.createElement("tr");
      tr.innerHTML = '<td colspan="3">No subjects found in this page window.</td>';
      el.riskTableBody.appendChild(tr);
      return;
    }

    for (const row of entries) {
      const tr = document.createElement("tr");
      const caps = row.risks.length
        ? row.risks.map((r) => `<span class="chip">${escapeHTML(r.risk)}</span>`).join("")
        : '<span class="chip">none</span>';
      tr.innerHTML = `<td>${escapeHTML(row.subject)}</td><td>${row.risks.length}</td><td>${caps}</td>`;
      el.riskTableBody.appendChild(tr);
    }
  }

  function renderBlastRadius(analysis) {
    const items = Object.entries(analysis.blast_radius || {});
    el.blastWrap.innerHTML = "";

    if (!items.length) {
      const p = document.createElement("p");
      p.className = "muted";
      p.textContent = "No ServiceAccount blast-radius entries were generated for this page window.";
      el.blastWrap.appendChild(p);
      return;
    }

    for (const [subject, data] of items) {
      const card = document.createElement("article");
      card.className = "blast-card";
      const caps = (data.risky_capabilities || []).map((x) => `<span class="chip">${escapeHTML(x)}</span>`).join("") || '<span class="chip">none</span>';
      const paths = (data.attack_paths || []).map((x) => `<li>${escapeHTML(x)}</li>`).join("") || "<li>No attack path inferred.</li>";
      card.innerHTML = `<h4>${escapeHTML(subject)}</h4><div>${caps}</div><ul>${paths}</ul>`;
      el.blastWrap.appendChild(card);
    }
  }

  function parseSubjectKey(subjectKey) {
    const [kind, namespace, ...rest] = String(subjectKey).split(":");
    return { kind, namespace, name: rest.join(":") };
  }

  function populateGraphNamespaceFilter(analysis) {
    const values = new Set([""]);
    for (const subject of Object.keys(analysis.effective_permissions || {})) {
      const parsed = parseSubjectKey(subject);
      if (parsed.namespace && parsed.namespace !== "*") values.add(parsed.namespace);
    }

    const current = el.graphNamespace.value;
    const sorted = Array.from(values).sort((a, b) => a.localeCompare(b));
    el.graphNamespace.innerHTML = "";
    for (const ns of sorted) {
      const option = document.createElement("option");
      option.value = ns;
      option.textContent = ns || "All";
      el.graphNamespace.appendChild(option);
    }
    if (sorted.includes(current)) el.graphNamespace.value = current;
  }

  function buildRoleIndex(analysis) {
    const out = {};

    for (const [subjectKey, info] of Object.entries(analysis.effective_permissions || {})) {
      const grants = info.grants || [];
      const rules = info.rules || [];

      for (const grant of grants) {
        const roleNodeId = `${grant.role_ref_kind}:${grant.role_ref_name}:${grant.binding_namespace || "*"}`;
        if (!out[roleNodeId]) out[roleNodeId] = { subjects: new Set(), rules: [] };
        out[roleNodeId].subjects.add(subjectKey);

        const roleLabel = `${grant.role_ref_kind}/${grant.role_ref_name}`;
        const scopeNs = grant.role_ref_kind === "Role" ? grant.binding_namespace : null;

        for (const rule of rules) {
          const ruleScope = rule.scope_namespace ?? null;
          if (rule.from === roleLabel && ruleScope === scopeNs) {
            const token = JSON.stringify(rule);
            if (!out[roleNodeId].rules.some((x) => JSON.stringify(x) === token)) out[roleNodeId].rules.push(rule);
          }
        }
      }
    }

    return out;
  }

  function getFilteredGraph(analysis) {
    const graph = analysis.graph || { nodes: [], edges: [] };
    const search = el.graphSearch.value.trim().toLowerCase();
    const namespace = el.graphNamespace.value;
    const riskyOnly = el.graphRiskyOnly.checked;

    const effective = analysis.effective_permissions || {};
    const matchedSubjects = new Set();

    for (const subjectKey of Object.keys(effective)) {
      const parsed = parseSubjectKey(subjectKey);
      if (namespace && parsed.namespace !== namespace) continue;
      if (search && !subjectKey.toLowerCase().includes(search)) continue;
      if (riskyOnly && !(effective[subjectKey].risky_capabilities || []).length) continue;
      matchedSubjects.add(subjectKey);
    }

    const filteredEdges = (graph.edges || []).filter((e) => matchedSubjects.has(e.from));
    const roleNodes = new Set(filteredEdges.map((e) => e.to));
    const nodeAllow = new Set([...matchedSubjects, ...roleNodes]);
    const filteredNodes = (graph.nodes || []).filter((n) => nodeAllow.has(n.id));

    return { nodes: filteredNodes, edges: filteredEdges };
  }

  function renderGraphEmptyState(analysis) {
    const summary = (analysis && analysis.summary) || {};
    const pagination = summary.pagination || {};
    const total = Number(pagination.total_subjects || 0);
    if (total > 0) {
      el.graphEmptyState.classList.add("hidden");
      el.graphEmptyState.textContent = "";
      return;
    }

    const isCluster = String(summary.source || "").toLowerCase() === "cluster";
    el.graphEmptyState.classList.remove("hidden");
    el.graphEmptyState.classList.add("warn");
    el.graphEmptyState.textContent = isCluster
      ? "No subjects found from live RBAC bindings. Check namespace filter and cluster RoleBinding/ClusterRoleBinding subjects."
      : "No subjects found in manifest. Add RoleBinding/ClusterRoleBinding entries with subjects.";
  }

  function renderGraph(analysis) {
    renderGraphEmptyState(analysis);
    const { nodes, edges } = getFilteredGraph(analysis);
    const layer = el.graphPanZoom;
    layer.innerHTML = "";

    if (!nodes.length) {
      el.inspectorBody.innerHTML = '<p class="muted">No nodes match the current graph filters.</p>';
      return;
    }

    const width = 1200;
    const height = 720;
    const pos = el.layout.value === "radial" ? radialLayout(nodes, width, height) : layeredLayout(nodes, width, height);

    for (const edge of edges) {
      const from = pos[edge.from];
      const to = pos[edge.to];
      if (!from || !to) continue;
      layer.appendChild(svg("line", { x1: from.x, y1: from.y, x2: to.x, y2: to.y, class: "edge" }));

      const mx = (from.x + to.x) / 2;
      const my = (from.y + to.y) / 2;
      const label = svg("text", { x: mx + 4, y: my - 4, class: "edge-label" });
      label.textContent = edge.type || "";
      layer.appendChild(label);
    }

    const visibleNodeIds = new Set(nodes.map((n) => n.id));
    if (state.selectedNodeId && !visibleNodeIds.has(state.selectedNodeId)) {
      state.selectedNodeId = null;
      el.inspectorBody.innerHTML = '<p class="muted">Selected node filtered out. Select another node.</p>';
    }

    for (const node of nodes) {
      const p = pos[node.id];
      if (!p) continue;

      const g = svg("g", { class: `node-group ${state.selectedNodeId === node.id ? "node-selected" : ""}` });
      const isSubject = node.type === "subject";
      const widthRect = Math.max(115, Math.min(280, (node.label || node.id).length * 7.6));
      const rect = svg("rect", {
        x: p.x - widthRect / 2,
        y: p.y - 15,
        rx: isSubject ? 14 : 6,
        ry: isSubject ? 14 : 6,
        width: widthRect,
        height: 30,
        class: isSubject ? "node-subject" : "node-role",
      });
      const txt = svg("text", { x: p.x, y: p.y + 4, class: "node-label", "text-anchor": "middle" });
      txt.textContent = node.label || node.id;

      g.appendChild(rect);
      g.appendChild(txt);
      g.addEventListener("click", () => {
        state.selectedNodeId = node.id;
        renderInspector(node.id, analysis);
        renderGraph(analysis);
      });
      layer.appendChild(g);
    }

    applyGraphTransform();
  }

  function renderInspector(nodeId, analysis) {
    if (!nodeId) {
      el.inspectorBody.innerHTML = '<p class="muted">Click a node to inspect.</p>';
      return;
    }

    const node = ((analysis.graph && analysis.graph.nodes) || []).find((n) => n.id === nodeId);
    if (!node) {
      el.inspectorBody.innerHTML = '<p class="muted">Node not found in this view.</p>';
      return;
    }

    if (node.type === "subject") {
      const info = (analysis.effective_permissions || {})[nodeId];
      if (!info) {
        el.inspectorBody.innerHTML = `<h4>${escapeHTML(node.label)}</h4><p class="muted">No subject data.</p>`;
        return;
      }

      const grants = (info.grants || []).map((g) => `<li>${escapeHTML(g.source_kind)} -> ${escapeHTML(g.role_ref_kind)}/${escapeHTML(g.role_ref_name)} (${escapeHTML(g.binding_namespace || "cluster")})</li>`).join("") || "<li>None</li>";
      const risks = (info.risky_capabilities || []).map((r) => `<span class="chip">${escapeHTML(r.risk)}</span>`).join("") || '<span class="chip">none</span>';

      el.inspectorBody.innerHTML = `<h4>${escapeHTML(node.label)}</h4><div><strong>Subject Key:</strong> ${escapeHTML(nodeId)}</div><h4>Risky Capabilities</h4><div>${risks}</div><h4>Bindings</h4><ul>${grants}</ul>`;
      return;
    }

    const roleData = state.roleIndex[nodeId];
    if (!roleData) {
      el.inspectorBody.innerHTML = `<h4>${escapeHTML(node.label)}</h4><p class="muted">No role index data found.</p>`;
      return;
    }

    const subjectList = Array.from(roleData.subjects).sort();
    const subjects = subjectList.map((s) => `<li>${escapeHTML(s)}</li>`).join("") || "<li>None</li>";

    const rules = roleData.rules
      .map((r) => {
        const groups = (r.apiGroups || []).join(",") || "";
        const resources = (r.resources || []).join(",") || "";
        const verbs = (r.verbs || []).join(",") || "";
        return `<li><strong>apiGroups:</strong> ${escapeHTML(groups)}<br/><strong>resources:</strong> ${escapeHTML(resources)}<br/><strong>verbs:</strong> ${escapeHTML(verbs)}<br/><strong>scope:</strong> ${escapeHTML(r.scope_namespace || "cluster")}</li>`;
      })
      .join("") || "<li>No rule details present in current page window.</li>";

    el.inspectorBody.innerHTML = `<h4>${escapeHTML(node.label)}</h4><div><strong>Role Node ID:</strong> ${escapeHTML(nodeId)}</div><h4>Bound Subjects (${subjectList.length})</h4><ul>${subjects}</ul><h4>Resolved Rules</h4><ul>${rules}</ul>`;
  }

  function layeredLayout(nodes, width, height) {
    const subjects = nodes.filter((n) => n.type === "subject");
    const roles = nodes.filter((n) => n.type !== "subject");
    const out = {};
    const sx = width * 0.24;
    const rx = width * 0.76;
    const sStep = Math.max(42, (height - 100) / Math.max(subjects.length, 1));
    const rStep = Math.max(32, (height - 100) / Math.max(roles.length, 1));
    for (let i = 0; i < subjects.length; i += 1) out[subjects[i].id] = { x: sx, y: 60 + i * sStep };
    for (let i = 0; i < roles.length; i += 1) out[roles[i].id] = { x: rx, y: 60 + i * rStep };
    return out;
  }

  function radialLayout(nodes, width, height) {
    const out = {};
    const cx = width / 2;
    const cy = height / 2;
    const subjects = nodes.filter((n) => n.type === "subject");
    const roles = nodes.filter((n) => n.type !== "subject");
    placeRing(subjects, cx, cy, Math.min(width, height) * 0.28, out);
    placeRing(roles, cx, cy, Math.min(width, height) * 0.42, out);
    return out;
  }

  function placeRing(nodes, cx, cy, radius, out) {
    const count = Math.max(nodes.length, 1);
    for (let i = 0; i < nodes.length; i += 1) {
      const t = (i / count) * Math.PI * 2 - Math.PI / 2;
      out[nodes[i].id] = { x: cx + Math.cos(t) * radius, y: cy + Math.sin(t) * radius };
    }
  }

  function svg(tag, attrs) {
    const n = document.createElementNS("http://www.w3.org/2000/svg", tag);
    Object.entries(attrs).forEach(([k, v]) => n.setAttribute(k, String(v)));
    return n;
  }

  function escapeHTML(value) {
    return String(value)
      .replaceAll("&", "&amp;")
      .replaceAll("<", "&lt;")
      .replaceAll(">", "&gt;")
      .replaceAll('"', "&quot;")
      .replaceAll("'", "&#039;");
  }

  function setLoading(on) {
    el.analyzeBtn.disabled = on;
    el.dotBtn.disabled = on;
    el.downloadJsonBtn.disabled = on;
    el.fitGraphBtn.disabled = on;
    el.saveViewBtn.disabled = on;
    el.loadViewBtn.disabled = on;
    el.deleteViewBtn.disabled = on;
  }

  function collectViewSettings() {
    return {
      source: el.source.value,
      namespaces: el.namespaces.value,
      layout: el.layout.value,
      page: String(parseIntInput(el.page, 1, 1, 100000)),
      pageSize: String(parseIntInput(el.pageSize, 200, 1, 2000)),
      maxSubjects: String(parseIntInput(el.maxSubjects, 2000, 1, 10000)),
      graphNamespace: el.graphNamespace.value,
      graphSearch: el.graphSearch.value,
      graphRiskyOnly: el.graphRiskyOnly.checked ? "1" : "0",
      tab: (el.tabs.find((t) => t.classList.contains("active")) || { dataset: { tab: "graph" } }).dataset.tab,
    };
  }

  function applyViewSettings(settings) {
    if (settings.source) el.source.value = settings.source;
    if (settings.namespaces !== undefined) el.namespaces.value = settings.namespaces;
    if (settings.layout) el.layout.value = settings.layout;
    if (settings.page) el.page.value = settings.page;
    if (settings.pageSize) el.pageSize.value = settings.pageSize;
    if (settings.maxSubjects) el.maxSubjects.value = settings.maxSubjects;
    updateSourceInputs();

    el.graphSearch.value = settings.graphSearch || "";
    el.graphRiskyOnly.checked = settings.graphRiskyOnly === "1";
    if (settings.tab) switchTab(settings.tab);
  }

  async function refreshServerViews() {
    const data = await getJSON("/api/views");
    state.viewBackend = data.backend || "unknown";
    state.viewShared = Boolean(data.shared);
    state.serverViews = {};

    const views = Array.isArray(data.views) ? data.views : [];
    for (const view of views) {
      if (!view || typeof view !== "object") continue;
      if (typeof view.name !== "string") continue;
      state.serverViews[view.name] = view.settings || {};
    }

    refreshSavedViewsDropdown();
  }

  function refreshSavedViewsDropdown() {
    const current = el.savedViewsSelect.value;
    const names = Object.keys(state.serverViews).sort((a, b) => a.localeCompare(b));
    el.savedViewsSelect.innerHTML = '<option value="">Saved views</option>';

    for (const name of names) {
      const option = document.createElement("option");
      option.value = name;
      option.textContent = name;
      el.savedViewsSelect.appendChild(option);
    }

    if (names.includes(current)) el.savedViewsSelect.value = current;
  }

  async function saveCurrentView() {
    const name = el.viewName.value.trim();
    if (!name) {
      el.pageStatus.textContent = "Enter a view name before saving.";
      return;
    }

    const settings = collectViewSettings();
    await sendJSON(`/api/views/${encodeURIComponent(name)}`, "PUT", { settings });
    await refreshServerViews();
    el.savedViewsSelect.value = name.toLowerCase().replaceAll(" ", "-");
    el.pageStatus.textContent = `Saved server view: ${name} (${state.viewBackend}${state.viewShared ? ", shared" : ", non-shared"})`;
  }

  function loadSelectedView() {
    const name = el.savedViewsSelect.value;
    if (!name || !state.serverViews[name]) {
      el.pageStatus.textContent = "Select a saved view to load.";
      return;
    }

    applyViewSettings(state.serverViews[name]);
    el.viewName.value = name;

    if (state.analysis) {
      const requestedNS = state.serverViews[name].graphNamespace || "";
      if (Array.from(el.graphNamespace.options).some((opt) => opt.value === requestedNS)) {
        el.graphNamespace.value = requestedNS;
      }
      renderGraph(state.analysis);
    }

    el.pageStatus.textContent = `Loaded server view: ${name}`;
  }

  async function deleteSelectedView() {
    const name = el.savedViewsSelect.value;
    if (!name || !state.serverViews[name]) {
      el.pageStatus.textContent = "Select a saved view to delete.";
      return;
    }

    await sendJSON(`/api/views/${encodeURIComponent(name)}`, "DELETE");
    await refreshServerViews();
    el.pageStatus.textContent = `Deleted server view: ${name}`;
  }

  function viewToQueryString(view) {
    const p = new URLSearchParams();
    for (const [key, value] of Object.entries(view)) {
      if (value !== undefined && value !== null && String(value) !== "") p.set(key, String(value));
    }
    return p.toString();
  }

  function applyViewFromURL() {
    const params = new URLSearchParams(window.location.search);
    if (!params.size) return;

    const settings = {
      source: params.get("source") || "",
      namespaces: params.get("namespaces") || "",
      layout: params.get("layout") || "",
      page: params.get("page") || "",
      pageSize: params.get("pageSize") || "",
      maxSubjects: params.get("maxSubjects") || "",
      graphNamespace: params.get("graphNamespace") || "",
      graphSearch: params.get("graphSearch") || "",
      graphRiskyOnly: params.get("graphRiskyOnly") || "0",
      tab: params.get("tab") || "graph",
    };

    applyViewSettings(settings);
  }

  async function copyShareLink() {
    const view = collectViewSettings();
    const url = `${window.location.origin}${window.location.pathname}?${viewToQueryString(view)}`;

    try {
      if (navigator.clipboard && navigator.clipboard.writeText) {
        await navigator.clipboard.writeText(url);
      } else {
        const temp = document.createElement("textarea");
        temp.value = url;
        document.body.appendChild(temp);
        temp.select();
        document.execCommand("copy");
        document.body.removeChild(temp);
      }
      el.pageStatus.textContent = "Share link copied to clipboard.";
    } catch (_err) {
      el.pageStatus.textContent = `Share link: ${url}`;
    }
  }

  async function runAnalysis() {
    if (el.source.value === "manifest" && !String(el.manifest.value || "").trim()) {
      el.pageStatus.textContent = "Manifest mode selected, but no YAML was provided.";
      switchTab("json");
      el.jsonOutput.textContent = "Error: Field 'manifest' is required when source=manifest";
      return;
    }

    setLoading(true);
    el.pageStatus.textContent = "Analyzing RBAC...";
    try {
      const analysis = await sendJSON("/api/analyze", "POST", buildPayload());
      state.analysis = analysis;
      state.roleIndex = buildRoleIndex(analysis);
      state.selectedNodeId = null;

      setMetrics(analysis.summary || {});
      populateGraphNamespaceFilter(analysis);

      renderRiskTable(analysis);
      renderBlastRadius(analysis);
      renderGraph(analysis);
      renderInspector(null, analysis);
      el.jsonOutput.textContent = JSON.stringify(analysis, null, 2);
      switchTab("graph");
    } catch (err) {
      el.pageStatus.textContent = `Analyze failed: ${err.message}`;
      el.jsonOutput.textContent = `Error: ${err.message}`;
      switchTab("json");
    } finally {
      setLoading(false);
    }
  }

  async function refreshDot() {
    setLoading(true);
    try {
      const data = await sendJSON("/api/graphviz", "POST", buildPayload());
      state.dot = data.dot || "";
      el.dotOutput.textContent = state.dot || "No DOT output";
      switchTab("dot");
    } catch (err) {
      el.dotOutput.textContent = `Error: ${err.message}`;
      switchTab("dot");
    } finally {
      setLoading(false);
    }
  }

  function downloadJSON() {
    if (!state.analysis) return;
    const blob = new Blob([JSON.stringify(state.analysis, null, 2)], { type: "application/json" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = "authvector-analysis.json";
    a.click();
    URL.revokeObjectURL(url);
  }

  function applyGraphTransform() {
    const t = state.graphTransform;
    el.graphPanZoom.setAttribute("transform", `translate(${t.x} ${t.y}) scale(${t.scale})`);
  }

  function resetGraphTransform() {
    state.graphTransform = { x: 20, y: 20, scale: 1 };
    applyGraphTransform();
  }

  function wireGraphInteractions() {
    el.graphSvg.addEventListener("wheel", (ev) => {
      ev.preventDefault();
      const factor = ev.deltaY < 0 ? 1.1 : 0.9;
      state.graphTransform.scale = Math.max(0.4, Math.min(2.8, state.graphTransform.scale * factor));
      applyGraphTransform();
    });

    el.graphSvg.addEventListener("mousedown", (ev) => {
      state.panActive = true;
      state.panStart = { x: ev.clientX, y: ev.clientY };
    });

    window.addEventListener("mouseup", () => {
      state.panActive = false;
    });

    window.addEventListener("mousemove", (ev) => {
      if (!state.panActive) return;
      const dx = ev.clientX - state.panStart.x;
      const dy = ev.clientY - state.panStart.y;
      state.panStart = { x: ev.clientX, y: ev.clientY };
      state.graphTransform.x += dx;
      state.graphTransform.y += dy;
      applyGraphTransform();
    });
  }

  async function checkSourceStatus() {
    try {
      const data = await getJSON("/api/sources");
      const saveInfo = `${data.saved_view_backend || "unknown"}${data.saved_view_shared ? " (shared)" : ""}`;
      if (data.in_cluster) {
        setStatus(`Live cluster mode is available. Default scope is all namespaces, including kube-system. Saved views backend: ${saveInfo}.`, "ok");
      } else {
        setStatus(`Live cluster mode is unavailable outside Kubernetes. Use manifest mode locally. Saved views backend: ${saveInfo}.`, "warn");
        el.source.value = "manifest";
      }
    } catch (err) {
      setStatus(`Could not detect source status: ${err.message}`, "warn");
    }
  }

  function updateSourceInputs() {
    const isManifest = el.source.value === "manifest";
    el.manifest.disabled = !isManifest;
    el.manifest.style.opacity = isManifest ? "1" : "0.55";
  }

  function wireEvents() {
    el.analyzeBtn.addEventListener("click", runAnalysis);
    el.dotBtn.addEventListener("click", refreshDot);
    el.downloadJsonBtn.addEventListener("click", downloadJSON);
    el.saveViewBtn.addEventListener("click", () => saveCurrentView().catch((err) => (el.pageStatus.textContent = `Save failed: ${err.message}`)));
    el.loadViewBtn.addEventListener("click", loadSelectedView);
    el.deleteViewBtn.addEventListener("click", () => deleteSelectedView().catch((err) => (el.pageStatus.textContent = `Delete failed: ${err.message}`)));
    el.copyLinkBtn.addEventListener("click", copyShareLink);

    el.savedViewsSelect.addEventListener("change", () => {
      const name = el.savedViewsSelect.value;
      if (name) el.viewName.value = name;
    });

    el.source.addEventListener("change", updateSourceInputs);
    el.layout.addEventListener("change", () => {
      if (state.analysis) renderGraph(state.analysis);
    });

    const filterUpdate = () => {
      if (state.analysis) renderGraph(state.analysis);
    };
    el.graphNamespace.addEventListener("change", filterUpdate);
    el.graphSearch.addEventListener("input", filterUpdate);
    el.graphRiskyOnly.addEventListener("change", filterUpdate);

    el.fitGraphBtn.addEventListener("click", () => {
      resetGraphTransform();
      if (state.analysis) renderGraph(state.analysis);
    });

    for (const tab of el.tabs) {
      tab.addEventListener("click", () => switchTab(tab.dataset.tab));
    }
  }

  wireEvents();
  wireGraphInteractions();
  resetGraphTransform();
  applyViewFromURL();
  updateSourceInputs();

  refreshServerViews().catch((err) => {
    el.pageStatus.textContent = `Could not load server views: ${err.message}`;
  });

  checkSourceStatus();
})();
