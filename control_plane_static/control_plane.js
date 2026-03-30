(function () {
  async function getJson(path) {
    const response = await fetch(path);
    if (!response.ok) {
      throw new Error(`Request failed: ${response.status}`);
    }
    return response.json();
  }

  async function postJson(path, payload) {
    const response = await fetch(path, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload || {}),
    });
    const text = await response.text();
    let parsed = {};
    if (text) {
      try {
        parsed = JSON.parse(text);
      } catch (error) {
        throw new Error(`Request failed: ${response.status}`);
      }
    }
    if (!response.ok) {
      throw new Error(parsed.error || `Request failed: ${response.status}`);
    }
    return parsed;
  }

  function esc(value) {
    return String(value ?? "")
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;")
      .replace(/"/g, "&quot;");
  }

  function number(value, digits = 2) {
    const parsed = Number(value || 0);
    return Number.isFinite(parsed) ? parsed.toFixed(digits) : "0.00";
  }

  function setGeneratedAt(value) {
    const node = document.getElementById("generatedAt");
    if (node) node.textContent = `Updated ${value}`;
  }

  function severityClass(level) {
    if (level === "high") return "sev-high";
    if (level === "medium") return "sev-medium";
    return "sev-low";
  }

  function statusClass(level) {
    if (level === "validated") return "status-pill status-monitor";
    if (level === "tested") return "status-pill";
    if (level === "untested") return "status-pill status-coverage_gap";
    return `status-pill status-${String(level || "monitor")}`;
  }

  function chip(text, tone = "") {
    return `<span class="chip ${tone}">${esc(text)}</span>`;
  }

  function renderCards(containerId, cards) {
    const container = document.getElementById(containerId);
    if (!container) return;
    container.innerHTML = cards.map((card) => `
      <article class="card">
        <div class="card-label">${esc(card.label)}</div>
        <div class="card-value">${esc(card.value)}</div>
        <div class="card-meta">${esc(card.meta || "")}</div>
      </article>
    `).join("");
  }

  function renderTable(containerId, headers, rows, sortable = true) {
    const container = document.getElementById(containerId);
    if (!container) return;
    if (!rows.length) {
      container.innerHTML = `<div class="empty">No rows available.</div>`;
      return;
    }
    let sortCol = -1;
    let sortDir = "asc";
    function render() {
      const sorted = sortCol >= 0
        ? rows.slice().sort((a, b) => {
            const av = (a[sortCol] || "").replace(/<[^>]*>/g, "").trim();
            const bv = (b[sortCol] || "").replace(/<[^>]*>/g, "").trim();
            const an = parseFloat(av);
            const bn = parseFloat(bv);
            const cmp = (!isNaN(an) && !isNaN(bn)) ? an - bn : av.localeCompare(bv);
            return sortDir === "asc" ? cmp : -cmp;
          })
        : rows;
      const head = headers.map((header, i) => {
        if (!sortable) return `<th>${esc(header)}</th>`;
        const cls = sortCol === i ? `sortable sort-${sortDir}` : "sortable";
        return `<th class="${cls}" data-col="${i}">${esc(header)}<span class="sort-arrow"></span></th>`;
      }).join("");
      const body = sorted.map((row) => `<tr>${row.map((cell) => `<td>${cell}</td>`).join("")}</tr>`).join("");
      container.innerHTML = `<table><thead><tr>${head}</tr></thead><tbody>${body}</tbody></table>`;
      if (sortable) {
        container.querySelectorAll("th.sortable").forEach((th) => {
          th.addEventListener("click", () => {
            const col = Number(th.dataset.col);
            if (sortCol === col) sortDir = sortDir === "asc" ? "desc" : "asc";
            else { sortCol = col; sortDir = "asc"; }
            render();
          });
        });
      }
    }
    render();
  }

  function renderBarChart(containerId, rows, options = {}) {
    const container = document.getElementById(containerId);
    if (!container) return;
    if (!rows.length) {
      container.innerHTML = `<div class="empty">${esc(options.emptyMessage || "No data available.")}</div>`;
      return;
    }
    const maxValue = Math.max(...rows.map((row) => Number(row.value || 0)), 1);
    container.innerHTML = `
      <div class="bar-chart">
        ${rows.map((row) => {
          const width = Math.max(4, Math.round((Number(row.value || 0) / maxValue) * 100));
          return `
            <div class="bar-row">
              <div class="bar-copy">
                <strong>${esc(row.label)}</strong>
                <span>${esc(row.meta || "")}</span>
              </div>
              <div class="bar-track">
                <div class="bar-fill" style="width:${width}%"></div>
              </div>
              <div class="bar-value">${esc(row.display || number(row.value || 0, options.digits ?? 2))}</div>
            </div>
          `;
        }).join("")}
      </div>
    `;
  }

  function renderTrendChart(containerId, points) {
    const container = document.getElementById(containerId);
    if (!container) return;
    if (!points.length) {
      container.innerHTML = `<div class="empty">No evaluation trend available yet.</div>`;
      return;
    }
    const width = 920;
    const height = 260;
    const padLeft = 48;
    const padRight = 20;
    const padTop = 16;
    const padBottom = 36;
    const innerWidth = width - padLeft - padRight;
    const innerHeight = height - padTop - padBottom;
    const maxY = Math.max(10, ...points.map((item) => Math.max(Number(item.composite_score || 0), Number(item.asr || 0) * 10)));
    const scaleX = (index) => padLeft + ((points.length === 1 ? 0 : index / (points.length - 1)) * innerWidth);
    const scaleY = (value) => padTop + innerHeight - ((Number(value || 0) / maxY) * innerHeight);
    const linePath = (getter) => points.map((item, index) => `${index === 0 ? "M" : "L"} ${scaleX(index)} ${scaleY(getter(item))}`).join(" ");
    const grid = [0, maxY / 2, maxY].map((value) => {
      const y = scaleY(value);
      return `<g><line x1="${padLeft}" y1="${y}" x2="${width - padRight}" y2="${y}" stroke="rgba(21,33,44,0.10)" /><text x="8" y="${y + 4}" fill="#5b6771" font-size="11">${number(value, 1)}</text></g>`;
    }).join("");
    const labels = points.filter((_, index) => index === 0 || index === points.length - 1 || index === Math.floor(points.length / 2)).map((item, index, arr) => {
      const originalIndex = points.findIndex((point) => point.attack_id === item.attack_id);
      const x = scaleX(originalIndex);
      return `<text x="${x}" y="${height - 10}" text-anchor="${index === 0 ? "start" : (index === arr.length - 1 ? "end" : "middle")}" fill="#5b6771" font-size="11">${esc(item.attack_id)}</text>`;
    }).join("");
    container.innerHTML = `
      <div class="chart-frame">
        <svg viewBox="0 0 ${width} ${height}" width="100%" height="260" role="img" aria-label="Trend chart">
          ${grid}
          <path d="${linePath((item) => item.composite_score)}" fill="none" stroke="#0f766e" stroke-width="3" stroke-linecap="round"></path>
          <path d="${linePath((item) => Number(item.asr || 0) * 10)}" fill="none" stroke="#c2410c" stroke-width="2.5" stroke-linecap="round" stroke-dasharray="5 4"></path>
          ${points.map((item, index) => `
            <circle cx="${scaleX(index)}" cy="${scaleY(item.composite_score)}" r="4" fill="#0f766e"></circle>
            <circle cx="${scaleX(index)}" cy="${scaleY(Number(item.asr || 0) * 10)}" r="3.5" fill="#c2410c"></circle>
          `).join("")}
          ${labels}
        </svg>
        <div class="chart-caption">Composite score in teal. ASR x 10 in orange to keep both signals visible on one axis.</div>
      </div>
    `;
  }

  function renderRelationshipGraph(containerId, graph) {
    const container = document.getElementById(containerId);
    if (!container) return;
    if (!graph || !graph.nodes || !graph.nodes.length) {
      container.innerHTML = `<div class="empty">No relationship graph available.</div>`;
      return;
    }
    const width = 920;
    const height = 360;
    const columns = {};
    graph.nodes.forEach((node) => {
      const key = Number(node.column || 0);
      if (!columns[key]) columns[key] = [];
      columns[key].push(node);
    });
    const columnKeys = Object.keys(columns).map(Number).sort((a, b) => a - b);
    const columnCount = Math.max(columnKeys.length, 1);
    const positions = {};
    columnKeys.forEach((column, columnIndex) => {
      const nodes = columns[column];
      const x = 120 + ((columnIndex / Math.max(columnCount - 1, 1)) * 680);
      const step = height / (nodes.length + 1);
      nodes.forEach((node, nodeIndex) => {
        positions[node.id] = { x, y: step * (nodeIndex + 1) };
      });
    });
    const colorFor = (node) => {
      if (node.kind === "target") return "#13212c";
      if (node.kind === "category") return node.severity === "high" ? "#9a3412" : "#0f766e";
      if (node.kind === "owasp") return "#2563eb";
      return "#c2410c";
    };
    const edges = graph.edges.map((edge) => {
      const source = positions[edge.source];
      const target = positions[edge.target];
      if (!source || !target) return "";
      return `<line x1="${source.x}" y1="${source.y}" x2="${target.x}" y2="${target.y}" stroke="rgba(21,33,44,0.18)" stroke-width="2" />`;
    }).join("");
    const nodes = graph.nodes.map((node) => {
      const pos = positions[node.id];
      if (!pos) return "";
      return `
        <g>
          <circle cx="${pos.x}" cy="${pos.y}" r="16" fill="${colorFor(node)}" />
          <text x="${pos.x}" y="${pos.y + 34}" text-anchor="middle" fill="#15212c" font-size="12">${esc(node.label)}</text>
        </g>
      `;
    }).join("");
    container.innerHTML = `
      <div class="graph-frame">
        <svg viewBox="0 0 ${width} ${height}" width="100%" height="360" role="img" aria-label="Relationship graph">
          ${edges}
          ${nodes}
        </svg>
        <div class="chart-caption">Target to category, then category to OWASP and MITRE ATLAS mappings.</div>
      </div>
    `;
  }

  function renderList(containerId, items, emptyMessage = "No items available.") {
    const container = document.getElementById(containerId);
    if (!container) return;
    container.innerHTML = items.length ? items.join("") : `<div class="empty">${esc(emptyMessage)}</div>`;
  }

  function openModal(modalId) {
    const modal = document.getElementById(modalId);
    if (modal) {
      modal.classList.add("open");
      modal.setAttribute("aria-hidden", "false");
    }
    document.body.style.overflow = "hidden";
  }

  function closeModal(modalId) {
    const modal = document.getElementById(modalId);
    if (modal) {
      modal.classList.remove("open");
      modal.setAttribute("aria-hidden", "true");
    }
    document.body.style.overflow = "";
  }

  function initModals() {
    document.querySelectorAll(".modal-backdrop").forEach((backdrop) => {
      backdrop.addEventListener("click", (e) => {
        if (e.target === backdrop) closeModal(backdrop.id);
      });
    });
    document.addEventListener("keydown", (e) => {
      if (e.key === "Escape") {
        document.querySelectorAll(".modal-backdrop.open").forEach((m) => closeModal(m.id));
      }
    });
  }

  function initCollapsible() {
    document.querySelectorAll(".panel[data-collapsible]").forEach((panel) => {
      const head = panel.querySelector(".panel-head");
      if (!head) return;
      if (!head.querySelector(".collapse-chevron")) {
        const chevron = document.createElement("span");
        chevron.className = "collapse-chevron";
        chevron.textContent = "\u25BC";
        head.appendChild(chevron);
      }
      head.addEventListener("click", (e) => {
        if (e.target.closest("a, button:not(.collapse-chevron)")) return;
        panel.classList.toggle("collapsed");
        const key = "collapse:" + (panel.dataset.collapsible || panel.querySelector("h2")?.textContent || "");
        try { sessionStorage.setItem(key, panel.classList.contains("collapsed") ? "1" : "0"); } catch (err) {}
      });
      const key = "collapse:" + (panel.dataset.collapsible || panel.querySelector("h2")?.textContent || "");
      try {
        const saved = sessionStorage.getItem(key);
        if (saved === "1") panel.classList.add("collapsed");
        else if (saved === "0") panel.classList.remove("collapsed");
      } catch (err) {}
    });
  }

  function initTabs(barId, storageKey) {
    const bar = document.getElementById(barId);
    if (!bar) return;
    bar.querySelectorAll(".tab-btn").forEach((btn) => {
      btn.addEventListener("click", () => {
        bar.querySelectorAll(".tab-btn").forEach((b) => b.classList.remove("active"));
        btn.classList.add("active");
        const target = btn.dataset.tab;
        document.querySelectorAll(`[data-tab-group='${barId}']`).forEach((tc) => {
          tc.classList.toggle("active", tc.dataset.tabId === target);
        });
        try { sessionStorage.setItem(storageKey, target); } catch (err) {}
      });
    });
    try {
      const saved = sessionStorage.getItem(storageKey);
      if (saved) {
        const savedBtn = bar.querySelector(`[data-tab='${saved}']`);
        if (savedBtn) { savedBtn.click(); return; }
      }
    } catch (err) {}
    const first = bar.querySelector(".tab-btn");
    if (first) first.click();
  }

  function renderPaginatedTable(containerId, headers, rows, pageSize = 20) {
    const container = document.getElementById(containerId);
    if (!container) return;
    if (!rows.length) {
      container.innerHTML = "<div class='empty'>No rows available.</div>";
      return;
    }
    let page = 0;
    const totalPages = Math.ceil(rows.length / pageSize);
    function render() {
      const start = page * pageSize;
      const slice = rows.slice(start, start + pageSize);
      const head = headers.map((h) => `<th>${esc(h)}</th>`).join("");
      const body = slice.map((row) => `<tr>${row.map((cell) => `<td>${cell}</td>`).join("")}</tr>`).join("");
      container.innerHTML = `<table><thead><tr>${head}</tr></thead><tbody>${body}</tbody></table>
        <div class="pagination">
          <button class="pg-prev"${page <= 0 ? " disabled" : ""}>Prev</button>
          <span>Page ${page + 1} of ${totalPages} (${rows.length} total)</span>
          <button class="pg-next"${page >= totalPages - 1 ? " disabled" : ""}>Next</button>
        </div>`;
      container.querySelector(".pg-prev")?.addEventListener("click", () => { if (page > 0) { page -= 1; render(); } });
      container.querySelector(".pg-next")?.addEventListener("click", () => { if (page < totalPages - 1) { page += 1; render(); } });
    }
    render();
  }

  function initExpandToggles() {
    document.addEventListener("click", (e) => {
      const toggle = e.target.closest(".expand-toggle");
      if (!toggle) return;
      const target = toggle.previousElementSibling;
      if (!target) return;
      const expanded = target.classList.toggle("expanded");
      toggle.textContent = expanded ? "Show less" : "Show more";
    });
  }

  function showLoading(containerId, message = "Loading…") {
    const el = document.getElementById(containerId);
    if (el) el.innerHTML = `<div class="loading-spinner">${esc(message)}</div>`;
  }

  (function initToastContainer() {
    if (!document.getElementById("toastContainer")) {
      const div = document.createElement("div");
      div.id = "toastContainer";
      div.className = "toast-container";
      document.body.appendChild(div);
    }
  })();

  function showToast(message, level = "ok", duration = 3000) {
    const container = document.getElementById("toastContainer");
    if (!container) return;
    const toast = document.createElement("div");
    toast.className = `toast toast-${level}`;
    toast.textContent = message;
    container.appendChild(toast);
    setTimeout(() => {
      toast.style.opacity = "0";
      toast.style.transform = "translateY(12px)";
      toast.style.transition = "opacity 0.25s, transform 0.25s";
      setTimeout(() => toast.remove(), 300);
    }, duration);
  }

  function confirmAction(message, onConfirm) {
    const existing = document.getElementById("confirmModal");
    if (existing) existing.remove();
    const backdrop = document.createElement("div");
    backdrop.id = "confirmModal";
    backdrop.className = "modal-backdrop open";
    backdrop.innerHTML = `<div class="modal-dialog" style="max-width:440px;text-align:center;padding:32px 28px;">
      <p style="margin:0 0 20px;font-size:15px;line-height:1.5;">${esc(message)}</p>
      <div style="display:flex;gap:12px;justify-content:center;">
        <button class="btn secondary" id="confirmCancel">Cancel</button>
        <button class="btn primary" id="confirmOk" style="background:var(--risk-high);border-color:var(--risk-high);color:#fff;">Confirm</button>
      </div>
    </div>`;
    document.body.appendChild(backdrop);
    document.body.style.overflow = "hidden";
    function close() { backdrop.remove(); document.body.style.overflow = ""; }
    backdrop.addEventListener("click", (e) => { if (e.target === backdrop) close(); });
    document.getElementById("confirmCancel")?.addEventListener("click", close);
    document.getElementById("confirmOk")?.addEventListener("click", () => { close(); onConfirm(); });
  }

  function renderSearchablePaginatedTable(containerId, headers, rows, rawData, searchFields, pageSize = 20) {
    const container = document.getElementById(containerId);
    if (!container) return;
    let filtered = rows;
    let page = 0;
    const searchId = `${containerId}_search`;
    function render() {
      const totalPages = Math.max(1, Math.ceil(filtered.length / pageSize));
      if (page >= totalPages) page = totalPages - 1;
      const start = page * pageSize;
      const slice = filtered.slice(start, start + pageSize);
      const head = headers.map((h) => `<th>${esc(h)}</th>`).join("");
      const body = slice.length
        ? slice.map((row) => `<tr>${row.map((cell) => `<td>${cell}</td>`).join("")}</tr>`).join("")
        : `<tr><td colspan="${headers.length}" class="muted" style="text-align:center;padding:18px;">No matching rows.</td></tr>`;
      container.innerHTML = `<div class="search-bar">
        <input type="text" id="${searchId}" placeholder="Filter by technique, category, attack ID…" />
        <span class="search-count">${filtered.length} of ${rows.length}</span>
      </div>
      <table><thead><tr>${head}</tr></thead><tbody>${body}</tbody></table>
      <div class="pagination">
        <button class="pg-prev"${page <= 0 ? " disabled" : ""}>Prev</button>
        <span>Page ${page + 1} of ${totalPages}</span>
        <button class="pg-next"${page >= totalPages - 1 ? " disabled" : ""}>Next</button>
      </div>`;
      const searchInput = document.getElementById(searchId);
      if (searchInput) {
        searchInput.addEventListener("input", (e) => {
          const q = e.target.value.toLowerCase().trim();
          filtered = !q ? rows : rows.filter((_, i) => {
            const data = rawData[i];
            return searchFields.some((field) => String(data[field] || "").toLowerCase().includes(q));
          });
          page = 0;
          render();
          const newInput = document.getElementById(searchId);
          if (newInput) { newInput.value = e.target.value; newInput.focus(); }
        });
      }
      container.querySelector(".pg-prev")?.addEventListener("click", () => { if (page > 0) { page -= 1; render(); } });
      container.querySelector(".pg-next")?.addEventListener("click", () => { if (page < totalPages - 1) { page += 1; render(); } });
    }
    if (!rows.length) {
      container.innerHTML = "<div class='empty'>No rows available.</div>";
      return;
    }
    render();
  }

  function copyToClipboard(text, buttonEl) {
    navigator.clipboard.writeText(text).then(() => {
      if (buttonEl) {
        const prev = buttonEl.textContent;
        buttonEl.textContent = "Copied!";
        buttonEl.classList.add("copied");
        setTimeout(() => {
          buttonEl.textContent = prev;
          buttonEl.classList.remove("copied");
        }, 1500);
      }
    }).catch(() => {});
  }

  function initCopyButtons() {
    document.addEventListener("click", (e) => {
      const btn = e.target.closest(".copy-btn");
      if (!btn) return;
      const target = btn.dataset.copyTarget;
      const el = target ? document.getElementById(target) : btn.previousElementSibling;
      if (el) copyToClipboard(el.textContent, btn);
    });
  }

  function initThemeToggle() {
    const saved = localStorage.getItem("theme");
    if (saved) document.documentElement.setAttribute("data-theme", saved);
    document.querySelectorAll(".theme-toggle").forEach((btn) => {
      btn.textContent = document.documentElement.getAttribute("data-theme") === "dark" ? "Light" : "Dark";
      btn.addEventListener("click", () => {
        const next = document.documentElement.getAttribute("data-theme") === "dark" ? "light" : "dark";
        document.documentElement.setAttribute("data-theme", next);
        localStorage.setItem("theme", next);
        btn.textContent = next === "dark" ? "Light" : "Dark";
      });
    });
  }

  window.getJson = getJson;
  window.postJson = postJson;
  window.esc = esc;
  window.number = number;
  window.setGeneratedAt = setGeneratedAt;
  window.severityClass = severityClass;
  window.statusClass = statusClass;
  window.chip = chip;
  window.renderCards = renderCards;
  window.renderTable = renderTable;
  window.renderBarChart = renderBarChart;
  window.renderTrendChart = renderTrendChart;
  window.renderRelationshipGraph = renderRelationshipGraph;
  window.renderList = renderList;
  window.openModal = openModal;
  window.closeModal = closeModal;
  window.initModals = initModals;
  window.initCollapsible = initCollapsible;
  window.initTabs = initTabs;
  window.renderPaginatedTable = renderPaginatedTable;
  window.initExpandToggles = initExpandToggles;
  window.showLoading = showLoading;
  window.showToast = showToast;
  window.confirmAction = confirmAction;
  window.renderSearchablePaginatedTable = renderSearchablePaginatedTable;
  window.copyToClipboard = copyToClipboard;
  window.initCopyButtons = initCopyButtons;
  window.initThemeToggle = initThemeToggle;
  window.AGENTBREAKER_REFRESH = async function () {
    if (typeof window.initialize === "function") {
      await window.initialize();
      return;
    }
    window.location.reload();
  };

  initThemeToggle();
  initCopyButtons();
})();
