const API_BASE = "";

const TABS = [
  { key: "scan", label: "Scan" },
  { key: "cve", label: "CVE" },
  { key: "mqtt", label: "MQTT" },
  { key: "ipcam", label: "IP CAM" },
  { key: "listening", label: "Hosts en écoute" },
  { key: "avance", label: "Avancé" },
];

const AVANCE_SUBREFS = [
  { key: "unify", label: "Unifier", test: (h) => true },
  { key: "cisco", label: "Cisco", test: (h) => matchesKeyword(h, "cisco") },
  { key: "firewall", label: "Firewall", test: (h) => matchesKeyword(h, "firewall|pfsense|opnsense|forti|ipsec") },
  { key: "onduleur", label: "Onduleur", test: (h) => hostCategories(h).includes("onduleur") || matchesKeyword(h, "onduleur|ups|apc") },
  { key: "solaire", label: "Solaire", test: (h) => hostCategories(h).includes("onduleur") || matchesKeyword(h, "sma|solar|inverter|victron|fronius|solis|sun") },
];

let activeTab = "scan";
let activeSubref = "unify";
let allHosts = [];
let hostModalHost = null;
let hostModalTab = "overview";
let hostModalOverviewHtml = "";
let globalAnon = false;
try { globalAnon = window.localStorage.getItem("ns-global-anon") === "1"; } catch (e) { globalAnon = false; }
const cveCache = {};

function $(sel) { return document.querySelector(sel); }

function escapeHtml(s) {
  if (s === null || s === undefined) return "";
  return String(s)
    .replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;").replace(/'/g, "&#39;");
}

function parseJsonField(val) {
  if (val === null || val === undefined) return null;
  if (Array.isArray(val)) return val;
  if (typeof val === "object") return val;
  if (typeof val === "string") {
    if (val.trim() === "") return null;
    try { return JSON.parse(val); } catch { return null; }
  }
  return null;
}

function toList(val) {
  const parsed = parseJsonField(val);
  if (parsed === null) return [];
  if (Array.isArray(parsed)) return parsed;
  return [parsed];
}

function hostCategories(h) {
  const cls = h.classifications || [];
  const cats = cls.map((c) => (c && c.category ? String(c.category).toLowerCase() : null));
  return cats.length === 0 ? ["unknown"] : cats;
}

function primaryCategory(h) {
  return hostCategories(h)[0] || "unknown";
}

function hostKeywords(h) {
  return [
    h.hostname || h.host_name,
    h.vendor,
    h.banner,
    h.os_guess || h.os,
    h.protocol,
    (h.classifications || []).map((c) => (c && c.rule) ? String(c.rule) : null),
  ]
    .filter(Boolean)
    .join(" ")
    .toLowerCase();
}

function matchesKeyword(h, pattern) {
  try {
    return new RegExp(pattern, "i").test(hostKeywords(h));
  } catch {
    return hostKeywords(h).includes(pattern);
  }
}

function severityClass(sev) {
  const s = String(sev || "").toLowerCase();
  if (s.includes("crit")) return "sev-critical";
  if (s === "high" || s.includes("high")) return "sev-high";
  if (s === "low" || s.includes("low")) return "sev-low";
  return "sev-medium";
}

function renderPortChips(openPortsRaw) {
  const ports = toList(openPortsRaw);
  if (ports.length === 0) return '<span class="port-chip port-none">—</span>';
  return ports
    .map((p) => {
      const label = String(p).trim();
      return `<span class="port-chip" title="Port ${escapeHtml(label)}">${escapeHtml(label)}</span>`;
    })
    .join(" ");
}

function renderCveBadges(cvesRaw) {
  const cves = toList(cvesRaw);
  if (cves.length === 0) return '<span class="cve-none">Aucune CVE</span>';
  return cves
    .map((c) => {
      const id = (c && (c.cve || c.cve_id || c.id)) ? String(c.cve || c.cve_id || c.id) : "CVE";
      const sev = c && c.severity ? String(c.severity) : "";
      const note = c && c.note ? String(c.note) : "";
      const title = [id, sev ? "sévérité: " + sev : "", note, "Cliquer pour le détail"].filter(Boolean).join(" — ");
      return `<button type="button" class="cve-badge ${severityClass(sev)} cve-clickable" data-cve="${escapeHtml(id)}" title="${escapeHtml(title)}">${escapeHtml(id)}</button>`;
    })
    .join(" ");
}

function renderStatusBadges(h) {
  const parts = [];
  if (h.online) {
    parts.push('<span class="host-badge badge-online" title="Hote detecte lors du dernier scan">ONLINE</span>');
  } else {
    parts.push('<span class="host-badge badge-offline" title="Hote non detecte lors du dernier scan">OFFLINE</span>');
  }
  if (h.is_new) {
    parts.push('<span class="host-badge badge-new" title="Nouveau hote depuis le dernier scan">NEW</span>');
  }
  if (h.is_sniffing) {
    parts.push('<span class="host-badge badge-sniffing" title="Detecte comme possible sniffer (mode promiscu)">&#128270; SNIFFING</span>');
  }
  return parts.join("");
}

function renderSniffingEvidence(h) {
  const evs = toList(h.sniffing_evidence);
  const rows = evs
    .map((e) => {
      if (!e || typeof e !== "object") return "";
      return `<div class="hd-ev-row mono">
        <span class="ev-label">MAC</span><span>${escapeHtml(e.mac || "—")}</span>
        <span class="ev-label">IP probe</span><span>${escapeHtml(e.random_ip || "—")}</span>
        <span class="ev-label">Horodatage</span><span>${escapeHtml(e.ts || "—")}</span>
      </div>`;
    })
    .join("");
  if (!rows) return "";
  return `<div class="hd-section hd-sniffing">
    <h4 class="hd-heading hud-alert-heading">&#128270; Preuves d'ecoute passive (sniffing)</h4>
    <p class="hd-ev-note">Cet hote a repondu a des requetes ARP vers des adresses IPs aléatoires inexistantes. Un hote normal ignore ces trames : cette reponse indique une possible capture du trafic (mode promiscu ou outil d'analyse).</p>
    <div class="hd-ev-list">${rows}</div>
  </div>`;
}

function renderCompliance(h) {
  const items = toList(h.compliance);
  if (items.length === 0) return "";
  const chips = items
    .map((c) => {
      if (!c || typeof c !== "object") return "";
      const sev = c.severity ? String(c.severity) : "";
      const label = c.check ? String(c.check) : "conformité";
      const msg = c.message ? String(c.message) : "";
      return `<span class="comp-chip comp-${escapeHtml(sev.toLowerCase())}" title="${escapeHtml(msg || label)}">${escapeHtml(label)}</span>`;
    })
    .join(" ");
  return `<div class="host-row host-compliance"><span class="key">Conformité</span><span class="val">${chips}</span></div>`;
}

function renderClassificationChips(h) {
  const cls = h.classifications || [];
  if (cls.length === 0) return '<span class="chip chip-default">inconnu</span>';
  return cls
    .map((c) => {
      const cat = (c && c.category) ? String(c.category).toLowerCase() : "unknown";
      const rule = (c && (c.matched_rule || c.rule)) ? String(c.matched_rule || c.rule) : "";
      const title = rule ? `rule: ${rule}` : cat;
      return `<span class="chip cat-${escapeHtml(cat)}" title="${escapeHtml(title)}">${escapeHtml(cat)}</span>`;
    })
    .join(" ");
}

function renderServiceTable(h) {
  const services = toList(h.services);
  if (services.length === 0) return "";
  const rows = services
    .map((s) => {
      if (!s || typeof s !== "object") return "";
      const port = s.port !== null && s.port !== undefined ? escapeHtml(s.port) : "—";
      const name = s.name ? escapeHtml(s.name) : "—";
      const product = [s.product, s.version].filter(Boolean).map(escapeHtml).join(" ") || "—";
      const mfr = s.manufacturer ? escapeHtml(s.manufacturer) : "—";
      return `<tr><td class="svc-port mono">${port}</td><td>${name}</td><td>${product}</td><td>${mfr}</td></tr>`;
    })
    .join("");
  return `<div class="host-row host-services">
    <span class="key">Services</span>
    <span class="val"><table class="service-table">
      <thead><tr><th>Port</th><th>Nom</th><th>Produit</th><th>Fabricant</th></tr></thead>
      <tbody>${rows}</tbody>
    </table></span>
  </div>`;
}

function collectCredentials(h) {
  const seen = new Set();
  const out = [];
  const push = (c) => {
    if (!c || typeof c !== "object") return;
    const user = c.username !== null && c.username !== undefined ? String(c.username) : "";
    const pass = c.password !== null && c.password !== undefined ? String(c.password) : "";
    const key = user + "\u0000" + pass;
    if (seen.has(key)) return;
    seen.add(key);
    out.push({ user, pass, note: c.note ? String(c.note) : "" });
  };
  (h.classifications || []).forEach((c) => {
    toList(c && c.default_credentials).forEach(push);
  });
  toList(h.services).forEach((s) => {
    if (s && typeof s === "object") toList(s.default_credentials).forEach(push);
  });
  return out;
}

function renderCredentials(h) {
  const creds = collectCredentials(h);
  if (creds.length === 0) return "";
  const items = creds
    .map((c) => {
      const note = c.note ? `<span class="cred-note">${escapeHtml(c.note)}</span>` : "";
      return `<span class="cred-item" title="Identifiants par défaut">${escapeHtml(c.user)} <span class="cred-sep">/</span> ${escapeHtml(c.pass)}${note}</span>`;
    })
    .join(" ");
  return `<div class="host-row host-creds"><span class="key">Credos</span><span class="val">${items}</span></div>`;
}

function buildHostRow(h) {
  const ip = h.ip_address || h.ip || "…";
  const mac = h.mac_address || h.mac || "";
  const hostname = h.hostname || h.host_name || "";
  const vendor = h.vendor || "";
  const openPorts = toList(h.open_ports !== undefined ? h.open_ports : h.ports);
  const online = !!h.online;
  const dispIp = globalAnon ? maskIPv4(ip) : ip;
  const dispHost = globalAnon && hostname ? maskHostname(hostname) : hostname;
  return `<tr data-ip="${escapeHtml(ip)}" class="host-row-interactive${online ? "" : " row-offline"}">
    <td class="mono">${escapeHtml(dispIp)}</td>
    <td>${dispHost ? escapeHtml(dispHost) : "—"}</td>
    <td class="mono">${mac ? escapeHtml(mac) : "—"}</td>
    <td>${vendor ? escapeHtml(vendor) : "—"}</td>
    <td><span class="chip cat-${escapeHtml(primaryCategory(h))}">${escapeHtml(primaryCategory(h))}</span></td>
    <td class="port-cell">${openPorts.length > 0 ? openPorts.length + " port(s)" : "—"}</td>
    <td>${renderStatusBadges(h)}</td>
  </tr>`;
}

function passesSearch(h) {
  const q = ($("#host-filter") && $("#host-filter").value || "").trim().toLowerCase();
  if (!q) return true;
  const hay = [
    h.ip_address || h.ip,
    h.mac_address || h.mac,
    h.hostname,
    h.vendor,
    h.os_guess || h.os,
    h.banner,
    (h.classifications || []).map((c) => (c && c.category) ? String(c.category) : null),
  ]
    .filter(Boolean)
    .join(" ")
    .toLowerCase();
  return hay.includes(q);
}

function matchesTab(h, tab) {
  switch (tab) {
    case "scan":
      return true;
    case "cve":
      return toList(h.cves).length > 0;
    case "mqtt":
      return hostCategories(h).includes("mqtt");
    case "ipcam":
      return hostCategories(h).includes("camera");
    case "listening":
      return toList(h.open_ports !== undefined ? h.open_ports : h.ports).length > 0;
    case "avance": {
      const subref = AVANCE_SUBREFS.find((s) => s.key === activeSubref) || AVANCE_SUBREFS[0];
      return subref.test(h);
    }
    default:
      return true;
  }
}

function getFilteredHosts() {
  return allHosts.filter((h) => passesSearch(h) && matchesTab(h, activeTab));
}

function tabCounts() {
  const counts = {};
  for (const t of TABS) counts[t.key] = 0;
  for (const h of allHosts) {
    if (!passesSearch(h)) continue;
    for (const t of TABS) {
      if (matchesTab(h, t.key)) counts[t.key] += 1;
    }
  }
  return counts;
}

function renderNav() {
  const bar = $("#main-nav");
  if (!bar) return;
  const counts = tabCounts();
  bar.innerHTML = TABS.map((t) => {
    const active = t.key === activeTab ? " active" : "";
    return `<button type="button" class="nav-tab${active}" data-tab="${t.key}">${t.label} <span class="nav-count">${counts[t.key]}</span></button>`;
  }).join("");
  bar.querySelectorAll(".nav-tab").forEach((b) => {
    b.addEventListener("click", () => {
      activeTab = b.dataset.tab;
      if (activeTab === "avance") activeSubref = "unify";
      renderAll();
    });
  });
}

function renderSubrefs() {
  const bar = $("#subref-bar");
  if (!bar) return;
  if (activeTab !== "avance") {
    bar.hidden = true;
    bar.innerHTML = "";
    return;
  }
  bar.hidden = false;
  bar.innerHTML = AVANCE_SUBREFS.map((s) => {
    const active = s.key === activeSubref ? " active" : "";
    return `<button type="button" class="subref${active}" data-subref="${s.key}">${s.label}</button>`;
  }).join("");
  bar.querySelectorAll(".subref").forEach((b) => {
    b.addEventListener("click", () => {
      activeSubref = b.dataset.subref;
      renderAll();
    });
  });
}

function renderResults() {
  const filtered = getFilteredHosts();
  const container = $("#hosts-tbody");
  const empty = $("#hosts-empty");
  const count = $("#scan-count");
  const title = $("#results-title");
  if (count) count.textContent = String(filtered.length);

  const tab = TABS.find((t) => t.key === activeTab);
  if (title) {
    title.textContent = activeTab === "avance"
      ? `Avancé — ${(AVANCE_SUBREFS.find((s) => s.key === activeSubref) || {}).label || "Unifier"}`
      : (tab ? tab.label : "Hosts");
  }

  if (container) {
    if (filtered.length === 0) {
      container.innerHTML = "";
      if (empty) empty.hidden = false;
    } else {
      if (empty) empty.hidden = true;
      container.innerHTML = filtered.map(buildHostRow).join("");
    }
  }
}

function renderAll() {
  renderNav();
  renderSubrefs();
  renderResults();
}

function setScanLoading(loading) {
  const btn = $("#scan-btn");
  const label = btn ? btn.querySelector(".btn-label") : null;
  const spin = btn ? btn.querySelector(".spinner") : null;
  if (btn) btn.disabled = loading;
  if (label) label.textContent = loading ? "Scan en cours…" : "Scanner";
  if (spin) spin.hidden = !loading;
}

async function checkStatus() {
  const pill = $("#api-status");
  const text = $("#api-status-text");
  try {
    const r = await fetch(`${API_BASE}/status`);
    const d = await r.json();
    if (pill) pill.classList.add("online");
    if (text) text.textContent = "API en ligne";
    const ver = $("#api-version");
    if (ver && d.version) ver.textContent = d.version;
  } catch (e) {
    if (pill) {
      pill.classList.remove("online");
      pill.classList.add("offline");
    }
    if (text) text.textContent = "API hors ligne";
    const ver = $("#api-version");
    if (ver) ver.textContent = "…";
  }
}

const SCAN_POLL_INTERVAL = 2000;

function renderScanResults(hosts) {
  allHosts = Array.isArray(hosts) ? hosts : [];
  activeTab = "scan";
  renderAll();
  const panel = $("#results-panel");
  if (panel) panel.scrollIntoView({ behavior: "smooth", block: "start" });
}

function pollScanStatus(scanId) {
  return new Promise((resolve, reject) => {
    const timer = setInterval(async () => {
      try {
        const r = await fetch(`${API_BASE}/scan/${scanId}`);
        if (!r.ok) {
          let msg = r.status + " " + r.statusText;
          try { const d = await r.json(); if (d && d.detail) msg = d.detail; } catch {}
          clearInterval(timer);
          reject(new Error(msg));
          return;
        }
        const d = await r.json();
        if (d.status === "completed") {
          clearInterval(timer);
          resolve(d.hosts || []);
        } else if (d.status === "error") {
          clearInterval(timer);
          reject(new Error(d.error || "Erreur inconnue du scan"));
        }
      } catch (e) {
        clearInterval(timer);
        reject(e);
      }
    }, SCAN_POLL_INTERVAL);
  });
}

async function startScan() {
  const cidr = $("#cidr").value.trim();
  if (!cidr) return;
  const err = $("#scan-error");
  if (err) { err.hidden = true; err.textContent = ""; }

  setScanLoading(true);
  try {
    const iface = $("#iface").value || "";
    const body = { cidr };
    if (iface) body.iface = iface;
    const r = await fetch(`${API_BASE}/scan`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(body),
    });
    if (!r.ok) {
      let msg = r.status + " " + r.statusText;
      try { const d = await r.json(); if (d && d.detail) msg = d.detail; } catch {}
      throw new Error(msg);
    }
    const d = await r.json();
    const scanId = d.scan_id;
    if (!scanId) throw new Error("scan_id manquant dans la réponse");

    const hosts = await pollScanStatus(scanId);
    renderScanResults(hosts);
  } catch (e) {
    if (err) {
      err.hidden = false;
      err.textContent = "Erreur de scan: " + (e && e.message ? e.message : String(e));
    }
  } finally {
    setScanLoading(false);
  }
}

async function loadHistory() {
  const err = $("#hosts-error");
  try {
    const r = await fetch(`${API_BASE}/hosts`);
    if (!r.ok) throw new Error(r.status + " " + r.statusText);
    const d = await r.json();
    allHosts = Array.isArray(d) ? d : (d.hosts || []);
    if (err) err.hidden = true;
    renderAll();
  } catch (e) {
    if (err) {
      err.hidden = false;
      err.textContent = (e && e.message) ? e.message : String(e);
    }
    allHosts = [];
    const container = $("#hosts-tbody");
    if (container) container.innerHTML = "";
  }
}

async function openCveModal(cveId) {
  const modal = $("#cve-modal");
  if (!modal) return;
  modal.classList.add("open");
  const title = $("#cve-modal-title");
  const desc = $("#cve-modal-desc");
  const refs = $("#cve-modal-refs");
  const rem = $("#cve-modal-rem");
  const meta = $("#cve-modal-meta");
  const foot = $("#cve-modal-foot");
  if (title) title.textContent = cveId;
  if (desc) desc.textContent = "Chargement...";
  if (refs) refs.innerHTML = "";
  if (rem) rem.innerHTML = "";
  if (meta) meta.innerHTML = "";
  if (foot) foot.innerHTML = "";
  try {
    const r = await fetch(`${API_BASE}/cves/${encodeURIComponent(cveId)}`);
    if (!r.ok) throw new Error("HTTP " + r.status);
    const d = await r.json();
    const sev = d.severity ? String(d.severity) : "";
    const cvss = d.cvss ? String(d.cvss) : "";
    if (title) title.textContent = d.cve || cveId;
    if (desc) desc.textContent = d.description || "Aucune description disponible";
    if (meta) {
      const parts = [];
      if (sev) parts.push(`<span class="sev-pill sev-${escapeHtml(sev.toLowerCase())}">${escapeHtml(sev)}</span>`);
      if (cvss) parts.push(`<span class="cvss-pill">CVSS ${escapeHtml(cvss)}</span>`);
      meta.innerHTML = parts.join(" ");
    }
    if (refs) {
      const refsArr = toList(d.references);
      if (refsArr.length === 0) {
        refs.innerHTML = "<span class='cve-none'>Aucune référence</span>";
      } else {
        refs.innerHTML = refsArr
          .map((u) => `<li><a href="${escapeHtml(String(u))}" target="_blank" rel="noopener noreferrer">${escapeHtml(String(u))}</a></li>`)
          .join("");
      }
    }
    if (rem) rem.innerHTML = d.remediation ? escapeHtml(String(d.remediation)) : "<span class='cve-none'>—</span>";
    if (foot) {
      const nvd = d.nvd_url || "https://nvd.nist.gov/vulnerabilities/detail/" + encodeURIComponent(cveId);
      foot.innerHTML = `<a class="btn nvd-btn" href="${escapeHtml(nvd)}" target="_blank" rel="noopener noreferrer">Ouvrir dans NVD</a>`;
    }
  } catch (e) {
    if (desc) desc.textContent = "Erreur: " + ((e && e.message) ? e.message : String(e));
    if (refs) refs.innerHTML = "";
    if (rem) rem.innerHTML = "";
    if (meta) meta.innerHTML = "";
  }
}

function closeCveModal() {
  const modal = $("#cve-modal");
  if (modal) modal.classList.remove("open");
}

function findHostByIp(ip) {
  return allHosts.find((h) => (h.ip_address || h.ip) === ip) || null;
}

function hostCveList(h) {
  return toList(h && h.cves !== undefined ? h.cves : null);
}

function hostCveId(c) {
  return (c && (c.cve || c.cve_id || c.id)) ? String(c.cve || c.cve_id || c.id) : "";
}

function maskIPv4(s) {
  return String(s).replace(/\b(\d{1,3}\.\d{1,3})\.\d{1,3}\.\d{1,3}\b/g, "$1.*.*");
}

function maskHostname(name) {
  const n = String(name);
  const parts = n.split(".");
  if (parts.length <= 1) return "***." + (n.split(".")[0] || "").slice(0, 2) + ".***";
  return parts.map((p, i) => (i === parts.length - 1 ? p : "***")).join(".");
}

function anonymizeHtml(html) {
  let out = String(html);
  out = out.replace(/\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b/g, (m) => maskIPv4(m));
  out = out.replace(/\b[a-zA-Z][a-zA-Z0-9-]*(?:\.[a-zA-Z0-9-]+)*\.[a-zA-Z]{2,}\b/g, (m) => maskHostname(m));
  return out;
}

function maybeAnon(html) {
  const s = String(html);
  return globalAnon ? anonymizeHtml(s) : s;
}

function updateGlobalAnonBtn() {
  const btn = $("#global-anon-btn");
  if (!btn) return;
  btn.classList.toggle("active", globalAnon);
  btn.textContent = globalAnon ? "Afficher l'original" : "Anonymiser";
}

function buildHostOverview(h) {
  const sections = [];

  const badges = renderStatusBadges(h);
  const infoRows = [
    ["IP", h.ip_address || h.ip || ""],
    ["MAC", h.mac_address || h.mac || ""],
    ["Constructeur", h.vendor || ""],
    ["OS", h.os_guess || h.os || ""],
    ["TTL", (h.ttl !== undefined && h.ttl !== null) ? String(h.ttl) : ""],
    ["Banner", h.banner || ""],
    ["Première détection", h.first_seen || ""],
    ["Dernière détection", h.last_seen || ""],
  ].filter((r) => r[1]);
  if (badges || infoRows.length) {
    sections.push(`<div class="hd-section">
      ${badges ? `<div class="hd-badges">${badges}</div>` : ""}
      <div class="hd-info">
        ${infoRows.map((r) => `<div class="hd-row"><span class="hd-key">${escapeHtml(r[0])}</span><span class="hd-val mono">${escapeHtml(r[1])}</span></div>`).join("")}
      </div>
    </div>`);
  }

  const portsRaw = h.open_ports !== undefined ? h.open_ports : h.ports;
  const ports = toList(portsRaw);
  if (ports.length > 0) {
    sections.push(`<div class="hd-section"><h4 class="hd-heading">Ports ouverts</h4><div class="hd-ports">${renderPortChips(portsRaw)}</div></div>`);
  }

  if ((h.classifications || []).length > 0) {
    sections.push(`<div class="hd-section"><h4 class="hd-heading">Classification</h4><div class="hd-chips">${renderClassificationChips(h)}</div></div>`);
  }

  const cves = hostCveList(h);
  if (cves.length > 0) {
    sections.push(`<div class="hd-section"><h4 class="hd-heading">Vulnérabilités</h4>
      <p class="hd-note">Sélectionnez une CVE dans les ONGLETS ci-dessus pour afficher son détail.</p>
      <div class="hd-cves">${renderCveBadges(h.cves)}</div></div>`);
  }

  const svc = renderServiceTable(h);
  if (svc) sections.push(`<div class="hd-section">${svc}</div>`);

  const creds = renderCredentials(h);
  if (creds) sections.push(`<div class="hd-section">${creds}</div>`);

  const sniff = renderSniffingEvidence(h);
  if (sniff) sections.push(`<div class="hd-section">${sniff}</div>`);

  const comp = renderCompliance(h);
  if (comp) sections.push(`<div class="hd-section">${comp}</div>`);

  return sections.length ? sections.join("") : '<p class="hd-empty">Aucun détail disponible pour ce hote.</p>';
}

function renderHostModalTabs(h) {
  const cves = hostCveList(h);
  let html = '<div class="hd-tabs" role="tablist">';
  html += `<button type="button" class="hd-tab${hostModalTab === "overview" ? " active" : ""}" data-tab="overview" role="tab">Vue d&#8217;ensemble</button>`;
  cves.forEach((c, i) => {
    const id = hostCveId(c) || ("cve-" + i);
    const sev = c && c.severity ? " " + escapeHtml(String(c.severity)) : "";
    html += `<button type="button" class="hd-tab${hostModalTab === id ? " active" : ""}" data-tab="${escapeHtml(id)}" role="tab" title="Afficher le détail ${escapeHtml(id)}">${escapeHtml(id)}${sev}</button>`;
  });
  html += "</div>";
  return html;
}

function renderCveDetailContent(d, cveId) {
  const parts = [];
  const id = (d && d.cve) ? d.cve : cveId;
  const sev = d && d.severity;
  const cvss = d && d.cvss;
  parts.push(`<div class="hd-section">
    <div class="hd-cve-head">
      <h4 class="hd-heading">${escapeHtml(id)}</h4>
      <div class="hd-cve-pills">
        ${sev ? `<span class="sev-pill ${severityClass(String(sev))}">${escapeHtml(String(sev))}</span>` : ""}
        ${cvss ? `<span class="cvss-pill">CVSS ${escapeHtml(String(cvss))}</span>` : ""}
      </div>
    </div>
  </div>`);

  if (d && d.description) {
    parts.push(`<div class="hd-section"><h5 class="hd-sub">Description</h5><div class="hd-prose">${escapeHtml(String(d.description))}</div></div>`);
  }

  const refs = d && d.references ? toList(d.references) : [];
  if (refs.length > 0) {
    parts.push(`<div class="hd-section"><h5 class="hd-sub">Références</h5><ul class="hd-refs">
      ${refs.map((r) => {
        const url = typeof r === "string" ? r : (r && (r.url || r.link));
        if (!url) return "";
        const safe = escapeHtml(url);
        return `<li><a href="${safe}" target="_blank" rel="noopener noreferrer">${safe}</a></li>`;
      }).filter(Boolean).join("")}
    </ul></div>`);
  }

  if (d && d.remediation) {
    parts.push(`<div class="hd-section"><h5 class="hd-sub">Remédiation</h5><div class="hd-prose">${escapeHtml(String(d.remediation))}</div></div>`);
  }

  if (d && d.nvd_url) {
    const safe = escapeHtml(String(d.nvd_url));
    parts.push(`<div class="hd-section"><div class="hd-refs"><a href="${safe}" target="_blank" rel="noopener noreferrer">Voir sur NVD &rarr;</a></div></div>`);
  }

  if (!d) {
    parts.push('<p class="hd-empty">Détail non disponible pour cette CVE (données locales uniquement).</p>');
  }
  return parts.join("");
}

async function loadCveDetail(cveId) {
  if (cveCache[cveId] !== undefined) return cveCache[cveId];
  try {
    const res = await fetch(`${API_BASE}/cves/${encodeURIComponent(cveId)}`, { headers: { Accept: "application/json" } });
    if (res.ok) {
      const data = await res.json();
      cveCache[cveId] = data;
      return data;
    }
    cveCache[cveId] = null;
    return null;
  } catch {
    cveCache[cveId] = null;
    return null;
  }
}

async function selectHostModalTab(key) {
  if (!hostModalHost) return;
  hostModalTab = key;
  const body = $("#host-modal-body");
  const tabsEl = body ? body.querySelector(".hd-tabs") : null;
  if (tabsEl) {
    tabsEl.querySelectorAll(".hd-tab").forEach((b) => b.classList.toggle("active", b.getAttribute("data-tab") === key));
  }
  const panel = body ? body.querySelector("#hd-tab-panel") : null;
  if (!panel) return;
  if (key === "overview") {
    panel.innerHTML = maybeAnon(hostModalOverviewHtml);
    return;
  }
  panel.innerHTML = '<p class="hd-empty">Chargement du détail…</p>';
  const cveId = key.replace(/^CVE-/i, "");
  const cveIdNorm = cveId.toUpperCase();
  const data = await loadCveDetail(cveIdNorm) || await loadCveDetail(cveId);
  if (hostModalTab !== key) return;
  panel.innerHTML = maybeAnon(renderCveDetailContent(data, cveIdNorm));
}

function openHostDetail(ip) {
  const h = findHostByIp(ip);
  const body = $("#host-modal-body");
  const title = $("#host-modal-title");
  if (!h || !body) return;

  hostModalHost = h;
  hostModalTab = "overview";

  const displayName = h.hostname || h.host_name || ip;
  if (title) title.textContent = maybeAnon(displayName);

  hostModalOverviewHtml = buildHostOverview(h);
  const cves = hostCveList(h);
  body.innerHTML = `${renderHostModalTabs(h)}<div id="hd-tab-panel" class="hd-tab-panel">${maybeAnon(hostModalOverviewHtml)}</div>`;

  const modal = $("#host-modal");
  if (modal) {
    modal.hidden = false;
    modal.classList.add("open");
  }
}

function toggleAnonymize() {
  globalAnon = !globalAnon;
  try { window.localStorage.setItem("ns-global-anon", globalAnon ? "1" : "0"); } catch (e) {}
  updateGlobalAnonBtn();
  const body = $("#host-modal-body");
  if (body && hostModalHost) {
    const title = $("#host-modal-title");
    const displayName = hostModalHost.hostname || hostModalHost.host_name || hostModalHost.ip;
    if (title) title.textContent = maybeAnon(displayName);
    if (hostModalTab === "overview") {
      const panel = body.querySelector("#hd-tab-panel");
      if (panel) panel.innerHTML = maybeAnon(hostModalOverviewHtml);
    } else {
      const id = hostModalTab;
      const cveIdNorm = id.replace(/^CVE-/i, "").toUpperCase();
      loadCveDetail(cveIdNorm).then((data) => {
        const panel = body.querySelector("#hd-tab-panel");
        if (panel && hostModalTab === id) panel.innerHTML = maybeAnon(renderCveDetailContent(data, cveIdNorm));
      });
    }
  }
  try { renderAll(); } catch (e) {}
  loadAlerts();
}

function closeHostModal() {
  const modal = $("#host-modal");
  if (!modal) return;
  modal.classList.remove("open");
  modal.hidden = true;
}

async function loadInterfaces() {
  const sel = $("#iface");
  if (!sel) return;
  try {
    const r = await fetch(`${API_BASE}/interfaces`);
    if (!r.ok) return;
    const d = await r.json();
    const list = Array.isArray(d) ? d : (d.interfaces || []);
    const current = sel.value;
    sel.innerHTML = '<option value="">Interface par défaut</option>' + list
      .map((it) => {
        const name = it && it.name ? String(it.name) : "";
        if (!name) return "";
        const extra = [it.state, it.type, it.mtu ? "MTU " + it.mtu : ""].filter(Boolean).join(" · ");
        const label = extra ? name + " (" + extra + ")" : name;
        return `<option value="${escapeHtml(name)}">${escapeHtml(label)}</option>`;
      })
      .join("");
    if (current) sel.value = current;
  } catch (e) {
    /* API indisponible : laisser l'option par défaut */
  }
}

async function loadAlerts() {
  const list = $("#alerts-list");
  const empty = $("#alerts-empty");
  const err = $("#alerts-error");
  const countEl = $("#alerts-count");
  if (err) { err.hidden = true; err.textContent = ""; }
  try {
    const r = await fetch(`${API_BASE}/alerts`);
    if (!r.ok) throw new Error("HTTP " + r.status);
    const data = await r.json();
    const alerts = toList(data);
    if (countEl) countEl.textContent = "(" + alerts.length + ")";
    if (!list) return;
    if (alerts.length === 0) {
      list.innerHTML = "";
      if (empty) empty.hidden = false;
      return;
    }
    if (empty) empty.hidden = true;
    const sorted = alerts.slice().sort((a, b) => {
      const at = a && a.timestamp ? new Date(a.timestamp).getTime() || 0 : 0;
      const bt = b && b.timestamp ? new Date(b.timestamp).getTime() || 0 : 0;
      return bt - at;
    });
    list.innerHTML = sorted
      .map((a) => {
        const sev = a && a.severity ? String(a.severity).toLowerCase() : "info";
        const host = a && a.host_ip ? maybeAnon(String(a.host_ip)) : "";
        const type = a && a.type ? maybeAnon(String(a.type)) : "";
        const msg = a && a.message ? maybeAnon(String(a.message)) : "";
        const ts = a && a.timestamp ? new Date(a.timestamp).toLocaleString() : "";
        return `<li class="alert-item alert-${escapeHtml(sev)}">
          <div class="alert-head">
            <span class="alert-sev sev-${escapeHtml(sev)}">${escapeHtml(sev)}</span>
            ${host ? `<span class="alert-host mono">${escapeHtml(host)}</span>` : ""}
            ${ts ? `<span class="alert-ts">${escapeHtml(ts)}</span>` : ""}
          </div>
          ${type ? `<div class="alert-type">${escapeHtml(type)}</div>` : ""}
          ${msg ? `<div class="alert-msg">${escapeHtml(msg)}</div>` : ""}
        </li>`;
      })
      .join("");
  } catch (e) {
    if (countEl) countEl.textContent = "";
    if (err) {
      err.hidden = false;
      err.textContent = (e && e.message) ? e.message : String(e);
    }
    if (list) list.innerHTML = "";
  }
}

const WIFI_SEVERITIES = {
  critique: "critical",
  haute: "high",
  moyenne: "medium",
  basse: "low"
};

function wifiSev(sev) {
  const s = String(sev || "").toLowerCase();
  if (WIFI_SEVERITIES[s]) return WIFI_SEVERITIES[s];
  if (["critical", "high", "medium", "low"].indexOf(s) !== -1) return s;
  return "low";
}

function wifiShowError(msg) {
  const err = $("#wifi-error");
  if (!err) return;
  err.hidden = false;
  err.textContent = msg || "";
}

function wifiHideError() {
  const err = $("#wifi-error");
  if (err) { err.hidden = true; err.textContent = ""; }
}

function wifiSetCount(n) {
  const el = $("#wifi-attacks-count");
  if (el) el.textContent = String(n);
}

function wifiRenderAttacks(attacks) {
  const list = $("#wifi-attacks-list");
  const empty = $("#wifi-attacks-empty");
  const items = toList(attacks);
  wifiSetCount(items.length);
  if (!list) return;
  if (items.length === 0) {
    list.innerHTML = "";
    if (empty) empty.hidden = false;
    return;
  }
  if (empty) empty.hidden = true;
  const sorted = items.slice().sort((a, b) => {
    const order = { critical: 0, high: 1, medium: 2, low: 3 };
    return (order[wifiSev(a && a.severity)] - order[wifiSev(b && b.severity)])
      || String((b && b.created_at) || "").localeCompare(String((a && a.created_at) || ""));
  });
  list.innerHTML = sorted
    .map((a) => {
      const sev = wifiSev(a && a.severity);
      const type = maybeAnon(a && a.type ? String(a.type) : "");
      const ssid = maybeAnon(a && a.ssid ? String(a.ssid) : "");
      const bssid = maybeAnon(a && a.bssid ? String(a.bssid) : "");
      const desc = maybeAnon(a && a.description ? String(a.description) : "");
      const id = (a && a.id) ? a.id : "";
      return `<div class="wifi-attack-item wifi-sev-${escapeHtml(sev)}" data-bssid="${escapeHtml(bssid)}" data-id="${escapeHtml(String(id))}">
        <div class="wifi-attack-head">
          <span class="wifi-sev-badge sev-${escapeHtml(sev)}">${escapeHtml(a && a.severity ? String(a.severity) : "")}</span>
          <span class="wifi-attack-type">${escapeHtml(type)}</span>
          <span class="wifi-attack-bssid mono">${escapeHtml(bssid)}</span>
        </div>
        ${ssid ? `<div class="wifi-attack-ssid">SSID : ${escapeHtml(ssid)}</div>` : ""}
        ${desc ? `<div class="wifi-attack-desc">${escapeHtml(desc)}</div>` : ""}
        <div class="wifi-attack-actions">
          <button type="button" class="btn-ghost btn-sm" data-wifi-ack="${escapeHtml(bssid)}">J'ai connaissance</button>
          ${id ? `<button type="button" class="btn-ghost btn-sm wifi-del" data-wifi-del="${escapeHtml(String(id))}">Supprimer</button>` : ""}
        </div>
      </div>`;
    })
    .join("");
}

function wifiRenderNetworks(networks) {
  const tbody = $("#wifi-tbody");
  const empty = $("#wifi-empty");
  const rows = toList(networks);
  if (!tbody) return;
  if (rows.length === 0) {
    tbody.innerHTML = "";
    if (empty) empty.hidden = false;
    return;
  }
  if (empty) empty.hidden = true;
  const sorted = rows.slice().sort((a, b) => {
    const qa = Number((a && a.quality) || 0);
    const qb = Number((b && b.quality) || 0);
    return qb - qa;
  });
  tbody.innerHTML = sorted
    .map((n) => {
      const ssid = maybeAnon(n && n.ssid ? String(n.ssid) : "(cache)");
      const bssid = maybeAnon(n && n.bssid ? String(n.bssid) : "");
      const mode = n && n.mode ? String(n.mode) : "";
      const sec = toList(n && n.security).map(String).join(", ");
      const quality = (n && n.quality != null) ? n.quality : "";
      const freq = (n && n.channel != null) ? String(n.channel) : "";
      const lastSeen = (n && n.last_seen) ? new Date(n.last_seen).toLocaleString() : "";
      return `<tr data-bssid="${escapeHtml(bssid)}">
        <td>${escapeHtml(ssid)}</td>
        <td class="mono">${escapeHtml(bssid)}</td>
        <td>${escapeHtml(mode)}</td>
        <td>${escapeHtml(sec)}</td>
        <td>${escapeHtml(String(quality))}%</td>
        <td>${escapeHtml(freq)}</td>
        <td>${escapeHtml(lastSeen)}</td>
        <td class="wifi-row-action">
          <button type="button" class="btn-ghost btn-sm" data-wifi-ack="${escapeHtml(bssid)}">OK</button>
        </td>
      </tr>`;
    })
    .join("");
}

async function wifiScan() {
  const btn = $("#wifi-scan-btn");
  wifiBtnLoading(btn, true, "Scanner le WiFi", "Analyse en cours…");
  wifiHideError();
  try {
    const r = await fetch(`${API_BASE}/wifi/scan`);
    if (!r.ok) throw new Error("HTTP " + r.status);
    const data = await r.json();
    wifiRenderNetworks(data.networks || []);
    if (data.attacks && data.attacks.length) {
      wifiRenderAttacks(data.attacks);
    }
    wifiLoad();
  } catch (e) {
    wifiShowError((e && e.message) ? e.message : String(e));
  } finally {
    wifiBtnLoading(btn, false, "Scanner le WiFi", "Analyse en cours…");
  }
}

async function wifiLoad() {
  try {
    const r = await fetch(`${API_BASE}/wifi/attacks?acknowledged=false`);
    if (!r.ok) throw new Error("HTTP " + r.status);
    const data = await r.json();
    wifiRenderAttacks(data.attacks || []);
  } catch (e) {
    const list = $("#wifi-attacks-list");
    if (list) list.innerHTML = "";
  }
}

async function wifiAcknowledge(bssid) {
  if (!bssid) return;
  try {
    const r = await fetch(`${API_BASE}/wifi/networks/${encodeURIComponent(bssid)}/acknowledge`, { method: "POST" });
    if (!r.ok) throw new Error("HTTP " + r.status);
    wifiLoad();
  } catch (e) {
    wifiShowError((e && e.message) ? e.message : String(e));
  }
}

async function wifiDeleteAttack(id) {
  if (!id) return;
  try {
    const r = await fetch(`${API_BASE}/wifi/attacks/${encodeURIComponent(id)}`, { method: "DELETE" });
    if (!r.ok) throw new Error("HTTP " + r.status);
    wifiLoad();
  } catch (e) {
    wifiShowError((e && e.message) ? e.message : String(e));
  }
}

function wifiBtnLoading(btn, loading, defaultLabel, loadingLabel) {
  if (!btn) return;
  btn.disabled = loading;
  const label = btn.querySelector(".btn-label");
  const spin = btn.querySelector(".spinner");
  if (label) label.textContent = loading ? loadingLabel : defaultLabel;
  if (spin) spin.hidden = !loading;
}

async function wifiClearAttacks() {
  const btn = $("#wifi-clear-btn");
  wifiBtnLoading(btn, true, "Vider les attaques", "Suppression…");
  try {
    const r = await fetch(`${API_BASE}/wifi/attacks`, { method: "DELETE" });
    if (!r.ok) throw new Error("HTTP " + r.status);
    wifiRenderAttacks([]);
  } catch (e) {
    wifiShowError((e && e.message) ? e.message : String(e));
  } finally {
    wifiBtnLoading(btn, false, "Vider les attaques", "Suppression…");
  }
}

document.addEventListener("DOMContentLoaded", () => {
  const form = $("#scan-form");
  if (form) form.addEventListener("submit", (e) => { e.preventDefault(); startScan(); });

  const refresh = $("#refresh-btn");
  if (refresh) refresh.addEventListener("click", loadHistory);

  const filter = $("#host-filter");
  if (filter) filter.addEventListener("input", renderAll);

  document.addEventListener("click", (e) => {
    const btn = e.target && e.target.closest ? e.target.closest(".cve-clickable") : null;
    if (btn) {
      e.preventDefault();
      openCveModal(btn.getAttribute("data-cve"));
    }
  });

  const modalClose = $("#cve-modal-close");
  if (modalClose) modalClose.addEventListener("click", closeCveModal);
  const modal = $("#cve-modal");
  if (modal) modal.addEventListener("click", (e) => { if (e.target === modal) closeCveModal(); });
  document.addEventListener("keydown", (e) => { if (e.key === "Escape") { closeCveModal(); closeHostModal(); } });

  const tbody = $("#hosts-tbody");
  if (tbody) tbody.addEventListener("click", (e) => {
    const row = e.target && e.target.closest ? e.target.closest("tr[data-ip]") : null;
    if (row) openHostDetail(row.getAttribute("data-ip"));
  });

  const hostClose = $("#host-modal-close");
  if (hostClose) hostClose.addEventListener("click", closeHostModal);
  const hostModal = $("#host-modal");
  if (hostModal) hostModal.addEventListener("click", (e) => {
    if (e.target === hostModal) closeHostModal();
    const tab = e.target && e.target.closest ? e.target.closest(".hd-tab") : null;
    if (tab) {
      const key = tab.getAttribute("data-tab");
      if (key && key !== hostModalTab) selectHostModalTab(key);
      return;
    }
    const badge = e.target && e.target.closest ? e.target.closest(".cve-clickable[data-cve]") : null;
    if (badge && hostModalHost) {
      const id = badge.getAttribute("data-cve");
      if (id) selectHostModalTab(id.toUpperCase());
    }
  });

  const globalAnonBtn = $("#global-anon-btn");
  if (globalAnonBtn) globalAnonBtn.addEventListener("click", toggleAnonymize);
  updateGlobalAnonBtn();

  const alertsRefresh = $("#alerts-refresh");
  if (alertsRefresh) alertsRefresh.addEventListener("click", loadAlerts);

  const wifiScanBtn = $("#wifi-scan-btn");
  if (wifiScanBtn) wifiScanBtn.addEventListener("click", wifiScan);
  const wifiClearBtn = $("#wifi-clear-btn");
  if (wifiClearBtn) wifiClearBtn.addEventListener("click", () => {
    if (!window.confirm("Supprimer toutes les alertes WiFi reconnues ?")) return;
    wifiClearAttacks();
  });
  document.addEventListener("click", (e) => {
    const target = e.target;
    if (!target || !target.closest) return;
    const ack = target.closest("[data-wifi-ack]");
    if (ack) {
      const bssid = ack.getAttribute("data-wifi-ack");
      if (bssid) wifiAcknowledge(bssid);
      return;
    }
    const del = target.closest("[data-wifi-del]");
    if (del) {
      const id = del.getAttribute("data-wifi-del");
      if (id) wifiDeleteAttack(id);
    }
  });

  loadInterfaces();
  checkStatus();
  loadHistory();
  loadAlerts();
  setInterval(checkStatus, 15000);
});
