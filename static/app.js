const tacticMap = { "reconnaissance": "Reconnaissance", "resource-development": "Resource Development", "initial-access": "Initial Access", "execution": "Execution", "persistence": "Persistence", "privilege-escalation": "Privilege Escalation", "defense-evasion": "Defense Evasion", "credential-access": "Credential Access", "discovery": "Discovery", "lateral-movement": "Lateral Movement", "collection": "Collection", "command-and-control": "Command and Control", "exfiltration": "Exfiltration", "impact": "Impact" };
const tacticOrder = Object.values(tacticMap);

const SCORE_RULE_MAX = 10;
const SCORE_MITIGATION_MAX = 5;
const SCORE_RULE_WEIGHT = 0.6;
const SCORE_MITIGATION_WEIGHT = 0.4;

let mitreObjects = [];
let techDetailsMap = {};
let nameToIdMap = {};
let matrixStructure = {};
let subTechsByParent = {};
let attackIdToTid = {};
let mitigationById = {};
let mitigationsByTechnique = {};
let currentRulesByParent = {};

let userRules = [];
let mitigationNotes = {};
let techTactics = {};
let pendingMitigationEdits = {};
let mitigationEntries = {};
let products = [];
let filterSearch = '';
let filterProducts = new Set();
let filterAllProducts = true;
let visibleExportRows = [];
let techsByMitigation = {};
let techChipPopoverEl = null;
let currentUser = null;
let currentRole = 'viewer';
let users = [];
let auditLogs = [];
// Kurallar sayfası filtre state'i — renderRulesList() her re-render'da bu değerleri
// kullanır; seçim re-render sonrasında da korunur (input value / select selected).
let rulesFilterSearch = '';
let rulesFilterProduct = '';
// Teknik bazlı puanlama konfigürasyonu — /api/technique-config'den yüklenir.
// { "T1059": { importance, rule_threshold, group_count, tool_count }, ... }
let techniqueConfig = {};
let teams = [];

function hasRole(role) {
  const level = { viewer: 1, editor: 2, admin: 3 };
  return (level[currentRole] || 0) >= (level[role] || 0);
}

async function apiFetch(url, options) {
  const res = await fetch(url, options);
  if (res.status === 401) {
    window.location.href = '/login';
    throw new Error('Oturum sona erdi');
  }
  return res;
}

function applyRoleUI() {
  const userBadge = document.getElementById('userBadge');
  if (userBadge && currentUser) {
    userBadge.textContent = `${currentUser.username} (${currentUser.role})`;
  }

  const resetBtn = document.getElementById('btnReset');
  if (resetBtn) resetBtn.classList.toggle('hidden', !hasRole('admin'));

  const settingsNav = document.querySelector('.nav-item[data-target="settingsPanel"]');
  if (settingsNav) settingsNav.classList.toggle('hidden', !hasRole('editor'));

  const csvFileInput = document.getElementById('csvFile');
  if (csvFileInput) csvFileInput.disabled = !hasRole('editor');

  // Ayarlar sekmelerini role göre gizle:
  //   CSV Yükleme → editor veya üstü
  //   Kullanıcılar + Audit Log → sadece admin
  document.getElementById('settingsCsvTab')?.classList.toggle('hidden', !hasRole('editor'));
  document.getElementById('settingsUsersTab')?.classList.toggle('hidden', !hasRole('admin'));
  document.getElementById('settingsAuditTab')?.classList.toggle('hidden', !hasRole('admin'));
  document.getElementById('settingsTeamsTab')?.classList.toggle('hidden', !hasRole('admin'));
}

async function init() {
  wireActions();
  try {
    const meRes = await apiFetch('/api/me');
    if (!meRes.ok) throw new Error('Kullanici bilgisi alinamadi');
    currentUser = await meRes.json();
    currentRole = currentUser.role || 'viewer';
    applyRoleUI();
    if (hasRole('admin')) {
      await loadUsers();
      await loadAuditLogs();
    }

    const [mitreRes, productsRes, rulesRes, notesRes, entriesRes, configRes, teamsRes] = await Promise.all([
      apiFetch('/api/mitre-min'),
      apiFetch('/api/products'),
      apiFetch('/api/rules'),
      apiFetch('/api/mitigation-notes'),
      apiFetch('/api/mitigation-entries'),
      apiFetch('/api/technique-config'),
      apiFetch('/api/teams')
    ]);

    if (!mitreRes.ok) throw new Error('MITRE verisi yüklenemedi');
    mitreObjects = (await mitreRes.json()).objects || [];
    products = productsRes.ok ? await productsRes.json() : [];
    userRules = rulesRes.ok ? await rulesRes.json() : [];
    const notes = notesRes.ok ? await notesRes.json() : [];
    mitigationNotes = normalizeNotes(notes);
    const entries = entriesRes.ok ? await entriesRes.json() : [];
    mitigationEntries = normalizeEntries(entries);
    techniqueConfig = configRes.ok ? await configRes.json() : {};
    teams = teamsRes.ok ? await teamsRes.json() : [];

    prepareMitreLookup();
    await loadProducts();
    populateTacticSelect();
    renderMitigationList();
    renderRulesList();
    renderMatrix();
  } catch (e) {
    document.getElementById('matrix').innerHTML = `Veri Hatası: ${e.message}`;
  }
}
async function reloadData() {
  const [productsRes, rulesRes, notesRes, entriesRes, teamsRes] = await Promise.all([
    apiFetch('/api/products'),
    apiFetch('/api/rules'),
    apiFetch('/api/mitigation-notes'),
    apiFetch('/api/mitigation-entries'),
    apiFetch('/api/teams')
  ]);
  products = productsRes.ok ? await productsRes.json() : [];
  userRules = rulesRes.ok ? await rulesRes.json() : [];
  const notes = notesRes.ok ? await notesRes.json() : [];
  mitigationNotes = normalizeNotes(notes);
  const entries = entriesRes.ok ? await entriesRes.json() : [];
  mitigationEntries = normalizeEntries(entries);
  teams = teamsRes.ok ? await teamsRes.json() : [];
  renderLegend();
  renderProductLegend();
  populateSourceSelect();
  renderProductsList();
  renderMitigationList();
  renderRulesList();
  if (hasRole('admin')) {
    await loadUsers();
    await loadAuditLogs();
  }
}

function normalizeNotes(list) {
  const out = {};
  list.forEach(n => {
    out[n.mitigation_id] = {
      checked: !!n.checked,
      comment: n.comment || '',
      team: n.team || ''
    };
  });
  return out;
}

function normalizeEntries(list) {
  const out = {};
  list.forEach(e => {
    if (!out[e.mitigation_id]) out[e.mitigation_id] = [];
    out[e.mitigation_id].push(e);
  });
  return out;
}

function buildTeamSelectEl(mitId) {
  const esc = s => String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');
  const sel = document.createElement('select');
  sel.className = 'mitigation-entry-team';
  sel.dataset.mit = mitId;
  sel.innerHTML = `<option value="">— Ekip Seçin —</option>` +
    teams.map(t => `<option value="${esc(t.name)}">${esc(t.name)}</option>`).join('');
  return sel;
}

async function reloadMitigationEntries() {
  const res = await apiFetch('/api/mitigation-entries');
  const entries = res.ok ? await res.json() : [];
  mitigationEntries = normalizeEntries(entries);
}

function prepareMitreLookup() {
  tacticOrder.forEach(t => matrixStructure[t] = []);
  subTechsByParent = {};
  attackIdToTid = {};
  mitigationById = {};
  mitigationsByTechnique = {};
  techsByMitigation = {};
  techDetailsMap = {};
  nameToIdMap = {};
  techTactics = {};

  mitreObjects.forEach(obj => {
    if (obj.type === 'attack-pattern' && !obj.revoked && !obj.x_mitre_deprecated) {
      const mitreRef = obj.external_references.find(ref => ref.source_name === 'mitre-attack');
      const tid = mitreRef ? mitreRef.external_id : null;
      if (tid) {
        const isSub = obj.x_mitre_is_subtechnique;
        const parentId = (isSub && tid.includes('.')) ? tid.split('.')[0] : tid;
        techDetailsMap[tid] = { id: tid, name: obj.name, isSub: isSub, parentId: parentId };
        nameToIdMap[obj.name.toLowerCase()] = tid;
        nameToIdMap[tid.toLowerCase()] = tid;
        attackIdToTid[obj.id] = tid;

        if (isSub) {
          if (!subTechsByParent[parentId]) subTechsByParent[parentId] = [];
          subTechsByParent[parentId].push({ id: tid, name: obj.name });
        } else if (obj.kill_chain_phases) {
          obj.kill_chain_phases.forEach(phase => {
            const prettyTactic = tacticMap[phase.phase_name];
            if (prettyTactic) {
              matrixStructure[prettyTactic].push({ id: tid, name: obj.name });
              if (!techTactics[tid]) techTactics[tid] = [];
              if (!techTactics[tid].includes(prettyTactic)) techTactics[tid].push(prettyTactic);
            }
          });
        }
      }
    }
  });

  mitreObjects.forEach(obj => {
    if (obj.type === 'course-of-action' && !obj.revoked && !obj.x_mitre_deprecated) {
      const mitreRef = obj.external_references.find(ref => ref.source_name === 'mitre-attack');
      const mid = mitreRef ? mitreRef.external_id : null;
      if (mid) mitigationById[obj.id] = { id: mid, name: obj.name, description: obj.description || '' };
    }
  });

  mitreObjects.forEach(obj => {
    if (obj.type === 'relationship' && obj.relationship_type === 'mitigates') {
      const tid = attackIdToTid[obj.target_ref];
      const mitigation = mitigationById[obj.source_ref];
      if (tid && mitigation) {
        if (!mitigationsByTechnique[tid]) mitigationsByTechnique[tid] = [];
        mitigationsByTechnique[tid].push(mitigation);
        if (!techsByMitigation[mitigation.id]) techsByMitigation[mitigation.id] = new Set();
        techsByMitigation[mitigation.id].add(tid);
      }
    }
  });

  Object.keys(subTechsByParent).forEach(parentId => {
    subTechsByParent[parentId].sort((a, b) => a.id.localeCompare(b.id));
  });
  Object.keys(mitigationsByTechnique).forEach(tid => {
    mitigationsByTechnique[tid].sort((a, b) => a.id.localeCompare(b.id));
  });
}




function buildExportRows() {
  return visibleExportRows.slice();
}


function buildFilterSummary() {
  const search = (filterSearch || '').trim();
  const productsSelected = (filterAllProducts || filterProducts.size === 0)
    ? 'Tümü'
    : Array.from(filterProducts).join(', ');
  return { search, productsSelected };
}

function downloadBlob(filename, content, mime) {
  const blob = new Blob([content], { type: mime });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  a.remove();
  URL.revokeObjectURL(url);
}

function exportCsv() {
  const rows = buildExportRows();
  const meta = buildFilterSummary();
  const header = ['type','tech_id','name','tactic','rule_count','mitigation_checked','products','score'];
  const lines = [];
  lines.push(`# export_date=${new Date().toISOString()}`);
  lines.push(`# search=${meta.search || 'none'}`);
  lines.push(`# products=${meta.productsSelected}`);
  lines.push(header.join(','));
  rows.forEach(r => {
    const line = [
      r.type,
      r.tech_id,
      r.name,
      r.tactic,
      r.rule_count,
      r.mitigation_checked,
      (r.products || []).join('|'),
      r.score.toFixed(2)
    ].map(v => `"${String(v).replace(/"/g,'""')}"`).join(',');
    lines.push(line);
  });
  downloadBlob('mitre_coverage.csv', lines.join('\n'), 'text/csv;charset=utf-8');
}

function exportLayer() {
  const rows = buildExportRows();
  const enabledProducts = (filterAllProducts || filterProducts.size === 0)
    ? products.map(p => p.name)
    : Array.from(filterProducts);
  const techniques = rows.map(r => ({
    techniqueID: r.tech_id,
    score: Math.round(r.score * 100),
    comment: `rules:${r.rule_count}, mitigations:${r.mitigation_checked}, products:${(r.products||[]).join('|')}`
  }));
  const legendItems = products.map(p => ({ label: p.name, color: p.color }));
  const layer = {
    name: 'MITRE Coverage Map',
    version: '4.6',
    domain: 'enterprise-attack',
    description: 'Generated from SOC Coverage Manager',
    filters: {
      platforms: ['Windows', 'Linux', 'macOS'],
      products: enabledProducts
    },
    legendItems: legendItems,
    gradient: {
      colors: ['#2a2f33', '#2e7d32'],
      minValue: 0,
      maxValue: 100
    },
    techniques: techniques
  };
  downloadBlob('mitre_layer.json', JSON.stringify(layer, null, 2), 'application/json;charset=utf-8');
}

function exportPdf() {
  const rows = buildExportRows();
  const meta = buildFilterSummary();
  const win = window.open('', '_blank');
  if (!win) return;
  const html = `<!DOCTYPE html><html><head><title>MITRE Coverage Report</title>
    <style>
      body{font-family:Inter,Arial,sans-serif;padding:24px;color:#111;}
      h1{font-size:20px;margin:0 0 8px 0;}
      .meta{display:flex;gap:16px;flex-wrap:wrap;font-size:12px;margin:8px 0 16px 0;color:#333;}
      .pill{background:#f1f5f9;border:1px solid #e2e8f0;border-radius:999px;padding:4px 10px;}
      table{width:100%;border-collapse:collapse;font-size:11px;}
      th,td{border:1px solid #e2e8f0;padding:6px;}
      th{background:#f8fafc;text-align:left;}
      .score{font-weight:600;}
    </style>
  </head><body>
    <h1>MITRE Coverage Report</h1>
    <div class="meta">
      <div class="pill">Date: ${new Date().toISOString().slice(0,10)}</div>
      <div class="pill">Search: ${meta.search || 'none'}</div>
      <div class="pill">Products: ${meta.productsSelected}</div>
      <div class="pill">Rows: ${rows.length}</div>
    </div>
    <table><thead><tr><th>Type</th><th>ID</th><th>Name</th><th>Tactic</th><th>Rules</th><th>Mitigations</th><th>Products</th><th>Score</th></tr></thead><tbody>
    ${rows.map(r => `<tr><td>${r.type}</td><td>${r.tech_id}</td><td>${r.name}</td><td>${r.tactic}</td><td>${r.rule_count}</td><td>${r.mitigation_checked}</td><td>${(r.products||[]).join(', ')}</td><td class="score">${r.score.toFixed(2)}</td></tr>`).join('')}
    </tbody></table>
  </body></html>`;
  win.document.write(html);
  win.document.close();
  win.focus();
  win.print();
}


function summarizeText(text, maxLen = 120) {
  if (!text) return '';
  const clean = text.replace(/\s+/g, ' ').trim();
  if (clean.length <= maxLen) return clean;
  return clean.slice(0, maxLen) + '...';
}

function renderFilters() {}

function matchesSearch(tech) {
  const term = filterSearch.trim().toLowerCase();
  if (!term) return true;
  const id = (tech.id || '').toLowerCase();
  const name = (tech.name || '').toLowerCase();
  return id.includes(term) || name.includes(term);
}

function matchesProduct(rules) {
  if (filterAllProducts || filterProducts.size === 0) return true;
  return rules.some(r => filterProducts.has(r.source));
}

function productColorMap() {
  const map = {};
  products.forEach(p => { map[p.name] = p.color; });
  return map;
}


function renderProductLegend() {
  const container = document.getElementById('productLegend');
  if (!container) return;
  container.innerHTML = '';
  products.forEach(p => {
    const item = document.createElement('div');
    item.className = 'product-legend-item';
    item.innerHTML = `<div class="product-legend-swatch" style="background:${p.color}"></div>${p.name}`;
    container.appendChild(item);
  });
}

function renderMitigationList() {
  const container = document.getElementById('mitigationList');
  if (!container) return;
  const map = {};
  Object.keys(mitigationsByTechnique).forEach(tid => {
    const list = mitigationsByTechnique[tid] || [];
    list.forEach(m => {
      if (!map[m.id]) map[m.id] = { id: m.id, name: m.name, description: m.description || '', techniques: [] };
      map[m.id].techniques.push(tid);
    });
  });
  const mitigations = Object.values(map).sort((a, b) => a.id.localeCompare(b.id));
  if (mitigations.length === 0) {
    container.innerHTML = '<div class="empty-state"><div class="empty-title">Kayıt yok</div><div class="empty-sub">Mitigation verisi bulunamadı.</div></div>';
    return;
  }
  const rows = mitigations.map(m => {
    const techLabels = m.techniques.map(tid => {
      const name = techDetailsMap[tid]?.name || tid;
      return { id: tid, label: `${tid} - ${name}` };
    });
    const preview = techLabels.slice(0, 4);
    const extra = techLabels.length - preview.length;
    const chips = techLabels.map(t => `<button class="tech-chip" type="button" data-tech-label="${t.label}">${techDetailsMap[t.id]?.name || t.id}</button>`).join('');
    const moreBtn = extra > 0 ? `<button class="tech-more" data-mit="${m.id}">Tümünü Göster</button>` : '';
    const entries = mitigationEntries[m.id] || [];
    const desc = m.description || '';
    const entryHtml = entries.length
      ? entries.map(e => `
          <div class="mitigation-entry">
            <div class="entry-team">${e.team}</div>
            <div class="entry-comment">${e.comment}</div>
            <button class="entry-delete" data-entry-id="${e.id}" data-mit="${m.id}">Sil</button>
          </div>
        `).join('')
      : '<div class="mitigation-empty">Kayıt yok.</div>';
    return `
      <div class="mitigation-list-row">
        <div class="mitigation-list-id mit-popup-btn" data-mit="${m.id}">${m.id}</div>
          <div class="mitigation-list-name">
          <button class="mit-name-popup-btn" data-mit="${m.id}">${m.name}</button>
          <div class="mitigation-list-desc">${summarizeText(desc, 90)}</div>
        </div>
        <div class="mitigation-list-tech">
          <div class="tech-chip-row" data-mit="${m.id}">${chips}</div>
          ${moreBtn}
        </div>
        <div class="mitigation-list-entries" data-mit="${m.id}">
          ${entryHtml}
          <div class="mitigation-entry-form" data-mit="${m.id}">
            <span class="mitigation-entry-team-placeholder" data-mit="${m.id}"></span>
            <textarea class="mitigation-entry-comment" data-mit="${m.id}" placeholder="Yorum"></textarea>
            <button class="action-btn btn-add mitigation-entry-add" data-mit="${m.id}">Ekle</button>
          </div>
        </div>
      </div>
    `;
  }).join('');
  container.innerHTML = `
    <div class="mitigation-list-header">
      <div>ID</div>
      <div>Mitigation</div>
      <div>Teknikler</div>
      <div>Ekip / Yorum</div>
    </div>
    ${rows}
  `;

  // Replace team input placeholders with selects
  container.querySelectorAll('.mitigation-entry-team-placeholder').forEach(ph => {
    const mitId = ph.dataset.mit;
    ph.replaceWith(buildTeamSelectEl(mitId));
  });

  container.querySelectorAll('.tech-more').forEach(btn => {
    btn.addEventListener('click', (e) => {
      const mitId = e.currentTarget.dataset.mit;
      const row = container.querySelector(`.tech-chip-row[data-mit="${mitId}"]`);
      if (!row) return;
      const open = row.classList.toggle('expanded');
      e.currentTarget.textContent = open ? 'Gizle' : 'Tümünü Göster';
    });
  });

  container.querySelectorAll('.tech-chip').forEach(chip => {
    chip.addEventListener('click', (e) => {
      const label = e.currentTarget.dataset.techLabel || '';
      if (!label) return;
      showTechChipPopover(e.currentTarget, label);
    });
  });

  container.querySelectorAll('.mitigation-entry-add').forEach(btn => {
    btn.addEventListener('click', async (e) => {
      const mitId = e.currentTarget.dataset.mit;
      const row = e.currentTarget.closest('.mitigation-list-entries');
      if (!mitId || !row) return;
      const teamInput = row.querySelector('.mitigation-entry-team');
      const commentInput = row.querySelector('.mitigation-entry-comment');
      const team = (teamInput?.value || '').trim();
      const comment = (commentInput?.value || '').trim();
      if (!team || !comment) {
        alert('Ekip ve yorum gerekli.');
        return;
      }
      const created = await addMitigationEntry(mitId, team, comment);
      if (!created) return;
      await reloadMitigationEntries();
      if (!mitigationNotes[mitId]) mitigationNotes[mitId] = { checked: false, comment: '', team: '' };
      mitigationNotes[mitId].checked = true;
      refreshTechniqueCardsForMitigation(mitId);
      renderMitigationList();
    });
  });

  container.querySelectorAll('.entry-delete').forEach(btn => {
    btn.addEventListener('click', async (e) => {
      const id = e.currentTarget.dataset.entryId;
      const mitId = e.currentTarget.dataset.mit;
      if (!id) return;
      const ok = await deleteMitigationEntry(id);
      if (!ok) return;
      await reloadMitigationEntries();
      if (!mitigationNotes[mitId]) mitigationNotes[mitId] = { checked: false, comment: '', team: '' };
      mitigationNotes[mitId].checked = (mitigationEntries[mitId]?.length > 0);
      if (mitId) refreshTechniqueCardsForMitigation(mitId);
      renderMitigationList();
    });
  });

  // Mitigation popup — ID veya ad tıklanınca açıklama + MITRE linki göster
  container.querySelectorAll('.mit-popup-btn, .mit-name-popup-btn').forEach(btn => {
    btn.addEventListener('click', (e) => {
      e.stopPropagation();
      const mitId = e.currentTarget.dataset.mit;
      const mitData = mitigations.find(mx => mx.id === mitId);
      if (!mitData) return;
      showMitDetailPopup(e.currentTarget, mitData.id, mitData.name, mitData.description);
    });
  });
}

// ── Kurallar Sayfası ──────────────────────────────────────────────────────────
// Tüm kuralları listeler. Her kural satırı:
//   • Kural adı  • Kaynak (ürün rengi ile)
//   • Teknik chipler (tıklanabilir popover, × ile kaldır)
//   • Teknik ekle input'u (autocomplete destekli) + + butonu
//   • Sil butonu (editor+)
//
// Sayfa üstünde filtre bar bulunur:
//   • Kural adı metin araması (rulesFilterSearch)
//   • Ürün dropdown filtresi (rulesFilterProduct)
//   • Temizle butonu
//
// State: userRules (global) + rulesFilterSearch/rulesFilterProduct (sayfa-local).
// Her re-render'da filtre değerleri input/select'e geri yazılır (state kaybolmaz).
function renderRulesList() {
  const container = document.getElementById('rulesList');
  if (!container) return;

  const colorMap = productColorMap();

  // Yeni Kural formu (sadece editor+)
  const sourceOptions = products.map(p => `<option value="${p.name}">${p.name}</option>`).join('');
  const addFormHtml = hasRole('editor') ? `
    <div class="rule-add-form">
      <div class="filter-group">
        <label>Tespit Adı</label>
        <input id="newRuleNameInline" type="text" placeholder="Tespit adı" />
      </div>
      <div class="filter-group">
        <label>Kaynak (Ürün)</label>
        <select id="newRuleSourceInline">
          <option value="">Kaynak seç</option>
          ${sourceOptions}
        </select>
      </div>
      <div class="filter-group">
        <label>Teknik (isteğe bağlı)</label>
        <div class="tech-autocomplete-wrapper" id="newRuleTechWrapper">
          <input class="rule-tech-input" type="text" id="newRuleTechInline" placeholder="T1059 veya teknik adı" />
          <div class="tech-autocomplete-dropdown hidden"></div>
        </div>
      </div>
      <div class="filter-group">
        <label style="visibility:hidden">_</label>
        <button class="action-btn btn-add" id="btnAddRuleInline">+ Tespit Ekle</button>
      </div>
    </div>
  ` : '';

  // Filter bar HTML
  const productOptions = products.map(p =>
    `<option value="${p.name}" ${rulesFilterProduct === p.name ? 'selected' : ''}>${p.name}</option>`
  ).join('');
  const filterBarHtml = `
    <div class="rules-filter-bar">
      <div class="filter-group">
        <label>Tespit Adı</label>
        <input id="rulesSearch" type="text" placeholder="Tespit adı ara..." value="${rulesFilterSearch.replace(/"/g, '&quot;')}" />
      </div>
      <div class="filter-group">
        <label>Ürün</label>
        <select id="rulesProductFilter">
          <option value="">Tümü</option>
          ${productOptions}
        </select>
      </div>
      <div class="filter-group">
        <label style="visibility:hidden">_</label>
        <button class="action-btn btn-reset" id="rulesClearFilter">Temizle</button>
      </div>
    </div>
  `;

  if (userRules.length === 0) {
    container.innerHTML = addFormHtml + filterBarHtml + '<div class="empty-state"><div class="empty-title">Tespit yok</div><div class="empty-sub">Henüz tespit eklenmemiş.</div></div>';
    wireRulesFilterEvents(container);
    wireAddRuleInline(container);
    container.querySelectorAll('.tech-autocomplete-wrapper').forEach(wireAutocomplete);
    return;
  }

  // Apply filters
  const visible = userRules.filter(r =>
    (!rulesFilterSearch || r.name.toLowerCase().includes(rulesFilterSearch.toLowerCase())) &&
    (!rulesFilterProduct || r.source === rulesFilterProduct)
  );

  const rows = visible.map(r => {
    const techs = (r.techniques && r.techniques.length > 0)
      ? r.techniques
      : (r.tech && r.tech !== 'None' ? [r.tech] : []);
    const techChips = techs.map(t => {
      const details = techDetailsMap[t];
      const techLabel = details ? `${t} - ${details.name}` : t;
      return `<span class="rule-tech-chip">
        <button class="tech-chip" type="button" data-tech-label="${techLabel}">${details?.name || t}</button>
        ${hasRole('editor') ? `<button class="rule-tech-remove" data-rule-id="${r.id}" data-tech-id="${t}" title="Tekniği kaldır">×</button>` : ''}
      </span>`;
    }).join('');
    const sourceColor = colorMap[r.source] || '#546e7a';
    return `
      <div class="mitigation-list-row rule-list-row">
        <div class="mitigation-list-name">${r.name}</div>
        <div class="mitigation-list-tech">
          <span class="source-tag" style="background:${sourceColor}">${r.source}</span>
        </div>
        <div class="rule-tech-list">
          ${techChips}
          ${hasRole('editor') ? `<span class="rule-tech-add">
            <div class="tech-autocomplete-wrapper" data-rule-id="${r.id}">
              <input class="rule-tech-input" type="text" placeholder="T1059 veya teknik adı" data-rule-id="${r.id}" />
              <div class="tech-autocomplete-dropdown hidden"></div>
            </div>
            <button class="action-btn btn-add rule-tech-add-btn" data-rule-id="${r.id}">+</button>
          </span>` : ''}
        </div>
        <div class="rule-actions">
          ${hasRole('editor') ? `<button class="action-btn btn-reset rule-delete" data-rule-id="${r.id}">Sil</button>` : ''}
        </div>
      </div>
    `;
  }).join('');

  const emptyNote = visible.length === 0
    ? '<div class="empty-state"><div class="empty-title">Sonuç yok</div><div class="empty-sub">Filtre kriterlerine uyan tespit bulunamadı.</div></div>'
    : '';

  container.innerHTML = `
    ${addFormHtml}
    ${filterBarHtml}
    <div class="mitigation-list-header rule-list-header">
      <div>Tespit Adı</div>
      <div>Kaynak</div>
      <div>Teknikler</div>
      <div>İşlemler</div>
    </div>
    ${rows}
    ${emptyNote}
  `;

  wireRulesFilterEvents(container);
  wireAddRuleInline(container);

  container.querySelectorAll('.tech-autocomplete-wrapper').forEach(wireAutocomplete);

  container.querySelectorAll('.tech-chip[data-tech-label]').forEach(chip => {
    chip.addEventListener('click', (e) => {
      const label = e.currentTarget.dataset.techLabel || '';
      if (!label) return;
      showTechChipPopover(e.currentTarget, label);
    });
  });

  container.querySelectorAll('.rule-tech-remove').forEach(btn => {
    btn.addEventListener('click', async (e) => {
      if (!hasRole('editor')) return;
      const ruleId = e.currentTarget.dataset.ruleId;
      const techId = e.currentTarget.dataset.techId;
      const res = await apiFetch(`/api/rules/${ruleId}/techniques/${techId}`, { method: 'DELETE' });
      if (!res.ok) return;
      const rule = userRules.find(r => r.id == ruleId);
      if (rule && rule.techniques) {
        rule.techniques = rule.techniques.filter(t => t !== techId);
      }
      renderRulesList();
      renderMatrix();
    });
  });

  container.querySelectorAll('.rule-tech-add-btn').forEach(btn => {
    btn.addEventListener('click', async (e) => {
      if (!hasRole('editor')) return;
      const ruleId = e.currentTarget.dataset.ruleId;
      const input = container.querySelector(`.rule-tech-input[data-rule-id="${ruleId}"]`);
      if (!input) return;
      const val = (input.value || '').trim();
      if (!val) return;
      const validation = validateTechniqueInput(val);
      if (!validation.ok) {
        alert(validation.message);
        return;
      }
      const techId = validation.tid;
      const res = await apiFetch(`/api/rules/${ruleId}/techniques`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ tech_id: techId })
      });
      if (!res.ok) {
        const err = await res.json().catch(() => ({}));
        alert(err.error || 'Teknik eklenemedi');
        return;
      }
      const rule = userRules.find(r => r.id == ruleId);
      if (rule) {
        if (!rule.techniques) rule.techniques = [];
        if (!rule.techniques.includes(techId)) rule.techniques.push(techId);
        rule.techniques.sort();
      }
      input.value = '';
      renderRulesList();
      renderMatrix();
    });
  });

  container.querySelectorAll('.rule-delete').forEach(btn => {
    btn.addEventListener('click', async (e) => {
      const ruleId = parseInt(e.currentTarget.dataset.ruleId);
      if (!ruleId || !hasRole('editor')) return;
      await deleteRule(ruleId);
    });
  });
}

// Filtre bar event'lerini bağlar. renderRulesList() her çağrısında çalışır;
// event'ler container'a bağlı olduğundan innerHTML değişince otomatik temizlenir.
function wireRulesFilterEvents(container) {
  const searchInput = container.querySelector('#rulesSearch');
  if (searchInput) {
    searchInput.addEventListener('input', (e) => {
      rulesFilterSearch = e.target.value || '';
      renderRulesList();
    });
  }
  const productSelect = container.querySelector('#rulesProductFilter');
  if (productSelect) {
    productSelect.addEventListener('change', (e) => {
      rulesFilterProduct = e.target.value || '';
      renderRulesList();
    });
  }
  const clearBtn = container.querySelector('#rulesClearFilter');
  if (clearBtn) {
    clearBtn.addEventListener('click', () => {
      rulesFilterSearch = '';
      rulesFilterProduct = '';
      renderRulesList();
    });
  }
}

// Kurallar sayfası üstündeki "Yeni Kural Ekle" formunu bağlar.
// name + source zorunlu; teknik isteğe bağlı (sonradan eklenebilir).
function wireAddRuleInline(container) {
  const btn = container.querySelector('#btnAddRuleInline');
  if (!btn) return;
  btn.addEventListener('click', async () => {
    const nameInput = container.querySelector('#newRuleNameInline');
    const sourceSelect = container.querySelector('#newRuleSourceInline');
    const techInput = container.querySelector('#newRuleTechInline');

    const name = (nameInput?.value || '').trim();
    const source = (sourceSelect?.value || '').trim();
    const tech = (techInput?.value || '').trim();

    if (!name) { alert('Tespit adı gerekli'); return; }
    if (!source) { alert('Kaynak (ürün) seçmelisiniz'); return; }

    let techId = '';
    if (tech) {
      const validation = validateTechniqueInput(tech);
      if (!validation.ok) { alert(validation.message); return; }
      techId = validation.tid;
    }

    const res = await apiFetch('/api/rules', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ name, tactic: 'none', tech: techId, source })
    });

    if (!res.ok) {
      const err = await res.json().catch(() => ({}));
      alert(err.error || 'Tespit eklenemedi');
      return;
    }

    const newRule = await res.json();
    userRules.push(newRule);
    renderRulesList();
    renderMatrix();
  });
}

// ── Teknik Autocomplete ───────────────────────────────────────────────────────
// .tech-autocomplete-wrapper içindeki input'a bağlanır.
// Davranış:
//   • 2+ karakter → techDetailsMap üzerinde filtre → max 12 sonuç dropdown'da
//   • T-kod ile başlama (t1059) veya isim içermesi (powershell) desteklenir
//   • Tıklama veya Enter → T-kodu input'a yazar, dropdown kapanır
//   • ArrowDown/ArrowUp → active item değişir
//   • Escape → dropdown kapanır
//   • Dışarı tıklama → dropdown kapanır (capture listener)
// + butonu validation için hâlâ validateTechniqueInput() kullanır.
function wireAutocomplete(wrapper) {
  const input = wrapper.querySelector('.rule-tech-input');
  const dropdown = wrapper.querySelector('.tech-autocomplete-dropdown');
  if (!input || !dropdown) return;

  input.addEventListener('input', () => {
    const q = (input.value || '').trim().toLowerCase();
    if (q.length < 2) { dropdown.classList.add('hidden'); return; }
    const matches = Object.values(techDetailsMap)
      .filter(t => t.id.toLowerCase().startsWith(q) || t.name.toLowerCase().includes(q))
      .slice(0, 12);
    if (!matches.length) { dropdown.classList.add('hidden'); return; }
    dropdown.innerHTML = matches.map(t =>
      `<div class="tech-autocomplete-item" data-tid="${t.id}">
         <span class="tac-id">${t.id}</span>
         <span class="tac-name">${t.name}</span>
       </div>`
    ).join('');
    dropdown.classList.remove('hidden');
  });

  dropdown.addEventListener('click', e => {
    const item = e.target.closest('.tech-autocomplete-item');
    if (!item) return;
    input.value = item.dataset.tid;
    dropdown.classList.add('hidden');
    input.focus();
  });

  input.addEventListener('keydown', e => {
    if (dropdown.classList.contains('hidden')) return;
    const items = [...dropdown.querySelectorAll('.tech-autocomplete-item')];
    const idx = items.findIndex(i => i.classList.contains('active'));
    if (e.key === 'ArrowDown') {
      e.preventDefault();
      if (idx >= 0) items[idx].classList.remove('active');
      items[Math.min(idx + 1, items.length - 1)].classList.add('active');
    } else if (e.key === 'ArrowUp') {
      e.preventDefault();
      if (idx >= 0) items[idx].classList.remove('active');
      items[Math.max(idx - 1, 0)].classList.add('active');
    } else if (e.key === 'Enter') {
      const active = dropdown.querySelector('.tech-autocomplete-item.active');
      if (active) { e.preventDefault(); input.value = active.dataset.tid; dropdown.classList.add('hidden'); }
    } else if (e.key === 'Escape') {
      dropdown.classList.add('hidden');
    }
  });

  document.addEventListener('click', e => {
    if (!wrapper.contains(e.target)) dropdown.classList.add('hidden');
  }, true);
}

let mitDetailPopupEl = null;

function showMitDetailPopup(anchorEl, mid, name, description) {
  if (mitDetailPopupEl) mitDetailPopupEl.remove();
  if (techChipPopoverEl) { techChipPopoverEl.remove(); techChipPopoverEl = null; }
  const esc = s => String(s || '').replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
  const mitreUrl = `https://attack.mitre.org/mitigations/${mid}/`;
  const rect = anchorEl.getBoundingClientRect();
  const pop = document.createElement('div');
  pop.className = 'mit-detail-popup';
  pop.innerHTML = `
    <div class="mit-detail-header">
      <span class="mit-detail-mid">${esc(mid)}</span>
      <span class="mit-detail-name">${esc(name)}</span>
    </div>
    <div class="mit-detail-desc">${esc(description) || '<em style="color:var(--d-text-3)">Açıklama bulunamadı.</em>'}</div>
    <div class="mit-detail-footer">
      <a class="mit-detail-link" href="${mitreUrl}" target="_blank" rel="noopener">MITRE ATT&amp;CK ↗</a>
    </div>
  `;
  const viewportW = window.innerWidth;
  let left = rect.left + window.scrollX;
  const popW = 440;
  if (left + popW > viewportW - 10) left = viewportW - popW - 10;
  pop.style.left = `${Math.max(10, left)}px`;
  pop.style.top = `${rect.bottom + window.scrollY + 6}px`;
  document.body.appendChild(pop);
  mitDetailPopupEl = pop;

  const close = (evt) => {
    if (!mitDetailPopupEl) return;
    if (evt.target === anchorEl || anchorEl.contains(evt.target)) return;
    if (mitDetailPopupEl.contains(evt.target)) return;
    mitDetailPopupEl.remove();
    mitDetailPopupEl = null;
    document.removeEventListener('click', close, true);
  };
  setTimeout(() => document.addEventListener('click', close, true), 0);
}

function showTechChipPopover(anchorEl, text) {
  if (techChipPopoverEl) techChipPopoverEl.remove();
  const rect = anchorEl.getBoundingClientRect();
  const pop = document.createElement('div');
  pop.className = 'tech-chip-popover';
  pop.textContent = text;
  pop.style.left = `${rect.left + window.scrollX}px`;
  pop.style.top = `${rect.bottom + window.scrollY + 6}px`;
  document.body.appendChild(pop);
  techChipPopoverEl = pop;

  const close = (evt) => {
    if (!techChipPopoverEl) return;
    if (evt.target === anchorEl || anchorEl.contains(evt.target)) return;
    if (techChipPopoverEl.contains(evt.target)) return;
    techChipPopoverEl.remove();
    techChipPopoverEl = null;
    document.removeEventListener('click', close, true);
  };
  setTimeout(() => document.addEventListener('click', close, true), 0);
}

function renderLegend() {
  const container = document.getElementById('legendContainer');
  if (!container) return;
  container.innerHTML = '';

  // "Tümü" reset butonu
  const allItem = document.createElement('div');
  allItem.className = 'legend-item legend-item--all' + (filterAllProducts ? '' : ' legend-item--off');
  allItem.innerHTML = `<div class="legend-box legend-box--all"></div> Tümü`;
  allItem.addEventListener('click', () => {
    filterAllProducts = true;
    filterProducts = new Set();
    renderLegend();
    renderMatrix();
  });
  container.appendChild(allItem);

  products.forEach(p => {
    const item = document.createElement('div');
    const isActive = filterAllProducts || filterProducts.has(p.name);
    item.className = 'legend-item' + (isActive ? '' : ' legend-item--off');
    item.setAttribute('data-product', p.name);
    item.innerHTML = `<div class="legend-box" style="background:${p.color}"></div> ${p.name}`;
    item.addEventListener('click', () => {
      if (filterAllProducts) {
        filterAllProducts = false;
        filterProducts = new Set(products.map(x => x.name));
      }
      if (filterProducts.has(p.name)) {
        filterProducts.delete(p.name);
      } else {
        filterProducts.add(p.name);
      }
      if (filterProducts.size === 0) {
        filterAllProducts = true;
      }
      renderLegend();
      renderMatrix();
    });
    container.appendChild(item);
  });
}

function populateSourceSelect() {
  const select = document.getElementById('newRuleSource');
  const panelSelect = document.getElementById('panelRuleSource');
  const modalSelect = document.getElementById('modalRuleSource');
  if (select) select.innerHTML = '';
  if (panelSelect) panelSelect.innerHTML = '';
  if (modalSelect) modalSelect.innerHTML = '';
  products.forEach(p => {
    if (select) {
      const opt = document.createElement('option');
      opt.value = p.name;
      opt.textContent = p.name;
      select.appendChild(opt);
    }
    if (panelSelect) {
      const opt2 = document.createElement('option');
      opt2.value = p.name;
      opt2.textContent = p.name;
      panelSelect.appendChild(opt2);
    }
    if (modalSelect) {
      const opt3 = document.createElement('option');
      opt3.value = p.name;
      opt3.textContent = p.name;
      modalSelect.appendChild(opt3);
    }
  });
}

function renderProductsList() {
  const list = document.getElementById('productList');
  if (!list) return;
  list.innerHTML = '';
  products.forEach(p => {
    const row = document.createElement('div');
    row.className = 'product-item';
    row.innerHTML = `
      <div class="product-info">
        <div class="product-swatch" style="background:${p.color}"></div>
        <div>${p.name}</div>
      </div>
      <div class="product-actions">
        <input class="product-color" type="color" value="${p.color}" data-id="${p.id}">
        <button class="product-apply" data-id="${p.id}">Uygula</button>
        <button class="product-delete" data-id="${p.id}">Sil</button>
      </div>
    `;
    list.appendChild(row);
  });
  list.querySelectorAll('.product-apply').forEach(btn => {
    btn.addEventListener('click', async (e) => {
      const id = e.currentTarget.dataset.id;
      const picker = list.querySelector(`.product-color[data-id=\"${id}\"]`);
      const color = picker ? picker.value : null;
      if (!color) return;
      await apiFetch(`/api/products/${id}`, {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ color })
      });
      await loadProducts();
      renderMatrix();
    });
  });

  list.querySelectorAll('.product-delete').forEach(btn => {
    btn.addEventListener('click', async (e) => {
      const id = e.currentTarget.dataset.id;
      await apiFetch(`/api/products/${id}`, { method: 'DELETE' });
      await loadProducts();
      renderMatrix();
    });
  });
}

async function loadProducts() {
  const res = await apiFetch('/api/products');
  products = res.ok ? await res.json() : [];
  renderLegend();
  renderProductLegend();
  populateSourceSelect();
  renderProductsList();
}

function renderUsersList() {
  const list = document.getElementById('userList');
  if (!list) return;
  list.innerHTML = '';
  users.forEach(u => {
    const row = document.createElement('div');
    row.className = 'user-item';
    row.innerHTML = `
      <div class="user-name">${u.username}</div>
      <select class="user-role" data-id="${u.id}">
        <option value="viewer" ${u.role === 'viewer' ? 'selected' : ''}>viewer</option>
        <option value="editor" ${u.role === 'editor' ? 'selected' : ''}>editor</option>
        <option value="admin" ${u.role === 'admin' ? 'selected' : ''}>admin</option>
      </select>
      <label><input type="checkbox" class="user-active" data-id="${u.id}" ${u.is_active ? 'checked' : ''}/> aktif</label>
      <div style="display:flex; gap:8px;">
        <input type="password" class="user-password" data-id="${u.id}" placeholder="yeni sifre (opsiyonel)" />
        <button class="action-btn btn-add user-apply" data-id="${u.id}">Uygula</button>
      </div>
    `;
    list.appendChild(row);
  });

  list.querySelectorAll('.user-apply').forEach(btn => {
    btn.addEventListener('click', async (e) => {
      const id = e.currentTarget.dataset.id;
      const roleEl = list.querySelector(`.user-role[data-id="${id}"]`);
      const activeEl = list.querySelector(`.user-active[data-id="${id}"]`);
      const passwordEl = list.querySelector(`.user-password[data-id="${id}"]`);
      const payload = {
        role: roleEl ? roleEl.value : 'viewer',
        is_active: !!(activeEl && activeEl.checked)
      };
      const pwd = passwordEl ? passwordEl.value.trim() : '';
      if (pwd) payload.password = pwd;
      const res = await apiFetch(`/api/users/${id}`, {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload)
      });
      if (!res.ok) {
        const err = await res.json().catch(() => ({}));
        alert(err.error || 'Kullanici guncellenemedi');
        return;
      }
      if (passwordEl) passwordEl.value = '';
      await loadUsers();
      await loadAuditLogs();
    });
  });
}

async function loadUsers() {
  if (!hasRole('admin')) return;
  const res = await apiFetch('/api/users');
  users = res.ok ? await res.json() : [];
  renderUsersList();
}

function renderAuditLogs() {
  const list = document.getElementById('auditList');
  if (!list) return;
  list.innerHTML = '';
  auditLogs.forEach(l => {
    const row = document.createElement('div');
    row.className = 'audit-item';
    row.innerHTML = `
      <div>${l.created_at || ''}</div>
      <div>${l.username || '-'}</div>
      <div>${l.action}:${l.target_type}</div>
      <div>${l.target_id || ''} ${l.detail || ''}</div>
    `;
    list.appendChild(row);
  });
}

async function loadAuditLogs() {
  if (!hasRole('admin')) return;
  const res = await apiFetch('/api/audit-logs?limit=200');
  auditLogs = res.ok ? await res.json() : [];
  renderAuditLogs();
}

function populateTacticSelect() {
  const select = document.getElementById('newRuleTactic');
  const panelSelect = document.getElementById('panelRuleTactic');
  if (select) select.innerHTML = '';
  if (panelSelect) panelSelect.innerHTML = '';
  tacticOrder.forEach(t => {
    if (select) {
      const opt = document.createElement('option');
      opt.value = t;
      opt.textContent = t;
      select.appendChild(opt);
    }
    if (panelSelect) {
      const opt2 = document.createElement('option');
      opt2.value = t;
      opt2.textContent = t;
      panelSelect.appendChild(opt2);
    }
  });
}


function getTacticForTech(tid) {
  if (techTactics[tid] && techTactics[tid].length > 0) return techTactics[tid][0];
  const parent = tid.includes('.') ? tid.split('.')[0] : tid;
  if (techTactics[parent] && techTactics[parent].length > 0) return techTactics[parent][0];
  return 'Unknown';
}

function enrichRules() {
  const out = [];
  userRules.forEach(r => {
    const techs = (r.techniques && r.techniques.length > 0)
      ? r.techniques
      : [r.tech];
    techs.forEach(rawTech => {
      if (!rawTech || rawTech === 'None') return;
      const key = rawTech.toLowerCase().trim();
      let tid = nameToIdMap[key];
      if (!tid && /^t\d{4}/i.test(key)) tid = rawTech.toUpperCase();
      if (!tid) return;
      const details = techDetailsMap[tid];
      const parentId = details ? details.parentId : tid.split('.')[0];
      out.push({ ...r, tid, parentId, isSub: details ? details.isSub : tid.includes('.') });
    });
  });
  return out;
}

function getMitigationNote(mitigationId) {
  if (!mitigationNotes[mitigationId]) {
    mitigationNotes[mitigationId] = { checked: false, comment: '', team: '' };
  }
  return mitigationNotes[mitigationId];
}

function getCheckedMitigationCountForTech(techId) {
  const mitigations = mitigationsByTechnique[techId] || [];
  let count = 0;
  mitigations.forEach(m => {
    const note = getMitigationNote(m.id);
    if (note.checked || (mitigationEntries[m.id]?.length > 0)) count += 1;
  });
  return count;
}


// Bir teknik için kaç mitigasyon olduğunu döner (subteknik ise parent'a düşer).
function getMitigationTotal(techId) {
  const direct = (mitigationsByTechnique[techId] || []).length;
  if (direct > 0) return direct;
  const parentId = techDetailsMap[techId]?.parentId;
  if (parentId && parentId !== techId)
    return (mitigationsByTechnique[parentId] || []).length;
  return 0;
}

// Teknik bazlı ağırlıklı skor hesabı:
//   kural skoru  (50%) = min(kuralSayısı / rule_threshold, 1)
//   mitigation   (30%) = min(checkedMit / mitTotal, 1)
//   çeşitlilik   (20%) = min(productCount / 2, 1)
// techniqueConfig'ten rule_threshold ve importance alınır; yoksa sabit fallback kullanılır.
function computeScore(techId, rulesCount, mitigationCount, sources) {
  const cfg = techniqueConfig[techId] || {};
  const threshold = cfg.rule_threshold || SCORE_RULE_MAX;
  const mitTotal = getMitigationTotal(techId) || SCORE_MITIGATION_MAX;
  const sourceSet = new Set(Array.isArray(sources) ? sources : []);
  const ruleScore = Math.min(rulesCount / threshold, 1.0);
  const mitScore  = Math.min(mitigationCount / mitTotal, 1.0);
  const divScore  = Math.min(sourceSet.size / 2, 1.0);
  return Math.min(ruleScore * 0.50 + mitScore * 0.30 + divScore * 0.20, 1.0);
}

// Ortak lerp & renk sabitleri
// Yeşil: soğuk/sade ton (önceki cırtlak #35c48b yerine daha yumuşak)
function _colorLerp(a, b, t) {
  return { r: Math.round(a.r + (b.r - a.r) * t),
           g: Math.round(a.g + (b.g - a.g) * t),
           b: Math.round(a.b + (b.b - a.b) * t) };
}
const _SCORE_DARK  = { r: 20,  g: 26,  b: 34  };
const _SCORE_AMBER = { r: 162, g: 112, b: 26  };  // biraz daha soğuk amber
const _SCORE_GREEN = { r: 48,  g: 165, b: 122 };  // soğuk/sade yeşil

function _scoreRgb(score) {
  return score < 0.40
    ? _colorLerp(_SCORE_DARK, _SCORE_AMBER, score / 0.40)
    : _colorLerp(_SCORE_AMBER, _SCORE_GREEN, (score - 0.40) / 0.60);
}

// Ana kart rengi — %20 saydamlık (dark bg üzerinde ince tint)
function scoreToColor(score) {
  const c = _scoreRgb(score);
  return `rgba(${c.r},${c.g},${c.b},0.20)`;
}

// Alt teknik kartı — biraz daha sönük (%13 saydamlık)
function scoreToSubColor(score) {
  const c = _scoreRgb(score);
  return `rgba(${c.r},${c.g},${c.b},0.13)`;
}





function applySourceDots(card, sources) {
  const map = productColorMap();
  const colors = Array.from(new Set(sources)).map(s => map[s]).filter(Boolean);
  const existing = card.querySelector('.product-dots');
  if (existing) existing.remove();
  if (!colors || colors.length === 0) return;
  const dots = document.createElement('div');
  dots.className = 'product-dots';
  const maxDots = 5;
  const show = colors.slice(0, maxDots);
  show.forEach(c => {
    const dot = document.createElement('span');
    dot.className = 'product-dot';
    dot.style.background = c;
    dots.appendChild(dot);
  });
  if (colors.length > maxDots) {
    const more = document.createElement('span');
    more.className = 'product-dot product-dot-more';
    more.textContent = `+${colors.length - maxDots}`;
    dots.appendChild(more);
  }
  card.appendChild(dots);
}

function applyTechniqueVisuals(card, techId, rulesCount, mitigationCount, sources) {
  const score = computeScore(techId, rulesCount, mitigationCount, sources);
  card.style.backgroundColor = scoreToColor(score);
  card.classList.toggle('covered', (rulesCount > 0 || mitigationCount > 0));

  // Önemli ama az kapsanmış teknikler kırmızı kenarlıkla işaretlenir
  const importance = techniqueConfig[techId]?.importance || 0.5;
  card.classList.toggle('critical-gap', importance >= 0.7 && score < 0.35);

  // Hover tooltip için skor verisi
  const cfg = techniqueConfig[techId] || {};
  const mitTotal = getMitigationTotal(techId) || SCORE_MITIGATION_MAX;
  card.dataset.scoreData = JSON.stringify({
    techId, rulesCount, mitigationCount,
    sources: [...new Set(Array.isArray(sources) ? sources : [])],
    score: Math.round(score * 100),
    importance: Math.round(importance * 100),
    threshold: cfg.rule_threshold || SCORE_RULE_MAX,
    mitTotal,
    groupCount: cfg.group_count || 0
  });

  applySourceDots(card, sources);
}

function updateTechniqueCard(parentId) {
  const card = document.querySelector(`.technique-card[data-tech-id="${parentId}"]`);
  if (!card) return;
  const rulesCount = currentRulesByParent[parentId] || 0;
  const mitigationCount = getCheckedMitigationCountForTech(parentId);
  const sources = enrichRules().filter(r => r.parentId === parentId).map(r => r.source);
  const score = computeScore(parentId, rulesCount, mitigationCount, sources);
  card.style.backgroundColor = scoreToColor(score);
  card.classList.toggle('covered', (rulesCount > 0 || mitigationCount > 0));
  const importance = techniqueConfig[parentId]?.importance || 0.5;
  card.classList.toggle('critical-gap', importance >= 0.7 && score < 0.35);
}

function updateSubtechCard(techId) {
  const card = document.querySelector(`.subtech-card[data-tech-id="${techId}"]`);
  if (!card) return;
  const enriched = enrichRules().filter(r => r.tid === techId);
  const rulesCount = enriched.length;
  const mitigationCount = getCheckedMitigationCountForTech(techId);
  const sources = enriched.map(r => r.source);
  const score = computeScore(techId, rulesCount, mitigationCount, sources);
  card.style.backgroundColor = scoreToSubColor(score);
  card.classList.toggle('covered', (rulesCount > 0 || mitigationCount > 0));
  const importance = techniqueConfig[techId]?.importance || 0.5;
  card.classList.toggle('critical-gap', importance >= 0.7 && score < 0.35);
}

function refreshTechniqueCardsForMitigation(mitId) {
  const techSet = techsByMitigation[mitId];
  if (!techSet) return;
  const parents = new Set();
  techSet.forEach(tid => {
    const details = techDetailsMap[tid];
    if (details && details.parentId) parents.add(details.parentId);
    else parents.add(tid);
    updateSubtechCard(tid);
  });
  parents.forEach(pid => updateTechniqueCard(pid));
}

function buildSubtechContainer(parentId, enrichedData, allowedSubs) {
  const container = document.createElement('div');
  container.className = 'subtech-container';
  const subTechs = allowedSubs || (subTechsByParent[parentId] || []);
  if (subTechs.length == 0) return container;

  subTechs.forEach(st => {
    const subCard = document.createElement('div');
    subCard.className = 'subtech-card';
    subCard.dataset.techId = st.id;

    const rulesForSub = enrichedData.filter(r => r.tid == st.id);
    const mitigationCount = getCheckedMitigationCountForTech(st.id);
    const sources = rulesForSub.map(r => r.source);
    applyTechniqueVisuals(subCard, st.id, rulesForSub.length, mitigationCount, sources);
    // Alt teknikler daha soluk gösterilir — ana tekniğin görsel ağırlığını korur
    const subScore = computeScore(st.id, rulesForSub.length, mitigationCount, sources);
    subCard.style.backgroundColor = scoreToSubColor(subScore);

    const idEl = document.createElement('div');
    idEl.className = 'technique-id';
    idEl.textContent = st.id;
    const nameEl = document.createElement('div');
    nameEl.className = 'technique-name';
    nameEl.textContent = st.name;
    subCard.appendChild(idEl);
    subCard.appendChild(nameEl);

    subCard.style.cursor = 'pointer';
    subCard.onclick = (e) => {
      e.stopPropagation();
      openModal(st.id, st.name, rulesForSub);
    };

    container.appendChild(subCard);
  });

  return container;
}



function validateTechniqueInput(inputValue) {
  const val = (inputValue || '').trim();
  if (!val) return { ok: false, message: 'Teknik alanı boÅŸ.' };
  const isId = /^T\d{4}(\.\d{3})?$/i.test(val);
  if (isId) {
    const tid = val.toUpperCase();
    if (!techDetailsMap[tid]) return { ok: false, message: 'Teknik ID bulunamadı.' };
    return { ok: true, tid };
  }
  const lookup = nameToIdMap[val.toLowerCase()];
  if (!lookup) return { ok: false, message: 'Teknik adı bulunamadı.' };
  return { ok: true, tid: lookup };
}

async function addRuleDirect(name, tactic, tech, source) {
  if (!hasRole('editor')) {
    alert('Bu islem icin editor yetkisi gerekir.');
    return;
  }
  const validation = validateTechniqueInput(tech);
  if (!validation.ok) {
    alert(validation.message);
    return;
  }
  const tid = validation.tid;
  const finalTactic = (tactic && tactic !== 'Unknown') ? tactic : getTacticForTech(tid);

  const res = await apiFetch('/api/rules', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ name, tactic: finalTactic, tech: tid, source })
  });

  if (!res.ok) {
    const err = await res.json().catch(() => ({}));
    alert(err.error || 'Tespit eklenemedi');
    return;
  }

  const created = await res.json();
  userRules.push(created);
  renderRulesList();
  renderMatrix();
  alert('Tespit eklendi');
}

async function addNewRule() {
  const nameEl = document.getElementById('newRuleName');
  const tacticEl = document.getElementById('newRuleTactic');
  const techEl = document.getElementById('newRuleTech');
  const sourceEl = document.getElementById('newRuleSource');
  if (!nameEl || !tacticEl || !techEl || !sourceEl) return;
  const name = nameEl.value.trim();
  const tactic = tacticEl.value.trim();
  const tech = techEl.value.trim();
  const source = sourceEl.value.trim();

  if (!name || !tactic || !tech || !source) {
    alert('Lütfen alanları doldurun.');
    return;
  }
  await addRuleDirect(name, tactic, tech, source);
}

async function deleteRule(ruleId) {
  if (!hasRole('editor')) return;
  const res = await apiFetch(`/api/rules/${ruleId}`, { method: 'DELETE' });
  if (!res.ok) return;
  userRules = userRules.filter(r => r.id !== ruleId);
  renderRulesList();
  renderMatrix();
  document.getElementById('ruleModal').style.display = 'none';
}

async function openModal(parentId, parentName, rules) {
  if (mitDetailPopupEl) { mitDetailPopupEl.remove(); mitDetailPopupEl = null; }
  if (techChipPopoverEl) { techChipPopoverEl.remove(); techChipPopoverEl = null; }
  document.getElementById('modalTitle').innerText = `${parentId} - ${parentName}`;
  const body = document.getElementById('modalBody');
  const colorMap = productColorMap();
  body.innerHTML = '';
  await reloadMitigationEntries();

  // Teknik açıklaması ve meta bilgisi
  const descDiv = document.createElement('div');
  descDiv.className = 'modal-tech-desc';
  descDiv.innerHTML = '<div style="color:var(--d-text-3);font-size:12px;padding:4px 0">Yükleniyor…</div>';
  body.appendChild(descDiv);

  apiFetch(`/api/technique-detail/${parentId}`)
    .then(r => r.json())
    .then(d => {
      const esc = s => String(s||'').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;');
      const platforms = (d.platforms||[]).join(', ');
      const lvl = d.importance_level || 1;
      const lvlLabels = ['','Düşük','Orta-Düşük','Orta','Yüksek','Kritik'];
      let h = '';
      if (d.description) h += `<div class="modal-desc-text">${esc(d.description.slice(0,500))}${d.description.length>=500?'…':''}</div>`;
      if (platforms) h += `<div class="modal-desc-meta">Platform: ${esc(platforms)}</div>`;
      h += `<div class="modal-desc-meta">Önem: <span class="importance-badge imp-level-${lvl}">${lvl} — ${lvlLabels[lvl]}</span>`;
      if (d.mitre_url) h += ` &nbsp;<a class="modal-mitre-link" href="${esc(d.mitre_url)}" target="_blank" rel="noopener">MITRE ↗</a>`;
      h += '</div>';
      descDiv.innerHTML = h;
    })
    .catch(() => { descDiv.innerHTML = ''; });

  const tabBar = document.createElement('div');
  tabBar.className = 'modal-tabs';
  tabBar.innerHTML = `
    <button class="tab-btn active" data-tab="mitigationsTab">Mitigations</button>
    <button class="tab-btn" data-tab="rulesTab">Tespitler</button>
  `;
  body.appendChild(tabBar);

  const mitigationsTab = document.createElement('div');
  mitigationsTab.className = 'tab-panel active';
  mitigationsTab.id = 'mitigationsTab';
  const rulesTab = document.createElement('div');
  rulesTab.className = 'tab-panel';
  rulesTab.id = 'rulesTab';
  body.appendChild(mitigationsTab);
  body.appendChild(rulesTab);

  tabBar.querySelectorAll('.tab-btn').forEach(btn => {
    btn.addEventListener('click', () => {
      const target = btn.dataset.tab;
      tabBar.querySelectorAll('.tab-btn').forEach(b => b.classList.remove('active'));
      btn.classList.add('active');
      body.querySelectorAll('.tab-panel').forEach(p => {
        p.classList.toggle('active', p.id === target);
      });
    });
  });

  const ruleSearchWrap = document.createElement('div');
  ruleSearchWrap.className = 'rule-search';
  ruleSearchWrap.innerHTML = `<label>Tespit Ara</label><input type="text" id="ruleSearchInput" placeholder="Tespit adı ara" />`;
  rulesTab.appendChild(ruleSearchWrap);

  const modalRuleAdd = document.createElement('div');
  modalRuleAdd.className = 'modal-rule-add';
  const tacticHint = getTacticForTech(parentId);
  modalRuleAdd.innerHTML = `
    <div class="modal-rule-title">Tespit Ekle</div>
    <div class="modal-rule-row">
      <input type="text" id="modalRuleName" placeholder="Tespit adı" />
      <select id="modalRuleSource"></select>
      <button class="action-btn btn-add" id="btnModalAddRule">Ekle</button>
    </div>
    <div class="modal-rule-hint">Taktik: ${tacticHint} | Teknik: ${parentId}</div>
  `;
  if (hasRole('editor')) {
    body.appendChild(modalRuleAdd);
  }
  populateSourceSelect();

  const mitigationSection = document.createElement('div');
  mitigationSection.className = 'mitigation-section';
  const mitigations = mitigationsByTechnique[parentId] || [];
  mitigationSection.innerHTML = `<div class="mitigation-title">Mitigations (${mitigations.length})</div>`;

  if (mitigations.length == 0) {
    const emptyMit = document.createElement('div');
    emptyMit.style.color = '#aaa';
    emptyMit.style.fontSize = '0.85rem';
    emptyMit.textContent = 'Bu teknik için Mitigation bulunamadı.';
    mitigationSection.appendChild(emptyMit);
  } else {
    mitigations.forEach(m => {
      const note = getMitigationNote(m.id);
      const row = document.createElement('div');
      row.className = 'mitigation-row';
      if (note.checked) row.classList.add('checked');
      const isChecked = note.checked || (mitigationEntries[m.id]?.length > 0);
      row.innerHTML = `
        <label class="mitigation-name">
          <span class="mit-status-indicator ${isChecked ? 'checked' : ''}" data-mit="${m.id}">${isChecked ? '✓' : '○'}</span>
          ${m.id} - ${m.name}
          <span class="mitigation-info" data-tech="${parentId}" data-mit="${m.id}">i</span>
        </label>
        <div class="mitigation-fields">
          <div class="mitigation-entries" data-mit="${m.id}"></div>
          <div class="mitigation-entry-form ${hasRole('editor') ? '' : 'hidden'}">
            <span class="mitigation-entry-team-placeholder" data-mit="${m.id}"></span>
            <textarea class="mitigation-entry-comment" data-mit="${m.id}" placeholder="Yorum"></textarea>
            <button class="action-btn btn-add mitigation-entry-add" data-mit="${m.id}">Ekle</button>
          </div>
          <div class="mitigation-pop" data-tech="${parentId}" data-mit="${m.id}">
            <div class="mitigation-meta">Kısa açıklama</div>
            <div class="mitigation-summary">${summarizeText(m.description || 'Açıklama bulunamadı.')}</div>
            <div class="mitigation-full">${m.description || 'Açıklama bulunamadı.'}</div>
            <button class="mitigation-more">Detay</button>
          </div>
        </div>
      `;
      renderMitigationEntries(row, m.id);
      // Replace team placeholder with select
      const teamPh = row.querySelector('.mitigation-entry-team-placeholder');
      if (teamPh) teamPh.replaceWith(buildTeamSelectEl(m.id));
      mitigationSection.appendChild(row);
    });
  }

  mitigationsTab.appendChild(mitigationSection);

  const grouped = {};
  grouped['Direct'] = rules.filter(r => !r.isSub);
  rules.filter(r => r.isSub).forEach(r => { if (!grouped[r.tid]) grouped[r.tid] = []; grouped[r.tid].push(r); });

  Object.keys(grouped).forEach(key => {
    const groupRules = grouped[key];
    if (groupRules.length == 0) return;
    const headerTitle = (key == 'Direct') ? 'DoÄŸrudan EÅŸleÅŸmeler' : `${key} - ${techDetailsMap[key]?.name || 'Unknown'}`;
    const groupDiv = document.createElement('div');
    groupDiv.className = 'sub-tech-group';
    groupDiv.innerHTML = `<div class="sub-tech-header">${headerTitle}</div>`;

    const table = document.createElement('table');
    table.className = 'table';
    let tbody = '<tbody>';
    groupRules.forEach(r => {
      tbody += `<tr data-rule-name="${r.name.toLowerCase()}">
        <td>${r.name}</td>
        <td style="text-align:right">
          <span class="source-tag" style="background:${colorMap[r.source] || "#546e7a"}">${r.source}</span>
          ${hasRole('editor') ? `<button class="delete-btn" onclick="deleteRule(${r.id})">Sil</button>` : ''}
        </td>
      </tr>`;
    });
    tbody += '</tbody>';
    table.innerHTML = tbody;

    groupDiv.appendChild(table);
    rulesTab.appendChild(groupDiv);
  });

  const mitigationSummary = document.createElement('div');
  mitigationSummary.className = 'mitigation-summary-section';
  const mitList = mitigationsByTechnique[parentId] || [];
  mitigationSummary.innerHTML = `<div class="mitigation-summary-title">Mitigations (Ekip/Yorum)</div>`;
  if (mitList.length === 0) {
    const empty = document.createElement('div');
    empty.className = 'mitigation-empty';
    empty.textContent = 'Kayıt yok.';
    mitigationSummary.appendChild(empty);
  } else {
    mitList.forEach(m => {
      const entries = mitigationEntries[m.id] || [];
      const block = document.createElement('div');
      block.className = 'mitigation-summary-row';
      const entriesHtml = entries.length
        ? entries.map(e => `<div class="mitigation-entry-line"><span>${e.team}</span> ${e.comment}</div>`).join('')
        : '<div class="mitigation-empty">Kayıt yok.</div>';
      block.innerHTML = `<div class="mitigation-summary-name">${m.id} - ${m.name}</div>${entriesHtml}`;
      mitigationSummary.appendChild(block);
    });
  }
  rulesTab.appendChild(mitigationSummary);

  mitigationsTab.querySelectorAll('.mitigation-entry-add').forEach(btn => {
    btn.addEventListener('click', async (e) => {
      const mitId = e.currentTarget.dataset.mit;
      const row = e.currentTarget.closest('.mitigation-row');
      if (!mitId || !row) return;
      const teamInput = row.querySelector('.mitigation-entry-team');
      const commentInput = row.querySelector('.mitigation-entry-comment');
      const team = (teamInput?.value || '').trim();
      const comment = (commentInput?.value || '').trim();
      if (!team || !comment) {
        alert('Ekip ve yorum gerekli.');
        return;
      }
      const created = await addMitigationEntry(mitId, team, comment);
      if (!created) return;
      await reloadMitigationEntries();
      if (teamInput) teamInput.value = '';
      if (commentInput) commentInput.value = '';
      if (!mitigationNotes[mitId]) mitigationNotes[mitId] = { checked: false, comment: '', team: '' };
      mitigationNotes[mitId].checked = true;
      refreshTechniqueCardsForMitigation(mitId);
      // Update status indicator
      const indicator = mitigationsTab.querySelector(`.mit-status-indicator[data-mit="${mitId}"]`);
      if (indicator) { indicator.textContent = '✓'; indicator.classList.add('checked'); }
      const mitigationRow = indicator?.closest('.mitigation-row');
      if (mitigationRow) { mitigationRow.classList.add('checked'); }
      refreshMitigationEntriesInModal(mitId, mitigationsTab);
    });
  });

  mitigationsTab.querySelectorAll('.mitigation-info').forEach(btn => {
    btn.addEventListener('click', (e) => {
      const row = e.currentTarget.closest('.mitigation-row');
      if (!row) return;
      const pop = row.querySelector('.mitigation-pop');
      if (!pop) return;
      const isOpen = pop.classList.contains('open');
      mitigationsTab.querySelectorAll('.mitigation-pop.open').forEach(p => p.classList.remove('open'));
      if (!isOpen) pop.classList.add('open');
    });
  });
  mitigationsTab.querySelectorAll('.mitigation-more').forEach(btn => {
    btn.addEventListener('click', (e) => {
      const pop = e.currentTarget.closest('.mitigation-pop');
      if (!pop) return;
      const full = pop.querySelector('.mitigation-full');
      if (!full) return;
      const isOpen = full.classList.toggle('open');
      e.currentTarget.textContent = isOpen ? 'Kısa' : 'Detay';
    });
  });

  const btnModalAdd = document.getElementById('btnModalAddRule');
  if (btnModalAdd) {
    btnModalAdd.addEventListener('click', async () => {
      const name = (document.getElementById('modalRuleName').value || '').trim();
      const source = (document.getElementById('modalRuleSource').value || '').trim();
      if (!name || !source) {
        alert('Lütfen alanları doldurun.');
        return;
      }
      await addRuleDirect(name, tacticHint, parentId, source);
    });
  }

  const ruleInput = document.getElementById('ruleSearchInput');
  if (ruleInput) {
    ruleInput.addEventListener('input', (e) => {
      const term = (e.target.value || '').toLowerCase();
      rulesTab.querySelectorAll('tr[data-rule-name]').forEach(tr => {
        const name = tr.getAttribute('data-rule-name') || '';
        tr.style.display = name.includes(term) ? '' : 'none';
      });
    });
  }

  // Admin: teknik bazlı önem ve kural eşiği override bölümü
  if (hasRole('admin')) {
    const cfg = techniqueConfig[parentId] || {};
    const cfgDiv = document.createElement('div');
    cfgDiv.className = 'tech-config-admin';
    const srcLabel = cfg.source === 'admin' ? 'admin override' : `auto (${cfg.group_count || 0} grup)`;
    cfgDiv.innerHTML = `
      <div class="tech-config-title">Teknik Yap\u0131land\u0131rmas\u0131 <span class="cfg-source-tag">${srcLabel}</span></div>
      <div class="tech-config-row">
        <label>\xd6nem (0.1\u20131.0)</label>
        <input type="number" id="cfgImportance" min="0.1" max="1.0" step="0.05" value="${(cfg.importance || 0.5).toFixed(2)}" />
        <small>Mevcut: ${cfg.group_count || 0} tehdit grubu, ${cfg.tool_count || 0} ara\xe7</small>
      </div>
      <div class="tech-config-row">
        <label>Tespit E\u015fi\u011fi</label>
        <select id="cfgThreshold">${[1,2,3,4,5,6,7,8,9,10].map(n =>
          `<option value="${n}"${(cfg.rule_threshold || 3) === n ? ' selected' : ''}>${n}</option>`
        ).join('')}</select>
        <small>\u201cYeterli kapsama\u201d i\xe7in gereken minimum tespit say\u0131s\u0131</small>
      </div>
      <button class="action-btn btn-add" id="btnSaveTechConfig">Kaydet</button>
    `;
    body.appendChild(cfgDiv);

    document.getElementById('btnSaveTechConfig').addEventListener('click', async () => {
      const importance     = parseFloat(document.getElementById('cfgImportance').value);
      const rule_threshold = parseInt(document.getElementById('cfgThreshold').value, 10);
      if (isNaN(importance) || isNaN(rule_threshold)) return;
      const res = await apiFetch(`/api/technique-config/${parentId}`, {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ importance, rule_threshold })
      });
      if (res.ok) {
        techniqueConfig[parentId] = {
          ...techniqueConfig[parentId],
          importance,
          rule_threshold,
          source: 'admin'
        };
        alert('Kaydedildi. Matris bir sonraki render\'da g\xfcncellenecek.');
      } else {
        alert('Kaydetme ba\u015far\u0131s\u0131z.');
      }
    });
  }

  document.getElementById('ruleModal').style.display = 'flex';
}


async function saveMitigationNote(mitId, note) {
  if (!hasRole('editor')) return;
  await apiFetch('/api/mitigation-notes', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      mitigation_id: mitId,
      checked: !!note.checked,
      comment: note.comment || '',
      team: note.team || ''
    })
  });
}

async function addMitigationEntry(mitId, team, comment) {
  if (!hasRole('editor')) return null;
  const res = await apiFetch('/api/mitigation-entries', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ mitigation_id: mitId, team, comment })
  });
  if (!res.ok) {
    const err = await res.json().catch(() => ({}));
    alert(err.error || 'Mitigation kaydı eklenemedi');
    return null;
  }
  return await res.json();
}

async function deleteMitigationEntry(entryId) {
  if (!hasRole('editor')) return false;
  const res = await apiFetch(`/api/mitigation-entries/${entryId}`, { method: 'DELETE' });
  if (!res.ok) return false;
  return true;
}

function renderMitigationEntries(row, mitId) {
  const list = row.querySelector('.mitigation-entries');
  if (!list) return;
  const entries = mitigationEntries[mitId] || [];
  if (entries.length === 0) {
    list.innerHTML = '<div class="mitigation-empty">Kayıt yok.</div>';
    return;
  }
  list.innerHTML = entries.map(e => `
    <div class="mitigation-entry">
      <div class="entry-team">${e.team}</div>
      <div class="entry-comment">${e.comment}</div>
      ${hasRole('editor') ? `<button class="entry-delete" data-entry-id="${e.id}">Sil</button>` : ''}
    </div>
  `).join('');

  list.querySelectorAll('.entry-delete').forEach(btn => {
    btn.addEventListener('click', async (evt) => {
      const id = evt.currentTarget.dataset.entryId;
      if (!id) return;
      const ok = await deleteMitigationEntry(id);
      if (!ok) return;
      await reloadMitigationEntries();
      if (!mitigationNotes[mitId]) mitigationNotes[mitId] = { checked: false, comment: '', team: '' };
      mitigationNotes[mitId].checked = (mitigationEntries[mitId]?.length > 0);
      refreshTechniqueCardsForMitigation(mitId);
      renderMitigationEntries(row, mitId);
    });
  });
}

function refreshMitigationEntriesInModal(mitId, root) {
  if (!root) return;
  root.querySelectorAll(`.mitigation-row`).forEach(r => {
    const entryList = r.querySelector('.mitigation-entries');
    if (!entryList) return;
    const rowMit = r.querySelector('[data-mit]')?.dataset?.mit;
    if (rowMit === mitId) renderMitigationEntries(r, mitId);
  });
}



function wireSidebarToggle() {
  const toggle = document.getElementById('sidebarToggle');
  const sidebar = document.querySelector('.sidebar');
  if (!toggle || !sidebar) return;
  toggle.addEventListener('click', () => {
    sidebar.classList.toggle('collapsed');
  });
}

function wireNavigation() {
  const items = document.querySelectorAll('.nav-item');
  const panels = document.querySelectorAll('.panel');
  items.forEach(item => {
    item.addEventListener('click', () => {
      const target = item.dataset.target;
      items.forEach(i => i.classList.remove('active'));
      item.classList.add('active');
      panels.forEach(p => p.classList.toggle('active', p.id === target));
    });
  });
}


async function addProduct() {
  if (!hasRole('admin')) {
    alert('Bu islem icin admin yetkisi gerekir.');
    return;
  }
  const name = document.getElementById('productName').value.trim();
  const color = document.getElementById('productColor').value.trim();
  if (!name || !color) {
    alert('Ãœrün adı ve renk gerekli.');
    return;
  }
  const res = await apiFetch('/api/products', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ name, color })
  });
  if (!res.ok) {
    const err = await res.json().catch(() => ({}));
    alert(err.error || 'Ãœrün eklenemedi');
    return;
  }
  document.getElementById('productName').value = '';
  await loadProducts();
  renderMatrix();
}

async function uploadCsv() {
  if (!hasRole('editor')) {
    alert('Bu islem icin editor yetkisi gerekir.');
    return;
  }
  const fileInput = document.getElementById('csvFile');
  const result = document.getElementById('uploadResult');
  result.textContent = '';
  if (!fileInput.files || fileInput.files.length === 0) {
    result.textContent = 'Lütfen bir CSV dosyası seçin.';
    return;
  }
  const form = new FormData();
  form.append('file', fileInput.files[0]);
  const res = await apiFetch('/api/rules/bulk', { method: 'POST', body: form });
  const payload = await res.json().catch(() => ({}));
  if (!res.ok) {
    result.textContent = payload.error || 'Yükleme baÅŸarısız.';
    return;
  }
  await reloadData();
  renderMatrix();
  const errors = (payload.errors || []).slice(0, 10).join(' | ');
  result.textContent = `Yüklendi: ${payload.inserted}. Hata: ${payload.errors.length}` + (errors ? ` (${errors})` : '');
}

async function addUser() {
  if (!hasRole('admin')) return;
  const username = (document.getElementById('newUsername')?.value || '').trim();
  const password = (document.getElementById('newUserPassword')?.value || '').trim();
  const role = (document.getElementById('newUserRole')?.value || '').trim();
  if (!username || !password || !role) {
    alert('Kullanici adi, sifre ve rol gerekli.');
    return;
  }
  const res = await apiFetch('/api/users', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ username, password, role })
  });
  if (!res.ok) {
    const err = await res.json().catch(() => ({}));
    alert(err.error || 'Kullanici eklenemedi');
    return;
  }
  document.getElementById('newUsername').value = '';
  document.getElementById('newUserPassword').value = '';
  document.getElementById('newUserRole').value = 'viewer';
  await loadUsers();
  await loadAuditLogs();
}

function wireSettings() {
  const addBtn = document.getElementById('btnAddProduct');
  if (addBtn) addBtn.addEventListener('click', addProduct);
  const uploadBtn = document.getElementById('btnUploadCsv');
  if (uploadBtn) uploadBtn.addEventListener('click', uploadCsv);
  const addUserBtn = document.getElementById('btnAddUser');
  if (addUserBtn) addUserBtn.addEventListener('click', addUser);
  const refreshAuditBtn = document.getElementById('btnRefreshAudit');
  if (refreshAuditBtn) refreshAuditBtn.addEventListener('click', loadAuditLogs);
  wireSettingsTabs();
}

// Ayarlar panelindeki 4 sekme butonuna click event'i bağlar.
// Aktif sekme: .settings-tab-btn.active + .settings-tab-panel.active (CSS ile görünür).
// Sekme yapısı (index.html):
//   stab-product  → Ürün Yönetimi (editor+)
//   stab-csv      → CSV Yükleme (editor+, applyRoleUI ile gizlenir)
//   stab-users    → Kullanıcılar (admin, applyRoleUI ile gizlenir)
//   stab-audit    → Audit Log (admin, applyRoleUI ile gizlenir)
function wireSettingsTabs() {
  const tabBar = document.getElementById('settingsTabBar');
  if (!tabBar) return;
  tabBar.querySelectorAll('.settings-tab-btn').forEach(btn => {
    btn.addEventListener('click', () => {
      tabBar.querySelectorAll('.settings-tab-btn').forEach(b => b.classList.remove('active'));
      btn.classList.add('active');
      document.querySelectorAll('.settings-tab-panel').forEach(p =>
        p.classList.toggle('active', p.id === btn.dataset.tab)
      );
    });
  });
}

function wireSearch() {
  const input = document.getElementById('techSearch');
  if (!input) return;
  input.addEventListener('input', (e) => {
    filterSearch = e.target.value || '';
    renderMatrix();
  });
}


function setFieldError(el, msg) {
  let hint = el.parentElement.querySelector('.field-error');
  if (!hint) {
    hint = document.createElement('div');
    hint.className = 'field-error';
    el.parentElement.appendChild(hint);
  }
  hint.textContent = msg || '';
  hint.style.display = msg ? 'block' : 'none';
  el.classList.toggle('input-error', !!msg);
}

function wireValidation() {
  const techInput = document.getElementById('newRuleTech');
  if (!techInput) return;
  techInput.addEventListener('input', () => {
    const val = techInput.value.trim();
    if (!val) {
      setFieldError(techInput, 'Teknik alanı boÅŸ.');
      return;
    }
    const isId = /^T\d{4}(\.\d{3})?$/i.test(val);
    if (isId) {
      const tid = val.toUpperCase();
      if (!techDetailsMap[tid]) {
        setFieldError(techInput, 'Teknik ID bulunamadı.');
      } else {
        setFieldError(techInput, '');
      }
      return;
    }
    const lookup = nameToIdMap[val.toLowerCase()];
    if (!lookup) {
      setFieldError(techInput, 'Teknik adı bulunamadı.');
      return;
    }
    setFieldError(techInput, '');
  });
}

function wireExport() {
  const btnCsv = document.getElementById('btnExportCsv');
  const btnPdf = document.getElementById('btnExportPdf');
  const btnLayer = document.getElementById('btnExportLayer');
  if (btnCsv) btnCsv.addEventListener('click', exportCsv);
  if (btnPdf) btnPdf.addEventListener('click', exportPdf);
  if (btnLayer) btnLayer.addEventListener('click', exportLayer);
}


function wireActions() {
  wireNavigation();
  wireSearch();
  wireExport();
  wireValidation();
  wireSidebarToggle();
  wireSettings();
  wireNewPanels();
  const addBtn = document.getElementById('btnAdd');
  if (addBtn) addBtn.addEventListener('click', addNewRule);
  document.getElementById('modalClose').addEventListener('click', () => {
    document.getElementById('ruleModal').style.display = 'none';
  });

  const resetBtn = document.getElementById('btnReset');
  if (resetBtn) {
    resetBtn.addEventListener('click', async () => {
      const confirmText = prompt('İÅŸlemi onaylamak için RESET yazın:');
      if (confirmText !== 'RESET') return;
      const res = await apiFetch('/api/admin/reset', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ confirm: 'RESET', reseed: true })
      });
      if (!res.ok) {
        const err = await res.json().catch(() => ({}));
        alert(err.error || 'Sıfırlama baÅŸarısız');
        return;
      }
      await reloadData();
      renderMatrix();
      alert('Veriler sıfırlandı ve yeniden yüklendi.');
    });
  }

  document.addEventListener('keydown', (e) => {
    if (e.key !== 'Escape') return;
    const modal = document.getElementById('ruleModal');
    if (modal && modal.style.display === 'flex') modal.style.display = 'none';
    if (mitDetailPopupEl) { mitDetailPopupEl.remove(); mitDetailPopupEl = null; }
    if (techChipPopoverEl) { techChipPopoverEl.remove(); techChipPopoverEl = null; }
  });

  const btnExpandAll = document.getElementById('btnExpandAll');
  if (btnExpandAll) {
    btnExpandAll.addEventListener('click', () => {
      const containers = document.querySelectorAll('.subtech-container');
      const anyOpen = [...containers].some(c => c.children.length > 0 && !c.classList.contains('open'));
      containers.forEach(c => { if (c.children.length > 0) c.classList.toggle('open', anyOpen); });
      document.querySelectorAll('.technique-card.has-subtechs').forEach(c => c.classList.toggle('expanded', anyOpen));
      btnExpandAll.textContent = anyOpen ? 'Hepsini Kapat' : 'Hepsini Aç';
    });
  }

  const logoutBtn = document.getElementById('btnLogout');
  if (logoutBtn) {
    logoutBtn.addEventListener('click', async () => {
      await apiFetch('/api/logout', { method: 'POST' });
      window.location.href = '/login';
    });
  }
}

init();


function renderMatrix() {
  const enrichedData = enrichRules();
  const container = document.getElementById('matrix');
  container.innerHTML = '';
  currentRulesByParent = {};
  visibleExportRows = [];
  let visibleColumns = 0;

  document.getElementById('totalRules').innerText = userRules.length;
  const uniqueParents = new Set(enrichedData.map(r => r.parentId));
  document.getElementById('coveredTechs').innerText = uniqueParents.size;

  tacticOrder.forEach(tactic => {
    const col = document.createElement('div');
    col.className = 'tactic-column';
    col.innerHTML = `<div class="tactic-header">${tactic}</div>`;
    const techniques = (matrixStructure[tactic] || []).sort((a, b) => a.id.localeCompare(b.id));

    techniques.forEach(tech => {
      const parentMatchesSearch = matchesSearch(tech);
      const parentRules = enrichedData.filter(r => r.parentId == tech.id);
      const parentMatchesProduct = matchesProduct(parentRules);

      const subTechs = subTechsByParent[tech.id] || [];
      const subMatches = subTechs.filter(st => {
        const rulesForSub = enrichedData.filter(r => r.tid == st.id);
        const subSearch = matchesSearch(st);
        const subProd = matchesProduct(rulesForSub);
        return subSearch && subProd;
      });

      if (!(parentMatchesSearch && parentMatchesProduct) && subMatches.length === 0) {
        return;
      }

      // export rows
      const parentRuleCount = parentRules.length;
      const parentMitCount = getCheckedMitigationCountForTech(tech.id);
      const parentSources = parentRules.map(r => r.source);
      visibleExportRows.push({
        type: "technique",
        tech_id: tech.id,
        name: tech.name,
        tactic: tactic,
        rule_count: parentRuleCount,
        mitigation_checked: parentMitCount,
        products: Array.from(new Set(parentSources)),
        score: computeScore(tech.id, parentRuleCount, parentMitCount, parentSources)
      });
      subMatches.forEach(st => {
        const subRules = enrichedData.filter(r => r.tid == st.id);
        const subRuleCount = subRules.length;
        const subMitCount = getCheckedMitigationCountForTech(st.id);
        const subSources = subRules.map(r => r.source);
        visibleExportRows.push({
          type: "subtechnique",
          tech_id: st.id,
          name: st.name,
          tactic: tactic,
          rule_count: subRuleCount,
          mitigation_checked: subMitCount,
          products: Array.from(new Set(subSources)),
          score: computeScore(st.id, subRuleCount, subMitCount, subSources)
        });
      });

      const rulesForCell = parentRules;
      const card = document.createElement('div');
      card.className = 'technique-card';
      card.dataset.techId = tech.id;
      currentRulesByParent[tech.id] = rulesForCell.length;

      if (rulesForCell.length > 0) {
        card.style.borderColor = '#fff';
      }

      const mitigationCount = getCheckedMitigationCountForTech(tech.id);
      const sources = rulesForCell.map(r => r.source);
      applyTechniqueVisuals(card, tech.id, rulesForCell.length, mitigationCount, sources);

      const idEl = document.createElement('div');
      idEl.className = 'technique-id';
      idEl.textContent = tech.id;
      const nameEl = document.createElement('div');
      nameEl.className = 'technique-name';
      nameEl.textContent = tech.name;

      const detailBtn = document.createElement('button');
      detailBtn.className = 'detail-btn';
      detailBtn.textContent = 'Detay';
      detailBtn.onclick = (e) => {
        e.stopPropagation();
        openModal(tech.id, tech.name, rulesForCell);
      };

      card.appendChild(idEl);
      card.appendChild(nameEl);
      card.appendChild(detailBtn);

      const subContainer = buildSubtechContainer(tech.id, enrichedData, subMatches);
      card.style.cursor = 'pointer';
      if (subContainer.children.length > 0) card.classList.add('has-subtechs');
      card.onclick = () => {
        if (subContainer && subContainer.children.length > 0) {
          const isOpen = subContainer.classList.toggle('open');
          card.classList.toggle('expanded', isOpen);
        }
      };

      col.appendChild(card);
      col.appendChild(subContainer);
    });

    if (col.children.length > 1) visibleColumns += 1;
    container.appendChild(col);
  });

  if (visibleColumns === 0) {
    container.innerHTML = `
      <div class="empty-state">
        <div class="empty-icon">
          <svg width="64" height="64" viewBox="0 0 24 24" fill="none" stroke="#6b7d88" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round">
            <circle cx="11" cy="11" r="7"></circle>
            <line x1="16.65" y1="16.65" x2="21" y2="21"></line>
          </svg>
        </div>
        <div class="empty-title">Sonuç bulunamadı</div>
        <div class="empty-sub">Arama veya ürün filtrelerini temizleyip tekrar deneyin.</div>
      </div>
    `;
  }

  const expBtn = document.getElementById('btnExpandAll');
  if (expBtn) expBtn.textContent = 'Hepsini Aç';

  updateMatrixStats();
  wireScoreTooltip();
}

function updateMatrixStats() {
  const parents = visibleExportRows.filter(r => r.type === 'technique');
  const subs    = visibleExportRows.filter(r => r.type === 'subtechnique');

  const totalP   = parents.length;
  const coveredP = parents.filter(r => r.rule_count > 0 || r.mitigation_checked > 0).length;
  const covPct   = totalP ? Math.round(coveredP / totalP * 100) : 0;

  const totalS   = subs.length;
  const coveredS = subs.filter(r => r.rule_count > 0 || r.mitigation_checked > 0).length;

  const avgScore = totalP
    ? Math.round(parents.reduce((s, r) => s + r.score, 0) / totalP * 100)
    : 0;

  const allRows = visibleExportRows;
  const avgAll  = allRows.length
    ? Math.round(allRows.reduce((s, r) => s + r.score, 0) / allRows.length * 100)
    : 0;

  const criticalGap = parents.filter(r => {
    const cfg = techniqueConfig[r.tech_id] || {};
    return (cfg.importance || 0.5) >= 0.7 && r.score < 0.35;
  }).length;

  const totalMitEntries = Object.values(mitigationEntries).reduce((s, a) => s + a.length, 0);

  const setVal = (id, text, cls) => {
    const el = document.getElementById(id);
    if (!el) return;
    el.textContent = text;
    el.className = 'mstat-val' + (cls ? ' ' + cls : '');
  };

  setVal('ms-total',    totalP);
  setVal('ms-covered',  totalP ? `${coveredP} / ${totalP} (${covPct}%)` : '—',
    covPct >= 70 ? 'good' : covPct >= 40 ? 'mid' : 'bad');
  setVal('ms-sub',      totalS ? `${coveredS} / ${totalS}` : '—',
    totalS && coveredS / totalS >= 0.5 ? 'good' : 'mid');
  setVal('ms-score',   avgScore,
    avgScore >= 60 ? 'good' : avgScore >= 35 ? 'mid' : 'bad');
  setVal('ms-avg-all', avgAll + '%',
    avgAll >= 60 ? 'good' : avgAll >= 35 ? 'mid' : 'bad');
  setVal('ms-gap',      criticalGap,
    criticalGap === 0 ? 'muted' : 'bad');
  setVal('ms-mitentry', totalMitEntries,
    totalMitEntries > 0 ? 'good' : 'muted');
}

// Teknik kartları üzerine gelinince kural/mitigation/önem/skor breakdown tooltip'i gösterir.
function wireScoreTooltip() {
  let tip = null;
  document.querySelectorAll('.technique-card[data-score-data], .subtech-card[data-score-data]')
    .forEach(card => {
      card.addEventListener('mouseenter', () => {
        if (tip) tip.remove();
        let d;
        try { d = JSON.parse(card.dataset.scoreData || '{}'); } catch { return; }
        if (!d.techId) return;
        const ruleBar  = Math.min(d.rulesCount / Math.max(d.threshold, 1), 1) * 100;
        const mitBar   = d.mitTotal > 0 ? Math.min(d.mitigationCount / d.mitTotal, 1) * 100 : 0;
        tip = document.createElement('div');
        tip.className = 'score-tooltip';
        tip.innerHTML = `
          <div class="score-tooltip-row">
            <span class="score-tooltip-label">Tespit</span>
            <span class="score-tooltip-val">${d.rulesCount}/${d.threshold}</span>
          </div>
          <div class="score-tooltip-bar"><div class="score-tooltip-fill" style="width:${ruleBar.toFixed(0)}%;background:#4f86c6"></div></div>
          <div class="score-tooltip-row">
            <span class="score-tooltip-label">Mitigation</span>
            <span class="score-tooltip-val">${d.mitigationCount}/${d.mitTotal}</span>
          </div>
          <div class="score-tooltip-bar"><div class="score-tooltip-fill" style="width:${mitBar.toFixed(0)}%;background:#35c48b"></div></div>
          <div class="score-tooltip-row">
            <span class="score-tooltip-label">\xc7e\u015fitlilik</span>
            <span class="score-tooltip-val">${d.sources.length} \xfcr\xfcn</span>
          </div>
          <div class="score-tooltip-divider"></div>
          <div class="score-tooltip-row">
            <span class="score-tooltip-label">\xd6nem</span>
            <span class="score-tooltip-val">${d.importance}% \xb7 ${d.groupCount} grup</span>
          </div>
          <div class="score-tooltip-row">
            <span class="score-tooltip-label">Toplam Skor</span>
            <span class="score-tooltip-val" style="color:#35c48b">${d.score}%</span>
          </div>
        `;
        const rect = card.getBoundingClientRect();
        tip.style.left = `${Math.min(rect.left, window.innerWidth - 210)}px`;
        tip.style.top  = `${rect.bottom + 4}px`;
        document.body.appendChild(tip);
      });
      card.addEventListener('mouseleave', () => { if (tip) { tip.remove(); tip = null; } });
    });
}

// ══════════════════════════════════════════════════════════════
// P0: GAP Analysis Panel
// ══════════════════════════════════════════════════════════════
const _esc = s => String(s || '').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');

let _gapData = null;

async function loadGapDashboard() {
  const el = document.getElementById('gapContent');
  if (!el) return;
  el.innerHTML = '<div style="color:var(--d-text-3);padding:20px">Yükleniyor…</div>';
  try {
    const res = await apiFetch('/api/gap-analysis');
    if (!res.ok) { el.innerHTML = '<div style="color:var(--d-red);padding:20px">GAP verisi yüklenemedi.</div>'; return; }
    _gapData = await res.json();
    renderGapDashboard(_gapData);
  } catch (e) {
    el.innerHTML = '<div style="color:var(--d-red);padding:20px">Hata: ' + _esc(e.message) + '</div>';
  }
}

function renderGapDashboard(data) {
  const el = document.getElementById('gapContent');
  if (!el || !data) return;

  const ov = data.overview || {};
  const total = ov.total_techniques || 0;
  const covered = ov.covered_techniques || 0;
  const pct = ov.coverage_pct || 0;
  const critCount = ov.critical_gap_count || 0;

  const IMP_LABEL = ['','Düşük','Orta-Düşük','Orta','Yüksek','Kritik'];
  const TACTIC_TR = {
    'reconnaissance':'Reconnaissance','resource-development':'Resource Development',
    'initial-access':'Initial Access','execution':'Execution',
    'persistence':'Persistence','privilege-escalation':'Privilege Escalation',
    'defense-evasion':'Defense Evasion','credential-access':'Credential Access',
    'discovery':'Discovery','lateral-movement':'Lateral Movement',
    'collection':'Collection','command-and-control':'Command & Control',
    'exfiltration':'Exfiltration','impact':'Impact'
  };

  // Stat cards
  let html = `<div class="gap-stat-cards">
    <div class="gap-stat-card">
      <div class="gap-stat-val">${total}</div>
      <div class="gap-stat-lbl">Toplam Teknik</div>
      <div class="gap-stat-sub">+${ov.total_subtechniques || 0} alt teknik</div>
    </div>
    <div class="gap-stat-card">
      <div class="gap-stat-val good">${covered} <span style="font-size:16px">(%${pct})</span></div>
      <div class="gap-stat-lbl">Kapsanan Teknik</div>
      <div class="gap-stat-sub">${ov.covered_subtechniques || 0} alt teknik kapsanmış</div>
    </div>
    <div class="gap-stat-card">
      <div class="gap-stat-val danger">${critCount}</div>
      <div class="gap-stat-lbl">Kritik Boşluk</div>
      <div class="gap-stat-sub">Önem ≥ 4, kapsanmamış</div>
    </div>
  </div>`;

  // Tactic progress bars
  html += '<div class="gap-section-title">Taktik Bazlı Kapsama</div>';
  (data.by_tactic || []).forEach(t => {
    const barPct = t.pct || 0;
    const cls = barPct < 30 ? 'low' : barPct < 60 ? 'mid' : '';
    html += `<div class="gap-tactic-row">
      <div class="gap-tactic-name">${_esc(t.label || t.tactic)}</div>
      <div class="gap-bar-wrap"><div class="gap-bar-fill ${cls}" style="width:${barPct}%"></div></div>
      <div class="gap-tactic-pct">%${barPct}</div>
      <div class="gap-tactic-count">${t.covered}/${t.total}</div>
    </div>`;
  });

  // Critical gaps
  html += '<div class="gap-section-title" style="margin-top:20px">Kritik Boşluklar (Önem ≥ 4, Kapsanmamış)</div>';
  const gaps = data.critical_gaps || [];
  if (gaps.length === 0) {
    html += '<div style="color:var(--d-text-3);font-size:12px;padding:10px 0">Kritik boşluk yok.</div>';
  } else {
    html += '<div class="gap-critical-list">';
    gaps.forEach(g => {
      const tacticLabel = TACTIC_TR[g.tactic] || g.tactic || '—';
      html += `<div class="gap-critical-item" onclick="openTechDetail('${_esc(g.tech_id)}')">
        <div class="gap-imp-dot lv-${g.importance_level}"></div>
        <div class="gap-critical-id">${_esc(g.tech_id)}</div>
        <div class="gap-critical-name">${_esc(g.name)}</div>
        <div class="gap-critical-tactic">${_esc(tacticLabel)}</div>
        ${hasRole('editor') ? `<button class="gap-critical-add" onclick="event.stopPropagation();openNewActionForTech('${_esc(g.tech_id)}','${_esc(g.name).replace(/'/g,'\\\'')}')" title="Aksiyon ekle">+ Aksiyon</button>` : ''}
      </div>`;
    });
    html += '</div>';
  }

  el.innerHTML = html;
}

// ══════════════════════════════════════════════════════════════
// P1: Action Items Panel
// ══════════════════════════════════════════════════════════════
let _actionItems = [];
let _actionsFilter = '';
let _editingActionId = null;

async function loadActionsPanel() {
  try {
    const res = await apiFetch('/api/action-items');
    if (!res.ok) return;
    _actionItems = await res.json();
    renderActionItems();
  } catch (e) { /* ignore */ }
}

function renderActionItems() {
  const tbody = document.getElementById('actionsTableBody');
  const emptyEl = document.getElementById('actionsEmpty');
  if (!tbody) return;

  const PRIORITY_LABEL = {1:'Düşük', 2:'Orta', 3:'Yüksek', 4:'Kritik'};
  const STATUS_LABEL = {open:'Açık', in_progress:'Devam', done:'Tamamlandı', cancelled:'İptal'};

  const filtered = _actionsFilter
    ? _actionItems.filter(a => a.status === _actionsFilter)
    : _actionItems;

  tbody.innerHTML = '';
  if (filtered.length === 0) {
    if (emptyEl) emptyEl.style.display = 'block';
    return;
  }
  if (emptyEl) emptyEl.style.display = 'none';

  filtered.forEach(item => {
    const tr = document.createElement('tr');
    tr.innerHTML = `
      <td>${item.tech_id ? `<strong style="color:var(--d-blue)">${_esc(item.tech_id)}</strong>` : '—'}</td>
      <td>${_esc(item.title)}</td>
      <td>${_esc(item.assigned_team_name || '—')}</td>
      <td><span class="priority-badge p-${item.priority}">${_esc(PRIORITY_LABEL[item.priority] || item.priority)}</span></td>
      <td><span class="status-badge s-${item.status}">${_esc(STATUS_LABEL[item.status] || item.status)}</span></td>
      <td>${_esc(item.due_date || '—')}</td>
      <td>
        <div class="action-item-actions">
          ${hasRole('editor') ? `
            <button class="action-item-btn" title="Düzenle" data-edit="${item.id}">✏️</button>
            <button class="action-item-btn del" title="Sil" data-del="${item.id}">🗑️</button>
          ` : ''}
        </div>
      </td>`;
    tbody.appendChild(tr);
  });

  // Wire edit/delete buttons
  tbody.querySelectorAll('[data-edit]').forEach(btn => {
    btn.addEventListener('click', () => openEditAction(parseInt(btn.dataset.edit)));
  });
  tbody.querySelectorAll('[data-del]').forEach(btn => {
    btn.addEventListener('click', () => deleteAction(parseInt(btn.dataset.del)));
  });
}

function openNewActionForTech(techId, techName) {
  // Switch to actions panel
  document.querySelectorAll('.nav-item').forEach(i => i.classList.remove('active'));
  document.querySelectorAll('.panel').forEach(p => p.classList.remove('active'));
  const navItem = document.querySelector('.nav-item[data-target="actionsPanel"]');
  const panel = document.getElementById('actionsPanel');
  if (navItem) navItem.classList.add('active');
  if (panel) panel.classList.add('active');

  loadActionsPanel();
  // Pre-fill form
  _editingActionId = null;
  const form = document.getElementById('actionFormCard');
  if (form) {
    form.classList.add('open');
    const titleEl = document.getElementById('actionTitle');
    const techEl = document.getElementById('actionTechId');
    if (titleEl) titleEl.value = techId ? `${techId} — Kapsama açığı kapatılacak` : '';
    if (techEl) techEl.value = techId || '';
    populateActionTeamSelect();
  }
}

function openEditAction(id) {
  const item = _actionItems.find(a => a.id === id);
  if (!item) return;
  _editingActionId = id;
  const form = document.getElementById('actionFormCard');
  if (!form) return;
  form.classList.add('open');
  document.getElementById('actionTitle').value = item.title || '';
  document.getElementById('actionTechId').value = item.tech_id || '';
  document.getElementById('actionPriority').value = item.priority || 2;
  document.getElementById('actionStatus').value = item.status || 'open';
  document.getElementById('actionDueDate').value = item.due_date || '';
  document.getElementById('actionDesc').value = item.description || '';
  populateActionTeamSelect(item.assigned_team_id);
}

function populateActionTeamSelect(selectedId) {
  const sel = document.getElementById('actionTeam');
  if (!sel) return;
  sel.innerHTML = '<option value="">— Ekip Seç —</option>';
  teams.forEach(t => {
    const opt = document.createElement('option');
    opt.value = t.id;
    opt.textContent = t.name;
    if (selectedId && t.id === selectedId) opt.selected = true;
    sel.appendChild(opt);
  });
}

async function saveAction() {
  if (!hasRole('editor')) return;
  const title = (document.getElementById('actionTitle')?.value || '').trim();
  if (!title) { alert('Başlık zorunlu.'); return; }

  const payload = {
    title,
    tech_id: (document.getElementById('actionTechId')?.value || '').trim().toUpperCase(),
    priority: parseInt(document.getElementById('actionPriority')?.value || '2'),
    status: document.getElementById('actionStatus')?.value || 'open',
    description: (document.getElementById('actionDesc')?.value || '').trim(),
    due_date: document.getElementById('actionDueDate')?.value || null,
    assigned_team_id: document.getElementById('actionTeam')?.value
      ? parseInt(document.getElementById('actionTeam').value) : null,
  };

  const url = _editingActionId ? `/api/action-items/${_editingActionId}` : '/api/action-items';
  const method = _editingActionId ? 'PUT' : 'POST';
  const res = await apiFetch(url, {
    method,
    headers: {'Content-Type': 'application/json'},
    body: JSON.stringify(payload),
  });
  if (!res.ok) { const e = await res.json().catch(() => ({})); alert(e.error || 'Kayıt başarısız'); return; }

  _editingActionId = null;
  document.getElementById('actionFormCard')?.classList.remove('open');
  await loadActionsPanel();
}

async function deleteAction(id) {
  if (!hasRole('editor')) return;
  if (!confirm('Aksiyonu silmek istiyor musunuz?')) return;
  await apiFetch(`/api/action-items/${id}`, {method: 'DELETE'});
  await loadActionsPanel();
}

function wireActionsPanel() {
  document.getElementById('btnNewAction')?.addEventListener('click', () => {
    _editingActionId = null;
    const form = document.getElementById('actionFormCard');
    if (!form) return;
    form.classList.toggle('open');
    if (form.classList.contains('open')) {
      document.getElementById('actionTitle').value = '';
      document.getElementById('actionTechId').value = '';
      document.getElementById('actionPriority').value = '2';
      document.getElementById('actionStatus').value = 'open';
      document.getElementById('actionDueDate').value = '';
      document.getElementById('actionDesc').value = '';
      populateActionTeamSelect();
    }
  });
  document.getElementById('actionFormCancel')?.addEventListener('click', () => {
    document.getElementById('actionFormCard')?.classList.remove('open');
    _editingActionId = null;
  });
  document.getElementById('actionFormSave')?.addEventListener('click', saveAction);

  // Filter buttons
  document.getElementById('actionsFilterBar')?.querySelectorAll('.actions-filter-btn').forEach(btn => {
    btn.addEventListener('click', () => {
      document.querySelectorAll('#actionsFilterBar .actions-filter-btn').forEach(b => b.classList.remove('active'));
      btn.classList.add('active');
      _actionsFilter = btn.dataset.filter || '';
      renderActionItems();
    });
  });
}

// ══════════════════════════════════════════════════════════════
// P0: Threat Actor Overlay
// ══════════════════════════════════════════════════════════════
let _threatActors = [];
let _activeThreatActor = null;

async function loadThreatActors() {
  try {
    const res = await apiFetch('/api/threat-actors');
    if (!res.ok) return;
    _threatActors = await res.json();
    populateThreatActorSelect();
  } catch (e) { /* ignore — MITRE data may not exist */ }
}

function populateThreatActorSelect() {
  const sel = document.getElementById('threatActorSelect');
  if (!sel) return;
  sel.innerHTML = '<option value="">— Seç —</option>';
  _threatActors.forEach(a => {
    const opt = document.createElement('option');
    opt.value = a.stix_id;
    opt.textContent = a.name + (a.id ? ` (${a.id})` : '');
    sel.appendChild(opt);
  });
}

function applyThreatOverlay(stixId) {
  const actor = _threatActors.find(a => a.stix_id === stixId);
  const allCards = document.querySelectorAll('.technique-card[data-tech-id], .subtech-card[data-tech-id]');
  const statEl = document.getElementById('threatActorStat');
  const clearBtn = document.getElementById('threatActorClear');

  if (!actor) {
    clearThreatOverlay();
    return;
  }

  _activeThreatActor = actor;
  const techSet = new Set(actor.technique_ids);
  const total = actor.technique_ids.length;

  allCards.forEach(card => {
    const tid = card.dataset.techId;
    if (techSet.has(tid)) {
      card.classList.add('threat-match');
      card.classList.remove('threat-dim');
    } else {
      card.classList.add('threat-dim');
      card.classList.remove('threat-match');
    }
  });

  const visibleIds = new Set([...allCards].map(c => c.dataset.techId));
  const visibleActorTechs = actor.technique_ids.filter(t => visibleIds.has(t)).length;

  if (statEl) {
    statEl.style.display = '';
    statEl.innerHTML = `<strong>${_esc(actor.name)}</strong>: ${visibleActorTechs}/${total} teknik`;
  }
  if (clearBtn) clearBtn.style.display = '';
}

function clearThreatOverlay() {
  _activeThreatActor = null;
  document.querySelectorAll('.technique-card, .subtech-card').forEach(card => {
    card.classList.remove('threat-match', 'threat-dim');
  });
  const statEl = document.getElementById('threatActorStat');
  const clearBtn = document.getElementById('threatActorClear');
  if (statEl) statEl.style.display = 'none';
  if (clearBtn) clearBtn.style.display = 'none';
  const sel = document.getElementById('threatActorSelect');
  if (sel) sel.value = '';
}

function wireThreatActors() {
  const sel = document.getElementById('threatActorSelect');
  if (sel) {
    sel.addEventListener('change', () => {
      if (sel.value) applyThreatOverlay(sel.value);
      else clearThreatOverlay();
    });
  }
  document.getElementById('threatActorClear')?.addEventListener('click', clearThreatOverlay);
}

// ══════════════════════════════════════════════════════════════
// Wire all new panels
// ══════════════════════════════════════════════════════════════
function wireNewPanels() {
  // GAP panel: load data when nav item is clicked
  document.querySelector('.nav-item[data-target="gapPanel"]')?.addEventListener('click', () => {
    loadGapDashboard();
  });
  // Actions panel: load data when nav item is clicked
  document.querySelector('.nav-item[data-target="actionsPanel"]')?.addEventListener('click', () => {
    loadActionsPanel();
  });

  wireActionsPanel();
  wireThreatActors();

  // Load threat actors in background after main init completes
  setTimeout(loadThreatActors, 1500);
}

