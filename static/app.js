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
let auditPagination = { page: 1, pages: 1, total: 0, per_page: 50 };
let auditFacetsLoaded = false;
let dataQuality = null;
let connectors = [];
let scopeRegistry = null;
let selectedEnvironmentId = null;
let selectedAssetGroupId = null;
// Kurallar sayfası filtre state'i — renderRulesList() her re-render'da bu değerleri
// kullanır; seçim re-render sonrasında da korunur (input value / select selected).
let rulesFilterSearch = '';
let rulesFilterProduct = '';
let rulesOpenGroups = null; // null = tümü açık (başlangıç), Set = kullanıcı toggle sonrası
let rulesSelectedIds = new Set(); // toplu teknik ekleme icin secili tespit id'leri

const COV_CYCLE = ['low', 'partial', 'full'];
const COV_LABEL = { low: 'Düşük', partial: 'Kısmi', full: 'Tam' };
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

  // Ayarlar sekmesi her zaman gorunur: viewer da dahil herkes kendi parolasini
  // "Hesabim" sekmesinden degistirebilmeli. Alt sekmeler (CSV, Kullanicilar,
  // Ekipler, Connector'lar) kendi rol kontrollerini asagida ayrica uyguluyor.
  const settingsNav = document.querySelector('.nav-item[data-target="settingsPanel"]');
  if (settingsNav) settingsNav.classList.remove('hidden');

  // Viewer icin varsayilan sekme "Urun Yonetimi" degil "Hesabim" olsun --
  // viewer o sekmede zaten hicbir seyi ekleyemez (yazma admin'e ozel).
  if (!hasRole('editor')) {
    const accountTabBtn = document.querySelector('.settings-tab-btn[data-tab="stab-account"]');
    const accountTabPanel = document.getElementById('stab-account');
    if (accountTabBtn && accountTabPanel) {
      document.querySelectorAll('.settings-tab-btn').forEach(b => b.classList.remove('active'));
      document.querySelectorAll('.settings-tab-panel').forEach(p => p.classList.remove('active'));
      accountTabBtn.classList.add('active');
      accountTabPanel.classList.add('active');
    }
  }

  const csvFileInput = document.getElementById('csvFile');
  if (csvFileInput) csvFileInput.disabled = !hasRole('editor');

  // Ayarlar sekmelerini role göre gizle:
  //   CSV Yükleme → editor veya üstü
  //   Kullanıcılar + Audit Log → sadece admin
  document.getElementById('settingsCsvTab')?.classList.toggle('hidden', !hasRole('editor'));
  document.getElementById('settingsUsersTab')?.classList.toggle('hidden', !hasRole('admin'));
  document.getElementById('settingsAuditTab')?.classList.toggle('hidden', !hasRole('admin'));
  document.getElementById('settingsTeamsTab')?.classList.toggle('hidden', !hasRole('admin'));
  document.getElementById('settingsConnectorsTab')?.classList.toggle('hidden', !hasRole('admin'));
  document.getElementById('auditNavItem')?.classList.toggle('hidden', !hasRole('admin'));
  document.getElementById('dataQualityRepair')?.classList.toggle('hidden', !hasRole('admin'));
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
function _ruleRow(r) {
  const level = r.coverage_level || 'full';
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
  const sliderHtml = hasRole('editor')
    ? `<div class="cov-slider" data-rule-id="${r.id}" data-level="${level}">
        <div class="cov-rail"><div class="cov-fill"></div><div class="cov-thumb"></div></div>
        <span class="cov-lbl">${COV_LABEL[level]}</span>
      </div>`
    : `<div class="cov-slider cov-readonly" data-level="${level}">
        <div class="cov-rail"><div class="cov-fill"></div><div class="cov-thumb"></div></div>
        <span class="cov-lbl">${COV_LABEL[level]}</span>
      </div>`;
  return `
    <div class="rule-list-row" data-rule-id="${r.id}">
      <div class="rl-select">
        ${hasRole('editor') ? `<input type="checkbox" class="rule-select-checkbox" data-rule-id="${r.id}" ${rulesSelectedIds.has(r.id) ? 'checked' : ''} />` : ''}
      </div>
      <div class="rl-name">${_esc(r.name)}</div>
      <div class="rl-cov">${sliderHtml}</div>
      <div class="rl-techs">
        ${techChips}
        ${hasRole('editor') ? `<span class="rule-tech-add">
          <div class="tech-autocomplete-wrapper" data-rule-id="${r.id}">
            <input class="rule-tech-input" type="text" placeholder="T1059 veya teknik adı" data-rule-id="${r.id}" />
            <div class="tech-autocomplete-dropdown hidden"></div>
          </div>
          <button class="action-btn btn-add rule-tech-add-btn" data-rule-id="${r.id}">+</button>
        </span>` : ''}
      </div>
      <div class="rl-actions">
        ${hasRole('editor') ? `<button class="action-btn btn-reset rule-delete" data-rule-id="${r.id}">Sil</button>` : ''}
      </div>
    </div>`;
}

function renderRulesList() {
  const container = document.getElementById('rulesList');
  if (!container) return;

  const colorMap = productColorMap();

  // Yeni Tespit formu (editor+)
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

  // Filtre bar
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

  // Toplu teknik ekleme toolbar'ı (editor+). Analistin tek tek her tespite
  // teknik eklemesi yerine, secilen N tespite ayni teknigi tek seferde eklemesi
  // icin. Mevcut tekli POST /api/rules/<id>/techniques endpoint'i sirayla
  // cagrilir; yeni bir bulk endpoint gerekmez.
  const bulkToolbarHtml = hasRole('editor') ? `
    <div class="rules-bulk-toolbar">
      <span class="bulk-count" id="bulkSelectedCount">0 tespit seçili</span>
      <button class="action-btn btn-reset" id="btnBulkSelectVisible">Görünenleri seç</button>
      <button class="action-btn btn-reset" id="btnBulkClearSelection">Seçimi temizle</button>
      <div class="tech-autocomplete-wrapper" id="bulkTechWrapper">
        <input class="rule-tech-input" type="text" id="bulkTechInput" placeholder="T1059 veya teknik adı" />
        <div class="tech-autocomplete-dropdown hidden"></div>
      </div>
      <button class="action-btn btn-add" id="btnBulkAddTechnique" disabled>Seçili tespitlere ekle</button>
      <span class="upload-result" id="bulkResult"></span>
    </div>
  ` : '';

  if (userRules.length === 0) {
    container.innerHTML = addFormHtml + filterBarHtml +
      '<div class="empty-state"><div class="empty-title">Tespit yok</div><div class="empty-sub">Henüz tespit eklenmemiş.</div></div>';
    wireRulesFilterEvents(container);
    wireAddRuleInline(container);
    container.querySelectorAll('.tech-autocomplete-wrapper').forEach(wireAutocomplete);
    return;
  }

  // Filtre uygula
  const visible = userRules.filter(r =>
    (!rulesFilterSearch || r.name.toLowerCase().includes(rulesFilterSearch.toLowerCase())) &&
    (!rulesFilterProduct || r.source === rulesFilterProduct)
  );

  // Ürüne göre grupla
  const groups = {};
  const groupOrder = [];
  visible.forEach(r => {
    if (!groups[r.source]) { groups[r.source] = []; groupOrder.push(r.source); }
    groups[r.source].push(r);
  });

  // Başlangıçta tüm gruplar açık
  if (rulesOpenGroups === null) rulesOpenGroups = new Set(groupOrder);

  const groupsHtml = groupOrder.map(src => {
    const color = colorMap[src] || '#546e7a';
    const rules = groups[src];
    const isOpen = rulesOpenGroups.has(src);
    const arrow = isOpen ? '▾' : '▸';
    const rowsHtml = rules.map(r => _ruleRow(r)).join('');
    return `
      <div class="rule-product-group">
        <div class="rule-product-header" data-product="${_esc(src)}">
          <span class="rule-product-toggle">${arrow}</span>
          <span class="rule-product-dot" style="background:${color}"></span>
          <span class="rule-product-name">${_esc(src)}</span>
          <span class="rule-product-count">${rules.length} tespit</span>
        </div>
        <div class="rule-product-body ${isOpen ? '' : 'collapsed'}">
          <div class="rule-list-header">
            <div></div>
            <div>Tespit Adı</div>
            <div>Kapsam</div>
            <div>Teknikler</div>
            <div></div>
          </div>
          ${rowsHtml}
        </div>
      </div>`;
  }).join('');

  const emptyNote = visible.length === 0
    ? '<div class="empty-state"><div class="empty-title">Sonuç yok</div></div>'
    : '';

  container.innerHTML = addFormHtml + filterBarHtml + bulkToolbarHtml + groupsHtml + emptyNote;

  wireRulesBulkToolbar(container, visible.map(r => r.id));
  wireRulesFilterEvents(container);
  wireAddRuleInline(container);
  container.querySelectorAll('.tech-autocomplete-wrapper').forEach(wireAutocomplete);

  // Accordion toggle
  container.querySelectorAll('.rule-product-header').forEach(hdr => {
    hdr.addEventListener('click', () => {
      const src = hdr.dataset.product;
      if (rulesOpenGroups.has(src)) rulesOpenGroups.delete(src);
      else rulesOpenGroups.add(src);
      renderRulesList();
    });
  });

  // Kapsam slider — tıkla veya sürükle
  container.querySelectorAll('.cov-slider:not(.cov-readonly)').forEach(slider => {
    const rail  = slider.querySelector('.cov-rail');
    const fill  = slider.querySelector('.cov-fill');
    const thumb = slider.querySelector('.cov-thumb');
    const lbl   = slider.querySelector('.cov-lbl');

    function snapLevel(pct) {
      return pct < 0.33 ? 'low' : pct < 0.67 ? 'partial' : 'full';
    }
    async function persistLevel(level) {
      const ruleId = parseInt(slider.dataset.ruleId);
      const rule = userRules.find(r => r.id === ruleId);
      if (rule && rule.coverage_level === level) return;
      const res = await apiFetch(`/api/rules/${ruleId}/coverage`, {
        method: 'PATCH',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ coverage_level: level })
      });
      if (res.ok && rule) rule.coverage_level = level;
    }
    function applyVisual(level) {
      slider.dataset.level = level;
      lbl.textContent = COV_LABEL[level];
    }

    // Tıklama: rail'in tıklanan noktasına snap
    rail.addEventListener('click', e => {
      const rect = rail.getBoundingClientRect();
      const pct  = Math.max(0, Math.min(1, (e.clientX - rect.left) / rect.width));
      const lvl  = snapLevel(pct);
      applyVisual(lvl);
      persistLevel(lvl);
    });

    // Sürükleme: thumb'ı rail boyunca serbestçe taşı, bırakınca snap
    thumb.addEventListener('mousedown', e => {
      e.preventDefault();
      e.stopPropagation();
      // Drag sırasında CSS geçişini kaldır (thumb imleci takip etsin)
      thumb.style.transition = 'none';
      fill.style.transition  = 'none';

      const onMove = e2 => {
        const rect = rail.getBoundingClientRect();
        const pct  = Math.max(0.0625, Math.min(0.9375, (e2.clientX - rect.left) / rect.width));
        const lvl  = snapLevel(pct);
        const clr  = lvl === 'low' ? '#c42b1c' : lvl === 'partial' ? '#ca8a04' : '#2d7d32';
        // Inline stil ile thumb imleci tam takip eder
        thumb.style.left       = `${pct * 100}%`;
        fill.style.width       = `${pct * 100}%`;
        thumb.style.background = clr;
        fill.style.background  = clr;
        lbl.textContent        = COV_LABEL[lvl];
        lbl.style.color        = clr;
      };

      const onUp = e2 => {
        document.removeEventListener('mousemove', onMove);
        document.removeEventListener('mouseup', onUp);
        const rect = rail.getBoundingClientRect();
        const pct  = Math.max(0, Math.min(1, (e2.clientX - rect.left) / rect.width));
        const lvl  = snapLevel(pct);
        // Inline stilleri temizle → CSS snap animasyonu devreye girer
        thumb.style.cssText = '';
        fill.style.cssText  = '';
        lbl.style.color     = '';
        applyVisual(lvl);
        persistLevel(lvl);
      };

      document.addEventListener('mousemove', onMove);
      document.addEventListener('mouseup', onUp);
    });
  });

  // Tech chip popover
  container.querySelectorAll('.tech-chip[data-tech-label]').forEach(chip => {
    chip.addEventListener('click', (e) => {
      const label = e.currentTarget.dataset.techLabel || '';
      if (label) showTechChipPopover(e.currentTarget, label);
    });
  });

  // Teknik kaldır
  container.querySelectorAll('.rule-tech-remove').forEach(btn => {
    btn.addEventListener('click', async (e) => {
      if (!hasRole('editor')) return;
      const ruleId = e.currentTarget.dataset.ruleId;
      const techId = e.currentTarget.dataset.techId;
      const res = await apiFetch(`/api/rules/${ruleId}/techniques/${techId}`, { method: 'DELETE' });
      if (!res.ok) return;
      const rule = userRules.find(r => r.id == ruleId);
      if (rule && rule.techniques) rule.techniques = rule.techniques.filter(t => t !== techId);
      renderRulesList();
      renderMatrix();
    });
  });

  // Teknik ekle
  container.querySelectorAll('.rule-tech-add-btn').forEach(btn => {
    btn.addEventListener('click', async (e) => {
      if (!hasRole('editor')) return;
      const ruleId = e.currentTarget.dataset.ruleId;
      const input = container.querySelector(`.rule-tech-input[data-rule-id="${ruleId}"]`);
      if (!input) return;
      const val = (input.value || '').trim();
      if (!val) return;
      const validation = validateTechniqueInput(val);
      if (!validation.ok) { alert(validation.message); return; }
      const techId = validation.tid;
      const res = await apiFetch(`/api/rules/${ruleId}/techniques`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ tech_id: techId })
      });
      if (!res.ok) { const err = await res.json().catch(() => ({})); alert(err.error || 'Teknik eklenemedi'); return; }
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

  // Tespit sil
  container.querySelectorAll('.rule-delete').forEach(btn => {
    btn.addEventListener('click', async (e) => {
      const ruleId = parseInt(e.currentTarget.dataset.ruleId);
      if (!ruleId || !hasRole('editor')) return;
      await deleteRule(ruleId);
    });
  });
}

function updateBulkToolbarUI(container) {
  const countEl = container.querySelector('#bulkSelectedCount');
  if (countEl) countEl.textContent = `${rulesSelectedIds.size} tespit seçili`;
  const addBtn = container.querySelector('#btnBulkAddTechnique');
  if (addBtn) addBtn.disabled = rulesSelectedIds.size === 0;
}

// Toplu teknik ekleme toolbar'ını bağlar. Checkbox toggle'ları tam bir
// renderRulesList() tetiklemez (438 satırda bu yavaş olurdu) — sadece Set'i
// ve toolbar sayacını günceller. Filtre/grup degisince zaten yeniden çizilir,
// checkbox durumu rulesSelectedIds Set'inden türetildiği için tutarlı kalır.
function wireRulesBulkToolbar(container, visibleIds) {
  container.querySelectorAll('.rule-select-checkbox').forEach(cb => {
    cb.addEventListener('change', (e) => {
      const ruleId = parseInt(e.currentTarget.dataset.ruleId);
      if (e.currentTarget.checked) rulesSelectedIds.add(ruleId);
      else rulesSelectedIds.delete(ruleId);
      updateBulkToolbarUI(container);
    });
  });

  const selectVisibleBtn = container.querySelector('#btnBulkSelectVisible');
  if (selectVisibleBtn) {
    selectVisibleBtn.addEventListener('click', () => {
      visibleIds.forEach(id => rulesSelectedIds.add(id));
      renderRulesList();
    });
  }

  const clearBtn = container.querySelector('#btnBulkClearSelection');
  if (clearBtn) {
    clearBtn.addEventListener('click', () => {
      rulesSelectedIds.clear();
      renderRulesList();
    });
  }

  const bulkWrapper = container.querySelector('#bulkTechWrapper');
  if (bulkWrapper) wireAutocomplete(bulkWrapper);

  const addBtn = container.querySelector('#btnBulkAddTechnique');
  if (addBtn) {
    addBtn.addEventListener('click', async () => {
      const input = container.querySelector('#bulkTechInput');
      const result = container.querySelector('#bulkResult');
      if (!input || rulesSelectedIds.size === 0) return;
      const validation = validateTechniqueInput(input.value);
      if (!validation.ok) { if (result) { result.textContent = validation.message; result.classList.add('error'); } return; }
      const techId = validation.tid;

      addBtn.disabled = true;
      if (result) { result.textContent = 'Ekleniyor...'; result.classList.remove('error'); }

      const ruleIds = Array.from(rulesSelectedIds);
      let okCount = 0;
      const failed = [];
      for (const ruleId of ruleIds) {
        const res = await apiFetch(`/api/rules/${ruleId}/techniques`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ tech_id: techId })
        });
        if (res.ok) {
          okCount += 1;
          const rule = userRules.find(r => r.id === ruleId);
          if (rule) {
            if (!rule.techniques) rule.techniques = [];
            if (!rule.techniques.includes(techId)) rule.techniques.push(techId);
            rule.techniques.sort();
          }
        } else {
          const rule = userRules.find(r => r.id === ruleId);
          failed.push(rule ? rule.name : ruleId);
        }
      }

      rulesSelectedIds.clear();
      renderRulesList();
      renderMatrix();
      const finalResult = document.getElementById('bulkResult');
      if (finalResult) {
        finalResult.textContent = failed.length === 0
          ? `${techId} — ${okCount} tespite eklendi.`
          : `${techId} — ${okCount} tespite eklendi, ${failed.length} başarısız (${failed.slice(0, 5).join(', ')}${failed.length > 5 ? '…' : ''})`;
        if (failed.length > 0) finalResult.classList.add('error');
      }
    });
  }

  updateBulkToolbarUI(container);
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
  const body = document.getElementById('auditTableBody');
  const empty = document.getElementById('auditEmpty');
  if (!body) return;
  body.innerHTML = '';
  auditLogs.forEach(log => {
    const row = document.createElement('tr');
    row.tabIndex = 0;
    row.innerHTML = `
      <td title="${_esc(log.created_at || '')}">${_esc(formatAuditTime(log.created_at))}</td>
      <td>${_esc(log.username || 'sistem')}</td>
      <td><span class="audit-action-badge">${_esc(log.action)}</span></td>
      <td title="${_esc(`${log.target_type}:${log.target_id || ''}`)}">${_esc(log.target_type)}${log.target_id ? ` · ${_esc(log.target_id)}` : ''}</td>
      <td title="${_esc(log.detail || '')}">${_esc(log.detail || '—')}</td>
      <td title="${_esc(log.request_id || '')}">${_esc((log.request_id || '—').slice(0, 12))}</td>`;
    const open = () => showAuditDetail(log);
    row.addEventListener('click', open);
    row.addEventListener('keydown', event => { if (event.key === 'Enter') open(); });
    body.appendChild(row);
  });
  if (empty) empty.style.display = auditLogs.length ? 'none' : 'block';

  const pageInfo = document.getElementById('auditPageInfo');
  if (pageInfo) pageInfo.textContent = `${auditPagination.page} / ${auditPagination.pages} · ${auditPagination.total} kayıt`;
  const prev = document.getElementById('auditPrev');
  const next = document.getElementById('auditNext');
  if (prev) prev.disabled = auditPagination.page <= 1;
  if (next) next.disabled = auditPagination.page >= auditPagination.pages;
}

function formatAuditTime(value) {
  if (!value) return '—';
  const normalized = value.includes('T') ? value : value.replace(' ', 'T') + 'Z';
  const date = new Date(normalized);
  return Number.isNaN(date.getTime()) ? value : date.toLocaleString('tr-TR');
}

function auditFilterParams(includePage = true) {
  const params = new URLSearchParams();
  const fields = {
    q: 'auditSearch', username: 'auditActor', action: 'auditAction',
    target_type: 'auditTargetType', date_from: 'auditDateFrom', date_to: 'auditDateTo'
  };
  Object.entries(fields).forEach(([key, id]) => {
    const value = document.getElementById(id)?.value?.trim();
    if (value) params.set(key, value);
  });
  if (includePage) {
    params.set('page', String(auditPagination.page));
    params.set('per_page', String(auditPagination.per_page));
  }
  return params;
}

function populateAuditFacets(facets) {
  if (auditFacetsLoaded || !facets) return;
  const fill = (id, rows, key) => {
    const select = document.getElementById(id);
    if (!select) return;
    rows.forEach(row => {
      const option = document.createElement('option');
      option.value = row[key];
      option.textContent = `${row[key]} (${row.count})`;
      select.appendChild(option);
    });
  };
  fill('auditAction', facets.actions || [], 'action');
  fill('auditTargetType', facets.target_types || [], 'target_type');
  auditFacetsLoaded = true;
}

function showAuditDetail(log) {
  const panel = document.getElementById('auditDetail');
  const body = document.getElementById('auditDetailBody');
  if (!panel || !body) return;
  const prettyJson = value => {
    if (!value) return '—';
    try { return JSON.stringify(JSON.parse(value), null, 2); } catch (_) { return value; }
  };
  const field = (label, value, cls = '') => `
    <div class="audit-detail-field">
      <div class="audit-detail-label">${_esc(label)}</div>
      <div class="audit-detail-value ${cls}">${_esc(value || '—')}</div>
    </div>`;
  body.innerHTML = `
    ${field('Zaman', formatAuditTime(log.created_at))}
    ${field('Kullanıcı', log.username || 'sistem')}
    ${field('İşlem', `${log.action} · ${log.target_type}${log.target_id ? ` · ${log.target_id}` : ''}`)}
    ${field('Detay', log.detail)}
    ${field('İstek ID', log.request_id)}
    ${field('IP adresi', log.ip_address)}
    ${field('User agent', log.user_agent)}
    <div class="audit-detail-field"><div class="audit-detail-label">Önce</div><pre class="audit-json">${_esc(prettyJson(log.before_json))}</pre></div>
    <div class="audit-detail-field"><div class="audit-detail-label">Sonra</div><pre class="audit-json">${_esc(prettyJson(log.after_json))}</pre></div>
    ${field('Önceki kayıt hash', log.prev_hash || 'Zincir başlangıcı')}
    ${field('Kayıt hash', log.entry_hash)}`;
  panel.classList.remove('hidden');
}

async function loadAuditLogs(resetPage = false) {
  if (!hasRole('admin')) return;
  if (resetPage) auditPagination.page = 1;
  const res = await apiFetch(`/api/audit-logs?${auditFilterParams().toString()}`);
  if (!res.ok) return;
  const payload = await res.json();
  auditLogs = payload.items || [];
  auditPagination = payload.pagination || auditPagination;
  populateAuditFacets(payload.facets);
  const integrity = payload.integrity || {};
  const badge = document.getElementById('auditIntegrity');
  if (badge) {
    badge.className = `integrity-badge ${integrity.valid ? 'valid' : 'invalid'}`;
    badge.textContent = integrity.valid ? `Bütünlük doğrulandı · ${integrity.checked}` : `Zincir hatası · #${integrity.broken_at_id}`;
  }
  const summary = document.getElementById('auditSummary');
  if (summary) {
    const failed = (payload.facets?.actions || []).find(item => item.action === 'login_failed')?.count || 0;
    summary.innerHTML = `
      <div class="ops-stat"><div class="ops-stat-value">${auditPagination.total}</div><div class="ops-stat-label">Filtrelenen Kayıt</div></div>
      <div class="ops-stat"><div class="ops-stat-value">${payload.facets?.actions?.length || 0}</div><div class="ops-stat-label">İşlem Türü</div></div>
      <div class="ops-stat"><div class="ops-stat-value">${payload.facets?.target_types?.length || 0}</div><div class="ops-stat-label">Hedef Türü</div></div>
      <div class="ops-stat"><div class="ops-stat-value ${failed ? 'warn' : 'good'}">${failed}</div><div class="ops-stat-label">Başarısız Giriş</div></div>
      <div class="ops-stat"><div class="ops-stat-value ${integrity.valid ? 'good' : 'danger'}">${integrity.valid ? 'Sağlam' : 'Hatalı'}</div><div class="ops-stat-label">Audit Zinciri</div></div>`;
  }
  renderAuditLogs();
}

async function downloadAuditEvidence() {
  const button = document.getElementById('auditEvidenceExport');
  if (button) button.disabled = true;
  try {
    const filters = Object.fromEntries(auditFilterParams(false).entries());
    const response = await apiFetch('/api/audit-logs/evidence', {
      method: 'POST',
      headers: {'Content-Type': 'application/json'},
      body: JSON.stringify(filters),
    });
    if (!response.ok) {
      const error = await response.json().catch(() => ({}));
      throw new Error(error.error || 'Kanıt paketi oluşturulamadı.');
    }
    const disposition = response.headers.get('Content-Disposition') || '';
    const match = disposition.match(/filename="?([^";]+)"?/i);
    downloadBlob(match?.[1] || 'audit-evidence.json', await response.text(), 'application/json;charset=utf-8');
    auditFacetsLoaded = false;
    await loadAuditLogs(true);
  } catch (error) {
    alert(error.message);
  } finally {
    if (button) button.disabled = false;
  }
}

function renderDataQuality() {
  if (!dataQuality) return;
  const summary = dataQuality.summary || {};
  const scoreClass = summary.quality_score >= 95 ? 'good' : summary.quality_score >= 80 ? 'warn' : 'danger';
  const summaryEl = document.getElementById('qualitySummary');
  if (summaryEl) summaryEl.innerHTML = `
    <div class="ops-stat"><div class="ops-stat-value ${scoreClass}">${summary.quality_score}%</div><div class="ops-stat-label">Güvenilirlik Skoru</div></div>
    <div class="ops-stat"><div class="ops-stat-value">${summary.total_rules}</div><div class="ops-stat-label">Toplam Tespit</div></div>
    <div class="ops-stat"><div class="ops-stat-value good">${summary.validly_mapped_rules}</div><div class="ops-stat-label">Geçerli Eşleşen</div></div>
    <div class="ops-stat"><div class="ops-stat-value danger">${summary.critical_issue_count}</div><div class="ops-stat-label">Kritik Sorun</div></div>
    <div class="ops-stat"><div class="ops-stat-value warn">${summary.warning_count}</div><div class="ops-stat-label">Uyarı</div></div>`;
  const dataset = dataQuality.dataset || {};
  const datasetEl = document.getElementById('qualityDataset');
  if (datasetEl) datasetEl.innerHTML = `
    <span><strong>${dataset.technique_count || 0}</strong> teknik</span>
    <span><strong>${dataset.mitigation_count || 0}</strong> mitigation</span>
    <span><strong>${((dataset.size_bytes || 0) / 1024 / 1024).toFixed(1)} MB</strong> MITRE veri seti</span>
    <span>Güncelleme: <strong>${_esc(formatAuditTime(dataset.modified_at))}</strong></span>
    <span>Gösterilen: <strong>${Math.min(dataQuality.issue_count || 0, 500)} / ${dataQuality.issue_count || 0}</strong></span>`;

  const typeSelect = document.getElementById('qualityType');
  if (typeSelect && typeSelect.options.length === 1) {
    [...new Set((dataQuality.issues || []).map(issue => issue.type))].sort().forEach(type => {
      const option = document.createElement('option');
      option.value = type;
      option.textContent = type.replaceAll('_', ' ');
      typeSelect.appendChild(option);
    });
  }
  renderQualityIssues();
}

function renderQualityIssues() {
  const body = document.getElementById('qualityIssuesBody');
  const empty = document.getElementById('qualityEmpty');
  if (!body || !dataQuality) return;
  const severity = document.getElementById('qualitySeverity')?.value || '';
  const type = document.getElementById('qualityType')?.value || '';
  const query = (document.getElementById('qualitySearch')?.value || '').trim().toLocaleLowerCase('tr-TR');
  const rows = (dataQuality.issues || []).filter(issue => {
    if (severity && issue.severity !== severity) return false;
    if (type && issue.type !== type) return false;
    const haystack = `${issue.entity_id} ${issue.value} ${issue.message}`.toLocaleLowerCase('tr-TR');
    return !query || haystack.includes(query);
  });
  body.innerHTML = rows.map(issue => `
    <tr>
      <td><span class="severity-badge ${_esc(issue.severity)}">${issue.severity === 'critical' ? 'Kritik' : 'Uyarı'}</span></td>
      <td>${_esc(issue.type.replaceAll('_', ' '))}</td>
      <td>#${_esc(issue.entity_id)}</td>
      <td title="${_esc(issue.value || '')}">${_esc(issue.value || '—')}${issue.suggested_value ? ` → ${_esc(issue.suggested_value)}` : ''}</td>
      <td title="${_esc(issue.message)}">${_esc(issue.message)}</td>
    </tr>`).join('');
  if (empty) empty.style.display = rows.length ? 'none' : 'block';
}

async function loadDataQuality() {
  const res = await apiFetch('/api/data-quality');
  if (!res.ok) return;
  dataQuality = await res.json();
  renderDataQuality();
}

async function repairDataQuality() {
  if (!hasRole('admin')) return;
  if (!confirm('Tanımlı güvenli düzeltmeler uygulansın mı? İşlem audit kaydına yazılacaktır.')) return;
  const res = await apiFetch('/api/data-quality/repair', {method: 'POST'});
  if (!res.ok) {
    const error = await res.json().catch(() => ({}));
    alert(error.error || 'Veri düzeltme işlemi başarısız.');
    return;
  }
  await reloadData();
  await loadDataQuality();
  if (hasRole('admin')) await loadAuditLogs(true);
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
function ruleCoverageWeight(rule) {
  return ({low: 0.25, partial: 0.60, full: 1.00})[rule?.coverage_level || 'full'] || 1.00;
}

function effectiveRuleCount(rules) {
  return (rules || []).reduce((total, rule) => total + ruleCoverageWeight(rule), 0);
}

function computeScore(techId, rulesCount, mitigationCount, sources, weightedRuleCount = rulesCount) {
  const cfg = techniqueConfig[techId] || {};
  const threshold = cfg.rule_threshold || SCORE_RULE_MAX;
  const mitTotal = getMitigationTotal(techId) || SCORE_MITIGATION_MAX;
  const sourceSet = new Set(Array.isArray(sources) ? sources : []);
  const ruleScore = Math.min(weightedRuleCount / threshold, 1.0);
  const mitScore  = Math.min(mitigationCount / mitTotal, 1.0);
  const divScore  = Math.min(sourceSet.size / 2, 1.0);
  return Math.min(ruleScore * 0.50 + mitScore * 0.30 + divScore * 0.20, 1.0);
}

// Ortak lerp & renk sabitleri
// Gradyan: koyu → kırmızı → turuncu → sarı-yeşil → koyu yeşil (5 durak)
function _colorLerp(a, b, t) {
  return { r: Math.round(a.r + (b.r - a.r) * t),
           g: Math.round(a.g + (b.g - a.g) * t),
           b: Math.round(a.b + (b.b - a.b) * t) };
}
const _SCORE_STOPS = [
  { s: 0.00, r: 20,  g: 26,  b: 34  }, // koyu (0%)
  { s: 0.30, r: 205, g: 50,  b: 50  }, // kırmızı
  { s: 0.50, r: 225, g: 135, b: 45  }, // turuncu
  { s: 0.70, r: 185, g: 205, b: 60  }, // sarı-yeşil
  { s: 1.00, r: 42,  g: 155, b: 55  }, // koyu yeşil
];

function _scoreRgb(score) {
  const st = _SCORE_STOPS;
  if (score <= st[0].s) return st[0];
  if (score >= st[st.length - 1].s) return st[st.length - 1];
  for (let i = 0; i < st.length - 1; i++) {
    if (score <= st[i + 1].s) {
      const t = (score - st[i].s) / (st[i + 1].s - st[i].s);
      return _colorLerp(st[i], st[i + 1], t);
    }
  }
  return st[st.length - 1];
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

function applyTechniqueVisuals(card, techId, rulesCount, mitigationCount, sources, weightedRuleCount = rulesCount) {
  const score = computeScore(techId, rulesCount, mitigationCount, sources, weightedRuleCount);
  card.style.backgroundColor = scoreToColor(score);
  card.classList.toggle('covered', (rulesCount > 0 || mitigationCount > 0));

  // Önemli ama az kapsanmış teknikler kırmızı kenarlıkla işaretlenir
  const importance = techniqueConfig[techId]?.importance || 0.5;
  card.classList.toggle('critical-gap', importance >= 0.7 && score < 0.35);

  // Hover tooltip için skor verisi
  const cfg = techniqueConfig[techId] || {};
  const mitTotal = getMitigationTotal(techId) || SCORE_MITIGATION_MAX;
  card.dataset.scoreData = JSON.stringify({
    techId, rulesCount, weightedRuleCount: Math.round(weightedRuleCount * 100) / 100, mitigationCount,
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
  const linkedRules = enrichRules().filter(r => r.parentId === parentId);
  const sources = linkedRules.map(r => r.source);
  const score = computeScore(parentId, rulesCount, mitigationCount, sources, effectiveRuleCount(linkedRules));
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
  const score = computeScore(techId, rulesCount, mitigationCount, sources, effectiveRuleCount(enriched));
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
    const weightedCount = effectiveRuleCount(rulesForSub);
    applyTechniqueVisuals(subCard, st.id, rulesForSub.length, mitigationCount, sources, weightedCount);
    // Alt teknikler daha soluk gösterilir — ana tekniğin görsel ağırlığını korur
    const subScore = computeScore(st.id, rulesForSub.length, mitigationCount, sources, weightedCount);
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
  const compactQuery = window.matchMedia('(max-width: 720px)');
  if (compactQuery.matches) sidebar.classList.add('collapsed');
  compactQuery.addEventListener('change', event => {
    if (event.matches) sidebar.classList.add('collapsed');
  });
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
      if (target === 'matrixPanel' && mitreObjects.length) renderMatrix();
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

async function changeOwnPassword() {
  const currentInput = document.getElementById('ownPasswordCurrent');
  const newInput = document.getElementById('ownPasswordNew');
  const result = document.getElementById('ownPasswordResult');
  result.textContent = '';
  result.classList.remove('error');

  const current_password = currentInput.value;
  const new_password = newInput.value;
  if (!current_password || !new_password) {
    result.textContent = 'Mevcut ve yeni parolayı gir.';
    result.classList.add('error');
    return;
  }

  const res = await apiFetch('/api/me/password', {
    method: 'PUT',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ current_password, new_password })
  });
  const payload = await res.json().catch(() => ({}));
  if (!res.ok) {
    result.textContent = payload.error || 'Parola değiştirilemedi.';
    result.classList.add('error');
    return;
  }
  currentInput.value = '';
  newInput.value = '';
  result.textContent = 'Parola güncellendi.';
}

function wireSettings() {
  const addBtn = document.getElementById('btnAddProduct');
  if (addBtn) addBtn.addEventListener('click', addProduct);
  const uploadBtn = document.getElementById('btnUploadCsv');
  if (uploadBtn) uploadBtn.addEventListener('click', uploadCsv);
  const addUserBtn = document.getElementById('btnAddUser');
  if (addUserBtn) addUserBtn.addEventListener('click', addUser);
  document.getElementById('connectorSave')?.addEventListener('click', saveConnector);
  document.getElementById('connectorCancel')?.addEventListener('click', resetConnectorForm);
  const refreshAuditBtn = document.getElementById('btnRefreshAudit');
  if (refreshAuditBtn) refreshAuditBtn.addEventListener('click', loadAuditLogs);
  const changePasswordBtn = document.getElementById('btnChangeOwnPassword');
  if (changePasswordBtn) changePasswordBtn.addEventListener('click', changeOwnPassword);
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
      if (btn.dataset.tab === 'stab-connectors') loadConnectors();
    });
  });
}

function resetConnectorForm() {
  const values = {
    connectorId: '', connectorName: '', connectorBaseUrl: '',
    connectorSecretEnv: 'QRADAR_SEC_TOKEN', connectorProduct: 'QRadar',
    connectorMappingsPath: '/console/plugins/app_proxy:UseCaseManager_Service/api/mappings',
    connectorCaBundle: ''
  };
  Object.entries(values).forEach(([id, value]) => {
    const input = document.getElementById(id);
    if (input) input.value = value;
  });
  document.getElementById('connectorVerifyTls').checked = true;
  document.getElementById('connectorImportRules').checked = true;
  document.getElementById('connectorEnabled').checked = true;
  document.getElementById('connectorSave').textContent = 'Connector Kaydet';
  document.getElementById('connectorCancel').classList.add('hidden');
}

function editConnector(connector) {
  const fields = {
    connectorId: connector.id,
    connectorName: connector.name,
    connectorBaseUrl: connector.base_url,
    connectorSecretEnv: connector.secret_env,
    connectorProduct: connector.product_name,
    connectorMappingsPath: connector.mappings_path,
    connectorCaBundle: connector.ca_bundle,
  };
  Object.entries(fields).forEach(([id, value]) => {
    const input = document.getElementById(id);
    if (input) input.value = value ?? '';
  });
  document.getElementById('connectorVerifyTls').checked = !!connector.verify_tls;
  document.getElementById('connectorImportRules').checked = !!connector.import_new_rules;
  document.getElementById('connectorEnabled').checked = !!connector.enabled;
  document.getElementById('connectorSave').textContent = 'Değişiklikleri Kaydet';
  document.getElementById('connectorCancel').classList.remove('hidden');
  document.getElementById('connectorName').focus();
}

function renderConnectors() {
  const host = document.getElementById('connectorList');
  if (!host) return;
  if (!connectors.length) {
    host.innerHTML = '<div class="settings-empty">Henüz QRadar connector tanımlanmadı.</div>';
    return;
  }
  host.innerHTML = connectors.map(connector => {
    const inv = connector.inventory || {};
    const run = (connector.recent_runs || [])[0];
    const status = connector.last_status === 'success' ? 'Başarılı' : connector.last_status === 'failed' ? 'Hatalı' : 'Henüz çalışmadı';
    const statusClass = connector.last_status === 'success' ? 'good' : connector.last_status === 'failed' ? 'bad' : 'warn';
    return `<article class="connector-card" data-connector-id="${connector.id}">
      <div class="connector-card-head">
        <div><strong>${_esc(connector.name)}</strong><span>${_esc(connector.base_url)}</span></div>
        <span class="conn-badge ${statusClass}">${status}</span>
      </div>
      <div class="connector-metrics">
        <div><strong>${inv.total || 0}</strong><span>Envanter</span></div>
        <div><strong>${connector.linked_rules || 0}</strong><span>Bağlı kural</span></div>
        <div><strong>${inv.active || 0}</strong><span>Aktif</span></div>
        <div><strong>${inv.stale || 0}</strong><span>Stale</span></div>
      </div>
      <div class="connector-meta">
        <span>Token: <strong class="${connector.token_configured ? 'good-text' : 'danger-text'}">${connector.token_configured ? 'Tanımlı' : 'Eksik'}</strong></span>
        <span>Son sync: <strong>${connector.last_sync_at ? _esc(formatAuditTime(connector.last_sync_at)) : '—'}</strong></span>
        <span>Sonuç: <strong>${run ? `${run.received} kayıt · ${run.mapping_count} mapping` : '—'}</strong></span>
      </div>
      ${connector.last_error ? `<div class="connector-error">${_esc(connector.last_error)}</div>` : ''}
      <div class="connector-card-actions">
        <button class="action-btn btn-neutral" data-action="edit">Düzenle</button>
        <button class="action-btn btn-neutral" data-action="test">Bağlantıyı Test Et</button>
        <button class="action-btn btn-add" data-action="sync" ${!connector.enabled ? 'disabled' : ''}>Şimdi Senkronize Et</button>
      </div>
    </article>`;
  }).join('');
  host.querySelectorAll('.connector-card').forEach(card => {
    const connector = connectors.find(item => item.id === Number(card.dataset.connectorId));
    card.querySelector('[data-action="edit"]')?.addEventListener('click', () => editConnector(connector));
    card.querySelector('[data-action="test"]')?.addEventListener('click', event => runConnectorAction(connector.id, 'test', event.currentTarget));
    card.querySelector('[data-action="sync"]')?.addEventListener('click', event => runConnectorAction(connector.id, 'sync', event.currentTarget));
  });
}

async function loadConnectors() {
  if (!hasRole('admin')) return;
  const response = await apiFetch('/api/connectors');
  if (!response.ok) return;
  connectors = await response.json();
  renderConnectors();
}

async function saveConnector() {
  if (!hasRole('admin')) return;
  const id = document.getElementById('connectorId').value;
  const payload = {
    name: document.getElementById('connectorName').value.trim(),
    base_url: document.getElementById('connectorBaseUrl').value.trim(),
    secret_env: document.getElementById('connectorSecretEnv').value.trim(),
    product_name: document.getElementById('connectorProduct').value.trim(),
    mappings_path: document.getElementById('connectorMappingsPath').value.trim(),
    ca_bundle: document.getElementById('connectorCaBundle').value.trim(),
    verify_tls: document.getElementById('connectorVerifyTls').checked,
    import_new_rules: document.getElementById('connectorImportRules').checked,
    enabled: document.getElementById('connectorEnabled').checked,
  };
  const response = await apiFetch(id ? `/api/connectors/${id}` : '/api/connectors', {
    method: id ? 'PUT' : 'POST',
    headers: {'Content-Type': 'application/json'},
    body: JSON.stringify(payload),
  });
  const result = await response.json().catch(() => ({}));
  if (!response.ok) {
    alert(result.error || 'Connector kaydedilemedi.');
    return;
  }
  resetConnectorForm();
  await loadConnectors();
}

async function runConnectorAction(id, action, button) {
  const original = button.textContent;
  button.disabled = true;
  button.textContent = action === 'sync' ? 'Senkronize ediliyor…' : 'Test ediliyor…';
  try {
    const response = await apiFetch(`/api/connectors/${id}/${action}`, {method: 'POST'});
    const result = await response.json().catch(() => ({}));
    if (!response.ok) throw new Error(result.error || 'Connector işlemi başarısız.');
    if (action === 'test') alert(`Bağlantı başarılı. ${result.mapping_records} mapping kaydı okundu.`);
    if (action === 'sync') {
      alert(`Senkronizasyon tamamlandı. ${result.received} kayıt okundu, ${result.rules_created} yeni kural oluşturuldu.`);
      await reloadData();
    }
    await loadConnectors();
  } catch (error) {
    alert(error.message);
    await loadConnectors();
  } finally {
    button.disabled = false;
    button.textContent = original;
  }
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
  wireScopeRegistry();
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
        score: computeScore(tech.id, parentRuleCount, parentMitCount, parentSources, effectiveRuleCount(parentRules))
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
          score: computeScore(st.id, subRuleCount, subMitCount, subSources, effectiveRuleCount(subRules))
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
      applyTechniqueVisuals(
        card, tech.id, rulesForCell.length, mitigationCount, sources,
        effectiveRuleCount(rulesForCell)
      );

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
  setMatrixStatLabels(['Teknik','Kapsanan','Alt Teknik Kapsama','Teknik Ort.','Genel Ort. %','Kritik Boşluk','Mitigation Girişi']);
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
        const weightedRules = d.weightedRuleCount ?? d.rulesCount;
        const ruleBar  = Math.min(weightedRules / Math.max(d.threshold, 1), 1) * 100;
        const mitBar   = d.mitTotal > 0 ? Math.min(d.mitigationCount / d.mitTotal, 1) * 100 : 0;
        tip = document.createElement('div');
        tip.className = 'score-tooltip';
        tip.innerHTML = `
          <div class="score-tooltip-row">
            <span class="score-tooltip-label">Tespit</span>
            <span class="score-tooltip-val">${d.rulesCount} adet · ${weightedRules}/${d.threshold} etkin</span>
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
// GAP panelinden teknik/alt-teknik modal açma
// Matrix davranışını birebir yansıtır:
//   • Parent teknik → tüm kurallar (parentId eşleşmesi)
//   • Alt teknik    → sadece o alt tekniğin kuralları (tid eşleşmesi)
// ══════════════════════════════════════════════════════════════
function openGapTechDetail(techId, techName) {
  const allRules = enrichRules();
  const isSub = techId.includes('.');
  let rules;
  if (isSub) {
    rules = allRules.filter(r => r.tid === techId);
  } else {
    rules = allRules.filter(r => r.parentId === techId || r.tid === techId);
  }
  // techName: techDetailsMap'teki isim varsa onu kullan, yoksa GAP'ten gelen ismi kullan
  const mapName = techDetailsMap[techId] ? techDetailsMap[techId].name : techName;
  openModal(techId, mapName || techName, rules);
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
  // Tüm teknikler (parent + alt) bazında sayılar
  const total   = ov.total_techniques || 0;
  const covered = ov.covered_techniques || 0;
  const pct     = ov.coverage_pct || 0;
  const mature = ov.mature_techniques || 0;
  const maturityPct = ov.maturity_pct || 0;
  const averageScore = ov.average_score_pct || 0;
  const critCount = ov.critical_gap_count || 0;
  const parentTotal   = ov.parent_total   || 0;
  const parentCovered = ov.parent_covered || 0;
  const subTotal   = ov.total_subtechniques   || 0;
  const subCovered = ov.covered_subtechniques || 0;

  const TACTIC_TR = {
    'reconnaissance':'Reconnaissance','resource-development':'Resource Development',
    'initial-access':'Initial Access','execution':'Execution',
    'persistence':'Persistence','privilege-escalation':'Privilege Escalation',
    'defense-evasion':'Defense Evasion','credential-access':'Credential Access',
    'discovery':'Discovery','lateral-movement':'Lateral Movement',
    'collection':'Collection','command-and-control':'Command & Control',
    'exfiltration':'Exfiltration','impact':'Impact'
  };

  // Stat cards — tüm teknikler üzerinden
  let html = `<div class="gap-stat-cards">
    <div class="gap-stat-card">
      <div class="gap-stat-val">${total}</div>
      <div class="gap-stat-lbl">Toplam Teknik</div>
      <div class="gap-stat-sub">${parentTotal} ana · ${subTotal} alt</div>
    </div>
    <div class="gap-stat-card">
      <div class="gap-stat-val good">${covered} <span style="font-size:16px">(${pct}%)</span></div>
      <div class="gap-stat-lbl">Tespit Bulunan</div>
      <div class="gap-stat-sub">${parentCovered} ana · ${subCovered} alt teknik</div>
    </div>
    <div class="gap-stat-card">
      <div class="gap-stat-val good">${mature} <span style="font-size:16px">(${maturityPct}%)</span></div>
      <div class="gap-stat-lbl">Olgun Kapsama</div>
      <div class="gap-stat-sub">Skor ≥ %70</div>
    </div>
    <div class="gap-stat-card">
      <div class="gap-stat-val">${averageScore}%</div>
      <div class="gap-stat-lbl">Ortalama Kapsama Skoru</div>
      <div class="gap-stat-sub">Tespit · mitigation · ürün çeşitliliği</div>
    </div>
    <div class="gap-stat-card">
      <div class="gap-stat-val danger">${critCount}</div>
      <div class="gap-stat-lbl">Kritik Boşluk</div>
      <div class="gap-stat-sub">Önem ≥ 4, tespit yok</div>
    </div>
  </div>`;

  // Tactic progress bars
  html += '<div class="gap-section-title">Taktik Bazlı Kapsama</div>';
  (data.by_tactic || []).forEach(t => {
    const barPct = t.average_score_pct || 0;
    const cls = barPct < 30 ? 'low' : barPct < 60 ? 'mid' : '';
    html += `<div class="gap-tactic-row">
      <div class="gap-tactic-name">${_esc(t.label || t.tactic)}</div>
      <div class="gap-bar-wrap"><div class="gap-bar-fill ${cls}" style="width:${barPct}%"></div></div>
      <div class="gap-tactic-pct">${barPct}%</div>
      <div class="gap-tactic-count" title="Tespit bulunan">${t.covered}/${t.total}</div>
    </div>`;
  });

  // Critical gaps
  html += '<div class="gap-section-title" style="margin-top:20px">Kritik Boşluklar (Önem ≥ 4, Skor &lt; %35)</div>';
  const gaps = data.critical_gaps || [];
  if (gaps.length === 0) {
    html += '<div style="color:var(--d-text-3);font-size:12px;padding:10px 0">Kritik boşluk yok.</div>';
  } else {
    html += '<div class="gap-critical-list">';
    gaps.forEach(g => {
      const tacticLabel = TACTIC_TR[g.tactic] || g.tactic || '—';
      const safeName = _esc(g.name).replace(/'/g, '&#39;');
      html += `<div class="gap-critical-item" onclick="openGapTechDetail('${_esc(g.tech_id)}','${safeName}')">
        <div class="gap-imp-dot lv-${g.importance_level}"></div>
        <div class="gap-critical-id">${_esc(g.tech_id)}</div>
        <div class="gap-critical-name">${_esc(g.name)}</div>
        <div class="gap-critical-tactic">${_esc(tacticLabel)}</div>
        <div class="gap-critical-score">${Math.round((g.coverage_score || 0) * 100)}%</div>
        ${hasRole('editor') ? `<button class="gap-critical-add" onclick="event.stopPropagation();openNewActionForTech('${_esc(g.tech_id)}','${safeName}')" title="Aksiyon ekle">+ Aksiyon</button>` : ''}
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
            <button class="action-item-btn" title="Düzenle" aria-label="Düzenle" data-edit="${item.id}">&#9998;</button>
            <button class="action-item-btn del" title="Sil" aria-label="Sil" data-del="${item.id}">&#x2715;</button>
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
const SCOPE_STATUS_LABELS = { unknown: 'Değerlendirilmedi', none: 'İzlenmiyor', partial: 'Kısmi izleme', full: 'Tam izleme' };
const SCOPE_MODE_LABELS = { agent: 'Ajan', log_forwarding: 'Log yönlendirme', api: 'API', network: 'Ağ gözlemi', hybrid: 'Hibrit', other: 'Diğer' };

function selectedScopeEnvironment() {
  return scopeRegistry?.environments.find(item => item.id === selectedEnvironmentId) || null;
}

function selectedScopeGroup() {
  return selectedScopeEnvironment()?.groups.find(item => item.id === selectedAssetGroupId) || null;
}

async function loadScopeRegistry() {
  const survey = document.getElementById('scopeSurvey');
  if (survey && !scopeRegistry) survey.innerHTML = '<div class="scope-empty"><strong>Kapsam yükleniyor</strong><span>Ortam ve varlık grupları hazırlanıyor.</span></div>';
  const res = await apiFetch('/api/scope-registry');
  if (!res.ok) {
    if (survey) survey.innerHTML = '<div class="scope-empty scope-error"><strong>Kapsam yüklenemedi</strong><span>Sayfayı yenileyip tekrar deneyin.</span></div>';
    return;
  }
  scopeRegistry = await res.json();
  const environments = scopeRegistry.environments || [];
  if (!environments.some(item => item.id === selectedEnvironmentId)) selectedEnvironmentId = (environments.find(item => item.active) || environments[0])?.id || null;
  const groups = selectedScopeEnvironment()?.groups || [];
  if (!groups.some(item => item.id === selectedAssetGroupId)) selectedAssetGroupId = (groups.find(item => item.active) || groups[0])?.id || null;
  renderScopeRegistry();
}

function renderScopeRegistry() {
  if (!scopeRegistry) return;
  const summary = scopeRegistry.summary || {};
  document.getElementById('scopeSummary').innerHTML = [
    ['Aktif ortam', summary.environment_count || 0], ['Varlık grubu', summary.group_count || 0],
    ['Kayıtlı varlık', Number(summary.asset_count || 0).toLocaleString('tr-TR')], ['Değerlendirilen ürün', summary.reviewed_deployments || 0]
  ].map(([label, value]) => `<div class="ops-stat"><strong>${value}</strong><span>${label}</span></div>`).join('');
  const envSelect = document.getElementById('scopeEnvironmentSelect');
  envSelect.innerHTML = scopeRegistry.environments.length
    ? scopeRegistry.environments.map(env => `<option value="${env.id}" ${env.id === selectedEnvironmentId ? 'selected' : ''}>${_esc(env.name)}${env.active ? '' : ' (pasif)'}</option>`).join('')
    : '<option value="">Henüz ortam yok</option>';
  const groups = selectedScopeEnvironment()?.groups || [];
  const groupSelect = document.getElementById('scopeGroupSelect');
  groupSelect.disabled = !groups.length;
  groupSelect.innerHTML = groups.length
    ? groups.map(group => `<option value="${group.id}" ${group.id === selectedAssetGroupId ? 'selected' : ''}>${_esc(group.name)}${group.active ? '' : ' (pasif)'}</option>`).join('')
    : '<option value="">Varlık grubu yok</option>';
  document.getElementById('scopeAddEnvironment').classList.toggle('hidden', !hasRole('admin'));
  document.getElementById('scopeEditEnvironment').classList.toggle('hidden', !hasRole('admin') || !selectedScopeEnvironment());
  document.getElementById('scopeAddGroup').classList.toggle('hidden', !hasRole('admin') || !selectedScopeEnvironment());
  document.getElementById('scopeEditGroup').classList.toggle('hidden', !hasRole('admin') || !selectedScopeGroup());
  renderMonitoringSurvey();
}

function openScopeEnvironmentEditor(environment = null) {
  document.getElementById('scopeGroupEditor').classList.add('hidden');
  document.getElementById('scopeEnvironmentId').value = environment?.id || '';
  document.getElementById('scopeEnvironmentName').value = environment?.name || '';
  document.getElementById('scopeEnvironmentCode').value = environment?.code || '';
  document.getElementById('scopeEnvironmentOwner').value = environment?.owner || '';
  document.getElementById('scopeEnvironmentCriticality').value = environment?.criticality || 3;
  document.getElementById('scopeEnvironmentDescription').value = environment?.description || '';
  document.getElementById('scopeEnvironmentActive').checked = environment ? Boolean(environment.active) : true;
  document.getElementById('scopeEnvironmentEditor').classList.remove('hidden');
  document.getElementById('scopeEnvironmentName').focus();
}

function openScopeGroupEditor(group = null) {
  if (!selectedScopeEnvironment()) return;
  document.getElementById('scopeEnvironmentEditor').classList.add('hidden');
  document.getElementById('scopeGroupId').value = group?.id || '';
  document.getElementById('scopeGroupName').value = group?.name || '';
  document.getElementById('scopeGroupPlatform').value = group?.platform || 'Linux';
  document.getElementById('scopeGroupType').value = group?.asset_type || 'Server';
  document.getElementById('scopeGroupCount').value = group?.asset_count || 0;
  document.getElementById('scopeGroupOwner').value = group?.owner || '';
  document.getElementById('scopeGroupCriticality').value = group?.criticality || 3;
  document.getElementById('scopeGroupActive').checked = group ? Boolean(group.active) : true;
  document.getElementById('scopeGroupEditor').classList.remove('hidden');
  document.getElementById('scopeGroupName').focus();
}

async function saveScopeEnvironment() {
  const id = document.getElementById('scopeEnvironmentId').value;
  const payload = {
    name: document.getElementById('scopeEnvironmentName').value.trim(), code: document.getElementById('scopeEnvironmentCode').value.trim(),
    owner: document.getElementById('scopeEnvironmentOwner').value.trim(), criticality: Number(document.getElementById('scopeEnvironmentCriticality').value),
    description: document.getElementById('scopeEnvironmentDescription').value.trim(), active: document.getElementById('scopeEnvironmentActive').checked
  };
  const res = await apiFetch(id ? `/api/environments/${id}` : '/api/environments', { method: id ? 'PUT' : 'POST', headers: {'Content-Type': 'application/json'}, body: JSON.stringify(payload) });
  const data = await res.json().catch(() => ({}));
  if (!res.ok) return alert(data.error || 'Ortam kaydedilemedi');
  if (!id && data.id) selectedEnvironmentId = data.id;
  selectedAssetGroupId = null;
  document.getElementById('scopeEnvironmentEditor').classList.add('hidden');
  await loadScopeRegistry();
}

async function saveScopeGroup() {
  const environment = selectedScopeEnvironment();
  if (!environment) return;
  const id = document.getElementById('scopeGroupId').value;
  const payload = {
    name: document.getElementById('scopeGroupName').value.trim(), platform: document.getElementById('scopeGroupPlatform').value,
    asset_type: document.getElementById('scopeGroupType').value, asset_count: Number(document.getElementById('scopeGroupCount').value),
    owner: document.getElementById('scopeGroupOwner').value.trim(), criticality: Number(document.getElementById('scopeGroupCriticality').value),
    active: document.getElementById('scopeGroupActive').checked
  };
  const res = await apiFetch(id ? `/api/asset-groups/${id}` : `/api/environments/${environment.id}/asset-groups`, { method: id ? 'PUT' : 'POST', headers: {'Content-Type': 'application/json'}, body: JSON.stringify(payload) });
  const data = await res.json().catch(() => ({}));
  if (!res.ok) return alert(data.error || 'Varlık grubu kaydedilemedi');
  if (!id && data.id) selectedAssetGroupId = data.id;
  document.getElementById('scopeGroupEditor').classList.add('hidden');
  await loadScopeRegistry();
}

function renderMonitoringSurvey() {
  const target = document.getElementById('scopeSurvey');
  const environment = selectedScopeEnvironment();
  const group = selectedScopeGroup();
  if (!environment || !group) {
    target.innerHTML = `<div class="scope-empty"><strong>${environment ? 'Varlık grubu gerekli' : 'İlk ortamı oluşturun'}</strong><span>${environment ? 'Bu ortam için bir varlık grubu ekleyin.' : 'KPI kapsamını tanımlamak için ortam ve varlık grubu kaydı gerekir.'}</span></div>`;
    return;
  }
  const deployments = new Map((group.deployments || []).map(item => [item.product_id, item]));
  const canEdit = hasRole('editor');
  const rows = (scopeRegistry.products || []).map(product => {
    const item = deployments.get(product.id) || {};
    const status = item.monitoring_status || 'unknown';
    const mode = item.monitoring_mode || 'other';
    const compatible = (scopeRegistry.connectors || []).filter(connector => connector.product_name === product.name && connector.enabled);
    const connectorOptions = ['<option value="">Connector seçilmedi</option>', ...compatible.map(connector => `<option value="${connector.id}" ${connector.id === item.connector_id ? 'selected' : ''}>${_esc(connector.name)}${connector.last_status === 'success' ? '' : ' · doğrulanmadı'}</option>`)].join('');
    const disabled = canEdit ? '' : 'disabled';
    return `<div class="scope-monitor-row" data-product-id="${product.id}">
      <div class="scope-product"><i style="background:${_esc(product.color || '#64748b')}"></i><div><strong>${_esc(product.name)}</strong><small>${item.reviewed_at ? `${_esc(item.reviewed_by || '')} · ${_esc(item.reviewed_at)}` : 'Henüz değerlendirilmedi'}</small></div></div>
      <label><span>İzleme durumu</span><select class="scope-monitor-status" ${disabled}>${Object.entries(SCOPE_STATUS_LABELS).map(([value,label]) => `<option value="${value}" ${value === status ? 'selected' : ''}>${label}</option>`).join('')}</select></label>
      <label><span>Yöntem</span><select class="scope-monitor-mode" ${disabled}>${Object.entries(SCOPE_MODE_LABELS).map(([value,label]) => `<option value="${value}" ${value === mode ? 'selected' : ''}>${label}</option>`).join('')}</select></label>
      <label><span>Kapsam %</span><input class="scope-monitor-percent" type="number" min="0" max="100" value="${item.coverage_percent || 0}" ${disabled}></label>
      <label><span>Connector</span><select class="scope-monitor-connector" ${disabled}>${connectorOptions}</select></label>
      <label><span>Sorumlu</span><input class="scope-monitor-owner" value="${_esc(item.owner || '')}" placeholder="SOC ekibi" ${disabled}></label>
      <label><span>Not / sınır</span><input class="scope-monitor-notes" value="${_esc(item.notes || '')}" placeholder="Hariç kalan cihazlar, log kapsamı..." ${disabled}></label>
      <div class="scope-evidence"><strong>${Number(item.connector_detection_count || 0).toLocaleString('tr-TR')}</strong><span>bağlı dış tespit</span></div>
    </div>`;
  }).join('');
  target.innerHTML = `<div class="scope-survey-head"><div><span class="scope-path">${_esc(environment.name)} / ${_esc(group.name)}</span><h2>Ürün İzleme Anketi</h2><p>${_esc(group.platform)} · ${_esc(group.asset_type)} · ${Number(group.asset_count).toLocaleString('tr-TR')} varlık · Kritiklik ${group.criticality}/5</p></div><div class="scope-trust-note"><strong>KPI kanıt kuralı</strong><span>Ürünün bulunması tek başına MITRE coverage değildir. Connector tespitleri ayrıca eşlenip doğrulanır.</span></div></div>
    <div class="scope-monitor-list">${rows || '<div class="scope-empty"><strong>Ürün bulunamadı</strong><span>Önce Ayarlar bölümünden ürün ekleyin.</span></div>'}</div>
    ${canEdit && rows ? '<div class="scope-survey-actions"><span>Her kaydetme işlemi kullanıcı ve zaman bilgisiyle audit loga yazılır.</span><button class="action-btn btn-add" id="scopeSaveMonitoring">Anketi Kaydet</button></div>' : ''}`;
  target.querySelectorAll('.scope-monitor-status').forEach(select => {
    const sync = () => {
      const row = select.closest('.scope-monitor-row');
      const percent = row.querySelector('.scope-monitor-percent');
      const connector = row.querySelector('.scope-monitor-connector');
      if (select.value === 'full') percent.value = 100;
      if (select.value === 'none' || select.value === 'unknown') percent.value = 0;
      if (select.value === 'partial' && (Number(percent.value) < 1 || Number(percent.value) > 99)) percent.value = 50;
      percent.disabled = !canEdit || select.value !== 'partial';
      connector.disabled = !canEdit || select.value === 'none' || select.value === 'unknown';
      if (connector.disabled && canEdit) connector.value = '';
    };
    select.addEventListener('change', sync);
    sync();
  });
  document.getElementById('scopeSaveMonitoring')?.addEventListener('click', saveScopeMonitoring);
}

async function saveScopeMonitoring() {
  const group = selectedScopeGroup();
  if (!group) return;
  const deployments = [...document.querySelectorAll('.scope-monitor-row')].map(row => ({
    product_id: Number(row.dataset.productId), monitoring_status: row.querySelector('.scope-monitor-status').value,
    monitoring_mode: row.querySelector('.scope-monitor-mode').value, coverage_percent: Number(row.querySelector('.scope-monitor-percent').value),
    connector_id: row.querySelector('.scope-monitor-connector').value || null, owner: row.querySelector('.scope-monitor-owner').value.trim(),
    notes: row.querySelector('.scope-monitor-notes').value.trim()
  }));
  const button = document.getElementById('scopeSaveMonitoring');
  button.disabled = true;
  const res = await apiFetch(`/api/asset-groups/${group.id}/monitoring`, { method: 'PUT', headers: {'Content-Type': 'application/json'}, body: JSON.stringify({deployments}) });
  const data = await res.json().catch(() => ({}));
  if (!res.ok) { button.disabled = false; return alert(data.error || 'İzleme anketi kaydedilemedi'); }
  await loadScopeRegistry();
}

function wireScopeRegistry() {
  document.getElementById('scopeAddEnvironment')?.addEventListener('click', () => openScopeEnvironmentEditor());
  document.getElementById('scopeEditEnvironment')?.addEventListener('click', () => openScopeEnvironmentEditor(selectedScopeEnvironment()));
  document.getElementById('scopeAddGroup')?.addEventListener('click', () => openScopeGroupEditor());
  document.getElementById('scopeEditGroup')?.addEventListener('click', () => openScopeGroupEditor(selectedScopeGroup()));
  document.getElementById('scopeSaveEnvironment')?.addEventListener('click', saveScopeEnvironment);
  document.getElementById('scopeSaveGroup')?.addEventListener('click', saveScopeGroup);
  document.querySelectorAll('[data-scope-cancel]').forEach(button => button.addEventListener('click', () => button.closest('.scope-editor').classList.add('hidden')));
  document.getElementById('scopeEnvironmentSelect')?.addEventListener('change', event => {
    selectedEnvironmentId = Number(event.target.value) || null;
    selectedAssetGroupId = (selectedScopeEnvironment()?.groups.find(item => item.active) || selectedScopeEnvironment()?.groups[0])?.id || null;
    renderScopeRegistry();
  });
  document.getElementById('scopeGroupSelect')?.addEventListener('change', event => { selectedAssetGroupId = Number(event.target.value) || null; renderScopeRegistry(); });
}

function wireNewPanels() {
  // Wiki sidebar navigation (Bilgilendirme panel)
  const wikiContent = document.querySelector('.wiki-content');
  document.querySelectorAll('.wiki-nav-item').forEach(btn => {
    btn.addEventListener('click', () => {
      const target = btn.dataset.wiki;
      document.querySelectorAll('.wiki-nav-item').forEach(b => b.classList.remove('active'));
      document.querySelectorAll('.wiki-page').forEach(p => p.classList.remove('active'));
      btn.classList.add('active');
      const page = document.getElementById(target);
      if (page) page.classList.add('active');
      if (wikiContent) wikiContent.scrollTop = 0;
    });
  });

  // TTP panel: load data when nav item is clicked
  document.querySelector('.nav-item[data-target="ttpPanel"]')?.addEventListener('click', () => {
    loadTtpList();
  });
  // GAP panel: load data when nav item is clicked
  document.querySelector('.nav-item[data-target="gapPanel"]')?.addEventListener('click', () => {
    loadGapDashboard();
  });
  // Actions panel: load data when nav item is clicked
  document.querySelector('.nav-item[data-target="actionsPanel"]')?.addEventListener('click', () => {
    loadActionsPanel();
  });
  document.querySelector('.nav-item[data-target="dataQualityPanel"]')?.addEventListener('click', () => {
    loadDataQuality();
  });
  document.querySelector('.nav-item[data-target="auditPanel"]')?.addEventListener('click', () => {
    loadAuditLogs();
  });
  document.querySelector('.nav-item[data-target="scopePanel"]')?.addEventListener('click', loadScopeRegistry);

  document.getElementById('dataQualityRefresh')?.addEventListener('click', loadDataQuality);
  document.getElementById('dataQualityRepair')?.addEventListener('click', repairDataQuality);
  document.getElementById('qualitySeverity')?.addEventListener('change', renderQualityIssues);
  document.getElementById('qualityType')?.addEventListener('change', renderQualityIssues);
  document.getElementById('qualitySearch')?.addEventListener('input', renderQualityIssues);

  document.getElementById('auditRefresh')?.addEventListener('click', () => loadAuditLogs());
  document.getElementById('auditExport')?.addEventListener('click', () => {
    window.location.href = `/api/audit-logs/export?${auditFilterParams(false).toString()}`;
  });
  document.getElementById('auditEvidenceExport')?.addEventListener('click', downloadAuditEvidence);
  document.getElementById('auditPrev')?.addEventListener('click', () => {
    if (auditPagination.page > 1) { auditPagination.page -= 1; loadAuditLogs(); }
  });
  document.getElementById('auditNext')?.addEventListener('click', () => {
    if (auditPagination.page < auditPagination.pages) { auditPagination.page += 1; loadAuditLogs(); }
  });
  document.getElementById('auditDetailClose')?.addEventListener('click', () => {
    document.getElementById('auditDetail')?.classList.add('hidden');
  });
  ['auditAction', 'auditTargetType', 'auditDateFrom', 'auditDateTo'].forEach(id => {
    document.getElementById(id)?.addEventListener('change', () => loadAuditLogs(true));
  });
  let auditSearchTimer = null;
  ['auditSearch', 'auditActor'].forEach(id => {
    document.getElementById(id)?.addEventListener('input', () => {
      clearTimeout(auditSearchTimer);
      auditSearchTimer = setTimeout(() => loadAuditLogs(true), 300);
    });
  });

  wireActionsPanel();
  wireThreatActors();

  // Load threat actors in background after main init completes
  setTimeout(loadThreatActors, 1500);

  // TTP search
  document.getElementById('ttpSearch')?.addEventListener('input', e => {
    if (_ttpData) renderTtpList(_ttpData, e.target.value);
  });
}


// ══════════════════════════════════════════════════════════════
// TTP Listesi
// ══════════════════════════════════════════════════════════════
const _TTP_TACTIC_LABELS = {
  'reconnaissance':'Reconnaissance','resource-development':'Resource Development',
  'initial-access':'Initial Access','execution':'Execution',
  'persistence':'Persistence','privilege-escalation':'Privilege Escalation',
  'defense-evasion':'Defense Evasion','credential-access':'Credential Access',
  'discovery':'Discovery','lateral-movement':'Lateral Movement',
  'collection':'Collection','command-and-control':'Command and Control',
  'exfiltration':'Exfiltration','impact':'Impact'
};

let _ttpData = null;

function _ttpRowBg(ruleCount, mitEntryCount, totalMits, ruleThreshold) {
  const ruleScore = Math.min(ruleCount / (ruleThreshold || 3), 1.0);
  const mitScore  = totalMits > 0 ? Math.min(mitEntryCount / totalMits, 1.0) : 0;
  const score = Math.min(ruleScore * 0.65 + mitScore * 0.35, 1.0);
  if (score < 0.01) return '';
  if (score < 0.30) return 'rgba(209,52,56,0.07)';
  if (score < 0.60) return 'rgba(202,112,16,0.09)';
  return 'rgba(57,135,37,0.14)';
}

async function loadTtpList() {
  if (_ttpData) {
    renderTtpList(_ttpData, document.getElementById('ttpSearch')?.value || '');
    return;
  }
  const el = document.getElementById('ttpContent');
  if (!el) return;
  el.innerHTML = '<div class="ttp-loading">Yükleniyor\u2026</div>';
  try {
    const res = await fetch('/api/ttp-list');
    if (!res.ok) throw new Error('HTTP ' + res.status);
    const data = await res.json();
    if (!Array.isArray(data)) throw new Error('Unexpected response');
    _ttpData = data;
    renderTtpList(_ttpData, '');
  } catch(e) {
    if (el) el.innerHTML = '<div class="ttp-loading">Veriler y\u00fcklenemedi: ' + e.message + '</div>';
  }
}

function renderTtpList(data, filter) {
  const el = document.getElementById('ttpContent');
  if (!el) return;
  filter = (filter || '').toLowerCase();

  let totalTechs = 0, coveredTechs = 0;
  data.forEach(tg => tg.techniques.forEach(t => {
    if (!t.is_subtechnique) {
      totalTechs++;
      if (t.rule_count > 0 || t.mitigation_entry_count > 0) coveredTechs++;
    }
  }));
  const totalEl = document.getElementById('ttpTotalCount');
  const coveredEl = document.getElementById('ttpCoveredCount');
  const ratioEl = document.getElementById('ttpCoverageRatio');
  if (totalEl) totalEl.textContent = totalTechs;
  if (coveredEl) coveredEl.textContent = coveredTechs;
  if (ratioEl) ratioEl.textContent = totalTechs ? Math.round(coveredTechs / totalTechs * 100) + '%' : '0%';

  let html = '';
  data.forEach(tg => {
    const tactic = tg.tactic;
    const label = _TTP_TACTIC_LABELS[tactic] || tactic;
    const parents = tg.techniques.filter(t => !t.is_subtechnique);
    const subs = {};
    tg.techniques.filter(t => t.is_subtechnique).forEach(t => {
      (subs[t.parent_id] = subs[t.parent_id] || []).push(t);
    });

    const visParents = parents.filter(t => {
      if (!filter) return true;
      if (t.tech_id.toLowerCase().includes(filter)) return true;
      if (t.name.toLowerCase().includes(filter)) return true;
      if ((subs[t.tech_id] || []).some(s =>
        s.tech_id.toLowerCase().includes(filter) || s.name.toLowerCase().includes(filter)
      )) return true;
      return false;
    });
    if (!visParents.length) return;

    html += `<div class="ttp-tactic-section"><div class="ttp-tactic-header">${_esc(label)}</div>`;

    visParents.forEach(t => {
      const subList = subs[t.tech_id] || [];
      const hasSubs = subList.length > 0;
      const bg = _ttpRowBg(t.rule_count, t.mitigation_entry_count, t.total_mitigations, t.rule_threshold);
      const bgStyle = bg ? ` style="background:${bg}"` : '';
      html += `<div class="ttp-tech-row" data-tech-id="${t.tech_id}"${bgStyle}>
        <span class="ttp-expand${hasSubs?' ttp-has-subs':''}" onclick="ttpToggle('${t.tech_id}','${tactic}')" title="${hasSubs?'Alt teknikleri a\u00e7/kapat':''}">${hasSubs?'\u25ba':''}</span>
        <span class="ttp-tech-id">${_esc(t.tech_id)}</span>
        <span class="ttp-tech-name" onclick="openTechDetail('${t.tech_id}')" title="Detay">${_esc(t.name)}</span>
        <span class="ttp-badge-rule" title="Tespit say\u0131s\u0131">\ud83d\udd0d ${t.rule_count}</span>
        <span class="ttp-badge-mit" title="Mitigation kapsama">${t.mitigation_entry_count}/${t.total_mitigations} Mitigation</span>
      </div>`;

      if (hasSubs) {
        html += `<div class="ttp-subs-container" id="ttp-subs-${t.tech_id}-${tactic}" style="display:none">`;
        subList
          .filter(s => !filter || s.tech_id.toLowerCase().includes(filter) || s.name.toLowerCase().includes(filter))
          .forEach(s => {
            const sbg = _ttpRowBg(s.rule_count, s.mitigation_entry_count, s.total_mitigations, s.rule_threshold);
            const sbgStyle = sbg ? ` style="background:${sbg}"` : '';
            html += `<div class="ttp-tech-row ttp-subtech"${sbgStyle}>
              <span class="ttp-expand"></span>
              <span class="ttp-tech-id">${_esc(s.tech_id)}</span>
              <span class="ttp-tech-name" onclick="openTechDetail('${s.tech_id}')" title="Detay">${_esc(s.name)}</span>
              <span class="ttp-badge-rule">\ud83d\udd0d ${s.rule_count}</span>
              <span class="ttp-badge-mit">${s.mitigation_entry_count}/${s.total_mitigations}</span>
            </div>`;
          });
        html += '</div>';
      }
    });
    html += '</div>';
  });

  el.innerHTML = html || '<div class="ttp-loading">Sonu\u00e7 bulunamad\u0131.</div>';
}

function ttpToggle(techId, tactic) {
  const sub = document.getElementById(`ttp-subs-${techId}-${tactic}`);
  if (!sub) return;
  const row = sub.previousElementSibling;
  const expandBtn = row ? row.querySelector('.ttp-expand') : null;
  if (sub.style.display === 'none') {
    sub.style.display = '';
    if (expandBtn) expandBtn.textContent = '\u25bc';
  } else {
    sub.style.display = 'none';
    if (expandBtn) expandBtn.textContent = '\u25ba';
  }
}

function openTechDetail(techId) {
  const detail = techDetailsMap[techId];
  if (!detail) return;
  const parentId = detail.isSub ? detail.parentId : techId;
  const parentDetail = techDetailsMap[parentId] || detail;
  const rules = enrichRules().filter(r => r.parentId === parentId || r.tid === parentId);
  openModal(parentId, parentDetail.name, rules);
}

function setMatrixStatLabels(labels) {
  document.querySelectorAll('#matrixStatBar .mstat-lbl').forEach((element, index) => {
    element.textContent = labels[index] || '';
  });
}

