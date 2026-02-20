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

    const [mitreRes, productsRes, rulesRes, notesRes, entriesRes] = await Promise.all([
      apiFetch('/api/mitre-min'),
      apiFetch('/api/products'),
      apiFetch('/api/rules'),
      apiFetch('/api/mitigation-notes'),
      apiFetch('/api/mitigation-entries')
    ]);

    if (!mitreRes.ok) throw new Error('MITRE verisi yÃ¼klenemedi');
    mitreObjects = (await mitreRes.json()).objects || [];
    products = productsRes.ok ? await productsRes.json() : [];
    userRules = rulesRes.ok ? await rulesRes.json() : [];
    const notes = notesRes.ok ? await notesRes.json() : [];
    mitigationNotes = normalizeNotes(notes);
    const entries = entriesRes.ok ? await entriesRes.json() : [];
    mitigationEntries = normalizeEntries(entries);

    prepareMitreLookup();
    await loadProducts();
    populateTacticSelect();
    renderMitigationList();
    renderRulesList();
    renderMatrix();
  } catch (e) {
    document.getElementById('matrix').innerHTML = `Veri HatasÄ±: ${e.message}`;
  }
}
async function reloadData() {
  const [productsRes, rulesRes, notesRes, entriesRes] = await Promise.all([
    apiFetch('/api/products'),
    apiFetch('/api/rules'),
    apiFetch('/api/mitigation-notes'),
    apiFetch('/api/mitigation-entries')
  ]);
  products = productsRes.ok ? await productsRes.json() : [];
  userRules = rulesRes.ok ? await rulesRes.json() : [];
  const notes = notesRes.ok ? await notesRes.json() : [];
  mitigationNotes = normalizeNotes(notes);
  const entries = entriesRes.ok ? await entriesRes.json() : [];
  mitigationEntries = normalizeEntries(entries);
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
    ? 'TÃ¼mÃ¼'
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
      if (!map[m.id]) map[m.id] = { id: m.id, name: m.name, techniques: [] };
      map[m.id].techniques.push(tid);
    });
  });
  const mitigations = Object.values(map).sort((a, b) => a.id.localeCompare(b.id));
  if (mitigations.length === 0) {
    container.innerHTML = '<div class="empty-state"><div class="empty-title">KayÄ±t yok</div><div class="empty-sub">Mitigation verisi bulunamadÄ±.</div></div>';
    return;
  }
  const rows = mitigations.map(m => {
    const techLabels = m.techniques.map(tid => {
      const name = techDetailsMap[tid]?.name || tid;
      return { id: tid, label: `${tid} - ${name}` };
    });
    const preview = techLabels.slice(0, 4);
    const extra = techLabels.length - preview.length;
    const chips = techLabels.map(t => `<button class="tech-chip" type="button" data-tech-label="${t.label}">${t.id}</button>`).join('');
    const moreBtn = extra > 0 ? `<button class="tech-more" data-mit="${m.id}">TÃ¼mÃ¼nÃ¼ GÃ¶ster</button>` : '';
    const entries = mitigationEntries[m.id] || [];
    const desc = mitigationById[m.id]?.description || '';
    const entryHtml = entries.length
      ? entries.map(e => `
          <div class="mitigation-entry">
            <div class="entry-team">${e.team}</div>
            <div class="entry-comment">${e.comment}</div>
            <button class="entry-delete" data-entry-id="${e.id}" data-mit="${m.id}">Sil</button>
          </div>
        `).join('')
      : '<div class="mitigation-empty">KayÄ±t yok.</div>';
    return `
      <div class="mitigation-list-row">
        <div class="mitigation-list-id">${m.id}</div>
          <div class="mitigation-list-name">
          ${m.name}
          <div class="mitigation-list-desc">${summarizeText(desc, 90)}</div>
        </div>
        <div class="mitigation-list-tech">
          <div class="tech-chip-row" data-mit="${m.id}">${chips}</div>
          ${moreBtn}
        </div>
        <div class="mitigation-list-entries" data-mit="${m.id}">
          ${entryHtml}
          <div class="mitigation-entry-form">
            <input class="mitigation-entry-team" data-mit="${m.id}" placeholder="Ekip">
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

  container.querySelectorAll('.tech-more').forEach(btn => {
    btn.addEventListener('click', (e) => {
      const mitId = e.currentTarget.dataset.mit;
      const row = container.querySelector(`.tech-chip-row[data-mit="${mitId}"]`);
      if (!row) return;
      const open = row.classList.toggle('expanded');
      e.currentTarget.textContent = open ? 'Gizle' : 'TÃ¼mÃ¼nÃ¼ GÃ¶ster';
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
      if (teamInput) teamInput.value = '';
      if (commentInput) commentInput.value = '';
      renderMitigationList();
    });
  });

  container.querySelectorAll('.entry-delete').forEach(btn => {
    btn.addEventListener('click', async (e) => {
      const id = e.currentTarget.dataset.entryId;
      if (!id) return;
      const ok = await deleteMitigationEntry(id);
      if (!ok) return;
      await reloadMitigationEntries();
      renderMitigationList();
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
        <label>Kural Adı</label>
        <input id="newRuleNameInline" type="text" placeholder="Kural adı" />
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
        <button class="action-btn btn-add" id="btnAddRuleInline">+ Kural Ekle</button>
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
        <label>Kural Adı</label>
        <input id="rulesSearch" type="text" placeholder="Kural adı ara..." value="${rulesFilterSearch.replace(/"/g, '&quot;')}" />
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
    container.innerHTML = addFormHtml + filterBarHtml + '<div class="empty-state"><div class="empty-title">Kural yok</div><div class="empty-sub">Henüz kural eklenmemiş.</div></div>';
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
        <button class="tech-chip" type="button" data-tech-label="${techLabel}">${t}</button>
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
    ? '<div class="empty-state"><div class="empty-title">Sonuç yok</div><div class="empty-sub">Filtre kriterlerine uyan kural bulunamadı.</div></div>'
    : '';

  container.innerHTML = `
    ${addFormHtml}
    ${filterBarHtml}
    <div class="mitigation-list-header rule-list-header">
      <div>Kural Adı</div>
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

    if (!name) { alert('Kural adı gerekli'); return; }
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
      alert(err.error || 'Kural eklenemedi');
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
    if (note.checked) count += 1;
  });
  return count;
}

function getCheckedMitigationCountForParent(parentId) {
  let count = getCheckedMitigationCountForTech(parentId);
  const subs = subTechsByParent[parentId] || [];
  subs.forEach(sub => { count += getCheckedMitigationCountForTech(sub.id); });
  return count;
}

function computeScore(rulesCount, mitigationCount) {
  const ruleScore = Math.min(rulesCount, SCORE_RULE_MAX) / SCORE_RULE_MAX;
  const mitScore = Math.min(mitigationCount, SCORE_MITIGATION_MAX) / SCORE_MITIGATION_MAX;
  return Math.min(1, (ruleScore * SCORE_RULE_WEIGHT) + (mitScore * SCORE_MITIGATION_WEIGHT));
}

function scoreToColor(score) {
  const start = { r: 20, g: 26, b: 34 };
  const end = { r: 53, g: 196, b: 139 };
  const r = Math.round(start.r + (end.r - start.r) * score);
  const g = Math.round(start.g + (end.g - start.g) * score);
  const b = Math.round(start.b + (end.b - start.b) * score);
  return `rgb(${r}, ${g}, ${b})`;
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

function applyTechniqueVisuals(card, rulesCount, mitigationCount, sources) {
  const score = computeScore(rulesCount, mitigationCount);
  card.style.backgroundColor = scoreToColor(score);
  card.classList.toggle('covered', (rulesCount > 0 || mitigationCount > 0));

  if (mitigationCount > 0) {
    card.innerHTML += `<div class="mitigation-badge">OK${mitigationCount}</div>`;
  }
  applySourceDots(card, sources);
}

function updateTechniqueCard(parentId) {
  const card = document.querySelector(`.technique-card[data-tech-id="${parentId}"]`);
  if (!card) return;
  const rulesCount = currentRulesByParent[parentId] || 0;
  const mitigationCount = getCheckedMitigationCountForParent(parentId);
  const score = computeScore(rulesCount, mitigationCount);
  card.style.backgroundColor = scoreToColor(score);
  card.classList.toggle('covered', (rulesCount > 0 || mitigationCount > 0));
  card.style.borderColor = (rulesCount > 0 || mitigationCount > 0) ? '#fff' : 'var(--card-border)';

  const badge = card.querySelector('.mitigation-badge');
  if (mitigationCount > 0) {
    if (badge) {
      badge.textContent = `OK${mitigationCount}`;
    } else {
      const newBadge = document.createElement('div');
      newBadge.className = 'mitigation-badge';
      newBadge.textContent = `OK${mitigationCount}`;
      card.appendChild(newBadge);
    }
  } else if (badge) {
    badge.remove();
  }
}

function updateSubtechCard(techId) {
  const card = document.querySelector(`.subtech-card[data-tech-id="${techId}"]`);
  if (!card) return;
  const rulesCount = enrichRules().filter(r => r.tid === techId).length;
  const mitigationCount = getCheckedMitigationCountForTech(techId);
  const score = computeScore(rulesCount, mitigationCount);
  card.style.backgroundColor = scoreToColor(score);
  card.classList.toggle('covered', (rulesCount > 0 || mitigationCount > 0));
  const badge = card.querySelector('.mitigation-badge');
  if (mitigationCount > 0) {
    if (badge) {
      badge.textContent = `OK${mitigationCount}`;
    } else {
      const newBadge = document.createElement('div');
      newBadge.className = 'mitigation-badge';
      newBadge.textContent = `OK${mitigationCount}`;
      card.appendChild(newBadge);
    }
  } else if (badge) {
    badge.remove();
  }
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
    applyTechniqueVisuals(subCard, rulesForSub.length, mitigationCount, sources);

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
  if (!val) return { ok: false, message: 'Teknik alanÄ± boÅŸ.' };
  const isId = /^T\d{4}(\.\d{3})?$/i.test(val);
  if (isId) {
    const tid = val.toUpperCase();
    if (!techDetailsMap[tid]) return { ok: false, message: 'Teknik ID bulunamadÄ±.' };
    return { ok: true, tid };
  }
  const lookup = nameToIdMap[val.toLowerCase()];
  if (!lookup) return { ok: false, message: 'Teknik adÄ± bulunamadÄ±.' };
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
    alert(err.error || 'Kural eklenemedi');
    return;
  }

  const created = await res.json();
  userRules.push(created);
  renderRulesList();
  renderMatrix();
  alert('Kural eklendi');
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
    alert('LÃ¼tfen alanlarÄ± doldurun.');
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
  document.getElementById('modalTitle').innerText = `${parentId} - ${parentName}`;
  const body = document.getElementById('modalBody');
  const colorMap = productColorMap();
  body.innerHTML = '';
  pendingMitigationEdits = {};
  await reloadMitigationEntries();

  const tabBar = document.createElement('div');
  tabBar.className = 'modal-tabs';
  tabBar.innerHTML = `
    <button class="tab-btn active" data-tab="mitigationsTab">Mitigations</button>
    <button class="tab-btn" data-tab="rulesTab">Kurallar</button>
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
  ruleSearchWrap.innerHTML = `<label>Rule Search</label><input type="text" id="ruleSearchInput" placeholder="Kural adÄ± ara" />`;
  rulesTab.appendChild(ruleSearchWrap);

  const modalRuleAdd = document.createElement('div');
  modalRuleAdd.className = 'modal-rule-add';
  const tacticHint = getTacticForTech(parentId);
  modalRuleAdd.innerHTML = `
    <div class="modal-rule-title">Kural Ekle</div>
    <div class="modal-rule-row">
      <input type="text" id="modalRuleName" placeholder="Kural adÄ±" />
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
    emptyMit.textContent = 'Bu teknik iÃ§in Mitigation bulunamadÄ±.';
    mitigationSection.appendChild(emptyMit);
  } else {
    mitigations.forEach(m => {
      const note = getMitigationNote(m.id);
      const row = document.createElement('div');
      row.className = 'mitigation-row';
      if (note.checked) row.classList.add('checked');
      row.innerHTML = `
        <label class="mitigation-name">
          <input type="checkbox" data-tech="${parentId}" data-mit="${m.id}" ${note.checked ? 'checked' : ''} ${hasRole('editor') ? '' : 'disabled'}>
          ${m.id} - ${m.name}
          <span class="mitigation-info" data-tech="${parentId}" data-mit="${m.id}">i</span>
        </label>
        <div class="mitigation-fields">
          <div class="mitigation-entries" data-mit="${m.id}"></div>
          <div class="mitigation-entry-form ${hasRole('editor') ? '' : 'hidden'}">
            <input class="mitigation-entry-team" data-mit="${m.id}" placeholder="Ekip">
            <textarea class="mitigation-entry-comment" data-mit="${m.id}" placeholder="Yorum"></textarea>
            <button class="action-btn btn-add mitigation-entry-add" data-mit="${m.id}">Ekle</button>
          </div>
          <div class="mitigation-pop" data-tech="${parentId}" data-mit="${m.id}">
            <div class="mitigation-meta">KÄ±sa aÃ§Ä±klama</div>
            <div class="mitigation-summary">${summarizeText(m.description || 'AÃ§Ä±klama bulunamadÄ±.')}</div>
            <div class="mitigation-full">${m.description || 'AÃ§Ä±klama bulunamadÄ±.'}</div>
            <button class="mitigation-more">Detay</button>
          </div>
        </div>
      `;
      renderMitigationEntries(row, m.id);
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
    empty.textContent = 'KayÄ±t yok.';
    mitigationSummary.appendChild(empty);
  } else {
    mitList.forEach(m => {
      const entries = mitigationEntries[m.id] || [];
      const block = document.createElement('div');
      block.className = 'mitigation-summary-row';
      const entriesHtml = entries.length
        ? entries.map(e => `<div class="mitigation-entry-line"><span>${e.team}</span> ${e.comment}</div>`).join('')
        : '<div class="mitigation-empty">KayÄ±t yok.</div>';
      block.innerHTML = `<div class="mitigation-summary-name">${m.id} - ${m.name}</div>${entriesHtml}`;
      mitigationSummary.appendChild(block);
    });
  }
  rulesTab.appendChild(mitigationSummary);

  mitigationsTab.querySelectorAll('.mitigation-row input[type="checkbox"]').forEach(cb => {
    cb.addEventListener('change', async (e) => {
      if (!hasRole('editor')) return;
      const mitId = e.target.dataset.mit;
      const note = getMitigationNote(mitId);
      note.checked = e.target.checked;
      const row = e.target.closest('.mitigation-row');
      if (row) row.classList.toggle('checked', e.target.checked);
      pendingMitigationEdits[mitId] = { ...note };
      refreshTechniqueCardsForMitigation(mitId);
    });
  });
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
      e.currentTarget.textContent = isOpen ? 'KÄ±sa' : 'Detay';
    });
  });

  const btnModalAdd = document.getElementById('btnModalAddRule');
  if (btnModalAdd) {
    btnModalAdd.addEventListener('click', async () => {
      const name = (document.getElementById('modalRuleName').value || '').trim();
      const source = (document.getElementById('modalRuleSource').value || '').trim();
      if (!name || !source) {
        alert('LÃ¼tfen alanlarÄ± doldurun.');
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

  if (hasRole('editor')) {
    const confirmWrap = document.createElement('div');
    confirmWrap.className = 'mitigation-confirm';
    confirmWrap.innerHTML = `<button class="action-btn btn-add" id="btnMitigationConfirm">Onayla</button>`;
    mitigationsTab.appendChild(confirmWrap);
  }

  const confirmBtn = document.getElementById('btnMitigationConfirm');
  if (confirmBtn) {
    confirmBtn.addEventListener('click', async () => {
      const pending = { ...pendingMitigationEdits };
      for (const mitId of Object.keys(pending)) {
        const note = pending[mitId];
        await saveMitigationNote(mitId, note);
      }
      // refresh in-memory notes
      Object.keys(pending).forEach(mid => {
        mitigationNotes[mid] = { ...mitigationNotes[mid], ...pending[mid] };
      });
      pendingMitigationEdits = {};
      renderMatrix();
      document.getElementById('ruleModal').style.display = 'none';
      alert('Kaydedildi');
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
    alert(err.error || 'Mitigation kaydÄ± eklenemedi');
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
    list.innerHTML = '<div class="mitigation-empty">KayÄ±t yok.</div>';
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
    alert('ÃœrÃ¼n adÄ± ve renk gerekli.');
    return;
  }
  const res = await apiFetch('/api/products', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ name, color })
  });
  if (!res.ok) {
    const err = await res.json().catch(() => ({}));
    alert(err.error || 'ÃœrÃ¼n eklenemedi');
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
    result.textContent = 'LÃ¼tfen bir CSV dosyasÄ± seÃ§in.';
    return;
  }
  const form = new FormData();
  form.append('file', fileInput.files[0]);
  const res = await apiFetch('/api/rules/bulk', { method: 'POST', body: form });
  const payload = await res.json().catch(() => ({}));
  if (!res.ok) {
    result.textContent = payload.error || 'YÃ¼kleme baÅŸarÄ±sÄ±z.';
    return;
  }
  await reloadData();
  renderMatrix();
  const errors = (payload.errors || []).slice(0, 10).join(' | ');
  result.textContent = `YÃ¼klendi: ${payload.inserted}. Hata: ${payload.errors.length}` + (errors ? ` (${errors})` : '');
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
      setFieldError(techInput, 'Teknik alanÄ± boÅŸ.');
      return;
    }
    const isId = /^T\d{4}(\.\d{3})?$/i.test(val);
    if (isId) {
      const tid = val.toUpperCase();
      if (!techDetailsMap[tid]) {
        setFieldError(techInput, 'Teknik ID bulunamadÄ±.');
      } else {
        setFieldError(techInput, '');
      }
      return;
    }
    const lookup = nameToIdMap[val.toLowerCase()];
    if (!lookup) {
      setFieldError(techInput, 'Teknik adÄ± bulunamadÄ±.');
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
  const addBtn = document.getElementById('btnAdd');
  if (addBtn) addBtn.addEventListener('click', addNewRule);
  document.getElementById('modalClose').addEventListener('click', () => {
    document.getElementById('ruleModal').style.display = 'none';
  });

  const resetBtn = document.getElementById('btnReset');
  if (resetBtn) {
    resetBtn.addEventListener('click', async () => {
      const confirmText = prompt('Ä°ÅŸlemi onaylamak iÃ§in RESET yazÄ±n:');
      if (confirmText !== 'RESET') return;
      const res = await apiFetch('/api/admin/reset', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ confirm: 'RESET', reseed: true })
      });
      if (!res.ok) {
        const err = await res.json().catch(() => ({}));
        alert(err.error || 'SÄ±fÄ±rlama baÅŸarÄ±sÄ±z');
        return;
      }
      await reloadData();
      renderMatrix();
      alert('Veriler sÄ±fÄ±rlandÄ± ve yeniden yÃ¼klendi.');
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
      const parentMitCount = getCheckedMitigationCountForParent(tech.id);
      const parentSources = parentRules.map(r => r.source);
      visibleExportRows.push({
        type: "technique",
        tech_id: tech.id,
        name: tech.name,
        tactic: tactic,
        rule_count: parentRuleCount,
        mitigation_checked: parentMitCount,
        products: Array.from(new Set(parentSources)),
        score: computeScore(parentRuleCount, parentMitCount)
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
          score: computeScore(subRuleCount, subMitCount)
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

      const mitigationCount = getCheckedMitigationCountForParent(tech.id);
      const sources = rulesForCell.map(r => r.source);
      applyTechniqueVisuals(card, rulesForCell.length, mitigationCount, sources);

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
      card.onclick = () => {
        if (subContainer) subContainer.classList.toggle('open');
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
        <div class="empty-title">SonuÃ§ bulunamadÄ±</div>
        <div class="empty-sub">Arama veya Ã¼rÃ¼n filtrelerini temizleyip tekrar deneyin.</div>
      </div>
    `;
  }
}

