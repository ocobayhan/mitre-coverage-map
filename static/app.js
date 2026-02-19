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
let products = [];
let filterSearch = '';
let filterProducts = new Set();
let filterAllProducts = true;
let visibleExportRows = [];

async function init() {
  wireActions();
  try {
    const [mitreRes, productsRes, rulesRes, notesRes] = await Promise.all([
      fetch('/api/mitre-min'),
      fetch('/api/products'),
      fetch('/api/rules'),
      fetch('/api/mitigation-notes')
    ]);

    if (!mitreRes.ok) throw new Error('MITRE verisi yüklenemedi');
    mitreObjects = (await mitreRes.json()).objects || [];
    products = productsRes.ok ? await productsRes.json() : [];
    userRules = rulesRes.ok ? await rulesRes.json() : [];
    const notes = notesRes.ok ? await notesRes.json() : [];
    mitigationNotes = normalizeNotes(notes);

    prepareMitreLookup();
    await loadProducts();
    populateTacticSelect();
    renderMatrix();
  } catch (e) {
    document.getElementById('matrix').innerHTML = `Veri Hatası: ${e.message}`;
  }
}
async function reloadData() {
  const [productsRes, rulesRes, notesRes] = await Promise.all([
    fetch('/api/products'),
    fetch('/api/rules'),
    fetch('/api/mitigation-notes')
  ]);
  products = productsRes.ok ? await productsRes.json() : [];
  userRules = rulesRes.ok ? await rulesRes.json() : [];
  const notes = notesRes.ok ? await notesRes.json() : [];
  mitigationNotes = normalizeNotes(notes);
  renderLegend();
  renderProductLegend();
  populateSourceSelect();
  renderProductsList();
}

function normalizeNotes(list) {
  const out = {};
  list.forEach(n => {
    if (!out[n.technique_id]) out[n.technique_id] = {};
    out[n.technique_id][n.mitigation_id] = {
      checked: !!n.checked,
      comment: n.comment || '',
      team: n.team || ''
    };
  });
  return out;
}

function prepareMitreLookup() {
  tacticOrder.forEach(t => matrixStructure[t] = []);
  subTechsByParent = {};
  attackIdToTid = {};
  mitigationById = {};
  mitigationsByTechnique = {};
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
      await fetch(`/api/products/${id}`, {
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
      await fetch(`/api/products/${id}`, { method: 'DELETE' });
      await loadProducts();
      renderMatrix();
    });
  });
}

async function loadProducts() {
  const res = await fetch('/api/products');
  products = res.ok ? await res.json() : [];
  renderLegend();
  renderProductLegend();
  populateSourceSelect();
  renderProductsList();
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
  return userRules.map((r) => {
    if (r.tech === 'None') return null;
    const searchKey = (r.tech || '').toLowerCase().trim();
    let tid = nameToIdMap[searchKey];
    if (!tid && /^t\d{4}/.test(searchKey)) tid = r.tech.toUpperCase();
    if (!tid) return null;
    const details = techDetailsMap[tid];
    const parentId = details ? details.parentId : tid.split('.')[0];
    return { ...r, tid: tid, parentId: parentId, isSub: details ? details.isSub : tid.includes('.') };
  }).filter(Boolean);
}

function getMitigationNote(techId, mitigationId) {
  if (!mitigationNotes[techId]) mitigationNotes[techId] = {};
  if (!mitigationNotes[techId][mitigationId]) {
    mitigationNotes[techId][mitigationId] = { checked: false, comment: '', team: '' };
  }
  return mitigationNotes[techId][mitigationId];
}

function getCheckedMitigationCountForTech(techId) {
  const notes = mitigationNotes[techId];
  if (!notes) return 0;
  return Object.values(notes).filter(n => n.checked).length;
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

function buildSubtechContainer(parentId, enrichedData, allowedSubs) {
  const container = document.createElement('div');
  container.className = 'subtech-container';
  const subTechs = allowedSubs || (subTechsByParent[parentId] || []);
  if (subTechs.length == 0) return container;

  subTechs.forEach(st => {
    const subCard = document.createElement('div');
    subCard.className = 'subtech-card';

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
  if (!val) return { ok: false, message: 'Teknik alanı boş.' };
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
  const validation = validateTechniqueInput(tech);
  if (!validation.ok) {
    alert(validation.message);
    return;
  }
  const tid = validation.tid;
  const finalTactic = (tactic && tactic !== 'Unknown') ? tactic : getTacticForTech(tid);

  const res = await fetch('/api/rules', {
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
    alert('Lütfen alanları doldurun.');
    return;
  }
  await addRuleDirect(name, tactic, tech, source);
}

async function deleteRule(ruleId) {
  const res = await fetch(`/api/rules/${ruleId}`, { method: 'DELETE' });
  if (!res.ok) return;
  userRules = userRules.filter(r => r.id !== ruleId);
  renderMatrix();
  document.getElementById('ruleModal').style.display = 'none';
}

function openModal(parentId, parentName, rules) {
  document.getElementById('modalTitle').innerText = `${parentId} - ${parentName}`;
  const body = document.getElementById('modalBody');
  const colorMap = productColorMap();
  body.innerHTML = '';
  pendingMitigationEdits[parentId] = { ...(mitigationNotes[parentId] || {}) };

  const ruleSearchWrap = document.createElement('div');
  ruleSearchWrap.className = 'rule-search';
  ruleSearchWrap.innerHTML = `<label>Rule Search</label><input type="text" id="ruleSearchInput" placeholder="Kural adı ara" />`;
  body.appendChild(ruleSearchWrap);

  const modalRuleAdd = document.createElement('div');
  modalRuleAdd.className = 'modal-rule-add';
  const tacticHint = getTacticForTech(parentId);
  modalRuleAdd.innerHTML = `
    <div class="modal-rule-title">Kural Ekle</div>
    <div class="modal-rule-row">
      <input type="text" id="modalRuleName" placeholder="Kural adı" />
      <select id="modalRuleSource"></select>
      <button class="action-btn btn-add" id="btnModalAddRule">Ekle</button>
    </div>
    <div class="modal-rule-hint">Taktik: ${tacticHint} | Teknik: ${parentId}</div>
  `;
  body.appendChild(modalRuleAdd);
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
      const note = getMitigationNote(parentId, m.id);
      const row = document.createElement('div');
      row.className = 'mitigation-row';
      if (note.checked) row.classList.add('checked');
      row.innerHTML = `
        <label class="mitigation-name">
          <input type="checkbox" data-tech="${parentId}" data-mit="${m.id}" ${note.checked ? 'checked' : ''}>
          ${m.id} - ${m.name}
          <span class="mitigation-info" data-tech="${parentId}" data-mit="${m.id}">i</span>
        </label>
        <div class="mitigation-fields">
          <input class="mitigation-team" data-tech="${parentId}" data-mit="${m.id}" placeholder="Ekip" value="${note.team || ''}">
          <textarea class="mitigation-comment" data-tech="${parentId}" data-mit="${m.id}" placeholder="Yorum">${note.comment || ''}</textarea>
          <div class="mitigation-pop" data-tech="${parentId}" data-mit="${m.id}">
            <div class="mitigation-meta">Kısa açıklama</div>
            <div class="mitigation-summary">${summarizeText(m.description || 'Açıklama bulunamadı.')}</div>
            <div class="mitigation-full">${m.description || 'Açıklama bulunamadı.'}</div>
            <button class="mitigation-more">Detay</button>
          </div>
        </div>
      `;
      mitigationSection.appendChild(row);
    });
  }

  body.appendChild(mitigationSection);

  const grouped = {};
  grouped['Direct'] = rules.filter(r => !r.isSub);
  rules.filter(r => r.isSub).forEach(r => { if (!grouped[r.tid]) grouped[r.tid] = []; grouped[r.tid].push(r); });

  Object.keys(grouped).forEach(key => {
    const groupRules = grouped[key];
    if (groupRules.length == 0) return;
    const headerTitle = (key == 'Direct') ? 'Doğrudan Eşleşmeler' : `${key} - ${techDetailsMap[key]?.name || 'Unknown'}`;
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
          <button class="delete-btn" onclick="deleteRule(${r.id})">Sil</button>
        </td>
      </tr>`;
    });
    tbody += '</tbody>';
    table.innerHTML = tbody;

    groupDiv.appendChild(table);
    body.appendChild(groupDiv);
  });

  body.querySelectorAll('.mitigation-row input[type="checkbox"]').forEach(cb => {
    cb.addEventListener('change', async (e) => {
      const techId = e.target.dataset.tech;
      const mitId = e.target.dataset.mit;
      const note = getMitigationNote(techId, mitId);
      note.checked = e.target.checked;
      const row = e.target.closest('.mitigation-row');
      if (row) row.classList.toggle('checked', e.target.checked);
      updateTechniqueCard(techId);
      pendingMitigationEdits[techId] = pendingMitigationEdits[techId] || {};
      pendingMitigationEdits[techId][mitId] = { ...note };
      updateTechniqueCard(techId);
    });
  });
  body.querySelectorAll('.mitigation-team').forEach(inp => {
    inp.addEventListener('input', (e) => {
      const techId = e.target.dataset.tech;
      const mitId = e.target.dataset.mit;
      const note = getMitigationNote(techId, mitId);
      note.team = e.target.value;
      pendingMitigationEdits[techId] = pendingMitigationEdits[techId] || {};
      pendingMitigationEdits[techId][mitId] = { ...note };
    });
  });

  body.querySelectorAll('.mitigation-row textarea').forEach(ta => {
    ta.addEventListener('input', (e) => {
      const techId = e.target.dataset.tech;
      const mitId = e.target.dataset.mit;
      const note = getMitigationNote(techId, mitId);
      note.comment = e.target.value;
      pendingMitigationEdits[techId] = pendingMitigationEdits[techId] || {};
      pendingMitigationEdits[techId][mitId] = { ...note };
    });
  });
  body.querySelectorAll('.mitigation-info').forEach(btn => {
    btn.addEventListener('click', (e) => {
      const row = e.currentTarget.closest('.mitigation-row');
      if (!row) return;
      const pop = row.querySelector('.mitigation-pop');
      if (!pop) return;
      const isOpen = pop.classList.contains('open');
      body.querySelectorAll('.mitigation-pop.open').forEach(p => p.classList.remove('open'));
      if (!isOpen) pop.classList.add('open');
    });
  });
  body.querySelectorAll('.mitigation-more').forEach(btn => {
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
      body.querySelectorAll('tr[data-rule-name]').forEach(tr => {
        const name = tr.getAttribute('data-rule-name') || '';
        tr.style.display = name.includes(term) ? '' : 'none';
      });
    });
  }

  const confirmWrap = document.createElement('div');
  confirmWrap.className = 'mitigation-confirm';
  confirmWrap.innerHTML = `<button class="action-btn btn-add" id="btnMitigationConfirm">Onayla</button>`;
  body.appendChild(confirmWrap);

  const confirmBtn = document.getElementById('btnMitigationConfirm');
  if (confirmBtn) {
    confirmBtn.addEventListener('click', async () => {
      const pending = pendingMitigationEdits[parentId] || {};
      for (const mitId of Object.keys(pending)) {
        const note = pending[mitId];
        await saveMitigationNote(parentId, mitId, note);
      }
      // refresh in-memory notes
      mitigationNotes[parentId] = { ...(mitigationNotes[parentId] || {}), ...pending };
      pendingMitigationEdits[parentId] = {};
      updateTechniqueCard(parentId);
      document.getElementById('ruleModal').style.display = 'none';
      alert('Kaydedildi');
    });
  }

  document.getElementById('ruleModal').style.display = 'flex';
}


async function saveMitigationNote(techId, mitId, note) {
  await fetch('/api/mitigation-notes', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      technique_id: techId,
      mitigation_id: mitId,
      checked: !!note.checked,
      comment: note.comment || '',
      team: note.team || ''
    })
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
  const name = document.getElementById('productName').value.trim();
  const color = document.getElementById('productColor').value.trim();
  if (!name || !color) {
    alert('Ürün adı ve renk gerekli.');
    return;
  }
  const res = await fetch('/api/products', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ name, color })
  });
  if (!res.ok) {
    const err = await res.json().catch(() => ({}));
    alert(err.error || 'Ürün eklenemedi');
    return;
  }
  document.getElementById('productName').value = '';
  await loadProducts();
  renderMatrix();
}

async function uploadCsv() {
  const fileInput = document.getElementById('csvFile');
  const result = document.getElementById('uploadResult');
  result.textContent = '';
  if (!fileInput.files || fileInput.files.length === 0) {
    result.textContent = 'Lütfen bir CSV dosyası seçin.';
    return;
  }
  const form = new FormData();
  form.append('file', fileInput.files[0]);
  const res = await fetch('/api/rules/bulk', { method: 'POST', body: form });
  const payload = await res.json().catch(() => ({}));
  if (!res.ok) {
    result.textContent = payload.error || 'Yükleme başarısız.';
    return;
  }
  await reloadData();
  renderMatrix();
  const errors = (payload.errors || []).slice(0, 10).join(' | ');
  result.textContent = `Yüklendi: ${payload.inserted}. Hata: ${payload.errors.length}` + (errors ? ` (${errors})` : '');
}

function wireSettings() {
  const addBtn = document.getElementById('btnAddProduct');
  if (addBtn) addBtn.addEventListener('click', addProduct);
  const uploadBtn = document.getElementById('btnUploadCsv');
  if (uploadBtn) uploadBtn.addEventListener('click', uploadCsv);
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
      setFieldError(techInput, 'Teknik alanı boş.');
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
  const addBtn = document.getElementById('btnAdd');
  if (addBtn) addBtn.addEventListener('click', addNewRule);
  document.getElementById('modalClose').addEventListener('click', () => {
    document.getElementById('ruleModal').style.display = 'none';
  });

  const resetBtn = document.getElementById('btnReset');
  if (resetBtn) {
    resetBtn.addEventListener('click', async () => {
      const confirmText = prompt('İşlemi onaylamak için RESET yazın:');
      if (confirmText !== 'RESET') return;
      const res = await fetch('/api/admin/reset', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ confirm: 'RESET', reseed: true })
      });
      if (!res.ok) {
        const err = await res.json().catch(() => ({}));
        alert(err.error || 'Sıfırlama başarısız');
        return;
      }
      await reloadData();
      renderMatrix();
      alert('Veriler sıfırlandı ve yeniden yüklendi.');
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
        <div class="empty-title">Sonuç bulunamadı</div>
        <div class="empty-sub">Arama veya ürün filtrelerini temizleyip tekrar deneyin.</div>
      </div>
    `;
  }
}
