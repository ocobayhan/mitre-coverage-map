// ATT&CK v19: eski "Defense Evasion" (TA0005) ikiye ayrildi — TA0005 artik
// "Stealth", yeni TA0112 "Defense Impairment" oldu. Sira MITRE'nin resmi
// matrisiyle ayni (Stealth once, Defense Impairment sonra).
const tacticMap = { "reconnaissance": "Reconnaissance", "resource-development": "Resource Development", "initial-access": "Initial Access", "execution": "Execution", "persistence": "Persistence", "privilege-escalation": "Privilege Escalation", "stealth": "Stealth", "defense-impairment": "Defense Impairment", "credential-access": "Credential Access", "discovery": "Discovery", "lateral-movement": "Lateral Movement", "collection": "Collection", "command-and-control": "Command and Control", "exfiltration": "Exfiltration", "impact": "Impact" };
const tacticOrder = Object.values(tacticMap);

// Bir teknik için "yeterli kapsama" sayılacak tespit sayısı — tüm teknikler
// bununla başlar, admin teknik bazında değiştirir. app.py ile aynı olmalı.
const DEFAULT_RULE_THRESHOLD = 2;

// Ürün seviyesi toplu iddia (origin='product_claim') hücre skoruna indirimli
// ağırlıkla katkı yapar — adı olan tespiti olmayan bir teknik artık yalnızca
// toplu iddiayla %100 gösteremez. Kullanıcı kararı (2026-07-29). app.py
// PRODUCT_CLAIM_SCORE_WEIGHT ile aynı olmalı.
const PRODUCT_CLAIM_SCORE_WEIGHT = 0.75;

// Özet "Ort. Skor" artık eşik-ağırlıklı ortalama; alt teknikler bu çarpanla
// dahil olur. Kullanıcı kararı (2026-07-29). app.py SUBTECHNIQUE_AVG_WEIGHT
// ile aynı olmalı.
const SUBTECHNIQUE_AVG_WEIGHT = 0.3;

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
// Kurallar sayfası filtre state'i — renderRulesList() her re-render'da bu değerleri
// kullanır; seçim re-render sonrasında da korunur (input value / select selected).
let rulesFilterSearch = '';
let rulesFilterProduct = '';
let rulesOpenGroups = null; // null = tümü açık (başlangıç), Set = kullanıcı toggle sonrası
let rulesSelectedIds = new Set(); // toplu teknik ekleme icin secili tespit id'leri

const COV_LABEL = { low: 'Düşük', half: 'Yarım', good: 'İyi', full: 'Tam' };
// Ürün kategorileri — yalnızca tespit kaynakları haritayı boyar ve ürün
// çeşitliliği bileşenine sayılır (bkz. app.py PRODUCT_CATEGORIES).
const PRODUCT_CATEGORY_LABELS = {
  tespit_kaynagi: 'Tespit kaynağı',
  onleyici_kontrol: 'Önleyici kontrol',
  zenginlestirme: 'Zenginleştirme',
};
// Teknik bazlı puanlama konfigürasyonu — /api/technique-config'den yüklenir.
// { "T1059": { rule_threshold, group_count, tool_count, source }, ... }
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

  // Ayarlar bölümü her zaman gorunur: viewer da dahil herkes kendi parolasini
  // "Hesabim" sekmesinden degistirebilmeli. Alt sekmeler (CSV, Kullanicilar,
  // Ekipler, Connector'lar) kendi rol kontrollerini asagida ayrica uyguluyor.
  const settingsNav = document.querySelector('.nav-item[data-section="settings"]');
  if (settingsNav) settingsNav.classList.remove('hidden');

  // Viewer yalnizca Harita'yi gorsun — Envanter ve Bosluklar navigasyondan
  // tamamen gizlenir (kullanici karari, 2026-08-15). API'ler hala viewer'a
  // acik (read-only), bu salt gezinme/gorunurluk kisitlamasi.
  const viewerOnlyMap = !hasRole('editor');
  document.querySelector('.nav-item[data-section="inventory"]')
    ?.classList.toggle('hidden', viewerOnlyMap);
  document.querySelector('.nav-item[data-section="gaps"]')
    ?.classList.toggle('hidden', viewerOnlyMap);
  // Eger viewer su an gizlenen bir bolumdeyse (orn. baska rolden dusurulme
  // sonrasi sayfa yenilenmeden), Harita'ya geri don.
  if (viewerOnlyMap && (activeSection === 'inventory' || activeSection === 'gaps')) {
    showPanel('matrixPanel');
  }

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

  const importFileInput = document.getElementById('importFile');
  if (importFileInput) importFileInput.disabled = !hasRole('editor');

  // Ayarlar sekmelerini role göre gizle:
  //   CSV Yükleme → editor veya üstü
  //   Kullanıcılar / Ekipler / Connector'lar → sadece admin
  document.getElementById('settingsCsvTab')?.classList.toggle('hidden', !hasRole('editor'));
  document.getElementById('settingsUsersTab')?.classList.toggle('hidden', !hasRole('admin'));
  document.getElementById('settingsTeamsTab')?.classList.toggle('hidden', !hasRole('admin'));
  document.getElementById('settingsConnectorsTab')?.classList.toggle('hidden', !hasRole('admin'));
  // Audit artık Ayarlar bölümünün alt sekmesi; görünürlüğü SECTIONS[].role
  // üzerinden visibleTabs() ile yönetiliyor, burada ayrıca gizlenmiyor.
  renderSectionTabs();
  document.getElementById('dataQualityRepair')?.classList.toggle('hidden', !hasRole('admin'));
}

async function init() {
  wireActions();
  renderScoreLegend();
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

    const [mitreRes, productsRes, rulesRes, entriesRes, configRes, teamsRes, scopeRes] = await Promise.all([
      apiFetch('/api/mitre-min'),
      apiFetch('/api/products'),
      apiFetch('/api/rules'),
      apiFetch('/api/mitigation-entries'),
      apiFetch('/api/technique-config'),
      apiFetch('/api/teams'),
      // Matris ortam seçicisi için gerekli; Kapsam Envanteri paneli
      // açılmadan da harita ortam filtresi çalışabilsin diye başta yüklenir.
      apiFetch('/api/scope-registry')
    ]);

    if (!mitreRes.ok) throw new Error('MITRE verisi yüklenemedi');
    mitreObjects = (await mitreRes.json()).objects || [];
    products = productsRes.ok ? await productsRes.json() : [];
    userRules = rulesRes.ok ? await rulesRes.json() : [];
    const entries = entriesRes.ok ? await entriesRes.json() : [];
    mitigationEntries = normalizeEntries(entries);
    techniqueConfig = configRes.ok ? await configRes.json() : {};
    teams = teamsRes.ok ? await teamsRes.json() : [];
    if (scopeRes.ok) scopeRegistry = await scopeRes.json();

    prepareMitreLookup();
    await loadProducts();
    populateTacticSelect();
    renderMatrixScopeSelect();
    renderMitigationList();
    renderRulesList();
    renderMatrix();
  } catch (e) {
    document.getElementById('matrix').innerHTML = `Veri Hatası: ${e.message}`;
  }
}
async function reloadData() {
  const [productsRes, rulesRes, entriesRes, teamsRes] = await Promise.all([
    apiFetch('/api/products'),
    apiFetch('/api/rules'),
    apiFetch('/api/mitigation-entries'),
    apiFetch('/api/teams')
  ]);
  products = productsRes.ok ? await productsRes.json() : [];
  userRules = rulesRes.ok ? await rulesRes.json() : [];
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

function normalizeEntries(list) {
  const out = {};
  list.forEach(e => {
    if (!out[e.mitigation_id]) out[e.mitigation_id] = [];
    out[e.mitigation_id].push(e);
  });
  return out;
}

function buildTeamSelectEl(mitId) {
  const sel = document.createElement('select');
  sel.className = 'mitigation-entry-team';
  sel.dataset.mit = mitId;
  sel.innerHTML = `<option value="">— Ekip —</option>` +
    teams.map(t => `<option value="${_esc(t.name)}">${_esc(t.name)}</option>`).join('');
  return sel;
}

// Mitigation'i hangi urunle sagliyoruz. Bos birakilabilir: surec, egitim veya
// politika ile saglanan mitigation'lar var; zorunlu tutmak uydurma urun
// secilmesine yol acardi.
function buildProductSelectEl(mitId) {
  const sel = document.createElement('select');
  sel.className = 'mitigation-entry-product';
  sel.dataset.mit = mitId;
  sel.innerHTML = `<option value="">— Ürün yok / süreç —</option>` +
    products.map(p => `<option value="${p.id}">${_esc(p.name)}</option>`).join('');
  return sel;
}

/** Tek bir mitigation kaydinin satiri — panel ve modal ayni gosterimi kullanir. */
function mitigationEntryHtml(e, extraDataAttr = '') {
  const product = e.product_name
    ? `<span class="entry-product" style="border-color:${_esc(productColorMap()[e.product_name] || 'var(--d-border)')}">${_esc(e.product_name)}</span>`
    : '';
  return `
    <div class="mitigation-entry">
      <div class="entry-head">
        <span class="entry-team">${_esc(e.team)}</span>
        ${product}
      </div>
      <div class="entry-comment">${_esc(e.comment)}</div>
      ${hasRole('editor')
        ? `<button class="entry-delete" data-entry-id="${e.id}"${extraDataAttr} title="Kaydı sil">×</button>`
        : ''}
    </div>`;
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
    const chips = techLabels.map(t => `<button class="tech-chip" type="button" data-tech-label="${_esc(t.label)}">${_esc(techDetailsMap[t.id]?.name || t.id)}</button>`).join('');
    const moreBtn = extra > 0 ? `<button class="tech-more" data-mit="${m.id}">Tümünü Göster</button>` : '';
    const entries = mitigationEntries[m.id] || [];
    const desc = m.description || '';
    const entryHtml = entries.length
      ? entries.map(e => mitigationEntryHtml(e, ` data-mit="${m.id}"`)).join('')
      : '<div class="mitigation-empty">Henüz kayıt yok — bu mitigation uygulanmıyor sayılır.</div>';
    // Ekleme formu yalnizca editor+ icin basilir. Onceden viewer da goruyordu;
    // buton backend'de reddedilse bile kullaniciya yanlis vaat veriyordu.
    const formHtml = hasRole('editor') ? `
          <div class="mitigation-entry-form" data-mit="${m.id}">
            <span class="mitigation-entry-team-placeholder" data-mit="${m.id}"></span>
            <span class="mitigation-entry-product-placeholder" data-mit="${m.id}"></span>
            <textarea class="mitigation-entry-comment" data-mit="${m.id}" placeholder="Nasıl sağlanıyor?"></textarea>
            <button class="action-btn btn-add mitigation-entry-add" data-mit="${m.id}">Ekle</button>
          </div>` : '';
    return `
      <div class="mitigation-list-row ${entries.length ? 'has-entries' : ''}">
        <div class="mitigation-list-id mit-popup-btn" data-mit="${m.id}">${_esc(m.id)}</div>
          <div class="mitigation-list-name">
          <button class="mit-name-popup-btn" data-mit="${m.id}">${_esc(m.name)}</button>
          <div class="mitigation-list-desc">${_esc(summarizeText(desc, 90))}</div>
        </div>
        <div class="mitigation-list-tech">
          <div class="tech-chip-row" data-mit="${m.id}">${chips}</div>
          ${moreBtn}
        </div>
        <div class="mitigation-list-entries" data-mit="${m.id}">
          ${entryHtml}
          ${formHtml}
        </div>
      </div>
    `;
  }).join('');
  container.innerHTML = `
    <div class="mitigation-list-header">
      <div>ID</div>
      <div>Mitigation</div>
      <div>Teknikler</div>
      <div>Kim / hangi ürünle sağlıyor</div>
    </div>
    ${rows}
  `;

  container.querySelectorAll('.mitigation-entry-team-placeholder').forEach(ph => {
    ph.replaceWith(buildTeamSelectEl(ph.dataset.mit));
  });
  container.querySelectorAll('.mitigation-entry-product-placeholder').forEach(ph => {
    ph.replaceWith(buildProductSelectEl(ph.dataset.mit));
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
      const productInput = row.querySelector('.mitigation-entry-product');
      const commentInput = row.querySelector('.mitigation-entry-comment');
      const team = (teamInput?.value || '').trim();
      const comment = (commentInput?.value || '').trim();
      const productId = productInput?.value ? Number(productInput.value) : null;
      if (!team || !comment) {
        alert('Ekip ve açıklama gerekli.');
        return;
      }
      const created = await addMitigationEntry(mitId, team, comment, productId);
      if (!created) return;
      await reloadMitigationEntries();
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
// Bir kural su an isim/urun duzenleme modundaysa id'si burada tutulur —
// renderRulesList() her cagrildiginda _ruleRow() bu satiri farkli cizer.
let rulesEditingId = null;

function _ruleRow(r) {
  const level = r.coverage_level || 'full';
  const techs = (r.techniques && r.techniques.length > 0)
    ? r.techniques
    : (r.tech && r.tech !== 'None' ? [r.tech] : []);

  if (hasRole('editor') && rulesEditingId === r.id) {
    const productOptions = products.map(p =>
      `<option value="${_esc(p.name)}" ${p.name === r.source ? 'selected' : ''}>${_esc(p.name)}</option>`
    ).join('');
    return `
      <div class="rule-list-row rule-row-editing" data-rule-id="${r.id}">
        <div class="rl-select"></div>
        <div class="rl-name">
          <input type="text" class="rule-edit-name" data-rule-id="${r.id}" value="${_esc(r.name)}" />
        </div>
        <div class="rl-cov">
          <label class="rule-edit-product-label">Ürün</label>
          <select class="rule-edit-source" data-rule-id="${r.id}">${productOptions}</select>
        </div>
        <div class="rl-techs"></div>
        <div class="rl-actions">
          <button class="action-btn btn-add rule-edit-save" data-rule-id="${r.id}">Kaydet</button>
          <button class="action-btn btn-reset rule-edit-cancel" data-rule-id="${r.id}">İptal</button>
        </div>
      </div>`;
  }

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
        ${hasRole('editor') ? `<button class="action-btn btn-reset rule-edit-btn" data-rule-id="${r.id}" title="Adını veya ürününü değiştir">Düzenle</button>
        <button class="action-btn btn-reset rule-delete" data-rule-id="${r.id}">Sil</button>` : ''}
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
      <div class="bulk-toolbar-row">
        <span class="bulk-count" id="bulkSelectedCount">0 tespit seçili</span>
        <button class="action-btn btn-reset" id="btnBulkSelectVisible">Görünenleri seç</button>
        <button class="action-btn btn-reset" id="btnBulkClearSelection">Seçimi temizle</button>
      </div>
      <div class="bulk-toolbar-row">
        <div class="tech-autocomplete-wrapper" id="bulkTechWrapper">
          <input class="rule-tech-input" type="text" id="bulkTechInput" placeholder="T1059 veya teknik adı" />
          <div class="tech-autocomplete-dropdown hidden"></div>
        </div>
        <button class="action-btn btn-add" id="btnBulkAddTechnique" disabled>Teknik ekle</button>
        <span class="bulk-toolbar-divider"></span>
        <select id="bulkCoverageSelect" disabled>
          <option value="low">Düşük</option>
          <option value="half">Yarım</option>
          <option value="good">İyi</option>
          <option value="full">Tam</option>
        </select>
        <button class="action-btn btn-add" id="btnBulkSetCoverage" disabled>Tespit Gücünü Değiştir</button>
        <span class="bulk-toolbar-divider"></span>
        <button class="action-btn btn-reset bulk-delete-btn" id="btnBulkDelete" disabled>Seçilenleri sil</button>
      </div>
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
            <div>Tespit Gücü</div>
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

  // Tespit gücü slider — tıkla veya sürükle
  container.querySelectorAll('.cov-slider:not(.cov-readonly)').forEach(slider => {
    const rail  = slider.querySelector('.cov-rail');
    const fill  = slider.querySelector('.cov-fill');
    const thumb = slider.querySelector('.cov-thumb');
    const lbl   = slider.querySelector('.cov-lbl');

    function snapLevel(pct) {
      return pct < 0.25 ? 'low' : pct < 0.50 ? 'half' : pct < 0.75 ? 'good' : 'full';
    }
    function levelColor(lvl) {
      return lvl === 'low' ? '#c42b1c' : lvl === 'half' ? '#ca8a04' : lvl === 'good' ? '#65a30d' : '#2d7d32';
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
      if (res.ok && rule) {
        rule.coverage_level = level;
        // Kaydetmek yetmiyor — Matrix'teki kart rengi de yeni kapsam
        // agirligini yansitmali (toplu degistirmedeki ayni desen).
        renderMatrix();
      }
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
        const clr  = levelColor(lvl);
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

  // Tespit adini / urununu duzenleme — Duzenle bir satiri edit moduna alir
  // (rulesEditingId), Kaydet PUT /api/rules/<id> cagirir, Iptal geri alir.
  container.querySelectorAll('.rule-edit-btn').forEach(btn => {
    btn.addEventListener('click', (e) => {
      rulesEditingId = parseInt(e.currentTarget.dataset.ruleId);
      renderRulesList();
    });
  });
  container.querySelectorAll('.rule-edit-cancel').forEach(btn => {
    btn.addEventListener('click', () => {
      rulesEditingId = null;
      renderRulesList();
    });
  });
  container.querySelectorAll('.rule-edit-save').forEach(btn => {
    btn.addEventListener('click', async (e) => {
      const ruleId = parseInt(e.currentTarget.dataset.ruleId);
      const row = e.currentTarget.closest('.rule-list-row');
      const nameInput = row?.querySelector('.rule-edit-name');
      const sourceSelect = row?.querySelector('.rule-edit-source');
      if (!ruleId || !nameInput || !sourceSelect) return;
      const name = nameInput.value.trim();
      const source = sourceSelect.value;
      if (!name) { alert('Tespit adı boş olamaz.'); return; }

      const res = await apiFetch(`/api/rules/${ruleId}`, {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ name, source })
      });
      if (!res.ok) {
        const err = await res.json().catch(() => ({}));
        alert(err.error || 'Kaydetme başarısız.');
        return;
      }
      const rule = userRules.find(r => r.id === ruleId);
      if (rule) { rule.name = name; rule.source = source; }
      rulesEditingId = null;
      renderRulesList();
      renderMatrix();
    });
  });
}

function updateBulkToolbarUI(container) {
  const countEl = container.querySelector('#bulkSelectedCount');
  if (countEl) countEl.textContent = `${rulesSelectedIds.size} tespit seçili`;
  const empty = rulesSelectedIds.size === 0;
  ['#btnBulkAddTechnique', '#btnBulkSetCoverage', '#bulkCoverageSelect', '#btnBulkDelete'].forEach(sel => {
    const el = container.querySelector(sel);
    if (el) el.disabled = empty;
  });
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

  // Toplu kapsam degistirme — tek tek PATCH /api/rules/<id>/coverage,
  // teknik ekleme ile ayni sirali-cagri deseni (yeni bir bulk endpoint gerekmez).
  const setCoverageBtn = container.querySelector('#btnBulkSetCoverage');
  if (setCoverageBtn) {
    setCoverageBtn.addEventListener('click', async () => {
      const select = container.querySelector('#bulkCoverageSelect');
      const result = container.querySelector('#bulkResult');
      if (!select || rulesSelectedIds.size === 0) return;
      const level = select.value;

      setCoverageBtn.disabled = true;
      if (result) { result.textContent = 'Güncelleniyor...'; result.classList.remove('error'); }

      const ruleIds = Array.from(rulesSelectedIds);
      let okCount = 0;
      const failed = [];
      for (const ruleId of ruleIds) {
        const res = await apiFetch(`/api/rules/${ruleId}/coverage`, {
          method: 'PATCH',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ coverage_level: level })
        });
        if (res.ok) {
          okCount += 1;
          const rule = userRules.find(r => r.id === ruleId);
          if (rule) rule.coverage_level = level;
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
          ? `Tespit gücü "${COV_LABEL[level]}" olarak ${okCount} tespitte güncellendi.`
          : `Tespit gücü ${okCount} tespitte güncellendi, ${failed.length} başarısız (${failed.slice(0, 5).join(', ')}${failed.length > 5 ? '…' : ''})`;
        if (failed.length > 0) finalResult.classList.add('error');
      }
    });
  }

  // Toplu silme — geri alinamaz, once onay istenir.
  const bulkDeleteBtn = container.querySelector('#btnBulkDelete');
  if (bulkDeleteBtn) {
    bulkDeleteBtn.addEventListener('click', async () => {
      const result = container.querySelector('#bulkResult');
      const count = rulesSelectedIds.size;
      if (count === 0) return;
      if (!confirm(`${count} tespiti kalıcı olarak silmek istediğinize emin misiniz? Bu işlem geri alınamaz.`)) {
        return;
      }

      bulkDeleteBtn.disabled = true;
      if (result) { result.textContent = 'Siliniyor...'; result.classList.remove('error'); }

      const ruleIds = Array.from(rulesSelectedIds);
      let okCount = 0;
      const failed = [];
      for (const ruleId of ruleIds) {
        const res = await apiFetch(`/api/rules/${ruleId}`, { method: 'DELETE' });
        if (res.ok) {
          okCount += 1;
          userRules = userRules.filter(r => r.id !== ruleId);
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
          ? `${okCount} tespit silindi.`
          : `${okCount} tespit silindi, ${failed.length} başarısız (${failed.slice(0, 5).join(', ')}${failed.length > 5 ? '…' : ''})`;
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
      // Tek tıkla bu ürünü izole et — "QRadar'a basınca QRadar'ın haritasını
      // göreyim" (kullanıcı kararı, 2026-07-29). Zaten yalnızca bu ürün
      // seçiliyse tekrar tıklamak "Tümü"ne döner; başka bir ürüne tıklamak
      // izolasyonu ona kaydırır (eskisi gibi çoklu seçim/dışlama değil).
      if (!filterAllProducts && filterProducts.size === 1 && filterProducts.has(p.name)) {
        filterAllProducts = true;
        filterProducts = new Set();
      } else {
        filterAllProducts = false;
        filterProducts = new Set([p.name]);
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
    const cat = p.category || 'tespit_kaynagi';
    row.innerHTML = `
      <div class="product-info">
        <div class="product-swatch" style="background:${p.color}"></div>
        <div>${p.name}<small class="product-cat-hint">${PRODUCT_CATEGORY_LABELS[cat] || cat}</small></div>
      </div>
      <div class="product-actions">
        <select class="product-category" data-id="${p.id}" title="Yalnızca tespit kaynakları haritayı boyar">
          ${Object.entries(PRODUCT_CATEGORY_LABELS).map(([v, l]) =>
            `<option value="${v}" ${v === cat ? 'selected' : ''}>${l}</option>`).join('')}
        </select>
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
      const catSel = list.querySelector(`.product-category[data-id=\"${id}\"]`);
      const color = picker ? picker.value : null;
      if (!color) return;
      const res = await apiFetch(`/api/products/${id}`, {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ color, category: catSel ? catSel.value : undefined })
      });
      if (!res.ok) {
        const err = await res.json().catch(() => ({}));
        alert(err.error || 'Ürün güncellenemedi');
        return;
      }
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

/** "Teknik Hedefleri" paneli — hangi teknige (ana+alt) kac etkin tespit
 * yeterli sayilir, tek bir liste ekranindan gorup duzenleme. Sadece admin
 * (SECTIONS'ta role:'admin'). Matrix'e hic yansimaz, kullanici karari
 * (2026-08-15): "hangi teknige kac tespit lazim olur... admin gorsun
 * sadece envanter kismina koyariz matriste bulunmasin". Veri zaten
 * techDetailsMap/techniqueConfig'te yukleniyor (init() sirasinda), ayrica
 * bir fetch gerekmez. PUT /api/technique-config/<id> zaten vardi
 * (Faz 4c'de modal'dan kaldirilan admin sekmesinin ayni backend'i). */
function renderTargetsTable() {
  const body = document.getElementById('targetsTableBody');
  const empty = document.getElementById('targetsEmpty');
  if (!body) return;
  const query = (document.getElementById('targetsSearch')?.value || '').trim().toLocaleLowerCase('tr-TR');

  const rows = Object.values(techDetailsMap)
    .map(t => {
      const cfg = techniqueConfig[t.id] || {};
      const tactics = t.isSub ? (techTactics[t.parentId] || []) : (techTactics[t.id] || []);
      return {
        id: t.id, name: t.name, isSub: t.isSub,
        tactics: tactics.join(', '),
        groupCount: cfg.group_count || 0,
        threshold: cfg.rule_threshold ?? DEFAULT_RULE_THRESHOLD,
      };
    })
    .filter(t => !query || `${t.id} ${t.name}`.toLocaleLowerCase('tr-TR').includes(query))
    .sort((a, b) => b.groupCount - a.groupCount || a.id.localeCompare(b.id));

  body.innerHTML = rows.map(t => `
    <tr data-tech-id="${t.id}">
      <td class="${t.isSub ? 'tt-sub-id' : ''}">${_esc(t.id)}</td>
      <td>${_esc(t.name)}</td>
      <td style="color:var(--d-text-3)">${_esc(t.tactics) || '—'}</td>
      <td>${t.groupCount}</td>
      <td><input type="number" class="targets-threshold-input" min="0" max="10" step="1"
                  value="${t.threshold}" data-tech-id="${t.id}" ${hasRole('admin') ? '' : 'disabled'} /></td>
    </tr>`).join('');
  if (empty) empty.style.display = rows.length ? 'none' : 'block';
}

function renderTargetsPanel() {
  renderTargetsTable();
}

async function saveTargetThreshold(input) {
  const techId = input.dataset.techId;
  const value = Math.max(0, Math.min(10, parseInt(input.value, 10) || 0));
  input.value = value;
  input.disabled = true;
  const res = await apiFetch(`/api/technique-config/${techId}`, {
    method: 'PUT',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ rule_threshold: value })
  });
  input.disabled = false;
  if (!res.ok) {
    const err = await res.json().catch(() => ({}));
    alert(err.error || 'Hedef kaydedilemedi.');
    return;
  }
  techniqueConfig[techId] = { ...(techniqueConfig[techId] || {}), rule_threshold: value };
  input.classList.remove('targets-saved-flash');
  void input.offsetWidth;
  input.classList.add('targets-saved-flash');
  // Hedef degisince ilgili teknigin (ve varsa ailesinin) skoru degisir —
  // Matrix'te acikken gorunur kalsin diye yeniden ciziyoruz.
  renderMatrix();
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

// Bir mitigation "isaretli" ise kaydi vardir — ayri bir checked bayragi yok.
function isMitigationChecked(mitigationId) {
  return (mitigationEntries[mitigationId] || []).length > 0;
}

function getCheckedMitigationCountForTech(techId) {
  const mitigations = mitigationsByTechnique[techId] || [];
  return mitigations.filter(m => isMitigationChecked(m.id)).length;
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

// Kapsama skoru: min(etkin tespit sayısı / teknik hedefi, 1).
// Hedef techniqueConfig.rule_threshold'dan gelir (varsayılan DEFAULT_RULE_THRESHOLD).
// product_claim kökenli kurallar indirimli ağırlıkla sayılır (bkz.
// PRODUCT_CLAIM_SCORE_WEIGHT) — adı olan tespiti olmayan bir teknik artık
// yalnızca toplu ürün iddiasıyla tam skor gösteremez.
function ruleCoverageWeight(rule) {
  // DeTT&CT Visibility Score'una (1-4) dayanan 4 kademeli agirlik — bkz.
  // docs/scoring_methodology.md #1. app.py'deki level_weight ile ayni olmali.
  const levelWeight = ({low: 0.25, half: 0.50, good: 0.75, full: 1.00})[rule?.coverage_level || 'full'] ?? 1.00;
  const originWeight = rule?.origin === 'product_claim' ? PRODUCT_CLAIM_SCORE_WEIGHT : 1.00;
  return levelWeight * originWeight;
}

// ─── Ortam boyutu ──────────────────────────────────────────────────────────
// Kurumda her ürün her yerde yok: Defender client'ta var ama Lumos server'da
// yok; QRadar server'lardan log alıyor ama client'lardan almıyor. Dolayısıyla
// bir tespit yalnızca ürünü o ortamı izliyorsa orada kapsama sağlar.
//
//   etkin ağırlık = coverage_level ağırlığı × deployment ağırlığı
//     deployment: full → 1.00, partial → coverage_percent/100, none|unknown → 0

// Seçili ortam. null = "Tüm ortamlar (birleşik)" — teknik kaç ortamda
// kapsanıyor onu gösterir, tek tek ortam gezmek zorunda kalınmasın.
let matrixScopeEnvId = null;

function envDeploymentWeights(env) {
  const map = {};
  for (const dep of env.deployments || []) {
    const status = dep.monitoring_status;
    if (status === 'full') map[dep.product_name] = 1.0;
    else if (status === 'partial') map[dep.product_name] = Math.max(0, Math.min(100, dep.coverage_percent || 0)) / 100;
    // none / unknown → hiç eklenmez (ağırlık 0)
  }
  return map;
}

/** Seçili ortamda ürün adı → izleme ağırlığı haritası (null = filtre yok). */
function scopeWeightMap() {
  if (!matrixScopeEnvId || !scopeRegistry) return null;
  const env = (scopeRegistry.environments || []).find(e => e.id === matrixScopeEnvId);
  return env ? envDeploymentWeights(env) : null;
}

/** Birleşik mod: her aktif ortam için ağırlık haritası. */
function allEnvWeightMaps() {
  return (scopeRegistry?.environments || [])
    .filter(e => e.active)
    .map(e => ({ id: e.id, name: e.name, weights: envDeploymentWeights(e) }));
}

/** Birleşik modda bir teknik kaç ortamda tespit ediliyor. */
function envCoverageRatio(rules) {
  const envs = allEnvWeightMaps();
  if (!envs.length) return null;
  const covered = envs.filter(e => (rules || []).some(r => (e.weights[r.source] ?? 0) > 0)).length;
  return { covered, total: envs.length };
}

/** Haritayı boyayan ürünler — önleyici kontrol ve CTI sayılmaz. */
function detectionSourceNames() {
  return new Set(products.filter(p => (p.category || 'tespit_kaynagi') === 'tespit_kaynagi').map(p => p.name));
}

/** Bir tespitin seçili ortamdaki geçerlilik ağırlığı (0 = orada geçerli değil). */
function scopeWeight(rule, weightMap) {
  if (!weightMap) return 1.0;
  return weightMap[rule?.source] ?? 0;
}

/** Seçili ortamda VE seçili ürün merceğinde gerçekten geçerli olan tespitler.
 * Ürün filtresi artık bir görünürlük kapısı DEĞİL — bir kural o an seçili
 * ürünlerden birine ait değilse buradan elenir, teknik kartı yine görünür
 * ama o ürünün kendi haritasıymış gibi boyanır (kapsamadığı teknikler
 * kapanmaz, sadece dürüstçe boş görünür). Kullanıcı kararı (2026-07-29). */
function rulesInScope(rules, weightMap) {
  let out = rules || [];
  if (weightMap) out = out.filter(r => scopeWeight(r, weightMap) > 0);
  if (!filterAllProducts && filterProducts.size > 0) {
    out = out.filter(r => filterProducts.has(r.source));
  }
  return out;
}

// "Tespit" kovasi SERT kanit ister: adi olan gercek bir tespit kurali.
// Urun seviyesi toplu iddia (origin='product_claim') skora katkida bulunur
// ama kovaya girmez — tek satirlik bir iddia 120 tekniği birden kapsanmis
// gosterirdi. Backend'deki ensure_rule_origin() ile ayni kural.
function namedRuleCount(rules) {
  return (rules || []).filter(r => r.origin !== 'product_claim').length;
}

function effectiveRuleCount(rules, weightMap) {
  return (rules || []).reduce(
    (total, rule) => total + ruleCoverageWeight(rule) * scopeWeight(rule, weightMap), 0
  );
}

/** Bir teknik için hedef tespit sayısı (admin teknik bazında değiştirebilir). */
// DIKKAT: `||` degil `??` kullan — 0 gecerli bir hedef ("tespit gerekmiyor"),
// falsy oldugu icin `||` onu sessizce DEFAULT_RULE_THRESHOLD'a cevirirdi.
function techniqueThreshold(techId) {
  return techniqueConfig[techId]?.rule_threshold ?? DEFAULT_RULE_THRESHOLD;
}

/** Kapsama skoru — tek satırda açıklanabilir:
 *      skor = min(etkin tespit sayısı / teknik hedefi, 1)
 *  Mitigation skora girmez (haritada ayrı kalkan işareti), ürün çeşitliliği de
 *  girmez (ürün noktaları olarak zaten görünür). Önceki 3 bileşenli ağırlıklı
 *  harman ve MITRE'den türetilen "önem" kavramı kaldırıldı — Faz 4 kararı.
 *  Hedef 0 = "bu teknik icin tespit gerekmiyor" → skor otomatik %100.
 *  thresholdOverride: alt tekniği olan üst teknikler için familyRollup()'tan
 *  gelen aile hedefi — verilmezse techniqueThreshold(techId) kullanılır. */
function computeScore(techId, rulesCount, mitigationCount, sources, weightedRuleCount = rulesCount, thresholdOverride = null) {
  const threshold = thresholdOverride ?? techniqueThreshold(techId);
  if (threshold <= 0) return 1.0;
  return Math.min(weightedRuleCount / threshold, 1.0);
}

/** Alt tekniği OLAN bir üst teknik için "aile" (rollup) hedef/etkin/kapsanma
 * değerlerini hesaplar — İKİ AYRI GÜVENCENİN KÜÇÜĞÜ. Tam gerekçe, canlı örnek
 * ve önceki iki denemenin (ham toplama, boşluk-tabanlı) neden yetmediği:
 * docs/scoring_methodology.md #3.
 *   family.hedef = kendi.hedef + Σ alt.hedef        [TAM toplam; kendi.hedef
 *                                                     genelde 0]
 *   cappedSum    = min(kendi.etkin, kendi.hedef)
 *                  + Σ min(alt.etkin, alt.hedef)     [her ÜYE kendi hedefinde
 *                                                     tavanlanır]
 *   dedupedSum   = ailenin (kendi+tüm altlar) dokunduğu BENZERSİZ kural
 *                  ID'lerinin toplam ağırlığı         [aynı kural birden
 *                                                     fazla üyeye eşliyse
 *                                                     YALNIZCA BİR KEZ sayılır]
 *   family.etkin = min(cappedSum, dedupedSum)
 * İkisi FARKLI aşırı-sayma senaryosunu önler (yalnızca cappedSum: aynı kural
 * hem üste hem birden fazla alta eşliyse N kez şişer; yalnızca dedupedSum:
 * bir alt teknikte çok sayıda bağımsız kural varsa fazlası kardeşlerin
 * eksiğini kapatmak için aileye taşar) — min() ikisini de aynı anda keser.
 * "Tespit" kovası buna bağımsız: kendi doğrudan kuralı VARSA ya da en az
 * bir alt tekniği zaten tespitliyse üst teknik de tespitli sayılır.
 * Alt tekniği yoksa "kendi" değerlerine indirgenir (ayrı bir dal gerekmez).
 * app.py _compute_gap_analysis() ile birebir aynı formül olmalı. enrichedRules
 * verilmezse enrichRules() taze çağrılır (performans kritik olmayan yerler için). */
function familyRollup(techId, ownRules, weightMap, enrichedRules) {
  const ownThreshold = techniqueThreshold(techId);
  const ownEffective = effectiveRuleCount(ownRules, weightMap);
  let cappedSum = ownThreshold > 0 ? Math.min(ownEffective, ownThreshold) : 0;
  let hedefSum = ownThreshold > 0 ? ownThreshold : 0;
  const ruleWeights = new Map(); // rule id -> agirlik, dedup icin
  (ownRules || []).forEach(r => {
    if (r && r.id != null) ruleWeights.set(r.id, ruleCoverageWeight(r) * scopeWeight(r, weightMap));
  });
  let covered = namedRuleCount(ownRules) > 0;
  const subTechs = subTechsByParent[techId] || [];
  if (subTechs.length) {
    const rules = enrichedRules || enrichRules();
    subTechs.forEach(st => {
      const stThreshold = techniqueThreshold(st.id);
      if (stThreshold <= 0) return;
      const stRules = rulesInScope(rules.filter(r => r.tid == st.id), weightMap);
      const stEffective = effectiveRuleCount(stRules, weightMap);
      cappedSum += Math.min(stEffective, stThreshold);
      hedefSum += stThreshold;
      stRules.forEach(r => {
        if (r && r.id != null) ruleWeights.set(r.id, ruleCoverageWeight(r) * scopeWeight(r, weightMap));
      });
      if (namedRuleCount(stRules) > 0) covered = true;
    });
  }
  let dedupedSum = 0;
  ruleWeights.forEach(w => { dedupedSum += w; });
  const effective = Math.min(cappedSum, dedupedSum);
  return { threshold: hedefSum, effective, covered };
}

/** Matris ortam seçicisini scopeRegistry'den doldurur. */
function renderMatrixScopeSelect() {
  const select = document.getElementById('matrixScopeSelect');
  if (!select) return;
  const envs = (scopeRegistry?.environments || []).filter(e => e.active);

  if (!envs.length) {
    select.innerHTML = '<option value="">Ortam tanımlı değil</option>';
    select.disabled = true;
    matrixScopeEnvId = null;
  } else {
    select.disabled = false;
    select.innerHTML = `<option value="">Tüm ortamlar (birleşik)</option>` +
      envs.map(env =>
        `<option value="${env.id}" ${env.id === matrixScopeEnvId ? 'selected' : ''}>${_esc(env.name)}</option>`
      ).join('');
  }
  updateMatrixScopeNote();
}

/** Hangi ürünlerin sayıldığını açıkça yazar — analist "neden bu kart kırmızı"
 *  sorusunu tooltip açmadan cevaplayabilsin. */
function updateMatrixScopeNote() {
  const note = document.getElementById('matrixScopeNote');
  if (!note) return;
  const detectionSources = detectionSourceNames();
  const weights = scopeWeightMap();

  if (!weights) {
    // Birleşik mod: her ortamın hangi kaynakları izlediğini özetle.
    const envs = allEnvWeightMaps();
    if (!envs.length) { note.classList.add('hidden'); return; }
    note.classList.remove('hidden');
    note.innerHTML = `<strong>Birleşik görünüm — ${envs.length} ortam.</strong> Hücrelerdeki rozet kaç ortamda tespit olduğunu gösterir. ` +
      envs.map(e => {
        const on = Object.keys(e.weights).filter(n => detectionSources.has(n));
        return `<span class="scope-chip ${on.length ? 'on' : 'off'}">${_esc(e.name)}: ${on.length ? _esc(on.join(', ')) : 'izleyen yok'}</span>`;
      }).join('');
    return;
  }

  const active = Object.entries(weights)
    .filter(([name]) => detectionSources.has(name))
    .sort((a, b) => b[1] - a[1]);
  const inactive = [...detectionSources].filter(n => !(n in weights)).sort();
  note.classList.remove('hidden');
  note.innerHTML = active.length
    ? `<strong>Bu ortamda sayılan tespit kaynakları:</strong> ` +
      active.map(([n, w]) => `<span class="scope-chip on">${_esc(n)}${w < 1 ? ` %${Math.round(w * 100)}` : ''}</span>`).join('') +
      (inactive.length ? ` <strong>İzlemiyor:</strong> ` + inactive.map(n => `<span class="scope-chip off">${_esc(n)}</span>`).join('') : '')
    : `<strong>Bu ortamı izleyen tespit kaynağı yok</strong> — tüm teknikler kapsamsız görünecek. Kapsam Envanteri'nden izleme durumu girin.`;
}

// Ortak lerp & renk sabitleri — kullanıcının yüklediği örnek HTML'deki
// getHeatColor() algoritmasından portlandı (2026-08-14): sıfır AYRI, DÜZ
// bir gri (gradyanın bir parçası değil — "hiç tespit yok" hâli belirsiz
// bir "çok düşük skor" tonuyla karışmasın), sıfırdan sonrası ise yumuşak
// (pastel'e yakın, doygun/neon değil) çok-duraklı bir geçiş. Örnekteki
// yön "yüksek=çok olay=kırmızı" idi (tehdit sayımı); bizde yüksek skor
// İYİ demek olduğu için yön ters çevrildi: kırmızı→turuncu→sarı→yeşil.
function _colorLerp(a, b, t) {
  return { r: Math.round(a.r + (b.r - a.r) * t),
           g: Math.round(a.g + (b.g - a.g) * t),
           b: Math.round(a.b + (b.b - a.b) * t) };
}
const _ZERO_COLOR = { r: 49, g: 55, b: 62 }; // #31373E — hiç tespit yok
const _SCORE_STOPS = [
  { s: 0.00, r: 214, g: 96,  b: 77  }, // yumuşak kırmızı
  { s: 0.45, r: 224, g: 150, b: 79  }, // yumuşak turuncu
  { s: 0.70, r: 224, g: 195, b: 79  }, // yumuşak sarı
  { s: 1.00, r: 90,  g: 160, b: 106 }, // yumuşak yeşil
];

function _scoreRgb(score) {
  if (score <= 0) return _ZERO_COLOR;
  const st = _SCORE_STOPS;
  if (score >= st[st.length - 1].s) return st[st.length - 1];
  for (let i = 0; i < st.length - 1; i++) {
    if (score <= st[i + 1].s) {
      const t = (score - st[i].s) / (st[i + 1].s - st[i].s);
      return _colorLerp(st[i], st[i + 1], t);
    }
  }
  return st[st.length - 1];
}

// Kart rengi — OPAK (örnekteki gibi; saydamlık denemeleri "cırtlak" veya
// "soluk" bulunmuştu — asıl sorun saydamlık değil, durak renklerinin
// canlılığıydı; bu durak renkleri zaten yumuşak, opak sorun olmamalı).
function scoreToColor(score) {
  const c = _scoreRgb(score);
  return `rgb(${c.r},${c.g},${c.b})`;
}
function scoreToSubColor(score) {
  return scoreToColor(score);
}

// Opak dolgu üzerinde metin okunaklı kalsın diye luminance'a göre
// siyah/beyaz seçer (örnekteki getHeatColor()'ın metin mantığıyla aynı).
function scoreTextColor(score) {
  const c = _scoreRgb(score);
  const luminance = (0.299 * c.r + 0.587 * c.g + 0.114 * c.b) / 255;
  return luminance > 0.55 ? '#111827' : '#ffffff';
}

// _SCORE_STOPS'tan tureyen paylasilan degrade string'i — hem statik lejant
// hem hover tooltip'teki "renk gaminda nerede" gostergesi bunu kullanir, tek
// kaynaktan (palet ileride degisirse ikisi de otomatik senkron kalir).
// scoreToColor(0) YAZILAMAZ — score<=0 icin hep _ZERO_COLOR donuyor, ilk
// durak olan yumusak kirmizi hic gorunmez. Sifir yerine DUZ bir "cap" olarak
// elle eklenir (%0-2 gri), asil gradyan %2'den baslar — CSS'te sonraki
// duragin nominal pozisyonu (0%) onceki duraktan (2%) geride kalamaz, otomatik
// %2'ye sabitlenir, gri->kirmizi keskin gecisi boylece olusur.
function _scoreGradientStops() {
  const zero = `rgb(${_ZERO_COLOR.r},${_ZERO_COLOR.g},${_ZERO_COLOR.b})`;
  const rest = _SCORE_STOPS.map(s => `rgb(${s.r},${s.g},${s.b}) ${s.s * 100}%`).join(', ');
  return `${zero} 0%, ${zero} 2%, ${rest}`;
}

// Skor lejantı — degrade bir kez (init'te) çizilir; imleç ise wireScoreTooltip'in
// mevcut hover mekanizmasına yaslanıp her kart hover'ında güncellenir (bkz.
// wireScoreTooltip, #scoreLegendCursor).
function renderScoreLegend() {
  const el = document.getElementById('scoreLegendContainer');
  if (!el) return;
  el.innerHTML = `
    <span class="score-legend-lbl">Düşük</span>
    <div class="score-legend-bar" style="background: linear-gradient(90deg, ${_scoreGradientStops()})">
      <div class="score-legend-cursor" id="scoreLegendCursor"></div>
    </div>
    <span class="score-legend-lbl">Yüksek</span>`;
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

// Kart görselleri: dolgu rengi YALNIZCA tespite bakar; mitigation ayrı bir
// kalkan işareti olarak gösterilir (renge karışmaz) — Faz 4 kararı.
function applyTechniqueVisuals(card, techId, rulesCount, mitigationCount, sources, weightedRuleCount = rulesCount, envRatio = null, namedCount = rulesCount, thresholdOverride = null, coveredOverride = null) {
  const score = computeScore(techId, rulesCount, mitigationCount, sources, weightedRuleCount, thresholdOverride);
  const covered = coveredOverride ?? (namedCount > 0);
  card.style.backgroundColor = scoreToColor(score);
  card.style.color = scoreTextColor(score);
  card.classList.toggle('covered', covered);
  card.classList.toggle('mitigated', mitigationCount > 0);

  const cfg = techniqueConfig[techId] || {};
  card.dataset.scoreData = JSON.stringify({
    techId,
    // fillTechniqueCell dataset.techName'e yazdi (bkz. fillTechniqueCell yorumu)
    name: card.dataset.techName || '', rulesCount, weightedRuleCount: Math.round(weightedRuleCount * 100) / 100, mitigationCount,
    sources: [...new Set(Array.isArray(sources) ? sources : [])],
    score: Math.round(score * 100),
    namedCount,
    threshold: thresholdOverride ?? techniqueThreshold(techId),
    mitTotal: getMitigationTotal(techId),
    groupCount: cfg.group_count || 0,
    envRatio,
  });

  applySourceDots(card, sources);
}

function updateTechniqueCard(parentId) {
  const card = document.querySelector(`.technique-card[data-tech-id="${parentId}"]`);
  if (!card) return;
  const weightMap = scopeWeightMap();
  // parentId DEGIL tid ile eslesir: bir alt teknige yazilan kural bu kartin
  // KENDI payini "tespitli" yapmaz — ama familyRollup() asagida ayni kurali
  // aileye genisletiyor (bkz. renderMatrix()'teki parentOwnRules notu).
  const linkedRules = rulesInScope(enrichRules().filter(r => r.tid === parentId), weightMap);
  const rollup = familyRollup(parentId, linkedRules, weightMap);
  const mitigationCount = getCheckedMitigationCountForTech(parentId);
  const score = rollup.threshold > 0 ? Math.min(rollup.effective / rollup.threshold, 1.0) : 1.0;
  card.style.backgroundColor = scoreToColor(score);
  card.style.color = scoreTextColor(score);
  card.classList.toggle('covered', rollup.covered);
  card.classList.toggle('mitigated', mitigationCount > 0);
}

function updateSubtechCard(techId) {
  const card = document.querySelector(`.subtech-card[data-tech-id="${techId}"]`);
  if (!card) return;
  const weightMap = scopeWeightMap();
  const enriched = rulesInScope(enrichRules().filter(r => r.tid === techId), weightMap);
  const rulesCount = enriched.length;
  const mitigationCount = getCheckedMitigationCountForTech(techId);
  const sources = enriched.map(r => r.source);
  const score = computeScore(techId, rulesCount, mitigationCount, sources, effectiveRuleCount(enriched, weightMap));
  card.style.backgroundColor = scoreToSubColor(score);
  card.style.color = scoreTextColor(score);
  card.classList.toggle('covered', namedRuleCount(enriched) > 0);
  card.classList.toggle('mitigated', mitigationCount > 0);
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

/** Teknik hücresinin içeriğini kurar — ad üstte, ID altta hafif saydam
 *  (kullanıcı kararı — tek satır "ID Ad" denemesi geri alındı). Ana ve alt
 *  teknik aynı düzeni kullanır, yalnızca boyut/yazı tipi CSS'te
 *  `.subtech-card` ile ayrışıyor (bkz. isSub → `is-sub` class'ı).
 *  Sayaçlar (tespit oranı, mitigation, ortam) kart yüzünde değil, hover
 *  tooltip'inde (bkz. wireScoreTooltip, card.dataset.scoreData) — o da
 *  adı card.dataset.techName üzerinden okur (ham/kaçışsız yazılır —
 *  `_esc(name)` YAZILMAZ, dataset zaten HTML-parse etmiyor, _esc ile
 *  yazılırsa tooltip'te çifte kaçış olur). Parametreler (ruleCount,
 *  weighted, mitigationCount, envRatio, thresholdOverride) burada
 *  tüketilmiyor ama imza aynı kalıyor — applyTechniqueVisuals() çağrıları
 *  aynı değerleri hâlâ kullanıyor. */
function fillTechniqueCell(cell, { id, name, ruleCount, weighted, mitigationCount, envRatio, isSub, thresholdOverride = null }) {
  cell.dataset.techName = name;
  cell.innerHTML = `<div class="tc-name">${_esc(name)}</div><div class="tc-foot"><span class="tc-id">${_esc(id)}</span></div>`;
  cell.classList.toggle('is-sub', !!isSub);
}

function buildSubtechContainer(parentId, enrichedData, allowedSubs, weightMap = scopeWeightMap()) {
  const container = document.createElement('div');
  container.className = 'subtech-container';
  const subTechs = allowedSubs || (subTechsByParent[parentId] || []);
  if (subTechs.length == 0) return container;

  subTechs.forEach(st => {
    const subCard = document.createElement('div');
    subCard.className = 'subtech-card';
    subCard.dataset.techId = st.id;

    const rulesForSub = rulesInScope(enrichedData.filter(r => r.tid == st.id), weightMap);
    const mitigationCount = getCheckedMitigationCountForTech(st.id);
    const sources = rulesForSub.map(r => r.source);
    const weightedCount = effectiveRuleCount(rulesForSub, weightMap);
    fillTechniqueCell(subCard, {
      id: st.id, name: st.name,
      ruleCount: rulesForSub.length, weighted: weightedCount,
      mitigationCount, envRatio: null, isSub: true,
    });
    applyTechniqueVisuals(subCard, st.id, rulesForSub.length, mitigationCount, sources,
                          weightedCount, null, namedRuleCount(rulesForSub));
    // applyTechniqueVisuals() kartı her zaman scoreToColor ile boyar (sub/ana
    // ayrımı bilmiyor) — alt teknik daha soluk görünsün diye burada
    // scoreToSubColor ile üzerine yazıyoruz.
    const subScore = computeScore(st.id, rulesForSub.length, mitigationCount, sources, weightedCount);
    subCard.style.backgroundColor = scoreToSubColor(subScore);

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

// Bir tespitin YALNIZCA bu teknikle eslemesini kaldirir — kural kalir,
// diger tekniklere eslemesi varsa onlar da kalir. deleteRule()'un aksine
// tum tespiti silmez. Modal'daki liste artik eski (bu teknige gore
// gruplanmis) oldugu icin ayni pattern'i (deleteRule) izleyip modal'i
// kapatiyoruz — kullanici karti tekrar tiklayip taze veriyle acabilir.
async function unlinkRuleTechnique(ruleId, techId) {
  if (!hasRole('editor')) return;
  const res = await apiFetch(`/api/rules/${ruleId}/techniques/${techId}`, { method: 'DELETE' });
  if (!res.ok) return;
  const rule = userRules.find(r => r.id === ruleId);
  if (rule && rule.techniques) rule.techniques = rule.techniques.filter(t => t !== techId);
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
  // Modal'i HEMEN goster — icerik (Mitigations fetch'i dahil) asagida asenkron
  // dolduruluyor. Eskiden display:flex en sonda atanip acilis animasyonu ancak
  // tum veri geldikten sonra baslardi; kullanici bunu "yavas" olarak yorumladi
  // (aslinda animasyon hizli, sorun icerik gelene kadarki bekleme suresiydi).
  document.getElementById('ruleModal').style.display = 'flex';
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
      let h = '';
      if (d.description) h += `<div class="modal-desc-text">${esc(d.description.slice(0,500))}${d.description.length>=500?'…':''}</div>`;
      if (platforms) h += `<div class="modal-desc-meta">Platform: ${esc(platforms)}</div>`;
      // Objektif MITRE sinyali — önceliklendirmeye yardımcı, skoru etkilemez.
      h += `<div class="modal-desc-meta">Bu tekniği <strong>${d.group_count || 0}</strong> tehdit grubu ve <strong>${d.tool_count || 0}</strong> araç kullanıyor`;
      if (d.mitre_url) h += ` &nbsp;<a class="modal-mitre-link" href="${esc(d.mitre_url)}" target="_blank" rel="noopener">MITRE ↗</a>`;
      h += '</div>';
      descDiv.innerHTML = h;
    })
    .catch(() => { descDiv.innerHTML = ''; });

  const tabBar = document.createElement('div');
  tabBar.className = 'modal-tabs';
  // Tespitler varsayilan/ilk sekme — mitigation daha az onemli, ileride
  // kullanilacak (kullanici karari, 2026-08-15).
  tabBar.innerHTML = `
    <button class="tab-btn active" data-tab="rulesTab">Tespitler</button>
    <button class="tab-btn" data-tab="mitigationsTab">Mitigations</button>
  `;
  body.appendChild(tabBar);

  const mitigationsTab = document.createElement('div');
  mitigationsTab.className = 'tab-panel';
  mitigationsTab.id = 'mitigationsTab';
  const rulesTab = document.createElement('div');
  rulesTab.className = 'tab-panel active';
  rulesTab.id = 'rulesTab';
  body.appendChild(rulesTab);
  body.appendChild(mitigationsTab);

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
    // Bug düzeltmesi: form body'ye ekleniyordu, yani Mitigations sekmesindeyken
    // de görünüyordu. Ait olduğu yer Tespitler sekmesi.
    rulesTab.appendChild(modalRuleAdd);
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
      const row = document.createElement('div');
      row.className = 'mitigation-row';
      const isChecked = isMitigationChecked(m.id);
      if (isChecked) row.classList.add('checked');
      row.innerHTML = `
        <label class="mitigation-name">
          <span class="mit-status-indicator ${isChecked ? 'checked' : ''}" data-mit="${m.id}">${isChecked ? '✓' : '○'}</span>
          ${_esc(m.id)} - ${_esc(m.name)}
          <span class="mitigation-info" data-tech="${parentId}" data-mit="${m.id}">i</span>
        </label>
        <div class="mitigation-fields">
          <div class="mitigation-entries" data-mit="${m.id}"></div>
          <div class="mitigation-entry-form ${hasRole('editor') ? '' : 'hidden'}">
            <span class="mitigation-entry-team-placeholder" data-mit="${m.id}"></span>
            <span class="mitigation-entry-product-placeholder" data-mit="${m.id}"></span>
            <textarea class="mitigation-entry-comment" data-mit="${m.id}" placeholder="Nasıl sağlanıyor?"></textarea>
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
      const teamPh = row.querySelector('.mitigation-entry-team-placeholder');
      if (teamPh) teamPh.replaceWith(buildTeamSelectEl(m.id));
      const prodPh = row.querySelector('.mitigation-entry-product-placeholder');
      if (prodPh) prodPh.replaceWith(buildProductSelectEl(m.id));
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
          ${hasRole('editor') ? `<button class="delete-btn" title="Bu tekniği bu tespitten kaldır (tespit kalır)" onclick="unlinkRuleTechnique(${r.id}, '${r.tid}')">Bu Teknikten Kaldır</button>` : ''}
          ${hasRole('editor') ? `<button class="delete-btn" title="Tüm tespiti kalıcı olarak sil" onclick="deleteRule(${r.id})">Sil</button>` : ''}
        </td>
      </tr>`;
    });
    tbody += '</tbody>';
    table.innerHTML = tbody;

    groupDiv.appendChild(table);
    rulesTab.appendChild(groupDiv);
  });

  // Not: Burada ikinci bir "Mitigations (Ekip/Yorum)" özeti render ediliyordu —
  // Mitigations sekmesindeki listenin birebir kopyasıydı. Kaldırıldı.

  mitigationsTab.querySelectorAll('.mitigation-entry-add').forEach(btn => {
    btn.addEventListener('click', async (e) => {
      const mitId = e.currentTarget.dataset.mit;
      const row = e.currentTarget.closest('.mitigation-row');
      if (!mitId || !row) return;
      const teamInput = row.querySelector('.mitigation-entry-team');
      const productInput = row.querySelector('.mitigation-entry-product');
      const commentInput = row.querySelector('.mitigation-entry-comment');
      const team = (teamInput?.value || '').trim();
      const comment = (commentInput?.value || '').trim();
      const productId = productInput?.value ? Number(productInput.value) : null;
      if (!team || !comment) {
        alert('Ekip ve açıklama gerekli.');
        return;
      }
      const created = await addMitigationEntry(mitId, team, comment, productId);
      if (!created) return;
      await reloadMitigationEntries();
      if (teamInput) teamInput.value = '';
      if (productInput) productInput.value = '';
      if (commentInput) commentInput.value = '';
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
}


async function addMitigationEntry(mitId, team, comment, productId = null) {
  if (!hasRole('editor')) return null;
  const res = await apiFetch('/api/mitigation-entries', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ mitigation_id: mitId, team, comment, product_id: productId })
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
  list.innerHTML = entries.map(e => mitigationEntryHtml(e)).join('');

  list.querySelectorAll('.entry-delete').forEach(btn => {
    btn.addEventListener('click', async (evt) => {
      const id = evt.currentTarget.dataset.entryId;
      if (!id) return;
      const ok = await deleteMitigationEntry(id);
      if (!ok) return;
      await reloadMitigationEntries();
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

// ─── Navigasyon: 4 bölüm, her biri birkaç alt sekme ────────────────────────
// Paneller fiziksel olarak birleştirilmedi — ID'leri, render fonksiyonları ve
// içlerindeki ~40 inline hasRole() kontrolü aynen duruyor; yalnızca üst
// seviyede gruplandılar. Böylece 12 ekranlık dağınıklık gitti ama davranış
// değişmedi.
const SECTIONS = {
  map: {
    label: 'Harita',
    tabs: [
      { panel: 'matrixPanel', label: 'Matris' },
    ],
  },
  inventory: {
    label: 'Envanter',
    tabs: [
      { panel: 'rulesPanel',      label: 'Tespitler' },
      { panel: 'targetsPanel',    label: 'Teknik Hedefleri', role: 'admin' },
      { panel: 'scopePanel',      label: 'Ortam & Kapsam' },
      { panel: 'mitigationPanel', label: 'Mitigation' },
    ],
  },
  gaps: {
    label: 'Boşluklar',
    tabs: [
      { panel: 'gapPanel',         label: 'GAP Analizi' },
      { panel: 'actionsPanel',     label: 'Aksiyon Planı' },
      { panel: 'dataQualityPanel', label: 'Veri Kalitesi' },
    ],
  },
  settings: {
    label: 'Ayarlar',
    tabs: [
      { panel: 'settingsPanel', label: 'Ayarlar' },
      { panel: 'auditPanel',    label: 'Audit', role: 'admin' },
    ],
  },
};

// Panel ilk kez açıldığında veri çeken yükleyiciler.
const PANEL_LOADERS = {
  gapPanel: () => loadGapDashboard(),
  actionsPanel: () => loadActionsPanel(),
  dataQualityPanel: () => loadDataQuality(),
  auditPanel: () => loadAuditLogs(),
  scopePanel: () => loadScopeRegistry(),
  targetsPanel: () => renderTargetsPanel(),
};

let activeSection = 'map';
const lastPanelBySection = {};

function visibleTabs(sectionKey) {
  return (SECTIONS[sectionKey]?.tabs || []).filter(t => !t.role || hasRole(t.role));
}

/** Bir paneli göster; gerekiyorsa bölümü de değiştirir. */
function showPanel(panelId) {
  const sectionKey = Object.keys(SECTIONS).find(
    key => SECTIONS[key].tabs.some(t => t.panel === panelId)
  );
  if (!sectionKey) return;
  activeSection = sectionKey;
  lastPanelBySection[sectionKey] = panelId;

  document.querySelectorAll('.nav-item[data-section]').forEach(
    item => item.classList.toggle('active', item.dataset.section === sectionKey)
  );
  document.querySelectorAll('.panel').forEach(
    p => p.classList.toggle('active', p.id === panelId)
  );
  renderSectionTabs();

  if (panelId === 'matrixPanel' && mitreObjects.length) renderMatrix();
  PANEL_LOADERS[panelId]?.();
}

function renderSectionTabs() {
  const bar = document.getElementById('sectionTabs');
  if (!bar) return;
  const tabs = visibleTabs(activeSection);
  // Tek sekmeli bölümde çubuk gereksiz gürültü.
  if (tabs.length < 2) { bar.innerHTML = ''; bar.classList.add('hidden'); return; }
  bar.classList.remove('hidden');
  const current = document.querySelector('.panel.active')?.id;
  bar.innerHTML = tabs.map(t =>
    `<button class="section-tab ${t.panel === current ? 'active' : ''}" data-panel="${t.panel}" role="tab">${t.label}</button>`
  ).join('');
  bar.querySelectorAll('.section-tab').forEach(btn =>
    btn.addEventListener('click', () => showPanel(btn.dataset.panel))
  );
}

function wireNavigation() {
  document.querySelectorAll('.nav-item[data-section]').forEach(item => {
    item.addEventListener('click', () => {
      const key = item.dataset.section;
      const tabs = visibleTabs(key);
      if (!tabs.length) return;
      // Bölüme dönerken en son bakılan sekmeye dön.
      const remembered = lastPanelBySection[key];
      showPanel(tabs.some(t => t.panel === remembered) ? remembered : tabs[0].panel);
    });
  });
  renderSectionTabs();
}


async function addProduct() {
  if (!hasRole('admin')) {
    alert('Bu islem icin admin yetkisi gerekir.');
    return;
  }
  const name = document.getElementById('productName').value.trim();
  const color = document.getElementById('productColor').value.trim();
  const category = document.getElementById('productCategory')?.value || 'tespit_kaynagi';
  if (!name || !color) {
    alert('Ürün adı ve renk gerekli.');
    return;
  }
  const res = await apiFetch('/api/products', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ name, color, category })
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

// ── Kapsama Ice Aktarimi ─────────────────────────────────────────────────────
// Iki asamali: once /preview (yazma yok) plani gosterir, kullanici gorup
// onaylayinca /apply yazar. Yanlis bir dosyanin haritayi aninda bozmamasi icin.
let importPlanPayload = null;   // onizlenen ham dosya icerigi (JSON) veya File (CSV)
let importPlanIsCsv = false;

async function previewImportFile() {
  if (!hasRole('editor')) {
    alert('Bu işlem için editor yetkisi gerekir.');
    return;
  }
  const fileInput = document.getElementById('importFile');
  const result = document.getElementById('uploadResult');
  const section = document.getElementById('importPlanSection');
  result.textContent = '';
  section.classList.add('hidden');
  importPlanPayload = null;

  const file = fileInput?.files?.[0];
  if (!file) {
    result.textContent = 'Lütfen bir dosya seçin.';
    return;
  }

  // CSV'nin satir satir onizlemesi yok — eski toplu yol oldugu gibi calisir,
  // ama artik ayni planlayiciyi kullandigi icin duplicate satirlar birlesiyor.
  importPlanIsCsv = /\.csv$/i.test(file.name);
  if (importPlanIsCsv) {
    importPlanPayload = file;
    document.getElementById('importSummary').innerHTML =
      '<div class="import-stat"><strong>CSV</strong><span>Doğrudan yükleme</span></div>';
    document.getElementById('importErrors').innerHTML = '';
    document.getElementById('importPlanTable').innerHTML =
      '<div class="import-hint">CSV yolunda önizleme yok; Uygula doğrudan yükler. ' +
      'Satır satır plan görmek için JSON kullanın.</div>';
    const applyBtn = document.getElementById('btnImportApply');
    if (applyBtn) applyBtn.disabled = false;
    section.classList.remove('hidden');
    return;
  }

  let raw;
  try {
    raw = JSON.parse(await file.text());
  } catch (e) {
    result.textContent = 'Geçersiz JSON: ' + e.message;
    return;
  }

  const res = await apiFetch('/api/import/coverage/preview', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(raw),
  });
  const plan = await res.json().catch(() => ({}));
  if (!res.ok) {
    result.textContent = plan.error || 'Önizleme başarısız.';
    return;
  }
  importPlanPayload = raw;
  renderImportPlan(plan);
  section.classList.remove('hidden');
}

function renderImportPlan(plan) {
  const s = plan.summary || {};
  const stat = (label, value, cls) =>
    '<div class="import-stat ' + (cls || '') + '"><strong>' + (value ?? 0) +
    '</strong><span>' + label + '</span></div>';
  document.getElementById('importSummary').innerHTML =
    stat('Yeni ürün', s.products_new) +
    stat('Yeni kural', s.rules_new) +
    stat('Güncellenecek', s.rules_updated) +
    stat('Değişmeyen', s.rules_unchanged) +
    stat('Eklenecek teknik', s.techniques_added) +
    stat('Tekniksiz kalacak', s.rules_without_technique, s.rules_without_technique ? 'warn' : '') +
    stat('Uyarı', s.warnings, s.warnings ? 'warn' : '') +
    stat('Hata', s.errors, s.errors ? 'bad' : '');

  // Hata = engelleyici (yapısal: bozuk şema, katalogda olmayan ürün — dosya
  // hiç uygulanamaz). Uyarı = engellemez (örn. tanınmayan teknik ID'si —
  // o satır geçerli kısmıyla veya tekniksiz eklenir, sonradan tamamlanır).
  const errors = plan.errors || [];
  document.getElementById('importErrors').innerHTML = errors.length
    ? '<div class="import-error-box"><strong>' + errors.length +
      ' hata — dosya uygulanamaz:</strong><ul>' +
      errors.map(e => '<li>' + _esc(e) + '</li>').join('') + '</ul></div>'
    : '';

  const warnings = plan.warnings || [];
  document.getElementById('importWarnings').innerHTML = warnings.length
    ? '<div class="import-warning-box"><strong>' + warnings.length +
      ' uyarı — uygulanabilir, gözden geçir:</strong><ul>' +
      warnings.map(w => '<li>' + _esc(w) + '</li>').join('') + '</ul></div>'
    : '';

  const rows = (plan.rules || []).filter(r => r.action !== 'noop');
  const productRows = (plan.products || []).filter(p => p.action === 'create');
  const badge = a => a === 'create'
    ? '<span class="import-badge new">yeni</span>'
    : '<span class="import-badge upd">güncelle</span>';

  const productHtml = productRows.length
    ? '<h4>Oluşturulacak ürünler</h4><ul class="import-product-list">' +
      productRows.map(p => '<li>' + _esc(p.name) +
        ' <span class="import-cat">' + _esc(p.category) + '</span></li>').join('') +
      '</ul>'
    : '';

  const ruleHtml = rows.length
    ? '<h4>Kurallar</h4><div class="import-table-wrap"><table class="import-table">' +
      '<thead><tr><th></th><th>Kural</th><th>Ürün</th><th>Eklenecek teknikler</th><th>Tespit Gücü</th></tr></thead><tbody>' +
      rows.map(r => {
        const orphan = !r.existing_techniques.length && !r.added_techniques.length;
        const techCell = orphan
          ? '<span class="import-badge warn">teknik yok</span>'
          : r.added_techniques.map(t => '<code>' + _esc(t) + '</code>').join(' ');
        return '<tr><td>' + badge(r.action) + '</td>' +
          '<td>' + _esc(r.name) + '</td>' +
          '<td>' + _esc(r.product) + '</td>' +
          '<td class="import-techs">' + techCell + '</td>' +
          '<td>' + _esc(COV_LABEL[r.coverage_level] || r.coverage_level) + '</td></tr>';
      }).join('') +
      '</tbody></table></div>'
    : '<div class="import-hint">Uygulanacak bir değişiklik yok — dosyadaki her şey zaten kayıtlı.</div>';

  document.getElementById('importPlanTable').innerHTML = productHtml + ruleHtml;

  const applyBtn = document.getElementById('btnImportApply');
  if (applyBtn) applyBtn.disabled = !plan.ok || (rows.length + productRows.length === 0);
}

async function applyImport() {
  if (!hasRole('editor')) return;
  const result = document.getElementById('uploadResult');
  if (!importPlanPayload) {
    result.textContent = 'Önce bir dosya önizleyin.';
    return;
  }

  let res;
  if (importPlanIsCsv) {
    const form = new FormData();
    form.append('file', importPlanPayload);
    res = await apiFetch('/api/rules/bulk', { method: 'POST', body: form });
  } else {
    res = await apiFetch('/api/import/coverage/apply', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(importPlanPayload),
    });
  }
  const payload = await res.json().catch(() => ({}));
  if (!res.ok) {
    result.textContent = payload.error || 'Uygulama başarısız.';
    if (payload.summary) renderImportPlan(payload);
    return;
  }

  await reloadData();
  renderMatrix();
  const a = payload.applied || {
    products_created: 0,
    rules_created: payload.inserted,
    rules_updated: payload.updated,
    techniques_added: payload.techniques_added,
  };
  result.textContent =
    'Uygulandı — ' + (a.products_created || 0) + ' ürün, ' +
    (a.rules_created || 0) + ' yeni kural, ' +
    (a.rules_updated || 0) + ' güncellenen kural, ' +
    (a.techniques_added || 0) + ' teknik eşlemesi.';
  document.getElementById('importPlanSection').classList.add('hidden');
  importPlanPayload = null;
}

async function copyMappingPrompt() {
  const res = await apiFetch('/api/import/mapping-prompt');
  if (!res.ok) { alert('Prompt alınamadı.'); return; }
  const data = await res.json();
  const btn = document.getElementById('btnCopyMappingPrompt');
  try {
    await navigator.clipboard.writeText(data.prompt);
    if (btn) {
      const old = btn.textContent;
      btn.textContent = 'Kopyalandı ✓';
      setTimeout(() => { btn.textContent = old; }, 1800);
    }
  } catch {
    // Pano izni yoksa kullanici elle kopyalayabilsin
    window.prompt('Prompt (Ctrl+C ile kopyalayın):', data.prompt);
  }
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
  document.getElementById('btnImportPreview')?.addEventListener('click', previewImportFile);
  document.getElementById('btnImportApply')?.addEventListener('click', applyImport);
  document.getElementById('btnCopyMappingPrompt')?.addEventListener('click', copyMappingPrompt);
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

// Matris tam ekran modu — gercek Fullscreen API degil, sadece kendi
// menu/ust cubugumuz gizlenir ("chrome sayfasinin tamami heatmap olsun,
// yandaki navigator ustteki kisim gitsin" — kullanici istegi).
function wireMatrixFullscreen() {
  const btn = document.getElementById('btnMatrixFullscreen');
  const shell = document.querySelector('.ms-shell');
  if (!btn || !shell) return;
  const setState = (on) => {
    shell.classList.toggle('matrix-fullscreen', on);
    btn.classList.toggle('active', on);
    btn.title = on ? 'Tam ekrandan çık (Esc)' : 'Tam ekran (menü ve üst çubuk gizlenir, Esc ile çık)';
  };
  btn.addEventListener('click', () => setState(!shell.classList.contains('matrix-fullscreen')));
  document.addEventListener('keydown', (e) => {
    if (e.key === 'Escape' && shell.classList.contains('matrix-fullscreen')) setState(false);
  });
}

function wireExport() {
  // btnExportPdf burada wire edilmiyor — /report'a yonlendiren capture-phase
  // handler'i templates/index.html'de tanimli (PDF Export artik DOM kazima
  // degil, sunucu tarafinda render edilen zengin rapor).
  const btnCsv = document.getElementById('btnExportCsv');
  const btnLayer = document.getElementById('btnExportLayer');
  if (btnCsv) btnCsv.addEventListener('click', exportCsv);
  if (btnLayer) btnLayer.addEventListener('click', exportLayer);
}


function wireActions() {
  wireNavigation();
  wireSearch();
  wireExport();
  wireMatrixFullscreen();
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

  const scopeSelect = document.getElementById('matrixScopeSelect');
  if (scopeSelect) {
    scopeSelect.addEventListener('change', (e) => {
      matrixScopeEnvId = e.target.value ? Number(e.target.value) : null;
      updateMatrixScopeNote();
      renderMatrix();
      // GAP ekranı açıksa bayat kalmasın; kapalıysa zaten açılışta yeniden çekiliyor.
      if (document.getElementById('gapPanel')?.classList.contains('active')) loadGapDashboard();
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
  // Seçili varlık grubunun ürün→ağırlık haritası; render boyunca sabit.
  const scopeWeights = scopeWeightMap();
  const container = document.getElementById('matrix');
  container.innerHTML = '';
  currentRulesByParent = {};
  visibleExportRows = [];
  let visibleColumns = 0;

  document.getElementById('totalRules').innerText = userRules.length;
  // Ust bardaki "Tespitli" sayisi updateMatrixStats() icinde ayarlanir —
  // seçili ortam ve filtrelerle aynı sayıyı göstermesi için tek kaynak orası.

  tacticOrder.forEach(tactic => {
    const col = document.createElement('div');
    col.className = 'tactic-column';
    col.innerHTML = `<div class="tactic-header">${tactic}</div>`;
    const header = col.querySelector('.tactic-header');
    // Teknik kartları artık col'un DOĞRUDAN çocuğu değil — referans projedeki
    // gibi sarmalanan bir ızgara (.tactic-techniques, flex-wrap) içinde,
    // birden fazlası aynı satıra sığabiliyor. col'a yalnızca DOLU ise
    // eklenir (subContainer'daki koşullu-ekleme deseninin aynısı).
    const techWrap = document.createElement('div');
    techWrap.className = 'tactic-techniques';
    const techniques = (matrixStructure[tactic] || []).sort((a, b) => a.id.localeCompare(b.id));
    // Başlık hover panelinin (Total/Unique/Average) verisi — arama filtresinden
    // BAĞIMSIZ, taktiğin TÜM tekniklerine göre (kullanıcı ne yazarsa yazsın
    // taktiğin gerçek kapsama durumunu göstersin). parentRollup ile aynı
    // kaynaktan (kartın rengini belirleyenle tutarlı) biriktirilir.
    let tacticTotal = 0, tacticCovered = 0;

    techniques.forEach(tech => {
      const parentMatchesSearch = matchesSearch(tech);
      // Ortam seçiliyse, o ortamda geçerli olmayan tespitler hesaba katılmaz —
      // kart yine görünür ama boşluğu dürüstçe gösterir.
      //
      // parentRules: fold-up'lı (üst teknik + TÜM alt tekniklerine yazılan
      // kurallar). Yalnızca modal içeriği için kullanılır (Direkt + alt
      // teknik başına gruplanmış görünüm). parentOwnRules: yalnızca
      // DOĞRUDAN bu tekniğe yazılan kurallar. İkisi de rulesInScope()
      // içinden geçiyor — seçili ürün merceğine uymayan kurallar buradan
      // otomatik elenir (bkz. rulesInScope() notu): ürün filtresi artık
      // görünürlüğü değil YALNIZCA rengi/skoru etkiler, o ürünün kendi
      // haritasıymış gibi — kapsamadığı teknikler kapanmaz, dürüstçe boş
      // görünür. Kullanıcı kararı (2026-07-29).
      //
      // Hücre rengi/skoru/kova artık ne salt "own" ne salt fold-up: alt
      // tekniği OLAN bir üst teknik "aile" (rollup) değerini kullanır —
      // kendi payı + tüm alt tekniklerinin (kendi hedefinde tavanlanmış)
      // toplamı. Alt tekniği yoksa aile = kendi. Bkz. familyRollup() ve
      // PROJECT_STATE.md 2026-07-29 (bu, aynı günün ERKEN saatlerindeki
      // "hiç fold-up yok" kararını üst teknik seviyesinde kısmen tersine
      // çevirir — kullanıcı: bir alt tekniği tamamen kapsanmış bir üst
      // teknik, kendisi "boş" görünmesin).
      const parentRules = rulesInScope(enrichedData.filter(r => r.parentId == tech.id), scopeWeights);
      const parentOwnRules = rulesInScope(enrichedData.filter(r => r.tid == tech.id), scopeWeights);
      const parentRollup = familyRollup(tech.id, parentOwnRules, scopeWeights, enrichedData);
      tacticTotal += parentRollup.effective;
      if (parentRollup.covered) tacticCovered += 1;

      const subTechs = subTechsByParent[tech.id] || [];
      // Ürün filtresi burada artik gorunurlugu etkilemiyor — yalnizca arama
      // metni bir alt teknigi/ust teknigi gizleyebilir.
      const subMatches = subTechs.filter(st => matchesSearch(st));

      if (!parentMatchesSearch && subMatches.length === 0) {
        return;
      }

      // export rows
      const parentRuleCount = parentOwnRules.length;
      const parentMitCount = getCheckedMitigationCountForTech(tech.id);
      const parentSources = parentOwnRules.map(r => r.source);
      visibleExportRows.push({
        type: "technique",
        tech_id: tech.id,
        name: tech.name,
        tactic: tactic,
        rule_count: parentRuleCount,
        named_rule_count: namedRuleCount(parentOwnRules),
        covered: parentRollup.covered,
        mitigation_checked: parentMitCount,
        products: Array.from(new Set(parentSources)),
        rule_threshold: parentRollup.threshold,
        score: parentRollup.threshold > 0 ? Math.min(parentRollup.effective / parentRollup.threshold, 1.0) : 1.0
      });
      subMatches.forEach(st => {
        const subRules = rulesInScope(enrichedData.filter(r => r.tid == st.id), scopeWeights);
        const subRuleCount = subRules.length;
        const subMitCount = getCheckedMitigationCountForTech(st.id);
        const subSources = subRules.map(r => r.source);
        visibleExportRows.push({
          type: "subtechnique",
          tech_id: st.id,
          name: st.name,
          tactic: tactic,
          rule_count: subRuleCount,
          named_rule_count: namedRuleCount(subRules),
          mitigation_checked: subMitCount,
          products: Array.from(new Set(subSources)),
          rule_threshold: techniqueThreshold(st.id),
          score: computeScore(st.id, subRuleCount, subMitCount, subSources, effectiveRuleCount(subRules, scopeWeights))
        });
      });

      const rulesForCell = parentOwnRules;
      const card = document.createElement('div');
      card.className = 'technique-card';
      card.dataset.techId = tech.id;
      currentRulesByParent[tech.id] = rulesForCell.length;

      const mitigationCount = getCheckedMitigationCountForTech(tech.id);
      const sources = rulesForCell.map(r => r.source);
      // weighted/threshold aile (rollup) değeri — kartın rengi/sayacı ile
      // "Tespit" kovası hep aynı sonuca varsın diye parentRollup kullanılır.
      const weighted = parentRollup.effective;
      // Birleşik modda (ortam seçilmemişken) kaç ortamda tespit olduğunu göster.
      const envRatio = scopeWeights ? null : envCoverageRatio(parentOwnRules);
      // Once icerik, sonra gorseller — applySourceDots karta DOM ekliyor,
      // innerHTML sonradan yazilirsa noktalar silinirdi.
      fillTechniqueCell(card, {
        id: tech.id, name: tech.name,
        ruleCount: rulesForCell.length, weighted, mitigationCount, envRatio, isSub: false,
        thresholdOverride: parentRollup.threshold,
      });
      applyTechniqueVisuals(
        card, tech.id, rulesForCell.length, mitigationCount, sources, weighted,
        envRatio, namedRuleCount(rulesForCell), parentRollup.threshold, parentRollup.covered
      );

      const subContainer = buildSubtechContainer(tech.id, enrichedData, subMatches, scopeWeights);
      card.style.cursor = 'pointer';

      // Alt tekniği olan kartlarda subContainer kartın DOM ÇOCUĞU olarak
      // eklenir (col'un değil) — hem CSS :hover'ın karttan flyout'a geçerken
      // kopmaması (hover, torunlar dahil sürer, kardeşler dahil sürmez) hem
      // de position:absolute'in doğru karta göre konumlanması için şart.
      // Alt tekniği olmayan kartlarda subContainer boş — hiç eklenmez
      // (yoksa görünmez de olsa hover/click yakalayan hayalet bir kutu olur).
      if (subContainer.children.length > 0) {
        card.classList.add('has-subtechs');
        card.appendChild(subContainer);
      }
      // Modal bilinçli olarak fold-up'lı parentRules alır (Direkt + alt
      // teknik başına gruplu görünüm) — drill-down'da tam aile görünsün.
      card.onclick = () => openModal(tech.id, tech.name, parentRules);

      techWrap.appendChild(card);
    });

    header.dataset.tacticStats = JSON.stringify({
      total: tacticTotal,
      covered: tacticCovered,
      techCount: techniques.length,
    });

    if (techWrap.children.length > 0) {
      col.appendChild(techWrap);
      visibleColumns += 1;
    }
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

  updateMatrixStats();
  wireScoreTooltip();
  wireTacticStatsTooltip();
}

// Taktik başlığına gelince Total / Unique Techniques (+%) / Average per
// Technique gösteren popup — kullanıcının paylaştığı referans görseldeki
// gibi. Veri renderMatrix()'in taktik döngüsünde header.dataset.tacticStats'a
// yazılıyor (arama filtresinden bağımsız, taktiğin TÜM teknikleri üzerinden).
function wireTacticStatsTooltip() {
  let tip = null;
  document.querySelectorAll('.tactic-header[data-tactic-stats]').forEach(header => {
    header.addEventListener('mouseenter', () => {
      if (tip) tip.remove();
      let d;
      try { d = JSON.parse(header.dataset.tacticStats || '{}'); } catch { return; }
      const pct = d.techCount > 0 ? Math.round((d.covered / d.techCount) * 100) : 0;
      const avg = d.covered > 0 ? Math.round(d.total / d.covered) : 0;
      const totalShown = Math.round(d.total * 10) / 10;
      tip = document.createElement('div');
      tip.className = 'tactic-stats-tooltip';
      tip.innerHTML = `
        <div class="tactic-stats-title">${_esc(header.textContent)}</div>
        <div class="tst-row"><span class="tst-lbl">Toplam</span><span class="tst-val">${totalShown}</span></div>
        <div class="tst-row"><span class="tst-lbl">Tespitli Teknik</span><span class="tst-val">${d.covered} (%${pct})</span></div>
        <div class="tst-row"><span class="tst-lbl">Teknik Başına Ort.</span><span class="tst-val">${avg}</span></div>
      `;
      document.body.appendChild(tip);
      // Basliğin ALTINA konumlanir (yana değil) — başlık zaten kolonun en
      // üstünde, sağda/solda komşu kolonlarla çakışma riski olmadan altta
      // rahatça yer var. Sağa taşarsa sola, ekrana clamp'lenir.
      const rect = header.getBoundingClientRect();
      const tipRect = tip.getBoundingClientRect();
      const gap = 6;
      let left = rect.left;
      if (left + tipRect.width + 8 > window.innerWidth) {
        left = window.innerWidth - tipRect.width - 8;
      }
      left = Math.max(8, left);
      tip.style.left = `${left}px`;
      tip.style.top = `${rect.bottom + gap}px`;
      // Baslangic durumu (opacity:0, kucuk transform) commit olsun diye
      // reflow zorlanir, sonra .visible eklenir — CSS transition boylece
      // gercekten "buyuyerek" acilir (kullanici: "az aksiyon kat").
      void tip.offsetWidth;
      tip.classList.add('visible');
    });
    header.addEventListener('mouseleave', () => { if (tip) { tip.remove(); tip = null; } });
  });
}

function updateMatrixStats() {
  setMatrixStatLabels(['Teknik','Tespit','Kapsamsız','Mitigation','Ort. Skor','Alt Teknik']);

  // Aynı teknik birden fazla taktikte görünebilir (örn. T1078 dört taktikte).
  // Metrikler benzersiz teknik üzerinden sayılır, ekrandaki kart sayısı üzerinden değil.
  const uniqBy = (rows) => [...new Map(rows.map(r => [r.tech_id, r])).values()];
  const parents = uniqBy(visibleExportRows.filter(r => r.type === 'technique'));
  const subs    = uniqBy(visibleExportRows.filter(r => r.type === 'subtechnique'));

  // İki ayrık kova — toplamı totalP. Mitigation ayrı kova değil; haritada
  // kalkan işareti olarak görünür, burada bilgi amaçlı ayrıca sayılır.
  // r.covered: kendi doğrudan kuralı VEYA en az bir alt tekniği tespitliyse
  // true (familyRollup() — bkz. renderMatrix()). named_rule_count>0 DEĞİL,
  // çünkü o yalnızca kendi payını sayar, aileyi değil.
  const totalP    = parents.length;
  const detected  = parents.filter(r => r.covered).length;
  const uncovered = totalP - detected;
  const mitigated = parents.filter(r => r.mitigation_checked > 0).length;
  const covPct    = totalP ? Math.round(detected / totalP * 100) : 0;

  const totalS    = subs.length;
  const detectedS = subs.filter(r => r.named_rule_count > 0).length;

  // Ort. Skor: esik-agirlikli ortalama, alt teknikler dahil ama daha dusuk
  // carpanla (bkz. SUBTECHNIQUE_AVG_WEIGHT). Ayni formul app.py
  // _compute_gap_analysis()'teki _avg_weight() ile birebir ayni olmali.
  const avgWeight = (r, isSub) => {
    const w = Math.max(r.rule_threshold ?? DEFAULT_RULE_THRESHOLD, 0);
    return isSub ? w * SUBTECHNIQUE_AVG_WEIGHT : w;
  };
  const scoreWeightTotal = parents.reduce((s, r) => s + r.score * avgWeight(r, false), 0)
    + subs.reduce((s, r) => s + r.score * avgWeight(r, true), 0);
  const weightTotal = parents.reduce((s, r) => s + avgWeight(r, false), 0)
    + subs.reduce((s, r) => s + avgWeight(r, true), 0);
  const avgScore = weightTotal ? Math.round(scoreWeightTotal / weightTotal * 100) : 0;

  // Ust bar ile serit ayni sayiyi gostersin — ortam secilince ikisi birden duser
  const topCovered = document.getElementById('coveredTechs');
  if (topCovered) topCovered.textContent = `${detected} / ${totalP}`;

  const setVal = (id, text, cls) => {
    const el = document.getElementById(id);
    if (!el) return;
    el.textContent = text;
    el.className = 'mstat-val' + (cls ? ' ' + cls : '');
  };

  setVal('ms-total',    totalP);
  setVal('ms-covered',  totalP ? `${detected} / ${totalP} (${covPct}%)` : '—',
    covPct >= 70 ? 'good' : covPct >= 40 ? 'mid' : 'bad');
  setVal('ms-uncovered', uncovered, uncovered === 0 ? 'good' : 'bad');
  setVal('ms-mitigated', mitigated, mitigated > 0 ? 'mid' : 'muted');
  setVal('ms-score',   avgScore + '%',
    avgScore >= 60 ? 'good' : avgScore >= 35 ? 'mid' : 'bad');
  setVal('ms-sub',      totalS ? `${detectedS} / ${totalS}` : '—',
    totalS && detectedS / totalS >= 0.5 ? 'good' : 'muted');
}

// Teknik kartları üzerine gelinince ad + rengin gradyanda nerede oldugunu
// + kapsayan ürünleri (yalnizca renk) gösteren sade bir tooltip. Bilinçli
// olarak kaldırılanlar (kullanıcı kararı — "artık sadece renkler
// konuşacak"): tespit sayısı/hedef, mitigation, tehdit grubu sayısı, ortam
// oranı — hepsi sayısal detaydı. Bu bilgiler API'den hâlâ geliyor
// (card.dataset.scoreData içinde), sadece burada basılmıyor.
function wireScoreTooltip() {
  let tip = null;
  document.querySelectorAll('.technique-card[data-score-data], .subtech-card[data-score-data]')
    .forEach(card => {
      card.addEventListener('mouseenter', () => {
        if (tip) tip.remove();
        let d;
        try { d = JSON.parse(card.dataset.scoreData || '{}'); } catch { return; }
        if (!d.techId) return;
        const legendCursor = document.getElementById('scoreLegendCursor');
        if (legendCursor) {
          legendCursor.style.left = `${d.score}%`;
          legendCursor.classList.add('active');
        }
        const colorMap = productColorMap();
        const dots = [...new Set(d.sources)]
          .map(s => `<span class="tt-dot" style="background:${colorMap[s] || '#666'}" title="${_esc(s)}"></span>`)
          .join('');
        tip = document.createElement('div');
        tip.className = 'score-tooltip';
        tip.innerHTML = `
          <div class="score-tooltip-title">${_esc(d.techId)} · ${_esc(d.name || '')}</div>
          <div class="tt-spectrum" title="Kapsama skoru: renk gradyanındaki konumu">
            <div class="tt-spectrum-bar" style="background: linear-gradient(90deg, ${_scoreGradientStops()})"></div>
            <div class="tt-spectrum-marker" style="left:${d.score}%"></div>
          </div>
          ${dots ? `<div class="tt-dots-row">${dots}</div>` : ''}
        `;
        document.body.appendChild(tip);
        // Kartin YANINA konumlandirilir (alt tarafina degil) — alt teknigi
        // olan kartlarda subtech-container zaten kartin ALTINDA aciliyor;
        // tooltip de oraya konsaydi ikisi ayni alanda ust uste biner, tooltip
        // (z-index 2100) flyout'u (z-index 5) tamamen ortuurdu. Sagda yer
        // yoksa sola donuyor, dikeyde kartin ustune hizalanip ekrana clamp'lenir.
        const rect = card.getBoundingClientRect();
        const tipRect = tip.getBoundingClientRect();
        const gap = 8;
        const overflowsRight = rect.right + gap + tipRect.width > window.innerWidth;
        const left = overflowsRight
          ? Math.max(8, rect.left - tipRect.width - gap)
          : rect.right + gap;
        const top = Math.max(8, Math.min(rect.top, window.innerHeight - tipRect.height - 8));
        tip.style.left = `${left}px`;
        tip.style.top = `${top}px`;
      });
      card.addEventListener('mouseleave', () => {
        if (tip) { tip.remove(); tip = null; }
        document.getElementById('scoreLegendCursor')?.classList.remove('active');
      });
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
    // Matristeki ortam seçimiyle aynı kapsamı kullan — iki ekran çelişmesin.
    const scopeQuery = matrixScopeEnvId ? `?environment_id=${matrixScopeEnvId}` : '';
    const res = await apiFetch(`/api/gap-analysis${scopeQuery}`);
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
  // Payda: ana teknikler. İki ayrık kova (tespit / kapsamsız) toplamı total
  // eder — matris şeridiyle aynı tanım. Mitigation ayrı kova değil, bilgi.
  const total     = ov.total_techniques || 0;
  const detected  = ov.detected_techniques || 0;
  const mitigated = ov.mitigated_techniques || 0;
  const uncovered = ov.uncovered_techniques || 0;
  const pct       = ov.coverage_pct || 0;
  const mature = ov.mature_techniques || 0;
  const maturityPct = ov.maturity_pct || 0;
  const averageScore = ov.average_score_pct || 0;
  const critCount = ov.critical_gap_count || 0;
  const subTotal    = ov.total_subtechniques    || 0;
  const subDetected = ov.detected_subtechniques || 0;

  const TACTIC_TR = {
    'reconnaissance':'Reconnaissance','resource-development':'Resource Development',
    'initial-access':'Initial Access','execution':'Execution',
    'persistence':'Persistence','privilege-escalation':'Privilege Escalation',
    'stealth':'Stealth','defense-impairment':'Defense Impairment','credential-access':'Credential Access',
    'discovery':'Discovery','lateral-movement':'Lateral Movement',
    'collection':'Collection','command-and-control':'Command & Control',
    'exfiltration':'Exfiltration','impact':'Impact'
  };

  // Stat cards — ana teknikler üzerinden (matris şeridiyle aynı tanım)
  let html = `<div class="gap-stat-cards">
    <div class="gap-stat-card">
      <div class="gap-stat-val">${total}</div>
      <div class="gap-stat-lbl">Ana Teknik</div>
      <div class="gap-stat-sub">Alt teknik: ${subDetected} / ${subTotal} kendi kuralı var</div>
    </div>
    <div class="gap-stat-card">
      <div class="gap-stat-val good">${detected} <span style="font-size:16px">(${pct}%)</span></div>
      <div class="gap-stat-lbl">Tespit</div>
      <div class="gap-stat-sub">Görebiliyoruz</div>
    </div>
    <div class="gap-stat-card">
      <div class="gap-stat-val danger">${uncovered}</div>
      <div class="gap-stat-lbl">Kapsamsız</div>
      <div class="gap-stat-sub">Hiç tespit yok</div>
    </div>
    <div class="gap-stat-card">
      <div class="gap-stat-val">${mitigated}</div>
      <div class="gap-stat-lbl">Mitigation'ı Olan</div>
      <div class="gap-stat-sub">Bilgi — skora ve renge girmez</div>
    </div>
    <div class="gap-stat-card">
      <div class="gap-stat-val">${averageScore}%</div>
      <div class="gap-stat-lbl">Ortalama Kapsama Skoru</div>
      <div class="gap-stat-sub">Etkin tespit / teknik hedefi</div>
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
  html += `<div class="gap-section-title" style="margin-top:20px">Tespitsiz Teknikler <span style="font-weight:400;color:var(--d-text-3)">— en çok tehdit grubunun kullandığı ilk ${Math.min(critCount, 50)}</span></div>`;
  const gaps = data.critical_gaps || [];
  if (gaps.length === 0) {
    html += '<div style="color:var(--d-text-3);font-size:12px;padding:10px 0">Kritik boşluk yok.</div>';
  } else {
    html += '<div class="gap-critical-list">';
    gaps.forEach(g => {
      const tacticLabel = TACTIC_TR[g.tactic] || g.tactic || '—';
      const safeName = _esc(g.name).replace(/'/g, '&#39;');
      html += `<div class="gap-critical-item" onclick="openGapTechDetail('${_esc(g.tech_id)}','${safeName}')">
        <div class="gap-critical-id">${_esc(g.tech_id)}</div>
        <div class="gap-critical-name">${_esc(g.name)}</div>
        <div class="gap-critical-tactic">${_esc(tacticLabel)}</div>
        <div class="gap-critical-score" title="Bu tekniği kaç tehdit grubu kullanıyor">${g.group_count || 0} grup</div>
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

const PRIORITY_LABEL = {1:'Düşük', 2:'Orta', 3:'Yüksek', 4:'Kritik'};
const STATUS_LABEL = {open:'Açık', in_progress:'Devam', done:'Tamamlandı', cancelled:'İptal'};

function renderActionItems() {
  const tbody = document.getElementById('actionsTableBody');
  const emptyEl = document.getElementById('actionsEmpty');
  if (!tbody) return;

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
  showPanel('actionsPanel');   // bölüm + sekme + veri yüklemesini birlikte yapar
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
// Wire all new panels
// ══════════════════════════════════════════════════════════════
const SCOPE_STATUS_LABELS = { unknown: 'Değerlendirilmedi', none: 'İzlenmiyor', partial: 'Kısmi izleme', full: 'Tam izleme' };
const SCOPE_MODE_LABELS = { agent: 'Ajan', log_forwarding: 'Log yönlendirme', api: 'API', network: 'Ağ gözlemi', hybrid: 'Hibrit', other: 'Diğer' };

function selectedScopeEnvironment() {
  return scopeRegistry?.environments.find(item => item.id === selectedEnvironmentId) || null;
}

async function loadScopeRegistry() {
  const survey = document.getElementById('scopeSurvey');
  if (survey && !scopeRegistry) survey.innerHTML = '<div class="scope-empty"><strong>Kapsam yükleniyor</strong><span>Ortamlar hazırlanıyor.</span></div>';
  const res = await apiFetch('/api/scope-registry');
  if (!res.ok) {
    if (survey) survey.innerHTML = '<div class="scope-empty scope-error"><strong>Kapsam yüklenemedi</strong><span>Sayfayı yenileyip tekrar deneyin.</span></div>';
    return;
  }
  scopeRegistry = await res.json();
  const environments = scopeRegistry.environments || [];
  if (!environments.some(item => item.id === selectedEnvironmentId)) {
    selectedEnvironmentId = (environments.find(item => item.active) || environments[0])?.id || null;
  }
  renderScopeRegistry();
  // Kapsam değişince harita ortam seçicisi ve kart renkleri bayat kalmasın.
  renderMatrixScopeSelect();
  if (mitreObjects.length) renderMatrix();
}

function renderScopeRegistry() {
  if (!scopeRegistry) return;
  const summary = scopeRegistry.summary || {};
  document.getElementById('scopeSummary').innerHTML = [
    ['Aktif ortam', summary.environment_count || 0],
    ['Kayıtlı varlık', Number(summary.asset_count || 0).toLocaleString('tr-TR')],
    ['Değerlendirilen ürün', summary.reviewed_deployments || 0],
  ].map(([label, value]) => `<div class="ops-stat"><strong>${value}</strong><span>${label}</span></div>`).join('');
  const envSelect = document.getElementById('scopeEnvironmentSelect');
  envSelect.innerHTML = scopeRegistry.environments.length
    ? scopeRegistry.environments.map(env => `<option value="${env.id}" ${env.id === selectedEnvironmentId ? 'selected' : ''}>${_esc(env.name)}${env.active ? '' : ' (pasif)'}</option>`).join('')
    : '<option value="">Henüz ortam yok</option>';
  document.getElementById('scopeAddEnvironment').classList.toggle('hidden', !hasRole('admin'));
  document.getElementById('scopeEditEnvironment').classList.toggle('hidden', !hasRole('admin') || !selectedScopeEnvironment());
  document.getElementById('scopeDeleteEnvironment').classList.toggle('hidden', !hasRole('admin') || !selectedScopeEnvironment());
  renderMonitoringSurvey();
}

function openScopeEnvironmentEditor(environment = null) {
  document.getElementById('scopeEnvironmentId').value = environment?.id || '';
  document.getElementById('scopeEnvironmentName').value = environment?.name || '';
  document.getElementById('scopeEnvironmentCode').value = environment?.code || '';
  document.getElementById('scopeEnvironmentOwner').value = environment?.owner || '';
  document.getElementById('scopeEnvironmentCriticality').value = environment?.criticality || 3;
  document.getElementById('scopeEnvironmentCount').value = environment?.asset_count || 0;
  document.getElementById('scopeEnvironmentDescription').value = environment?.description || '';
  document.getElementById('scopeEnvironmentActive').checked = environment ? Boolean(environment.active) : true;
  document.getElementById('scopeEnvironmentEditor').classList.remove('hidden');
  document.getElementById('scopeEnvironmentName').focus();
}

async function saveScopeEnvironment() {
  const id = document.getElementById('scopeEnvironmentId').value;
  const payload = {
    name: document.getElementById('scopeEnvironmentName').value.trim(),
    code: document.getElementById('scopeEnvironmentCode').value.trim(),
    owner: document.getElementById('scopeEnvironmentOwner').value.trim(),
    criticality: Number(document.getElementById('scopeEnvironmentCriticality').value),
    asset_count: Number(document.getElementById('scopeEnvironmentCount').value),
    description: document.getElementById('scopeEnvironmentDescription').value.trim(),
    active: document.getElementById('scopeEnvironmentActive').checked,
  };
  const res = await apiFetch(id ? `/api/environments/${id}` : '/api/environments',
    { method: id ? 'PUT' : 'POST', headers: {'Content-Type': 'application/json'}, body: JSON.stringify(payload) });
  const data = await res.json().catch(() => ({}));
  if (!res.ok) return alert(data.error || 'Ortam kaydedilemedi');
  if (!id && data.id) selectedEnvironmentId = data.id;
  document.getElementById('scopeEnvironmentEditor').classList.add('hidden');
  await loadScopeRegistry();
}

async function deleteScopeEnvironment() {
  const environment = selectedScopeEnvironment();
  if (!environment) return;
  if (!confirm(`"${environment.name}" ortamı ve tüm izleme kayıtları silinecek. Emin misiniz?`)) return;
  const res = await apiFetch(`/api/environments/${environment.id}`, { method: 'DELETE' });
  if (!res.ok) {
    const data = await res.json().catch(() => ({}));
    return alert(data.error || 'Ortam silinemedi');
  }
  selectedEnvironmentId = null;
  await loadScopeRegistry();
}

function renderMonitoringSurvey() {
  const target = document.getElementById('scopeSurvey');
  const environment = selectedScopeEnvironment();
  if (!environment) {
    target.innerHTML = '<div class="scope-empty"><strong>İlk ortamı oluşturun</strong><span>Kapsamı tanımlamak için en az bir ortam kaydı gerekir.</span></div>';
    return;
  }
  const deployments = new Map((environment.deployments || []).map(item => [item.product_id, item]));
  const canEdit = hasRole('editor');
  // Yalnızca tespit kaynakları izleme anketine girer; önleyici kontrol ve CTI
  // ürünleri haritayı boyamadığı için burada sorulmaz.
  const products = (scopeRegistry.products || []).filter(
    p => (p.category || 'tespit_kaynagi') === 'tespit_kaynagi'
  );
  const rows = products.map(product => {
    const item = deployments.get(product.id) || {};
    const status = item.monitoring_status || 'unknown';
    const mode = item.monitoring_mode || 'other';
    const compatible = (scopeRegistry.connectors || []).filter(c => c.product_name === product.name && c.enabled);
    const connectorOptions = ['<option value="">Connector seçilmedi</option>', ...compatible.map(c =>
      `<option value="${c.id}" ${c.id === item.connector_id ? 'selected' : ''}>${_esc(c.name)}${c.last_status === 'success' ? '' : ' · doğrulanmadı'}</option>`)].join('');
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
  const emptyMsg = '<div class="scope-empty"><strong>Tespit kaynağı ürün yok</strong><span>Ayarlar → Ürün Yönetimi bölümünden en az bir "tespit kaynağı" ürün ekleyin.</span></div>';
  target.innerHTML = `<div class="scope-survey-head"><div><span class="scope-path">${_esc(environment.name)}</span><h2>Ürün İzleme Anketi</h2><p>${Number(environment.asset_count || 0).toLocaleString('tr-TR')} varlık · Kritiklik ${environment.criticality}/5</p></div><div class="scope-trust-note"><strong>Bu anket haritayı doğrudan besler</strong><span>Bir ürün burada izlemiyorsa, o ürünün tespitleri bu ortamda kapsamaya sayılmaz.</span></div></div>
    <div class="scope-monitor-list">${rows || emptyMsg}</div>
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
  const environment = selectedScopeEnvironment();
  if (!environment) return;
  const deployments = [...document.querySelectorAll('.scope-monitor-row')].map(row => ({
    product_id: Number(row.dataset.productId), monitoring_status: row.querySelector('.scope-monitor-status').value,
    monitoring_mode: row.querySelector('.scope-monitor-mode').value, coverage_percent: Number(row.querySelector('.scope-monitor-percent').value),
    connector_id: row.querySelector('.scope-monitor-connector').value || null, owner: row.querySelector('.scope-monitor-owner').value.trim(),
    notes: row.querySelector('.scope-monitor-notes').value.trim()
  }));
  const button = document.getElementById('scopeSaveMonitoring');
  button.disabled = true;
  const res = await apiFetch(`/api/environments/${environment.id}/monitoring`, { method: 'PUT', headers: {'Content-Type': 'application/json'}, body: JSON.stringify({deployments}) });
  const data = await res.json().catch(() => ({}));
  if (!res.ok) { button.disabled = false; return alert(data.error || 'İzleme anketi kaydedilemedi'); }
  await loadScopeRegistry();
}

function wireScopeRegistry() {
  document.getElementById('scopeAddEnvironment')?.addEventListener('click', () => openScopeEnvironmentEditor());
  document.getElementById('scopeEditEnvironment')?.addEventListener('click', () => openScopeEnvironmentEditor(selectedScopeEnvironment()));
  document.getElementById('scopeDeleteEnvironment')?.addEventListener('click', deleteScopeEnvironment);
  document.getElementById('scopeSaveEnvironment')?.addEventListener('click', saveScopeEnvironment);
  document.querySelectorAll('[data-scope-cancel]').forEach(button => button.addEventListener('click', () => button.closest('.scope-editor').classList.add('hidden')));
  document.getElementById('scopeEnvironmentSelect')?.addEventListener('change', event => {
    selectedEnvironmentId = Number(event.target.value) || null;
    renderScopeRegistry();
  });
}

function wireNewPanels() {
  // Not: Bilgilendirme wiki'si /docs route'una taşındı (templates/docs.html),
  // sekme geçişi orada kendi inline script'inde.

  // Panel veri yükleyicileri artık PANEL_LOADERS üzerinden showPanel()'de
  // tetikleniyor (bkz. wireNavigation) — sekmeye tıklanınca da çalışsın diye.

  document.getElementById('dataQualityRefresh')?.addEventListener('click', loadDataQuality);
  document.getElementById('dataQualityRepair')?.addEventListener('click', repairDataQuality);
  document.getElementById('qualitySeverity')?.addEventListener('change', renderQualityIssues);
  document.getElementById('qualityType')?.addEventListener('change', renderQualityIssues);
  document.getElementById('qualitySearch')?.addEventListener('input', renderQualityIssues);

  document.getElementById('targetsSearch')?.addEventListener('input', renderTargetsTable);
  // Delege edilmis dinleyici: tbody her renderTargetsTable()'da yeniden
  // yazildigi icin tek tek input'lara degil sabit ust elemana baglanir.
  document.getElementById('targetsTableBody')?.addEventListener('change', (e) => {
    if (e.target.matches('.targets-threshold-input')) saveTargetThreshold(e.target);
  });

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
}


function setMatrixStatLabels(labels) {
  document.querySelectorAll('#matrixStatBar .mstat-lbl').forEach((element, index) => {
    element.textContent = labels[index] || '';
  });
}

