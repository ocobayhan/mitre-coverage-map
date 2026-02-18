const SOURCE_COLORS = { 'QRadar': 'var(--color-qradar)', 'DFE': 'var(--color-dfe)', 'DefO365': 'var(--color-mdo)', 'DefIdentity': 'var(--color-mdi)', 'Other': 'var(--color-other)' };
const PRIORITY_ORDER = ['QRadar', 'DFE', 'DefO365', 'DefIdentity', 'Other'];
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

async function init() {
  try {
    const [mitreRes, rulesRes, notesRes] = await Promise.all([
      fetch('/api/mitre'),
      fetch('/api/rules'),
      fetch('/api/mitigation-notes')
    ]);

    if (!mitreRes.ok) throw new Error('MITRE verisi yüklenemedi');
    mitreObjects = (await mitreRes.json()).objects || [];
    userRules = rulesRes.ok ? await rulesRes.json() : [];
    const notes = notesRes.ok ? await notesRes.json() : [];
    mitigationNotes = normalizeNotes(notes);

    prepareMitreLookup();
    populateTacticSelect();
    wireActions();
    renderMatrix();
  } catch (e) {
    document.getElementById('matrix').innerHTML = `Veri Hatası: ${e.message}`;
  }
}
async function reloadData() {
  const [rulesRes, notesRes] = await Promise.all([
    fetch('/api/rules'),
    fetch('/api/mitigation-notes')
  ]);
  userRules = rulesRes.ok ? await rulesRes.json() : [];
  const notes = notesRes.ok ? await notesRes.json() : [];
  mitigationNotes = normalizeNotes(notes);
}

function normalizeNotes(list) {
  const out = {};
  list.forEach(n => {
    if (!out[n.technique_id]) out[n.technique_id] = {};
    out[n.technique_id][n.mitigation_id] = { checked: !!n.checked, comment: n.comment || '' };
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
            if (prettyTactic) matrixStructure[prettyTactic].push({ id: tid, name: obj.name });
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

function populateTacticSelect() {
  const select = document.getElementById('newRuleTactic');
  select.innerHTML = '';
  tacticOrder.forEach(t => {
    const opt = document.createElement('option');
    opt.value = t;
    opt.textContent = t;
    select.appendChild(opt);
  });
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
  if (!mitigationNotes[techId][mitigationId]) mitigationNotes[techId][mitigationId] = { checked: false, comment: '' };
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
  const start = { r: 42, g: 47, b: 51 };
  const end = { r: 46, g: 125, b: 50 };
  const r = Math.round(start.r + (end.r - start.r) * score);
  const g = Math.round(start.g + (end.g - start.g) * score);
  const b = Math.round(start.b + (end.b - start.b) * score);
  return `rgb(${r}, ${g}, ${b})`;
}



function applyTechniqueVisuals(card, rulesCount, mitigationCount, winningSource) {
  const score = computeScore(rulesCount, mitigationCount);
  card.style.backgroundColor = scoreToColor(score);
  card.classList.toggle('covered', (rulesCount > 0 || mitigationCount > 0));

  if (mitigationCount > 0) {
    card.innerHTML += `<div class="mitigation-badge">OK${mitigationCount}</div>`;
  }
  if (winningSource) {
    card.innerHTML += `<div class="source-pill" style="background:${SOURCE_COLORS[winningSource]}"></div>`;
  }
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

function buildSubtechContainer(parentId, enrichedData) {
  const container = document.createElement('div');
  container.className = 'subtech-container';
  const subTechs = subTechsByParent[parentId] || [];
  if (subTechs.length == 0) return container;

  subTechs.forEach(st => {
    const subCard = document.createElement('div');
    subCard.className = 'subtech-card';

    const rulesForSub = enrichedData.filter(r => r.tid == st.id);
    let winningSource = null;
    if (rulesForSub.length > 0) {
      let highestPriorityIndex = 999;
      rulesForSub.forEach(r => {
        const pIndex = PRIORITY_ORDER.indexOf(r.source);
        if (pIndex != -1 && pIndex < highestPriorityIndex) {
          highestPriorityIndex = pIndex;
          winningSource = r.source;
        }
      });
    }

    const mitigationCount = getCheckedMitigationCountForTech(st.id);
    applyTechniqueVisuals(subCard, rulesForSub.length, mitigationCount, winningSource);

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

function renderMatrix() {
  const enrichedData = enrichRules();
  const container = document.getElementById('matrix');
  container.innerHTML = '';
  currentRulesByParent = {};

  document.getElementById('totalRules').innerText = userRules.length;
  const uniqueParents = new Set(enrichedData.map(r => r.parentId));
  document.getElementById('coveredTechs').innerText = uniqueParents.size;

  tacticOrder.forEach(tactic => {
    const col = document.createElement('div');
    col.className = 'tactic-column';
    col.innerHTML = `<div class="tactic-header">${tactic}</div>`;
    const techniques = (matrixStructure[tactic] || []).sort((a, b) => a.id.localeCompare(b.id));

    techniques.forEach(tech => {
      const rulesForCell = enrichedData.filter(r => r.parentId == tech.id);
      const card = document.createElement('div');
      card.className = 'technique-card';
      card.dataset.techId = tech.id;
      currentRulesByParent[tech.id] = rulesForCell.length;

      let winningSource = null;
      if (rulesForCell.length > 0) {
        let highestPriorityIndex = 999;
        rulesForCell.forEach(r => {
          const pIndex = PRIORITY_ORDER.indexOf(r.source);
          if (pIndex != -1 && pIndex < highestPriorityIndex) {
            highestPriorityIndex = pIndex;
            winningSource = r.source;
          }
        });
        card.style.borderColor = '#fff';
      }

      const mitigationCount = getCheckedMitigationCountForParent(tech.id);
      applyTechniqueVisuals(card, rulesForCell.length, mitigationCount, winningSource);

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

      const subContainer = buildSubtechContainer(tech.id, enrichedData);
      card.style.cursor = 'pointer';
      card.onclick = () => {
        if (subContainer) subContainer.classList.toggle('open');
      };

      col.appendChild(card);
      col.appendChild(subContainer);
    });

    container.appendChild(col);
  });
}


async function addNewRule() {
  const name = document.getElementById('newRuleName').value.trim();
  const tactic = document.getElementById('newRuleTactic').value.trim();
  const tech = document.getElementById('newRuleTech').value.trim();
  const source = document.getElementById('newRuleSource').value.trim();

  if (!name || !tactic || !tech || !source) {
    alert('Lütfen alanları doldurun.');
    return;
  }

  const res = await fetch('/api/rules', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ name, tactic, tech, source })
  });

  if (!res.ok) {
    const err = await res.json().catch(() => ({}));
    alert(err.error || 'Kural eklenemedi');
    return;
  }

  const created = await res.json();
  userRules.push(created);
  renderMatrix();
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
  body.innerHTML = '';

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
        <textarea class="mitigation-comment" data-tech="${parentId}" data-mit="${m.id}" placeholder="Ekip / uygulama notu">${note.comment || ''}</textarea>
        <div class="mitigation-pop" data-tech="${parentId}" data-mit="${m.id}">${m.description || 'Aciklama bulunamadi.'}</div>
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
      tbody += `<tr>
        <td>${r.name}</td>
        <td style="text-align:right">
          <span class="source-tag" style="background:${SOURCE_COLORS[r.source]}">${r.source}</span>
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
      await saveMitigationNote(techId, mitId, note);
    });
  });
  body.querySelectorAll('.mitigation-row textarea').forEach(ta => {
    ta.addEventListener('input', async (e) => {
      const techId = e.target.dataset.tech;
      const mitId = e.target.dataset.mit;
      const note = getMitigationNote(techId, mitId);
      note.comment = e.target.value;
      await saveMitigationNote(techId, mitId, note);
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
      comment: note.comment || ''
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

function wireActions() {
  wireNavigation();
  wireSidebarToggle();
  document.getElementById('btnAdd').addEventListener('click', addNewRule);
  document.getElementById('modalClose').addEventListener('click', () => {
    document.getElementById('ruleModal').style.display = 'none';
  });

  const resetBtn = document.getElementById('btnReset');
  if (resetBtn) {
    resetBtn.addEventListener('click', async () => {
      const confirmText = prompt('Islemi onaylamak icin RESET yazin:');
      if (confirmText !== 'RESET') return;
      const res = await fetch('/api/admin/reset', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ confirm: 'RESET', reseed: true })
      });
      if (!res.ok) {
        const err = await res.json().catch(() => ({}));
        alert(err.error || 'Sifirlama basarisiz');
        return;
      }
      await reloadData();
      renderMatrix();
      alert('Veriler sifirlandi ve yeniden yuklendi.');
    });
  }


  const resizer = document.getElementById('dragHandle');
  const matrixContainer = document.getElementById('matrix');
  resizer.addEventListener('mousedown', function (e) {
    e.preventDefault();
    document.addEventListener('mousemove', resize);
    document.addEventListener('mouseup', stopResize);
  });
  function resize(e) {
    const newHeight = e.clientY - matrixContainer.getBoundingClientRect().top;
    if (newHeight > 100 && newHeight < window.innerHeight - 80) matrixContainer.style.height = newHeight + 'px';
  }
  function stopResize() {
    document.removeEventListener('mousemove', resize);
    document.removeEventListener('mouseup', stopResize);
  }
}

init();








