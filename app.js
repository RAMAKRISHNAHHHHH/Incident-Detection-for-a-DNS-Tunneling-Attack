(() => {
  let allQueries = [];
  let incidents = [];
  let selectedApex = null;
  let filterText = '';

  const el = (id) => document.getElementById(id);

  function init(queries) {
    allQueries = queries;
    incidents = Detector.analyze(allQueries);
    selectedApex = incidents[0]?.apex || null;
    renderStats();
    renderIncidents();
    renderDetail();
    streamLog();
  }

  // ---------------- Stats strip ----------------

  function renderStats() {
    const critical = incidents.filter(i => i.severity === 'critical').length;
    const suspicious = incidents.filter(i => i.severity === 'suspicious').length;
    const topScore = incidents[0]?.score ?? 0;

    el('stat-total').textContent = allQueries.length.toLocaleString();
    el('stat-domains').textContent = incidents.length;
    el('stat-flagged').textContent = critical + suspicious;
    el('stat-top').textContent = topScore;

    const flaggedTile = el('tile-flagged');
    flaggedTile.className = 'stat ' + (critical > 0 ? 'tone-critical' : suspicious > 0 ? 'tone-suspicious' : 'tone-safe');
    const topTile = el('tile-top');
    topTile.className = 'stat ' + (topScore >= 70 ? 'tone-critical' : topScore >= 40 ? 'tone-suspicious' : 'tone-safe');
  }

  // ---------------- Incident list ----------------

  function renderIncidents() {
    const list = el('incident-list');
    const q = filterText.trim().toLowerCase();
    const filtered = incidents.filter(i =>
      !q || i.apex.toLowerCase().includes(q) || i.sourceIPs.some(ip => ip.includes(q))
    );

    el('incident-count').textContent = `${filtered.length} domain${filtered.length === 1 ? '' : 's'}`;

    if (!filtered.length) {
      list.innerHTML = `<div class="empty-hint">No domains match “${escapeHtml(filterText)}”.</div>`;
      return;
    }

    list.innerHTML = filtered.map((inc, idx) => `
      <div class="incident-row ${inc.apex === selectedApex ? 'active' : ''}" data-apex="${escapeHtml(inc.apex)}" style="animation-delay:${idx * 22}ms">
        <div class="sev-bar ${inc.severity}"></div>
        <div class="incident-main">
          <div class="domain">${escapeHtml(inc.apex)}</div>
          <div class="meta">${inc.totalQueries} queries · ${inc.uniqueSubdomains} unique subdomains · ${inc.sourceIPs.length} source IP${inc.sourceIPs.length === 1 ? '' : 's'} · dominant type ${inc.dominantType}</div>
        </div>
        <div class="score-pill ${inc.severity}">${inc.score}</div>
        <div class="sev-label">${severityLabel(inc.severity)}</div>
      </div>
    `).join('');

    list.querySelectorAll('.incident-row').forEach(row => {
      row.addEventListener('click', () => {
        selectedApex = row.dataset.apex;
        renderIncidents();
        renderDetail();
      });
    });
  }

  function severityLabel(sev) {
    if (sev === 'critical') return 'Likely tunneling';
    if (sev === 'suspicious') return 'Needs review';
    return 'Normal pattern';
  }

  // ---------------- Detail panel ----------------

  function renderDetail() {
    const inc = incidents.find(i => i.apex === selectedApex);
    const wrap = el('detail-panel');
    if (!inc) {
      wrap.innerHTML = '<div class="empty-hint">Select a domain to inspect its signals.</div>';
      return;
    }

    el('detail-title').textContent = inc.apex;
    el('detail-score').className = `score-pill ${inc.severity}`;
    el('detail-score').textContent = inc.score;

    el('metric-grid').innerHTML = `
      <div class="metric-cell"><div class="k">Avg. label entropy</div><div class="v">${inc.avgEntropy.toFixed(2)} bits</div></div>
      <div class="metric-cell"><div class="k">Longest label</div><div class="v">${inc.maxLabelLen} chars</div></div>
      <div class="metric-cell"><div class="k">Unique subdomain ratio</div><div class="v">${(inc.uniqueRatio * 100).toFixed(0)}%</div></div>
      <div class="metric-cell"><div class="k">Query rate</div><div class="v">${inc.queriesPerMinute.toFixed(1)}/min</div></div>
      <div class="metric-cell"><div class="k">TXT/NULL/CNAME share</div><div class="v">${(inc.tunnelingTypeRatio * 100).toFixed(0)}%</div></div>
      <div class="metric-cell"><div class="k">Source IPs</div><div class="v">${inc.sourceIPs.join(', ')}</div></div>
    `;

    const signalNames = {
      entropyTerm: 'Entropy',
      lengthTerm: 'Label length',
      charsetTerm: 'Charset shape',
      uniqueTerm: 'Uniqueness',
      typeTerm: 'Query type',
      rateTerm: 'Query rate',
      volumeTerm: 'Volume',
    };
    el('signal-bars').innerHTML = Object.entries(inc.signals).map(([k, v]) => `
      <div class="signal-row">
        <div class="name">${signalNames[k]}</div>
        <div class="signal-track"><div class="signal-fill" style="width:${(v * 100).toFixed(0)}%; background:${v > 0.7 ? 'var(--critical)' : v > 0.4 ? 'var(--suspicious)' : 'var(--safe)'}"></div></div>
        <div class="pct">${(v * 100).toFixed(0)}%</div>
      </div>
    `).join('');

    el('sample-queries').innerHTML = inc.samples.map(s => `
      <div class="sample-line"><span class="qtype">${s.queryType}</span><span class="ts">${new Date(s.timestamp).toLocaleTimeString()}</span>${escapeHtml(s.queryName)}</div>
    `).join('') || '<div class="empty-hint">No sample queries.</div>';
  }

  // ---------------- Live log stream (hero) ----------------

  function streamLog() {
    const stream = el('log-stream');
    stream.innerHTML = '';
    const ordered = [...allQueries].sort((a, b) => new Date(a.timestamp) - new Date(b.timestamp));
    let i = 0;
    const chunk = Math.max(1, Math.floor(ordered.length / 120));

    clearInterval(window.__logTimer);
    window.__logTimer = setInterval(() => {
      if (i >= ordered.length) { clearInterval(window.__logTimer); return; }
      for (let c = 0; c < chunk && i < ordered.length; c++, i++) {
        const q = ordered[i];
        const { apex, subLabels } = Detector.splitName(q.queryName);
        const inc = incidents.find(x => x.apex === apex);
        const entropy = subLabels.length ? Detector.shannonEntropy(subLabels.join('')) : 0;
        const flag = inc && inc.severity !== 'clean' && entropy > 3.2 ? inc.severity : null;

        const line = document.createElement('div');
        line.className = 'log-line' + (flag ? ` flag-${flag}` : '');
        line.innerHTML = `<span class="ts">${new Date(q.timestamp).toLocaleTimeString()}</span><span class="ip">${q.srcIp}</span>${q.queryType.padEnd(4)} ${escapeHtml(q.queryName)}${flag ? `<span class="tag">${flag}</span>` : ''}`;
        stream.appendChild(line);
      }
      stream.scrollTop = stream.scrollHeight;
    }, 45);
  }

  // ---------------- Helpers ----------------

  function escapeHtml(str) {
    return String(str).replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
  }

  // ---------------- Controls ----------------

  window.addEventListener('DOMContentLoaded', () => {
    init(DataSource.buildDataset());

    el('search-box').addEventListener('input', (e) => {
      filterText = e.target.value;
      renderIncidents();
    });

    el('btn-rescan').addEventListener('click', () => {
      init(DataSource.buildDataset());
    });

    el('file-input').addEventListener('change', (e) => {
      const file = e.target.files[0];
      if (!file) return;
      const reader = new FileReader();
      reader.onload = () => {
        try {
          const parsed = DataSource.parseUploadedLog(reader.result);
          if (!parsed.length) throw new Error('No valid query records found.');
          init(parsed);
        } catch (err) {
          alert('Could not read log file: ' + err.message);
        }
      };
      reader.readAsText(file);
      e.target.value = '';
    });
  });
})();
