// Reachflow CSV Processor — frontend
(() => {
  const $ = (id) => document.getElementById(id);

  const state = {
    upload: null,       // { upload_id, filename, columns, total_rows, preview }
    jobId: null,
    snapshot: null,
    eventSource: null,
    workerTimer: null,
    timeSeries: [],     // for ETA: array of {t, done}
  };

  // ----------------------- Sidebar / jobs list -----------------------

  async function loadJobsList() {
    try {
      const r = await fetch('/api/jobs');
      const data = await r.json();
      renderJobsList(data.jobs || []);
    } catch (e) {
      $('jobsList').innerHTML = '<div class="empty">Error cargando jobs</div>';
    }
  }

  function renderJobsList(jobs) {
    const el = $('jobsList');
    if (!jobs.length) {
      el.innerHTML = '<div class="empty">Sin trabajos aún</div>';
      return;
    }
    el.innerHTML = jobs.map(j => {
      const active = j.id === state.jobId ? 'active' : '';
      const pct = j.total ? Math.round((j.done_count / j.total) * 100) : 0;
      return `
        <div class="job-item ${active}" data-id="${j.id}">
          <div class="job-item-top">
            <div class="job-item-name" title="${escapeHtml(j.input_name || j.id)}">${escapeHtml(j.input_name || j.id)}</div>
            <button class="job-delete" data-del="${j.id}" title="Borrar trabajo">🗑</button>
          </div>
          <div class="job-item-meta">
            <span class="job-item-status">${j.status}</span>
            <span>· ${j.done_count}/${j.total} (${pct}%)</span>
          </div>
        </div>`;
    }).join('');
    el.querySelectorAll('.job-delete').forEach(b => {
      b.addEventListener('click', (e) => {
        e.stopPropagation();
        deleteJob(b.dataset.del, b.closest('.job-item').querySelector('.job-item-name').textContent);
      });
    });
    el.querySelectorAll('.job-item').forEach(el => {
      el.addEventListener('click', () => openJob(el.dataset.id));
    });
  }

  // ----------------------- Setup view: upload -----------------------

  function setupDropzone() {
    const dz = $('dropZone');
    const fi = $('fileInput');
    dz.addEventListener('click', () => fi.click());
    fi.addEventListener('change', () => fi.files[0] && uploadFile(fi.files[0]));
    ['dragenter', 'dragover'].forEach(ev => dz.addEventListener(ev, e => {
      e.preventDefault(); dz.classList.add('dragover');
    }));
    ['dragleave', 'drop'].forEach(ev => dz.addEventListener(ev, e => {
      e.preventDefault(); dz.classList.remove('dragover');
    }));
    dz.addEventListener('drop', e => {
      e.preventDefault();
      const f = e.dataTransfer.files[0];
      if (f) uploadFile(f);
    });
  }

  async function uploadFile(file) {
    const fd = new FormData();
    fd.append('file', file);
    $('dropZone').querySelector('.dz-title').textContent = `Subiendo ${file.name}…`;
    try {
      const r = await fetch('/api/jobs/upload', { method: 'POST', body: fd });
      if (!r.ok) throw new Error((await r.json()).detail || r.statusText);
      const data = await r.json();
      state.upload = data;
      showSetupForm(data);
    } catch (e) {
      alert('Error al subir: ' + e.message);
      $('dropZone').querySelector('.dz-title').textContent = 'Arrastrá tu CSV acá';
    }
  }

  function showSetupForm(up) {
    $('fileName').textContent = up.filename;
    $('rowCount').textContent = up.total_rows;
    const sel = $('domainCol');
    sel.innerHTML = '';
    up.columns.forEach(c => {
      const o = document.createElement('option');
      o.value = c; o.textContent = c;
      if (/dom(ain|inio)|website|url/i.test(c)) o.selected = true;
      sel.appendChild(o);
    });
    // preview
    const pt = $('previewTable');
    if (up.preview && up.preview.length) {
      const head = up.columns.map(c => `<th>${escapeHtml(c)}</th>`).join('');
      const rows = up.preview.map(r =>
        '<tr>' + up.columns.map(c => `<td>${escapeHtml(r[c] ?? '')}</td>`).join('') + '</tr>'
      ).join('');
      pt.innerHTML = `<table><thead><tr>${head}</tr></thead><tbody>${rows}</tbody></table>`;
    } else {
      pt.innerHTML = '<div class="empty">Sin filas</div>';
    }
    $('setupForm').classList.remove('hidden');
  }

  async function startJob() {
    if (!state.upload) return;
    const fd = new FormData();
    fd.append('upload_id', state.upload.upload_id);
    fd.append('filename', state.upload.filename);
    fd.append('domain_column', $('domainCol').value);
    fd.append('per_row_timeout', $('optTimeout').value);
    fd.append('max_concurrent', $('optConcurrent').value);
    fd.append('parallel_workers', $('optWorkers').value);
    const vMode = $('optVariantsMode').value;
    fd.append('variants_mode', vMode);
    fd.append('discover_variants', vMode === 'none' ? 'false' : 'true');
    fd.append('do_whois', $('optWhois').checked ? 'true' : 'false');
    fd.append('autostart', 'true');
    try {
      const r = await fetch('/api/jobs/create', { method: 'POST', body: fd });
      if (!r.ok) throw new Error((await r.json()).detail || r.statusText);
      const data = await r.json();
      openJob(data.job_id);
      loadJobsList();
    } catch (e) {
      alert('Error: ' + e.message);
    }
  }

  // ----------------------- Job view -----------------------

  function openJob(jobId) {
    if (state.eventSource) { state.eventSource.close(); state.eventSource = null; }
    if (state.workerTimer) { clearInterval(state.workerTimer); state.workerTimer = null; }
    state.jobId = jobId;
    state.timeSeries = [];
    showView('jobView');
    connectEvents(jobId);
    loadJobsList();
  }

  function connectEvents(jobId) {
    const es = new EventSource(`/api/jobs/${jobId}/events`);
    state.eventSource = es;
    es.addEventListener('snapshot', e => onSnapshot(JSON.parse(e.data)));
    es.addEventListener('row_done', e => onRowDone(JSON.parse(e.data)));
    es.addEventListener('row_start', e => onRowStart(JSON.parse(e.data)));
    es.addEventListener('worker_step', e => onWorkerStep(JSON.parse(e.data)));
    es.addEventListener('progress', e => onProgress(JSON.parse(e.data)));
    es.addEventListener('status', e => onStatus(JSON.parse(e.data)));
    es.addEventListener('finished', e => onSnapshot(JSON.parse(e.data)));
    es.onerror = () => {
      // Auto-reconectar tras 2s si no es estado final
      setTimeout(() => {
        if (state.snapshot && !['completed','stopped','error'].includes(state.snapshot.status)) {
          connectEvents(jobId);
        }
      }, 2000);
    };
    // Timer para refrescar elapsed de workers cada segundo
    state.workerTimer = setInterval(renderWorkers, 1000);
  }

  function onSnapshot(snap) {
    state.snapshot = snap;
    $('jobTitle').textContent = snap.input_name || snap.id;
    const opts = snap.options || {};
    $('jobSub').textContent = `Columna: ${snap.domain_column} · Workers: ${opts.parallel_workers || 5} · Timeout: ${opts.per_row_timeout || 90}s · Variantes: ${opts.discover_variants ? 'sí' : 'no'}`;

    updateStats(snap.done_count, snap.total, snap.stats);
    updateAggregates(snap.aggregates || {});
    setStatus(snap.status);
    renderWorkers();
    // Reset table from last_rows
    $('resultsBody').innerHTML = '';
    (snap.last_rows || []).forEach(r => appendRow(r));
    scrollResults();
  }

  function onProgress(p) {
    if (!state.snapshot) return;
    state.snapshot.done_count = p.done_count;
    state.snapshot.stats = p.stats;
    if (p.aggregates) state.snapshot.aggregates = p.aggregates;
    updateStats(p.done_count, p.total, p.stats);
    updateAggregates(p.aggregates || {});
  }

  function updateAggregates(a) {
    $('aggPoor').textContent = a.score_poor ?? 0;
    $('aggFair').textContent = a.score_fair ?? 0;
    $('aggGood').textContent = a.score_good ?? 0;
    $('aggExcellent').textContent = a.score_excellent ?? 0;
    $('aggWithDomains').textContent = a.with_active_domains ?? 0;
    $('aggRedir').textContent = a.with_redirecting ?? 0;
    $('aggRedirMain').textContent = a.with_redirect_to_main ?? 0;
    $('aggColdReady').textContent = a.with_cold_email_ready ?? 0;
    $('aggWhoisMatch').textContent = a.with_whois_match ?? 0;
    $('aggTotalActive').textContent = a.total_variants_active ?? 0;
    $('aggTotalMX').textContent = a.total_cold_email_variants ?? 0;
    $('aggTotalReady').textContent = a.total_cold_email_ready ?? 0;
  }

  function onStatus(s) {
    if (state.snapshot) {
      state.snapshot.status = s.status;
      // is_active se infiere del status: running/paused implican que hay
      // un main_task vivo. completed/stopped/error implican que no.
      if (s.status === 'running' || s.status === 'paused') {
        state.snapshot.is_active = true;
      } else if (['completed', 'stopped', 'error'].includes(s.status)) {
        state.snapshot.is_active = false;
      }
    }
    setStatus(s.status);
  }

  function _getOrCreateWorker(id) {
    if (!state.snapshot) return null;
    if (!Array.isArray(state.snapshot.workers)) state.snapshot.workers = [];
    let w = state.snapshot.workers.find(x => x.id === id);
    if (!w) {
      w = { id };
      state.snapshot.workers.push(w);
    }
    return w;
  }

  function onRowStart(r) {
    const w = _getOrCreateWorker(r.worker);
    if (w) {
      w.index = r.index;
      w.domain = r.domain;
      w.step = 'iniciando';
      w.started_at_client = Date.now();
    }
    renderWorkers();
  }

  function onWorkerStep(s) {
    const w = _getOrCreateWorker(s.worker);
    if (w) w.step = s.step;
    renderWorkers();
  }

  function onRowDone(r) {
    const w = _getOrCreateWorker(r.worker);
    if (w) {
      w.domain = null; w.index = null; w.step = ''; w.started_at_client = null;
    }
    appendRow(r);
    scrollResults();
    renderWorkers();
  }

  function updateStats(done, total, stats) {
    $('statProgress').textContent = `${done} / ${total}`;
    const pct = total ? (done / total) * 100 : 0;
    $('progressFill').style.width = pct + '%';
    $('statOk').textContent = stats?.ok ?? 0;
    $('statErr').textContent = stats?.error ?? 0;
    $('statTimeout').textContent = (stats?.timeout ?? 0) + (stats?.skipped ? ` (+${stats.skipped} skip)` : '');
    // ETA
    state.timeSeries.push({ t: Date.now(), done });
    if (state.timeSeries.length > 30) state.timeSeries.shift();
    if (state.timeSeries.length >= 2 && done < total) {
      const a = state.timeSeries[0], b = state.timeSeries[state.timeSeries.length-1];
      const elapsed = (b.t - a.t) / 1000;
      const progressed = b.done - a.done;
      if (progressed > 0 && elapsed > 0) {
        const rate = progressed / elapsed; // dominios/s
        const remaining = (total - done) / rate;
        $('statEta').textContent = formatEta(remaining);
      }
    } else if (done >= total) {
      $('statEta').textContent = '✓ Listo';
    }
  }

  function setStatus(status) {
    const el = $('statStatus');
    const isActive = state.snapshot?.is_active === true;

    // Si el status persistido dice "running" pero el proceso actual no está
    // procesando nada, el job fue interrumpido. Mostramos un estado claro.
    const effectiveStatus = (status === 'running' && !isActive) ? 'interrupted' : status;

    let displayLabel = effectiveStatus;
    if (effectiveStatus === 'interrupted') displayLabel = 'interrumpido';
    else if (isActive && (status === 'error' || status === 'stopped')) {
      displayLabel = `${status} (workers activos)`;
    }
    el.textContent = displayLabel;
    el.className = 'pill ' + (effectiveStatus || '');

    const running = effectiveStatus === 'running' || (isActive && effectiveStatus !== 'paused');
    const paused = effectiveStatus === 'paused';
    const canResume = !running && !paused && effectiveStatus !== 'completed';
    $('pauseBtn').classList.toggle('hidden', !running);
    $('resumeBtn').classList.toggle('hidden', !(paused || canResume));
    $('resumeBtn').textContent = paused ? '▶ Reanudar' : '▶ Reanudar (recuperar)';
    $('stopBtn').disabled = !(running || paused);
  }

  function renderWorkers() {
    const grid = $('workersGrid');
    const opts = state.snapshot?.options || {};
    const nW = opts.parallel_workers || 5;
    const ws = state.snapshot?.workers || [];
    const tiles = [];
    for (let i = 0; i < nW; i++) {
      const w = ws.find(x => x.id === i) || { id: i, domain: null };
      const active = !!w.domain;
      let elapsed = '';
      if (active) {
        const t0 = w.started_at_client || (w.elapsed ? (Date.now() - w.elapsed*1000) : Date.now());
        elapsed = formatSeconds((Date.now() - t0) / 1000);
      }
      tiles.push(`
        <div class="worker-tile ${active ? 'active' : 'idle'}">
          <div class="worker-tile-header">
            <span class="worker-id">W#${i}</span>
            <span class="worker-timer">${elapsed}</span>
          </div>
          <div class="worker-domain">${active ? escapeHtml(w.domain) : '— idle —'}</div>
          <div class="worker-step">${active ? escapeHtml(w.step || '') : ''}</div>
          ${active ? `<button class="worker-skip" data-worker="${i}">skip</button>` : ''}
        </div>
      `);
    }
    grid.innerHTML = tiles.join('');
    grid.querySelectorAll('.worker-skip').forEach(b => {
      b.addEventListener('click', () => skipWorker(parseInt(b.dataset.worker, 10)));
    });
  }

  function appendRow(r) {
    const tb = $('resultsBody');
    const cls = r.status === 'error' ? 'row-error'
              : r.status === 'timeout' ? 'row-timeout'
              : r.status === 'skipped' ? 'row-skipped' : '';
    const yesNo = v => v === true || v === 'True' || v === 'true'
      ? '<span class="check-yes">✓</span>'
      : '<span class="check-no">·</span>';
    const tr = document.createElement('tr');
    tr.className = cls;
    const activeCount = r.variants_active ?? '';
    const activeList = r.active_domains || '';
    const readyCount = r.cold_email_ready_count ?? '';
    const readyList = r.cold_email_ready_domains || '';
    const redirCount = r.redirecting_count ?? '';
    const redirList = r.redirecting_domains || '';
    const mainCount = r.redirecting_to_main_count ?? '';
    const mainList = r.redirecting_to_main || '';
    const whoisCount = r.whois_same_entity_count;
    const whoisEntity = r.whois_main_entity || '';
    const whoisAllMatch = r.whois_all_match === true || r.whois_all_match === 'True' || r.whois_all_match === 'true';
    const whoisCell = (whoisCount === undefined || whoisCount === null || whoisCount === '')
      ? '<span class="check-no">·</span>'
      : `<span class="cold-list" title="${escapeHtml(whoisEntity)}">${whoisCount}${whoisAllMatch ? ' ✓' : ''}</span>`;
    tr.innerHTML = `
      <td>${r.index ?? ''}</td>
      <td title="${escapeHtml(r.domain || '')}">${escapeHtml(r.domain || '')}</td>
      <td>${escapeHtml(r.status || '')}</td>
      <td>${yesNo(r.has_spf)}</td>
      <td>${yesNo(r.has_dkim)}</td>
      <td>${yesNo(r.has_dmarc)}</td>
      <td>${escapeHtml(r.mx_provider || '')}</td>
      <td>${escapeHtml(r.security_score || '')}</td>
      <td><span class="cold-list" title="${escapeHtml(activeList)}">${activeCount}</span></td>
      <td><span class="cold-list cold-ready" title="${escapeHtml(readyList)}">${readyCount}</span></td>
      <td><span class="cold-list" title="${escapeHtml(redirList)}">${redirCount}</span></td>
      <td><span class="cold-list" title="${escapeHtml(mainList)}">${mainCount}</span></td>
      <td>${whoisCell}</td>
      <td>${r.seconds ?? ''}s</td>
    `;
    tb.appendChild(tr);
    while (tb.children.length > 300) tb.removeChild(tb.firstChild);
  }

  function scrollResults() {
    const wrap = document.querySelector('.table-wrap');
    if (wrap) wrap.scrollTop = wrap.scrollHeight;
  }

  // ----------------------- Controls -----------------------

  async function postCtrl(path) {
    if (!state.jobId) return;
    try {
      const r = await fetch(`/api/jobs/${state.jobId}/${path}`, { method: 'POST' });
      if (!r.ok) throw new Error((await r.json()).detail || r.statusText);
    } catch (e) {
      alert('Error: ' + e.message);
    }
  }

  async function skipWorker(workerId) {
    if (!state.jobId) return;
    await fetch(`/api/jobs/${state.jobId}/skip?worker_id=${workerId}`, { method: 'POST' });
  }

  async function deleteJob(jobId, name) {
    if (!confirm(`¿Borrar el trabajo "${name}"? Esta acción no se puede deshacer.`)) return;
    try {
      const r = await fetch(`/api/jobs/${jobId}`, { method: 'DELETE' });
      if (!r.ok) throw new Error((await r.json()).detail || r.statusText);
      if (state.jobId === jobId) {
        if (state.eventSource) { state.eventSource.close(); state.eventSource = null; }
        if (state.workerTimer) { clearInterval(state.workerTimer); state.workerTimer = null; }
        state.jobId = null;
        showView('setupView');
      }
      loadJobsList();
    } catch (e) {
      alert('Error: ' + e.message);
    }
  }

  function updateVariantsHint() {
    const mode = $('optVariantsMode').value;
    const hints = {
      'cascade': 'Arranca con 40 cold. Si encuentra ≥1 activa, expande a las 150. Lo mejor de ambos mundos.',
      'cold': '~40 patrones típicos de cold email (getX, Xmail, X.io, etc) — solo si querés algo rapidísimo',
      'full': '~150 variantes — máxima cobertura, ~4x más lento que cold',
      'none': 'Solo verifica SPF/DKIM/DMARC/MX del dominio principal, sin variantes',
    };
    $('variantsHint').textContent = hints[mode] || '';
  }

  function updateWorkersHint() {
    const n = parseInt($('optWorkers').value, 10) || 0;
    let txt;
    if (n <= 3) txt = `${n} = muy conservador, no satura DNS`;
    else if (n <= 7) txt = `${n} = balance estable recomendado`;
    else if (n <= 12) txt = `${n} = rápido, puede saturar DNS en redes lentas`;
    else txt = `${n} = arriesgado, posibles timeouts si DNS rate-limita`;
    $('workersHint').textContent = txt;
  }

  function downloadCsv() {
    if (!state.jobId) return;
    window.location.href = `/api/jobs/${state.jobId}/download`;
  }

  // ----------------------- Views & helpers -----------------------

  function showView(id) {
    document.querySelectorAll('.view').forEach(v => v.classList.toggle('active', v.id === id));
  }

  function newJob() {
    if (state.eventSource) { state.eventSource.close(); state.eventSource = null; }
    if (state.workerTimer) { clearInterval(state.workerTimer); state.workerTimer = null; }
    state.jobId = null;
    state.snapshot = null;
    state.upload = null;
    $('setupForm').classList.add('hidden');
    $('dropZone').querySelector('.dz-title').textContent = 'Arrastrá tu CSV acá';
    $('fileInput').value = '';
    showView('setupView');
    loadJobsList();
  }

  function escapeHtml(s) {
    if (s === null || s === undefined) return '';
    return String(s)
      .replaceAll('&', '&amp;').replaceAll('<', '&lt;').replaceAll('>', '&gt;')
      .replaceAll('"', '&quot;').replaceAll("'", '&#039;');
  }

  function formatSeconds(s) {
    if (s < 60) return `${Math.floor(s)}s`;
    const m = Math.floor(s / 60), r = Math.floor(s % 60);
    return `${m}m ${r}s`;
  }

  function formatEta(s) {
    if (!isFinite(s) || s <= 0) return '—';
    if (s < 60) return `~${Math.ceil(s)}s`;
    if (s < 3600) return `~${Math.ceil(s/60)}m`;
    return `~${(s/3600).toFixed(1)}h`;
  }

  // ----------------------- Init -----------------------

  document.addEventListener('DOMContentLoaded', () => {
    setupDropzone();
    $('startBtn').addEventListener('click', startJob);
    $('newJobBtn').addEventListener('click', newJob);
    $('pauseBtn').addEventListener('click', () => postCtrl('pause'));
    $('resumeBtn').addEventListener('click', () => postCtrl('resume'));
    $('stopBtn').addEventListener('click', () => {
      if (confirm('¿Detener el procesamiento? Podrás reanudarlo después.')) postCtrl('stop');
    });
    $('skipAllBtn').addEventListener('click', () => postCtrl('skip'));
    $('downloadBtn').addEventListener('click', downloadCsv);
    $('optVariantsMode').addEventListener('change', updateVariantsHint);
    $('optWorkers').addEventListener('input', updateWorkersHint);
    updateVariantsHint();
    updateWorkersHint();
    loadJobsList();
    // Refresca el sidebar cada 10s. Si hay un job activo, los eventos SSE
    // ya actualizan su progreso en tiempo real; este polling solo refleja
    // cambios en otros jobs guardados.
    setInterval(loadJobsList, 10000);
  });
})();
