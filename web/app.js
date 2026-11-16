/**
 * ShadowNet dashboard client.
 * Vanilla ES6+: fetches the JSON report, renders KPIs / panels / alert table,
 * and draws the traffic timeline on an HTML5 <canvas>.
 * All log-derived strings are inserted with textContent (never innerHTML),
 * because attack payloads are attacker-controlled input.
 */
(() => {
  'use strict';

  const $ = (id) => document.getElementById(id);
  const SEVERITIES = ['critical', 'high', 'medium', 'low'];
  const COLORS = { critical: '#ff4d6d', high: '#ff9f43', medium: '#f6d55c', low: '#5b9dff' };
  const NORMAL = '#22d3ee';
  const MALICIOUS = '#ff4d6d';

  const state = {
    report: null,
    severities: new Set(),   // empty set = show all
    type: '',
    query: '',
    sqrtScale: false,
    reveal: 1,               // 0..1 chart draw-in animation progress
    hover: -1,               // hovered timeline bucket
  };

  // ---------- helpers ----------
  const fmt = (n) => Number(n).toLocaleString('en-US');
  const clock = (epoch) => new Date(epoch * 1000).toLocaleTimeString([], { hour12: false });
  const el = (tag, props = {}, ...children) => {
    const node = Object.assign(document.createElement(tag), props);
    node.append(...children);
    return node;
  };
  const setStatus = (text, mode = '') => {
    $('status-text').textContent = text;
    $('status').className = `status ${mode}`;
  };

  /** Ease a KPI number from its current value to the target. */
  function countUp(node, target) {
    const from = Number(node.dataset.value || 0);
    const t0 = performance.now();
    node.dataset.value = target;
    const step = (now) => {
      const p = Math.min(1, (now - t0) / 600);
      node.textContent = fmt(Math.round(from + (target - from) * (1 - (1 - p) ** 3)));
      if (p < 1) requestAnimationFrame(step);
    };
    requestAnimationFrame(step);
  }

  // ---------- data ----------
  async function load(simulate = false) {
    const button = $('simulate');
    button.disabled = true;
    setStatus(simulate ? 'Generating attack wave…' : 'Loading report…', 'busy');
    try {
      const res = await fetch(simulate ? '/api/simulate' : '/api/report',
        { method: simulate ? 'POST' : 'GET' });
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      state.report = await res.json();
      render();
      setStatus(`Engine online · analysed ${clock(Date.parse(state.report.generated_at) / 1000)}`);
    } catch (err) {
      setStatus(`Engine unreachable (${err.message})`, 'error');
    } finally {
      button.disabled = false;
    }
  }

  // ---------- rendering ----------
  function render() {
    const { summary: s, by_type: byType, by_severity: bySev, top_attackers: top } = state.report;

    countUp($('kpi-total'), s.total_requests);
    countUp($('kpi-blocked'), s.blocked_threats);
    countUp($('kpi-critical'), s.critical_ips);
    countUp($('kpi-rps'), s.peak_rps);
    $('kpi-total-sub').textContent = `${fmt(s.unique_ips)} unique source IPs`;
    $('kpi-blocked-sub').textContent = `${s.threat_ratio}% of all traffic`;
    $('kpi-critical-sub').textContent = `${s.alert_count} alerts raised`;

    // Attack vector bars (click to filter the table by type).
    const max = Math.max(1, ...Object.values(byType));
    const sevOf = Object.fromEntries(state.report.alerts.map((a) => [a.type, a.severity]));
    $('vectors').replaceChildren(...Object.entries(byType).map(([type, count]) => {
      const fill = el('div', { className: 'fill' });
      fill.style.background = COLORS[sevOf[type]] || NORMAL;
      requestAnimationFrame(() => { fill.style.width = `${(count / max) * 100}%`; });
      fill.style.width = '0';
      const li = el('li', { title: `Filter alerts: ${type}` },
        el('div', { className: 'row' }, el('span', { textContent: type }), el('span', { textContent: fmt(count) })),
        el('div', { className: 'track' }, fill));
      li.classList.toggle('active', state.type === type);
      li.onclick = () => { state.type = state.type === type ? '' : type; syncFilters(); };
      return li;
    }));

    // Top attackers (click an IP to search for it).
    $('attackers').replaceChildren(...top.map((a) => {
      const ip = el('span', { className: 'ip', textContent: a.ip, title: 'Show alerts for this IP' });
      ip.onclick = () => { state.query = a.ip; $('search').value = a.ip; renderTable(); };
      return el('li', {},
        el('div', {}, ip, el('small', { textContent: a.types.join(' · ') })),
        el('span', { className: 'hits', textContent: `${fmt(a.hits)} hits` }));
    }));

    // Severity chips with counts.
    $('sev-filter').replaceChildren(...SEVERITIES.map((sev) => {
      const chip = el('button', { className: 'chip', type: 'button', textContent: `${sev} ${bySev[sev] || 0}` });
      chip.style.setProperty('--c', COLORS[sev]);
      chip.classList.toggle('active', state.severities.has(sev));
      chip.setAttribute('aria-pressed', state.severities.has(sev));
      chip.onclick = () => {
        state.severities.has(sev) ? state.severities.delete(sev) : state.severities.add(sev);
        syncFilters();
      };
      return chip;
    }));

    // Type dropdown.
    if (!(state.type in byType)) state.type = '';
    $('type-filter').replaceChildren(el('option', { value: '', textContent: 'All attack types' }),
      ...Object.keys(byType).map((t) => el('option', { value: t, textContent: t })));
    $('type-filter').value = state.type;

    renderTable();
    animateChart();
  }

  /** Re-render the controls that mirror filter state, then the table. */
  function syncFilters() {
    $('type-filter').value = state.type;
    [...$('sev-filter').children].forEach((chip, i) => {
      const on = state.severities.has(SEVERITIES[i]);
      chip.classList.toggle('active', on);
      chip.setAttribute('aria-pressed', on);
    });
    [...$('vectors').children].forEach((li) =>
      li.classList.toggle('active', li.querySelector('span').textContent === state.type));
    renderTable();
  }

  function renderTable() {
    const q = state.query.trim().toLowerCase();
    const all = state.report.alerts;
    const rows = all.filter((a) =>
      (!state.severities.size || state.severities.has(a.severity)) &&
      (!state.type || a.type === state.type) &&
      (!q || `${a.ip} ${a.sample} ${a.type} ${a.id}`.toLowerCase().includes(q)));

    $('alert-count').textContent = rows.length === all.length ? all.length : `${rows.length} / ${all.length}`;
    $('empty').hidden = rows.length > 0;
    $('alerts').replaceChildren(...rows.map((a) => {
      const badge = el('span', { className: 'badge', textContent: a.severity });
      badge.style.setProperty('--c', COLORS[a.severity]);
      return el('tr', {},
        el('td', { className: 'mono', textContent: a.id }),
        el('td', {}, badge),
        el('td', { textContent: a.type }),
        el('td', { className: 'mono', textContent: a.ip }),
        el('td', { className: 'num', textContent: fmt(a.count) }),
        el('td', { className: 'mono', textContent: `${clock(a.first_seen)} → ${clock(a.last_seen)}` }),
        el('td', { className: 'evidence' }, a.detail, el('code', { textContent: a.sample })));
    }));
  }

  // ---------- canvas chart ----------
  const canvas = $('chart');
  const ctx = canvas.getContext('2d');
  const PAD = { top: 14, right: 14, bottom: 26, left: 44 };

  function animateChart() {
    if (matchMedia('(prefers-reduced-motion: reduce)').matches) { state.reveal = 1; return drawChart(); }
    const t0 = performance.now();
    const step = (now) => {
      state.reveal = Math.min(1, (now - t0) / 900);
      drawChart();
      if (state.reveal < 1) requestAnimationFrame(step);
    };
    requestAnimationFrame(step);
  }

  /** Pick a "nice" axis maximum (1, 2, 2.5, 5 × 10^n) at or above value. */
  function niceMax(value) {
    const pow = 10 ** Math.floor(Math.log10(Math.max(value, 1)));
    return [1, 2, 2.5, 5, 10].map((m) => m * pow).find((m) => m >= value);
  }

  function drawChart() {
    if (!state.report) return;
    const { normal, malicious, bucket_seconds: bucket, start } = state.report.timeline;
    const dpr = window.devicePixelRatio || 1;
    const W = canvas.clientWidth, H = canvas.clientHeight;
    if (canvas.width !== W * dpr || canvas.height !== H * dpr) {
      canvas.width = W * dpr; canvas.height = H * dpr;
    }
    ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
    ctx.clearRect(0, 0, W, H);

    const n = normal.length;
    const plotW = W - PAD.left - PAD.right, plotH = H - PAD.top - PAD.bottom;
    const yMax = niceMax(Math.max(...normal, ...malicious, 1));
    const scale = (v) => (state.sqrtScale ? Math.sqrt(v / yMax) : v / yMax);
    const x = (i) => PAD.left + (n > 1 ? (i / (n - 1)) * plotW : 0);
    const y = (v) => PAD.top + plotH - scale(v) * plotH;

    // Grid + Y labels.
    ctx.font = '11px ui-monospace, Menlo, Consolas, monospace';
    ctx.textBaseline = 'middle';
    const ticks = state.sqrtScale ? [0, 0.0625, 0.25, 0.5625, 1] : [0, 0.25, 0.5, 0.75, 1];
    ticks.forEach((f) => {
      const yy = y(f * yMax);
      ctx.strokeStyle = '#1f2b3d'; ctx.lineWidth = 1;
      ctx.beginPath(); ctx.moveTo(PAD.left, yy + 0.5); ctx.lineTo(W - PAD.right, yy + 0.5); ctx.stroke();
      ctx.fillStyle = '#7d8da6'; ctx.textAlign = 'right';
      ctx.fillText(fmt(Math.round(f * yMax)), PAD.left - 8, yy);
    });
    // X labels.
    ctx.textAlign = 'center'; ctx.textBaseline = 'top';
    const labels = Math.max(2, Math.min(7, Math.floor(plotW / 110)));
    for (let k = 0; k <= labels; k++) {
      const i = Math.round((k / labels) * (n - 1));
      ctx.textAlign = k === 0 ? 'left' : k === labels ? 'right' : 'center';
      ctx.fillText(clock(start + i * bucket).slice(0, 5), x(i), H - PAD.bottom + 8);
    }

    // Series are clipped to the animated reveal width.
    ctx.save();
    ctx.beginPath();
    ctx.rect(PAD.left, 0, plotW * state.reveal + 1, H);
    ctx.clip();
    const series = (data, color) => {
      const gradient = ctx.createLinearGradient(0, PAD.top, 0, PAD.top + plotH);
      gradient.addColorStop(0, `${color}66`);
      gradient.addColorStop(1, `${color}00`);
      ctx.beginPath();
      data.forEach((v, i) => (i ? ctx.lineTo(x(i), y(v)) : ctx.moveTo(x(i), y(v))));
      ctx.strokeStyle = color; ctx.lineWidth = 1.6; ctx.lineJoin = 'round';
      ctx.shadowColor = color; ctx.shadowBlur = 8;
      ctx.stroke();
      ctx.shadowBlur = 0;
      ctx.lineTo(x(n - 1), PAD.top + plotH); ctx.lineTo(x(0), PAD.top + plotH); ctx.closePath();
      ctx.fillStyle = gradient; ctx.fill();
    };
    series(normal, NORMAL);
    series(malicious, MALICIOUS);
    ctx.restore();

    // Hover crosshair + markers.
    const tip = $('tooltip');
    if (state.hover >= 0 && state.hover < n) {
      const i = state.hover, xx = x(i);
      ctx.strokeStyle = '#7d8da6'; ctx.setLineDash([4, 4]);
      ctx.beginPath(); ctx.moveTo(xx, PAD.top); ctx.lineTo(xx, PAD.top + plotH); ctx.stroke();
      ctx.setLineDash([]);
      [[normal[i], NORMAL], [malicious[i], MALICIOUS]].forEach(([v, color]) => {
        ctx.beginPath(); ctx.arc(xx, y(v), 4, 0, Math.PI * 2);
        ctx.fillStyle = color; ctx.fill();
        ctx.strokeStyle = '#070b12'; ctx.lineWidth = 2; ctx.stroke();
      });
      const t = start + i * bucket;
      tip.replaceChildren(
        el('div', { textContent: `${clock(t)} – ${clock(t + bucket)}` }),
        el('div', {}, 'Normal    ', el('b', { className: 'n', textContent: fmt(normal[i]) })),
        el('div', {}, 'Malicious ', el('b', { className: 'm', textContent: fmt(malicious[i]) })));
      tip.hidden = false;
      const flip = xx > W - 190;
      tip.style.left = flip ? '' : `${xx + 14}px`;
      tip.style.right = flip ? `${W - xx + 14}px` : '';
      tip.style.top = `${PAD.top + 6}px`;
    } else {
      tip.hidden = true;
    }
  }

  canvas.addEventListener('mousemove', (e) => {
    if (!state.report) return;
    const n = state.report.timeline.normal.length;
    const plotW = canvas.clientWidth - PAD.left - PAD.right;
    const i = Math.round(((e.offsetX - PAD.left) / plotW) * (n - 1));
    state.hover = Math.max(0, Math.min(n - 1, i));
    drawChart();
  });
  canvas.addEventListener('mouseleave', () => { state.hover = -1; drawChart(); });
  window.addEventListener('resize', drawChart);

  // ---------- wiring ----------
  $('simulate').addEventListener('click', () => load(true));
  $('type-filter').addEventListener('change', (e) => { state.type = e.target.value; syncFilters(); });
  $('search').addEventListener('input', (e) => { state.query = e.target.value; renderTable(); });
  $('scale').addEventListener('click', (e) => {
    state.sqrtScale = !state.sqrtScale;
    e.target.textContent = `Scale: ${state.sqrtScale ? 'Sqrt' : 'Linear'}`;
    drawChart();
  });

  load();
})();
