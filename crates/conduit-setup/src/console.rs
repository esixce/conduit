// ---------------------------------------------------------------------------
// Embedded HTML console
// ---------------------------------------------------------------------------

pub const CONSOLE_HTML: &str = r##"<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Conduit Console</title>
<link rel="icon" href="data:image/svg+xml,<svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 100 100'><text y='.9em' font-size='90'>⚡</text></svg>">
<style>
* { margin: 0; padding: 0; box-sizing: border-box; }
body {
  background: #0d1117;
  color: #e6edf3;
  font-family: 'SF Mono', 'Fira Code', 'Cascadia Code', 'Consolas', monospace;
  font-size: 13px;
  height: 100vh;
  display: flex;
  flex-direction: column;
}
header {
  background: #161b22;
  border-bottom: 1px solid #30363d;
  padding: 12px 20px;
  display: flex;
  align-items: center;
  gap: 20px;
  flex-wrap: wrap;
}
h1 { font-size: 16px; font-weight: 600; letter-spacing: 2px; text-transform: uppercase; color: #f0883e; }
.inputs { display: flex; gap: 10px; align-items: center; flex-wrap: wrap; }
.inputs label { color: #8b949e; font-size: 12px; display: flex; align-items: center; gap: 6px; }
.inputs input {
  background: #0d1117; border: 1px solid #30363d; color: #e6edf3;
  padding: 4px 8px; border-radius: 4px; font-family: inherit; font-size: 12px; width: 260px;
}
.inputs input:focus { border-color: #58a6ff; outline: none; }
button {
  background: #238636; color: #fff; border: none; padding: 5px 14px;
  border-radius: 4px; cursor: pointer; font-family: inherit; font-size: 12px; font-weight: 600;
}
button:hover { background: #2ea043; }
button.disconnect { background: #da3633; }
button.disconnect:hover { background: #f85149; }
.status-row { display: flex; gap: 14px; font-size: 12px; align-items: center; }
.node-badge {
  display: flex; align-items: center; gap: 5px; position: relative;
  padding: 3px 10px; border-radius: 12px; border: 1px solid #30363d; cursor: default;
}
.node-badge.ok { border-color: #238636; background: rgba(35,134,54,0.1); }
.node-badge.ok.creator-badge { border-color: #1f6feb; background: rgba(31,111,235,0.1); }
.node-badge.ok.seeder-badge { border-color: #d29922; background: rgba(210,153,34,0.1); }
.dot { width: 8px; height: 8px; border-radius: 50%; display: inline-block; }
.dot.off { background: #484f58; animation: pulse-off 2s infinite; }
.dot.on { background: #3fb950; animation: none; }
.dot.creator.on { background: #58a6ff; }
.dot.seeder.on { background: #d29922; }
@keyframes pulse-off { 0%,100% { opacity: .4; } 50% { opacity: 1; } }

/* Node popover (hover card) */
.node-popover {
  display: none; position: absolute; top: calc(100% + 8px); left: 50%; transform: translateX(-50%);
  z-index: 100; min-width: 340px; max-width: 420px;
  background: #161b22; border: 1px solid #30363d; border-radius: 8px;
  padding: 14px 18px; font-size: 12px;
  box-shadow: 0 8px 24px rgba(0,0,0,0.4);
  pointer-events: auto;
}
.node-popover::before {
  content: ''; position: absolute; top: -6px; left: 50%; transform: translateX(-50%);
  border-left: 6px solid transparent; border-right: 6px solid transparent; border-bottom: 6px solid #30363d;
}
.node-badge:hover .node-popover { display: block; }
.node-popover h3 { font-size: 13px; margin-bottom: 10px; font-weight: 600; letter-spacing: 1px; }
.node-popover.creator h3 { color: #58a6ff; }
.node-popover.seeder h3 { color: #d29922; }
.node-popover.buyer h3 { color: #3fb950; }
.node-popover .row { display: flex; justify-content: space-between; padding: 3px 0; border-bottom: 1px solid #21262d; }
.node-popover .row:last-child { border-bottom: none; }
.node-popover .lbl { color: #8b949e; }
.node-popover .val { color: #e6edf3; text-align: right; }
.node-popover .val.good { color: #3fb950; }
.node-popover .val.warn { color: #d29922; }
.node-popover .val.bad { color: #f85149; }
.node-popover .id { color: #79c0ff; font-size: 11px; word-break: break-all; }
.ch-bar {
  height: 6px; border-radius: 3px; background: #21262d; margin-top: 6px; overflow: hidden;
}
.ch-bar-fill { height: 100%; border-radius: 3px; }

/* Timeline */
#timeline-hdr {
  padding: 8px 20px; background: #161b22; border-bottom: 1px solid #30363d;
  font-size: 11px; color: #8b949e; text-transform: uppercase; letter-spacing: 1px;
  display: flex; justify-content: space-between; align-items: center;
}
#timeline-hdr .count { color: #58a6ff; }
#timeline {
  flex: 1; overflow-y: auto; padding: 0 20px;
}
#timeline:empty::after {
  content: "Waiting for events... Connect to your nodes, then trigger a sell/buy.";
  display: block; padding: 40px 0; text-align: center; color: #484f58; font-style: italic;
}
.event {
  display: flex; gap: 10px; padding: 5px 0;
  border-bottom: 1px solid #21262d; align-items: baseline;
  animation: flash 0.6s ease-out;
}
@keyframes flash { 0% { background: rgba(88,166,255,0.08); } 100% { background: transparent; } }
.event:last-child { border-bottom: none; }
.ts { color: #484f58; min-width: 70px; }
.role { min-width: 70px; font-weight: 600; font-size: 11px; text-transform: uppercase; letter-spacing: 1px; }
.role.creator { color: #58a6ff; }
.role.seeder { color: #d29922; }
.role.buyer { color: #3fb950; }
.etype { color: #f0883e; min-width: 200px; font-weight: 600; }
.edata { color: #8b949e; word-break: break-all; }
.edata .key { color: #d2a8ff; }
.edata .hash { color: #79c0ff; }
.edata .amount { color: #3fb950; }
.edata .msg { color: #e6edf3; font-style: italic; }
</style>
</head>
<body>
<header>
  <h1>⚡ Conduit</h1>
  <div class="inputs">
    <label>Creator <input id="url1" placeholder="http://creator-ip:3000"></label>
    <label>Seeder <input id="url3" placeholder="http://seeder-ip:3002 (optional)"></label>
    <label>Buyer <input id="url2" placeholder="http://buyer-ip:3001"></label>
    <button id="btn" onclick="toggle()">Connect</button>
  </div>
  <div class="status-row">
    <div id="badge1" class="node-badge"><span id="d1" class="dot creator off"></span> creator<div id="pop1" class="node-popover creator"></div></div>
    <div id="badge3" class="node-badge"><span id="d3" class="dot seeder off"></span> seeder<div id="pop3" class="node-popover seeder"></div></div>
    <div id="badge2" class="node-badge"><span id="d2" class="dot off"></span> buyer<div id="pop2" class="node-popover buyer"></div></div>
  </div>
</header>

<div id="timeline-hdr">
  <span>Event Timeline</span>
  <span><span id="evcount" class="count">0</span> events</span>
</div>
<div id="timeline"></div>

<script>
let sources = [];
let connected = false;
let evCount = 0;
let infoTimers = [];
const tl = document.getElementById('timeline');

function toggle() {
  if (connected) { disconnect(); return; }
  const u1 = document.getElementById('url1').value.replace(/\/+$/, '') || document.getElementById('url1').placeholder;
  const u3 = (document.getElementById('url3').value || '').replace(/\/+$/, '');
  const u2 = document.getElementById('url2').value.replace(/\/+$/, '') || document.getElementById('url2').placeholder;
  sources = [];
  if (u1) sources.push({ url: u1, dot: 'd1', badge: 'badge1', role: 'creator', card: null });
  if (u3) sources.push({ url: u3, dot: 'd3', badge: 'badge3', role: 'seeder', card: null });
  if (u2) sources.push({ url: u2, dot: 'd2', badge: 'badge2', role: 'buyer', card: null });
  if (!sources.length) return;

  sources.forEach(s => {
    // SSE connection
    const es = new EventSource(s.url + '/api/events');
    s.es = es;
    es.onopen = () => {
      document.getElementById(s.dot).className = 'dot ' + s.role + ' on';
      const badgeSuffix = s.role === 'creator' ? ' creator-badge' : (s.role === 'seeder' ? ' seeder-badge' : '');
      document.getElementById(s.badge).className = 'node-badge ok' + badgeSuffix;
    };
    es.onerror = () => {
      document.getElementById(s.dot).className = 'dot off';
      document.getElementById(s.badge).className = 'node-badge';
    };
    es.onmessage = (e) => { try { addEvent(JSON.parse(e.data)); } catch(err) {} };

    // Fetch node info immediately and every 10s
    fetchInfo(s);
    const t = setInterval(() => fetchInfo(s), 10000);
    infoTimers.push(t);
  });

  connected = true;
  const btn = document.getElementById('btn');
  btn.textContent = 'Disconnect';
  btn.className = 'disconnect';
}

function disconnect() {
  sources.forEach(s => { if (s.es) s.es.close(); });
  infoTimers.forEach(t => clearInterval(t));
  infoTimers = [];
  document.getElementById('d1').className = 'dot creator off';
  document.getElementById('d3').className = 'dot seeder off';
  document.getElementById('d2').className = 'dot off';
  document.getElementById('badge1').className = 'node-badge';
  document.getElementById('badge3').className = 'node-badge';
  document.getElementById('badge2').className = 'node-badge';
  document.getElementById('pop1').innerHTML = '';
  document.getElementById('pop3').innerHTML = '';
  document.getElementById('pop2').innerHTML = '';
  tl.innerHTML = '';
  evCount = 0;
  document.getElementById('evcount').textContent = '0';
  sources = [];
  connected = false;
  document.getElementById('btn').textContent = 'Connect';
  document.getElementById('btn').className = '';
}

async function fetchInfo(s) {
  try {
    const r = await fetch(s.url + '/api/info');
    const info = await r.json();
    renderCard(s, info);
  } catch(e) {
    // Node unreachable — card stays stale or empty
  }
}

function renderCard(s, info) {
  // Determine popover element from badge -> find nested .node-popover
  const popId = s.badge.replace('badge', 'pop');
  const pop = document.getElementById(popId);
  if (!pop) return;

  const totalBal = info.onchain_balance_sats + info.lightning_balance_sats;
  const balClass = totalBal > 0 ? 'good' : 'bad';

  let chHtml = '';
  if (info.channels && info.channels.length > 0) {
    info.channels.forEach((ch, i) => {
      const total = ch.outbound_msat + ch.inbound_msat;
      const outPct = total > 0 ? (ch.outbound_msat / total * 100) : 0;
      const statusClass = ch.usable ? 'good' : (ch.ready ? 'warn' : 'bad');
      const statusText = ch.usable ? 'USABLE' : (ch.ready ? 'READY' : 'PENDING');
      const barColor = s.role === 'creator' ? '#58a6ff' : (s.role === 'seeder' ? '#d29922' : '#3fb950');
      chHtml += '<div class="row"><span class="lbl">Channel ' + (i+1) + '</span><span class="val ' + statusClass + '">' + statusText + ' · ' + fmt(ch.value_sats) + ' sats</span></div>';
      chHtml += '<div class="row"><span class="lbl">out / in</span><span class="val">' + fmt(ch.outbound_msat/1000) + ' / ' + fmt(ch.inbound_msat/1000) + ' sats</span></div>';
      chHtml += '<div class="ch-bar"><div class="ch-bar-fill" style="width:' + outPct + '%;background:' + barColor + '"></div></div>';
    });
  } else {
    chHtml = '<div class="row"><span class="lbl">Channels</span><span class="val bad">NONE</span></div>';
  }

  pop.innerHTML =
    '<h3>' + s.role.toUpperCase() + '</h3>' +
    '<div class="row"><span class="lbl">Node ID</span></div>' +
    '<div class="id">' + esc(info.node_id) + '</div>' +
    '<div class="row" style="margin-top:8px"><span class="lbl">On-chain</span><span class="val">' + fmt(info.onchain_balance_sats) + ' sats</span></div>' +
    '<div class="row"><span class="lbl">Spendable</span><span class="val">' + fmt(info.spendable_onchain_sats) + ' sats</span></div>' +
    '<div class="row"><span class="lbl">Lightning</span><span class="val ' + balClass + '">' + fmt(info.lightning_balance_sats) + ' sats</span></div>' +
    '<div style="margin-top:10px;border-top:1px solid #30363d;padding-top:8px">' + chHtml + '</div>';
}

function fmt(n) { return Number(n).toLocaleString(); }

function addEvent(ev) {
  evCount++;
  document.getElementById('evcount').textContent = evCount;

  const div = document.createElement('div');
  div.className = 'event';

  const ts = document.createElement('span');
  ts.className = 'ts';
  ts.textContent = ev.timestamp || '';

  const role = document.createElement('span');
  role.className = 'role ' + (ev.role || '');
  role.textContent = ev.role || '';

  const etype = document.createElement('span');
  etype.className = 'etype';
  etype.textContent = ev.event_type || '';

  const edata = document.createElement('span');
  edata.className = 'edata';
  edata.innerHTML = formatData(ev.data || {});

  div.appendChild(ts);
  div.appendChild(role);
  div.appendChild(etype);
  div.appendChild(edata);
  tl.appendChild(div);
  tl.scrollTop = tl.scrollHeight;

  // Refresh node info on notable events
  if (['PAYMENT_RECEIVED','PAYMENT_CONFIRMED','HTLC_RECEIVED','PAYMENT_SENT','TRANSPORT_PAID','CONTENT_PAID','TRANSPORT_INVOICE_CREATED'].includes(ev.event_type)) {
    sources.forEach(s => fetchInfo(s));
  }
}

function formatData(d) {
  const parts = [];
  for (const [k, v] of Object.entries(d)) {
    if (k === 'message') {
      parts.push('<span class="msg">' + esc(v) + '</span>');
    } else if (k === 'key' || k === 'preimage') {
      parts.push(k + '=<span class="key">' + esc(v) + '</span>');
    } else if (k.includes('hash')) {
      parts.push(k + '=<span class="hash">' + esc(v) + '</span>');
    } else if (k.includes('amount') || k.includes('msat') || k.includes('sats') || k.includes('fee') || k.includes('price') || k.includes('bytes')) {
      parts.push(k + '=<span class="amount">' + esc(String(v)) + '</span>');
    } else if (k === 'bolt11') {
      const s = String(v);
      parts.push('bolt11=<span class="hash">' + esc(s.length > 40 ? s.slice(0,40) + '...' : s) + '</span>');
    } else if (k === 'event') {
      const s = String(v);
      parts.push(esc(s.length > 80 ? s.slice(0,80) + '...' : s));
    } else {
      parts.push(k + '=' + esc(String(v)));
    }
  }
  return parts.join('  ');
}

function esc(s) { const d = document.createElement('div'); d.textContent = s; return d.innerHTML; }
</script>
</body>
</html>"##;
