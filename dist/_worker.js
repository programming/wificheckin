// Shift Worker Attendance Tracker — Cloudflare Pages Advanced Mode
// All routes handled here: /checkin, /admin, /admin/login, /myip
// Timestamps stored in UTC, displayed in Singapore time (UTC+8, no DST)

const SG_OFFSET_MS = 8 * 60 * 60 * 1000;

// ─── Utility: Singapore time ──────────────────────────────────────────────────

function toSGDate(utcDate) {
  return new Date(utcDate.getTime() + SG_OFFSET_MS);
}

function nowSG() {
  return toSGDate(new Date());
}

function formatSGTime(utcDateOrString) {
  const d = utcDateOrString instanceof Date
    ? toSGDate(utcDateOrString)
    : toSGDate(new Date(utcDateOrString + 'Z')); // DB timestamps are UTC without Z
  return d.toLocaleString('en-SG', {
    year: 'numeric', month: '2-digit', day: '2-digit',
    hour: '2-digit', minute: '2-digit', second: '2-digit',
    hour12: false
  });
}

// Compute UTC boundaries for a Singapore calendar day (YYYY-MM-DD)
function sgDayToUTCRange(sgDateStr) {
  // sgDateStr = "2024-07-15"
  const [y, m, d] = sgDateStr.split('-').map(Number);
  const startSG = new Date(Date.UTC(y, m - 1, d, 0, 0, 0) - SG_OFFSET_MS);
  const endSG   = new Date(Date.UTC(y, m - 1, d, 23, 59, 59, 999) - SG_OFFSET_MS);
  // Format as SQLite DATETIME strings (UTC)
  const fmt = (dt) => dt.toISOString().replace('T', ' ').replace(/\.\d+Z$/, '');
  return { start: fmt(startSG), end: fmt(endSG) };
}

function todaySG() {
  const sg = nowSG();
  const y = sg.getUTCFullYear();
  const m = String(sg.getUTCMonth() + 1).padStart(2, '0');
  const d = String(sg.getUTCDate()).padStart(2, '0');
  return `${y}-${m}-${d}`;
}

// ─── IP matching (exact + CIDR IPv4/IPv6) ────────────────────────────────────

function ipToBuffer(ip) {
  if (ip.includes(':')) {
    // IPv6: expand and parse
    return parseIPv6(ip);
  } else {
    // IPv4
    return parseIPv4(ip);
  }
}

function parseIPv4(ip) {
  const parts = ip.trim().split('.');
  if (parts.length !== 4) return null;
  const buf = new Uint8Array(4);
  for (let i = 0; i < 4; i++) {
    const n = parseInt(parts[i], 10);
    if (isNaN(n) || n < 0 || n > 255) return null;
    buf[i] = n;
  }
  return buf;
}

function parseIPv6(ip) {
  ip = ip.trim();
  // Handle IPv4-mapped IPv6
  if (ip.startsWith('::ffff:') && ip.includes('.')) {
    const v4 = ip.slice(7);
    const v4buf = parseIPv4(v4);
    if (!v4buf) return null;
    const buf = new Uint8Array(16);
    buf[10] = 0xff; buf[11] = 0xff;
    buf[12] = v4buf[0]; buf[13] = v4buf[1]; buf[14] = v4buf[2]; buf[15] = v4buf[3];
    return buf;
  }
  const halves = ip.split('::');
  if (halves.length > 2) return null;
  const buf = new Uint8Array(16);
  const left = halves[0] ? halves[0].split(':') : [];
  const right = halves[1] ? halves[1].split(':') : [];
  const total = left.length + right.length;
  if (total > 8) return null;
  let idx = 0;
  for (const g of left) {
    const v = parseInt(g, 16);
    if (isNaN(v)) return null;
    buf[idx++] = (v >> 8) & 0xff;
    buf[idx++] = v & 0xff;
  }
  idx = 16 - right.length * 2;
  for (const g of right) {
    const v = parseInt(g, 16);
    if (isNaN(v)) return null;
    buf[idx++] = (v >> 8) & 0xff;
    buf[idx++] = v & 0xff;
  }
  return buf;
}

function normaliseIP(ip) {
  ip = ip.trim();
  // For comparison purposes normalise IPv4 addresses to canonical form
  if (!ip.includes(':')) {
    const buf = parseIPv4(ip);
    if (!buf) return ip;
    return Array.from(buf).join('.');
  }
  // IPv6: parse then rebuild
  const buf = parseIPv6(ip);
  if (!buf) return ip.toLowerCase();
  // Rebuild from buffer
  const groups = [];
  for (let i = 0; i < 16; i += 2) {
    groups.push(((buf[i] << 8) | buf[i + 1]).toString(16));
  }
  return groups.join(':');
}

function ipInCIDR(ip, cidr) {
  const [network, prefixStr] = cidr.split('/');
  const prefix = parseInt(prefixStr, 10);
  if (isNaN(prefix)) return false;

  const ipBuf = ipToBuffer(ip);
  const netBuf = ipToBuffer(network);
  if (!ipBuf || !netBuf) return false;
  if (ipBuf.length !== netBuf.length) return false;

  const bytes = Math.floor(prefix / 8);
  const bits  = prefix % 8;

  for (let i = 0; i < bytes; i++) {
    if (ipBuf[i] !== netBuf[i]) return false;
  }
  if (bits > 0 && bytes < ipBuf.length) {
    const mask = 0xff & (0xff << (8 - bits));
    if ((ipBuf[bytes] & mask) !== (netBuf[bytes] & mask)) return false;
  }
  return true;
}

function isIPAllowed(clientIP, allowedIPs) {
  if (!allowedIPs || !clientIP) return false;
  const normClient = normaliseIP(clientIP);
  for (const entry of allowedIPs.split(',')) {
    const e = entry.trim();
    if (!e) continue;
    if (e.includes('/')) {
      if (ipInCIDR(clientIP, e)) return true;
    } else {
      if (normClient === normaliseIP(e)) return true;
    }
  }
  return false;
}

// ─── HMAC session helpers ─────────────────────────────────────────────────────

async function computeSessionToken(adminKey) {
  const enc = new TextEncoder();
  const key = await crypto.subtle.importKey(
    'raw', enc.encode(adminKey), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']
  );
  const sig = await crypto.subtle.sign('HMAC', key, enc.encode('admin-session'));
  return Array.from(new Uint8Array(sig)).map(b => b.toString(16).padStart(2, '0')).join('');
}

function parseCookies(header) {
  const cookies = {};
  if (!header) return cookies;
  for (const part of header.split(';')) {
    const [k, ...rest] = part.trim().split('=');
    if (k) cookies[k.trim()] = rest.join('=').trim();
  }
  return cookies;
}

async function isAdminAuthenticated(request, adminKey) {
  const cookieHeader = request.headers.get('Cookie') || '';
  const cookies = parseCookies(cookieHeader);
  const sessionCookie = cookies['admin_session'];
  if (!sessionCookie) return false;
  const expected = await computeSessionToken(adminKey);
  // Constant-time compare
  if (sessionCookie.length !== expected.length) return false;
  const enc = new TextEncoder();
  const a = enc.encode(sessionCookie);
  const b = enc.encode(expected);
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a[i] ^ b[i];
  return diff === 0;
}

// ─── CSV injection sanitiser ──────────────────────────────────────────────────

function csvSafe(val) {
  if (val === null || val === undefined) return '';
  const s = String(val);
  if (s.length > 0 && ['=', '+', '-', '@', '\t', '\r'].includes(s[0])) {
    return "'" + s;
  }
  // Escape double quotes
  return s.replace(/"/g, '""');
}

function toCSV(rows) {
  const header = [
    'Worker Name', 'Time (Singapore)', 'IP Address', 'Status', 'Flag Reason',
    'Browser', 'Browser Version', 'OS', 'OS Version',
    'Screen Resolution', 'Colour Depth', 'Device Pixel Ratio', 'Touch Support', 'Canvas Hash'
  ];
  const lines = [header.map(h => `"${csvSafe(h)}"`).join(',')];
  for (const row of rows) {
    let fp = {};
    try { fp = JSON.parse(row.fingerprint_json || '{}'); } catch { fp = {}; }
    lines.push([
      `"${csvSafe(row.name)}"`,
      `"${csvSafe(formatSGTime(row.timestamp))}"`,
      `"${csvSafe(row.ip_address)}"`,
      `"${csvSafe(row.flagged ? 'REVIEW' : 'OK')}"`,
      `"${csvSafe(row.flag_reason || '')}"`,
      `"${csvSafe(fp.browserName || '')}"`,
      `"${csvSafe(fp.browserVersion || '')}"`,
      `"${csvSafe(fp.osName || '')}"`,
      `"${csvSafe(fp.osVersion || '')}"`,
      `"${csvSafe(fp.screenRes || '')}"`,
      `"${csvSafe(fp.colorDepth || '')}"`,
      `"${csvSafe(fp.devicePixelRatio || '')}"`,
      `"${csvSafe(fp.touchSupport ?? '')}"`,
      `"${csvSafe(fp.canvasHash || '')}"`
    ].join(','));
  }
  return lines.join('\r\n');
}

// ─── HTML helpers ─────────────────────────────────────────────────────────────

const BASE_CSS = `
* { box-sizing: border-box; margin: 0; padding: 0; }
body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
       background: #f4f4f5; color: #18181b; min-height: 100vh; }
.card { background: #fff; border-radius: 12px; box-shadow: 0 1px 4px rgba(0,0,0,.1);
        padding: 2rem; max-width: 480px; margin: 2rem auto; }
h1 { font-size: 1.6rem; margin-bottom: .5rem; }
h2 { font-size: 1.2rem; margin-bottom: 1rem; color: #3f3f46; }
.time { font-size: 1.1rem; color: #52525b; margin-bottom: 1rem; }
.notice { font-size: .85rem; color: #52525b; margin-bottom: 1.5rem;
          border-left: 3px solid #d4d4d8; padding-left: .75rem; }
.btn { display: block; width: 100%; padding: 1rem; font-size: 1.2rem; font-weight: 700;
       border: none; border-radius: 8px; cursor: pointer; text-align: center;
       text-decoration: none; }
.btn-green { background: #16a34a; color: #fff; }
.btn-green:hover { background: #15803d; }
.btn-red { background: #dc2626; color: #fff; }
.btn-blue { background: #2563eb; color: #fff; }
.btn-blue:hover { background: #1d4ed8; }
.btn-sm { display: inline-block; width: auto; padding: .35rem .8rem;
          font-size: .85rem; font-weight: 600; border-radius: 6px;
          border: none; cursor: pointer; text-decoration: none; }
.btn-gray { background: #e4e4e7; color: #18181b; }
.btn-gray:hover { background: #d4d4d8; }
.btn-orange { background: #ea580c; color: #fff; }
.err { background: #fef2f2; border: 1px solid #fca5a5; color: #991b1b;
       border-radius: 8px; padding: 1rem; margin-bottom: 1rem; }
.ok  { background: #f0fdf4; border: 1px solid #86efac; color: #166534;
       border-radius: 8px; padding: 1rem; margin-bottom: 1rem; }
input[type=text], input[type=password], input[type=date], input[type=time] {
  width: 100%; padding: .55rem .75rem; border: 1px solid #d4d4d8;
  border-radius: 6px; font-size: 1rem; margin-bottom: .75rem; }
label { display: block; font-size: .9rem; font-weight: 600;
        margin-bottom: .25rem; color: #3f3f46; }
`;

const ADMIN_CSS = `
${BASE_CSS}
body { max-width: 1100px; margin: 0 auto; padding: 1rem; background: #f4f4f5; }
.admin-header { display: flex; align-items: center; justify-content: space-between;
                margin-bottom: 1.5rem; flex-wrap: wrap; gap: .5rem; }
.admin-header h1 { font-size: 1.4rem; }
table { width: 100%; border-collapse: collapse; background: #fff;
        border-radius: 10px; overflow: hidden;
        box-shadow: 0 1px 4px rgba(0,0,0,.08); margin-bottom: 2rem; }
th { background: #f4f4f5; text-align: left; padding: .6rem .8rem;
     font-size: .82rem; color: #52525b; text-transform: uppercase; letter-spacing: .04em; }
td { padding: .55rem .8rem; font-size: .9rem; border-top: 1px solid #f4f4f5; }
tr.flagged td { background: #fefce8; }
.badge-ok   { background: #dcfce7; color: #166534; padding: .15rem .5rem;
              border-radius: 999px; font-size: .78rem; font-weight: 700; }
.badge-rev  { background: #fef9c3; color: #854d0e; padding: .15rem .5rem;
              border-radius: 999px; font-size: .78rem; font-weight: 700;
              border: 1px solid #fde047; }
.section { background: #fff; border-radius: 10px; padding: 1.2rem 1.5rem;
           margin-bottom: 1.5rem; box-shadow: 0 1px 4px rgba(0,0,0,.08); }
.section h2 { margin-bottom: 1rem; font-size: 1rem; color: #3f3f46; }
.worker-row { display: flex; align-items: center; gap: .6rem; flex-wrap: wrap;
              padding: .5rem 0; border-bottom: 1px solid #f4f4f5; }
.worker-row:last-child { border-bottom: none; }
.worker-name { flex: 1; font-weight: 600; min-width: 140px; }
.inactive { color: #a1a1aa; text-decoration: line-through; }
.filter-row { display: flex; gap: .75rem; align-items: center; flex-wrap: wrap;
              margin-bottom: 1rem; }
.filter-row input[type=date] { width: auto; margin: 0; }
.myip { font-size: .82rem; color: #52525b; }
`;

function page(title, css, body) {
  return `<!DOCTYPE html><html lang="en"><head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>${title}</title>
<style>${css}</style>
</head><body>${body}</body></html>`;
}

function errorPage(title, message) {
  return page(title, BASE_CSS, `<div class="card">
<h1>${title}</h1>
<p style="margin-top:.75rem;color:#52525b;">${message}</p>
</div>`);
}

// ─── Fingerprint comparison ───────────────────────────────────────────────────

const FP_FIELDS = ['browserName', 'browserVersion', 'osName', 'osVersion',
                   'screenRes', 'colorDepth', 'devicePixelRatio', 'touchSupport', 'canvasHash'];

function compareFingerprints(baseline, current) {
  const changed = [];
  for (const f of FP_FIELDS) {
    if (String(baseline[f] ?? '') !== String(current[f] ?? '')) changed.push(f);
  }
  return changed;
}

// ─── Settings (ALLOWED_IPS stored in DB, env var is fallback) ────────────────
// Module-level cache so repeated requests on the same isolate skip the DB read.

let allowedIPsCache = null;
let allowedIPsCachedAt = 0;
const ALLOWED_IPS_TTL_MS = 30_000;

async function getAllowedIPs(env) {
  const now = Date.now();
  if (allowedIPsCache !== null && now - allowedIPsCachedAt < ALLOWED_IPS_TTL_MS) {
    return allowedIPsCache;
  }
  try {
    const row = await env.DB.prepare(
      "SELECT value FROM settings WHERE key = 'ALLOWED_IPS'"
    ).first();
    if (row && row.value) {
      allowedIPsCache = row.value;
      allowedIPsCachedAt = now;
      return allowedIPsCache;
    }
  } catch { /* fall through */ }
  return env.ALLOWED_IPS || '';
}

function invalidateAllowedIPsCache() {
  allowedIPsCache = null;
  allowedIPsCachedAt = 0;
}

async function getStartTime(env) {
  try {
    const row = await env.DB.prepare(
      "SELECT value FROM settings WHERE key = 'START_TIME'"
    ).first();
    if (row && row.value) return row.value;
  } catch { /* fall through */ }
  return '09:30';
}

// Convert a SG date string + "HH:MM" start time to a UTC datetime string for DB comparison.
function startTimeCutoffUTC(sgDateStr, startTime) {
  const [y, mo, d] = sgDateStr.split('-').map(Number);
  const [h, mi] = startTime.split(':').map(Number);
  const cutoff = new Date(Date.UTC(y, mo - 1, d) - SG_OFFSET_MS + h * 3_600_000 + mi * 60_000);
  return cutoff.toISOString().replace('T', ' ').replace(/\.\d+Z$/, '');
}

// ─── Route handlers ───────────────────────────────────────────────────────────

async function handleMyIP(request) {
  const ip = request.headers.get('CF-Connecting-IP') || 'unknown';
  return new Response(ip, {
    headers: { 'Content-Type': 'text/plain', 'Cache-Control': 'no-store' }
  });
}

// GET /checkin?token=...
async function handleCheckinGet(request, env) {
  const url = new URL(request.url);
  const token = url.searchParams.get('token');
  if (!token) return new Response(errorPage('Invalid Link', 'No token provided.'),
    { status: 400, headers: { 'Content-Type': 'text/html' } });

  const worker = await env.DB.prepare(
    'SELECT id, first_name, last_name, active FROM workers WHERE token = ?'
  ).bind(token).first();

  if (!worker || !worker.active) {
    return new Response(errorPage(
      'Link Not Valid',
      'This link is no longer valid, please contact your manager.'
    ), { status: 404, headers: { 'Content-Type': 'text/html' } });
  }

  const clientIP = request.headers.get('CF-Connecting-IP') || '';
  const allowed = isIPAllowed(clientIP, await getAllowedIPs(env));
  if (!allowed) {
    return new Response(errorPage(
      'Wrong Network',
      'You must be connected to the shop WiFi to check in. Please do not use mobile data.'
    ), { status: 403, headers: { 'Content-Type': 'text/html' } });
  }

  const sgNow = nowSG();
  const timeStr = sgNow.toLocaleString('en-SG', {
    weekday: 'long', year: 'numeric', month: 'long', day: 'numeric',
    hour: '2-digit', minute: '2-digit', second: '2-digit', hour12: false
  });

  const html = page('Check In', BASE_CSS, `
<div class="card">
  <h1>Hello, ${escHtml(worker.first_name)}!</h1>
  <div class="time">${timeStr}</div>
  <p class="notice">When you check in, we record your device and network details to confirm
  you are on site. This is used only for attendance.</p>
  <button class="btn btn-green" id="checkinBtn" onclick="submitCheckin('${escHtml(token)}')">
    CHECK IN
  </button>
  <p id="status" style="margin-top:1rem;text-align:center;color:#52525b;"></p>
</div>
<script>
async function sha256hex(str) {
  const buf = await crypto.subtle.digest('SHA-256',
    new TextEncoder().encode(str));
  return Array.from(new Uint8Array(buf)).map(b=>b.toString(16).padStart(2,'0')).join('');
}

function parseUA(ua) {
  let browserName = 'Unknown', browserVersion = 'Unknown';
  let osName = 'Unknown', osVersion = 'Unknown';
  // Browser
  const browsers = [
    [/Edg\\/([\\d.]+)/, 'Edge'],
    [/OPR\\/([\\d.]+)/, 'Opera'],
    [/Chrome\\/([\\d.]+)/, 'Chrome'],
    [/Firefox\\/([\\d.]+)/, 'Firefox'],
    [/Safari\\/([\\d.]+)/, 'Safari'],
  ];
  for (const [re, name] of browsers) {
    const m = ua.match(re);
    if (m) { browserName = name; browserVersion = m[1]; break; }
  }
  // OS
  const oses = [
    [/Windows NT ([\\d.]+)/, 'Windows'],
    [/Mac OS X ([\\d_]+)/, 'macOS'],
    [/Android ([\\d.]+)/, 'Android'],
    [/iPhone OS ([\\d_]+)/, 'iOS'],
    [/iPad; CPU OS ([\\d_]+)/, 'iPadOS'],
    [/Linux/, 'Linux'],
  ];
  for (const [re, name] of oses) {
    const m = ua.match(re);
    if (m) {
      osName = name;
      osVersion = m[1] ? m[1].replace(/_/g, '.') : 'Unknown';
      break;
    }
  }
  return { browserName, browserVersion, osName, osVersion };
}

async function collectFingerprint() {
  const ua = navigator.userAgent;
  const parsed = parseUA(ua);
  const screenRes = screen.width + 'x' + screen.height;
  const colorDepth = screen.colorDepth;
  const devicePixelRatio = window.devicePixelRatio || 1;
  const touchSupport = ('ontouchstart' in window) || navigator.maxTouchPoints > 0;

  // Canvas fingerprint
  let canvasHash = 'unavailable';
  try {
    const canvas = document.createElement('canvas');
    canvas.width = 200; canvas.height = 50;
    const ctx = canvas.getContext('2d');
    ctx.fillStyle = '#f0f0f0';
    ctx.fillRect(0, 0, 200, 50);
    ctx.fillStyle = '#1a1a2e';
    ctx.font = '16px Arial';
    ctx.fillText('AtlasCheckin\u00A9fingerprint', 10, 30);
    ctx.strokeStyle = '#e94560';
    ctx.beginPath(); ctx.arc(160, 25, 18, 0, Math.PI * 2); ctx.stroke();
    canvasHash = await sha256hex(canvas.toDataURL());
  } catch(e) {}

  return {
    browserName: parsed.browserName,
    browserVersion: parsed.browserVersion,
    osName: parsed.osName,
    osVersion: parsed.osVersion,
    screenRes,
    colorDepth,
    devicePixelRatio,
    touchSupport,
    canvasHash
  };
}

async function submitCheckin(token) {
  const btn = document.getElementById('checkinBtn');
  const status = document.getElementById('status');
  btn.disabled = true;
  btn.textContent = 'Collecting info…';
  status.textContent = '';
  try {
    const fp = await collectFingerprint();
    const res = await fetch('/checkin', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ token, fingerprint: fp })
    });
    const html = await res.text();
    document.open(); document.write(html); document.close();
  } catch(e) {
    status.textContent = 'Error: ' + e.message;
    btn.disabled = false;
    btn.textContent = 'CHECK IN';
  }
}
<\/script>`);

  return new Response(html, { headers: { 'Content-Type': 'text/html' } });
}

// POST /checkin  (JSON body: { token, fingerprint })
async function handleCheckinPost(request, env) {
  let body;
  try { body = await request.json(); } catch {
    return new Response(errorPage('Error', 'Invalid request.'),
      { status: 400, headers: { 'Content-Type': 'text/html' } });
  }

  const { token, fingerprint } = body;
  if (!token || !fingerprint) {
    return new Response(errorPage('Error', 'Missing data.'),
      { status: 400, headers: { 'Content-Type': 'text/html' } });
  }

  const worker = await env.DB.prepare(
    'SELECT id, first_name, last_name, active FROM workers WHERE token = ?'
  ).bind(token).first();

  if (!worker || !worker.active) {
    return new Response(errorPage('Link Not Valid',
      'This link is no longer valid, please contact your manager.'),
      { status: 404, headers: { 'Content-Type': 'text/html' } });
  }

  const clientIP = request.headers.get('CF-Connecting-IP') || '';
  if (!isIPAllowed(clientIP, await getAllowedIPs(env))) {
    return new Response(errorPage('Wrong Network',
      'You must be connected to the shop WiFi to check in. Please do not use mobile data.'),
      { status: 403, headers: { 'Content-Type': 'text/html' } });
  }

  // Fingerprint comparison
  // NOTE: Flags are advisory, not proof of cheating. Browser/OS updates, new phones,
  // or canvas rendering changes routinely trigger mismatches. Always treat as "review."
  let flagged = 0;
  let flagReason = null;
  const fpHash = await sha256(JSON.stringify(fingerprint));

  const existing = await env.DB.prepare(
    'SELECT fingerprint_json FROM fingerprints WHERE worker_id = ?'
  ).bind(worker.id).first();

  if (!existing) {
    // First check-in: save as baseline
    await env.DB.prepare(
      'INSERT INTO fingerprints (worker_id, fingerprint_json) VALUES (?, ?)'
    ).bind(worker.id, JSON.stringify(fingerprint)).run();
  } else {
    let baseline;
    try { baseline = JSON.parse(existing.fingerprint_json); } catch { baseline = {}; }
    const changed = compareFingerprints(baseline, fingerprint);
    if (changed.length >= 2) {
      flagged = 1;
      flagReason = changed.join(', ');
    }
  }

  await env.DB.prepare(
    `INSERT INTO checkins (worker_id, ip_address, fingerprint_hash, fingerprint_json, flagged, flag_reason)
     VALUES (?, ?, ?, ?, ?, ?)`
  ).bind(worker.id, clientIP, fpHash, JSON.stringify(fingerprint), flagged, flagReason).run();

  const sgNow = nowSG();
  const timeStr = sgNow.toLocaleString('en-SG', {
    weekday: 'long', year: 'numeric', month: 'long', day: 'numeric',
    hour: '2-digit', minute: '2-digit', second: '2-digit', hour12: false
  });

  const reviewNote = flagged
    ? `<div class="err" style="margin-top:1rem;">
        Your check-in has been recorded. Your manager may review this entry.
       </div>`
    : '';

  const html = page('Checked In', BASE_CSS, `
<div class="card">
  <div class="ok">
    <strong>Checked in!</strong><br>
    ${escHtml(worker.first_name)} ${escHtml(worker.last_name)}
  </div>
  <div class="time">${timeStr}</div>
  ${reviewNote}
</div>`);

  return new Response(html, { headers: { 'Content-Type': 'text/html' } });
}

async function sha256(str) {
  const buf = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(str));
  return Array.from(new Uint8Array(buf)).map(b => b.toString(16).padStart(2, '0')).join('');
}

function escHtml(s) {
  return String(s ?? '')
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

// ─── Admin: Login ─────────────────────────────────────────────────────────────

function loginPage(error = '') {
  return page('Admin Login', BASE_CSS, `
<div class="card">
  <h1>Admin Login</h1>
  ${error ? `<div class="err">${escHtml(error)}</div>` : ''}
  <form method="POST" action="/admin/login">
    <label>Password</label>
    <input type="password" name="key" autocomplete="current-password" required>
    <button type="submit" class="btn btn-blue">Log In</button>
  </form>
</div>`);
}

async function handleAdminLogin(request, env) {
  const clientIP = request.headers.get('CF-Connecting-IP') || 'unknown';

  // Check rate limit
  const lockRow = await env.DB.prepare(
    'SELECT fail_count, locked_until FROM admin_login_attempts WHERE ip_address = ?'
  ).bind(clientIP).first();

  if (lockRow && lockRow.locked_until) {
    const lockedUntil = new Date(lockRow.locked_until + 'Z');
    if (lockedUntil > new Date()) {
      const remaining = Math.ceil((lockedUntil - new Date()) / 1000 / 60);
      return new Response(loginPage(`Too many failed attempts. Try again in ${remaining} minute(s).`),
        { status: 429, headers: { 'Content-Type': 'text/html' } });
    }
  }

  const formData = await request.formData();
  const key = formData.get('key') || '';

  // Constant-time compare to avoid timing attacks on the admin password.
  const enc = new TextEncoder();
  const a = enc.encode(key.padEnd(128));
  const b = enc.encode((env.ADMIN_KEY || '').padEnd(128));
  let diff = key.length ^ (env.ADMIN_KEY || '').length;
  for (let i = 0; i < a.length; i++) diff |= a[i] ^ b[i];
  if (diff === 0) {
    // Success: reset fail count
    await env.DB.prepare(
      'DELETE FROM admin_login_attempts WHERE ip_address = ?'
    ).bind(clientIP).run();

    const sessionToken = await computeSessionToken(env.ADMIN_KEY);
    return new Response(null, {
      status: 302,
      headers: {
        'Location': '/admin',
        'Set-Cookie': `admin_session=${sessionToken}; HttpOnly; Secure; SameSite=Strict; Path=/admin; Max-Age=86400`
      }
    });
  }

  // Failed: increment counter
  const failCount = (lockRow?.fail_count || 0) + 1;
  let lockedUntilStr = null;
  if (failCount >= 5) {
    // Lock for 15 minutes
    const lockTime = new Date(Date.now() + 15 * 60 * 1000);
    lockedUntilStr = lockTime.toISOString().replace('T', ' ').replace(/\.\d+Z$/, '');
  }

  await env.DB.prepare(`
    INSERT INTO admin_login_attempts (ip_address, fail_count, locked_until)
    VALUES (?, ?, ?)
    ON CONFLICT(ip_address) DO UPDATE SET fail_count = ?, locked_until = ?
  `).bind(clientIP, failCount, lockedUntilStr, failCount, lockedUntilStr).run();

  const msg = failCount >= 5
    ? 'Too many failed attempts. You are locked out for 15 minutes.'
    : `Incorrect password. ${5 - failCount} attempt(s) remaining.`;

  return new Response(loginPage(msg), { status: 401, headers: { 'Content-Type': 'text/html' } });
}

// ─── Admin: Main view ─────────────────────────────────────────────────────────

async function handleAdminView(request, env) {
  const url = new URL(request.url);
  const selectedDate = url.searchParams.get('date') || todaySG();
  const clientIP = request.headers.get('CF-Connecting-IP') || 'unknown';

  // Export CSV?
  if (url.searchParams.get('export') === 'csv') {
    return handleAdminExport(selectedDate, env);
  }

  const { start, end } = sgDayToUTCRange(selectedDate);
  const currentAllowedIPs = await getAllowedIPs(env);
  const currentStartTime = await getStartTime(env);

  const checkins = await env.DB.prepare(`
    SELECT c.id, w.first_name || ' ' || w.last_name AS name,
           c.timestamp, c.ip_address, c.flagged, c.flag_reason
    FROM checkins c
    JOIN workers w ON w.id = c.worker_id
    WHERE c.timestamp >= ? AND c.timestamp <= ?
    ORDER BY c.timestamp ASC
  `).bind(start, end).all();

  const workers = await env.DB.prepare(
    'SELECT id, first_name, last_name, token, active FROM workers ORDER BY first_name, last_name'
  ).all();

  const rows = (checkins.results || []).map(r => {
    const flag = r.flagged ? 1 : 0;
    return `<tr class="${flag ? 'flagged' : ''}">
      <td>${escHtml(r.name)}</td>
      <td>${escHtml(formatSGTime(r.timestamp))}</td>
      <td>${escHtml(r.ip_address || '')}</td>
      <td>${flag
        ? '<span class="badge-rev">REVIEW</span>'
        : '<span class="badge-ok">OK</span>'}</td>
      <td style="font-size:.82rem;color:#52525b;">${escHtml(r.flag_reason || '')}</td>
    </tr>`;
  }).join('');

  const workerRows = (workers.results || []).map(w => {
    const checkinUrl = `https://atlascheckin.pages.dev/checkin?token=${encodeURIComponent(w.token)}`;
    const activeLabel = w.active ? 'Active' : '<span style="color:#a1a1aa;">Inactive</span>';
    const toggleLabel = w.active ? 'Deactivate' : 'Activate';
    const nameClass = w.active ? '' : 'inactive';
    return `<div class="worker-row">
      <span class="worker-name ${nameClass}">${escHtml(w.first_name)} ${escHtml(w.last_name)}</span>
      <span>${activeLabel}</span>
      <button class="btn btn-sm btn-gray"
        onclick="copyURL('${escHtml(checkinUrl)}')">Copy URL</button>
      <form method="POST" action="/admin/worker/${w.id}/toggle" style="display:inline">
        <button type="submit" class="btn btn-sm ${w.active ? 'btn-orange' : 'btn-blue'}">
          ${toggleLabel}
        </button>
      </form>
      <form method="POST" action="/admin/worker/${w.id}/reset-fp" style="display:inline">
        <button type="submit" class="btn btn-sm btn-gray"
          onclick="return confirm('Reset fingerprint baseline for ${escHtml(w.first_name)}?')">
          Reset Baseline
        </button>
      </form>
      <form method="POST" action="/admin/worker/${w.id}/delete" style="display:inline">
        <button type="submit" class="btn btn-sm btn-red"
          onclick="return confirm('Permanently delete ${escHtml(w.first_name)} ${escHtml(w.last_name)} and all their records? This cannot be undone.')">
          Delete
        </button>
      </form>
    </div>`;
  }).join('');

  const flagNote = '<p style="font-size:.82rem;color:#52525b;margin-top:.5rem;">'
    + 'REVIEW flags are advisory. Browser/OS updates and new phones can trigger them. '
    + 'Always treat as "worth a look," not proof of anything.</p>';

  const html = page('Admin — Attendance', ADMIN_CSS, `
<div class="admin-header">
  <h1>Attendance Admin</h1>
  <span class="myip">Your IP: <strong>${escHtml(clientIP)}</strong></span>
  <div style="display:flex;gap:.5rem;">
    <a href="/admin/late?date=${escHtml(selectedDate)}" class="btn btn-sm btn-orange">Late Arrivals</a>
    <a href="/admin/logout" class="btn btn-sm btn-gray">Log Out</a>
  </div>
</div>

<div class="section">
  <h2>Check-ins for ${escHtml(selectedDate)}</h2>
  <div class="filter-row">
    <form method="GET" action="/admin">
      <input type="date" name="date" value="${escHtml(selectedDate)}" onchange="this.form.submit()">
    </form>
    <a href="/admin?date=${escHtml(selectedDate)}&export=csv" class="btn btn-sm btn-gray">
      Export to CSV
    </a>
  </div>
  ${rows
    ? `<table>
        <thead><tr>
          <th>Worker Name</th><th>Time (SGT)</th><th>IP Address</th>
          <th>Status</th><th>Flag Reason</th>
        </tr></thead>
        <tbody>${rows}</tbody>
       </table>${flagNote}`
    : '<p style="color:#52525b;">No check-ins recorded for this day.</p>'}
</div>

<div class="section">
  <h2>Settings</h2>
  <label style="margin-bottom:.25rem;">Allowed IPs</label>
  <p style="font-size:.85rem;color:#52525b;margin-bottom:.5rem;">
    Comma-separated exact IPs or CIDR ranges. Your current IP is <strong>${escHtml(clientIP)}</strong>.
    Open <a href="/myip" target="_blank">/myip</a> on the shop WiFi to find its IP.
  </p>
  <form method="POST" action="/admin/settings/allowed-ips" style="display:flex;gap:.75rem;align-items:flex-start;flex-wrap:wrap;margin-bottom:1.2rem;">
    <input type="text" name="allowed_ips" value="${escHtml(currentAllowedIPs)}"
      placeholder="e.g. 203.1.2.3,10.0.0.0/24"
      style="flex:1;min-width:260px;margin:0;font-family:monospace;">
    <button type="submit" class="btn btn-sm btn-blue" style="white-space:nowrap;">Save</button>
  </form>
  <label style="margin-bottom:.25rem;">Shift Start Time (Singapore time)</label>
  <p style="font-size:.85rem;color:#52525b;margin-bottom:.5rem;">
    Workers who check in after this time are marked <strong>LATE</strong> on the Late Arrivals page.
  </p>
  <form method="POST" action="/admin/settings/start-time" style="display:flex;gap:.75rem;align-items:flex-start;flex-wrap:wrap;">
    <input type="time" name="start_time" value="${escHtml(currentStartTime)}"
      style="width:auto;margin:0;">
    <button type="submit" class="btn btn-sm btn-blue" style="white-space:nowrap;">Save</button>
  </form>
</div>

<div class="section">
  <h2>Workers</h2>
  ${workerRows || '<p style="color:#52525b;">No workers yet.</p>'}
  <form method="POST" action="/admin/worker/add"
    style="margin-top:1.2rem;padding-top:1.2rem;border-top:1px solid #f4f4f5;">
    <h2 style="margin-bottom:.75rem;">Add New Worker</h2>
    <div style="display:flex;gap:.75rem;flex-wrap:wrap;">
      <div style="flex:1;min-width:140px;">
        <label>First Name</label>
        <input type="text" name="first_name" required>
      </div>
      <div style="flex:1;min-width:140px;">
        <label>Last Name</label>
        <input type="text" name="last_name" required>
      </div>
    </div>
    <button type="submit" class="btn btn-blue" style="max-width:200px;">Add Worker</button>
  </form>
</div>

<script>
function copyURL(url) {
  navigator.clipboard.writeText(url).then(
    () => alert('Copied: ' + url),
    () => prompt('Copy this URL:', url)
  );
}
<\/script>`);

  return new Response(html, { headers: { 'Content-Type': 'text/html' } });
}

async function handleAdminExport(selectedDate, env) {
  const { start, end } = sgDayToUTCRange(selectedDate);
  const checkins = await env.DB.prepare(`
    SELECT w.first_name || ' ' || w.last_name AS name,
           c.timestamp, c.ip_address, c.flagged, c.flag_reason, c.fingerprint_json
    FROM checkins c
    JOIN workers w ON w.id = c.worker_id
    WHERE c.timestamp >= ? AND c.timestamp <= ?
    ORDER BY c.timestamp ASC
  `).bind(start, end).all();

  const csv = toCSV(checkins.results || []);
  return new Response(csv, {
    headers: {
      'Content-Type': 'text/csv',
      'Content-Disposition': `attachment; filename="attendance-${selectedDate}.csv"`,
      'Cache-Control': 'no-store'
    }
  });
}

async function handleAddWorker(request, env) {
  const formData = await request.formData();
  const firstName = (formData.get('first_name') || '').trim();
  const lastName  = (formData.get('last_name')  || '').trim();
  if (!firstName || !lastName) {
    return new Response(null, { status: 302, headers: { 'Location': '/admin' } });
  }
  const token = crypto.randomUUID();
  await env.DB.prepare(
    'INSERT INTO workers (first_name, last_name, token) VALUES (?, ?, ?)'
  ).bind(firstName, lastName, token).run();
  return new Response(null, { status: 302, headers: { 'Location': '/admin' } });
}

async function handleToggleWorker(workerId, env) {
  const worker = await env.DB.prepare(
    'SELECT active FROM workers WHERE id = ?'
  ).bind(workerId).first();
  if (!worker) return new Response(null, { status: 302, headers: { 'Location': '/admin' } });
  await env.DB.prepare(
    'UPDATE workers SET active = ? WHERE id = ?'
  ).bind(worker.active ? 0 : 1, workerId).run();
  return new Response(null, { status: 302, headers: { 'Location': '/admin' } });
}

async function handleResetFingerprint(workerId, env) {
  await env.DB.prepare(
    'DELETE FROM fingerprints WHERE worker_id = ?'
  ).bind(workerId).run();
  return new Response(null, { status: 302, headers: { 'Location': '/admin' } });
}

async function handleDeleteWorker(workerId, env) {
  // Delete all related records first (FK constraint order), then the worker row.
  await env.DB.prepare('DELETE FROM checkins    WHERE worker_id = ?').bind(workerId).run();
  await env.DB.prepare('DELETE FROM fingerprints WHERE worker_id = ?').bind(workerId).run();
  await env.DB.prepare('DELETE FROM workers      WHERE id = ?').bind(workerId).run();
  return new Response(null, { status: 302, headers: { 'Location': '/admin' } });
}

async function handleLateView(request, env) {
  const url = new URL(request.url);
  const selectedDate = url.searchParams.get('date') || todaySG();
  const startTime = await getStartTime(env);
  const { start, end } = sgDayToUTCRange(selectedDate);
  const cutoff = startTimeCutoffUTC(selectedDate, startTime);

  // All active workers
  const workersRes = await env.DB.prepare(
    'SELECT id, first_name, last_name FROM workers WHERE active = 1 ORDER BY first_name, last_name'
  ).all();

  // First check-in per worker for the day
  const firstRes = await env.DB.prepare(`
    SELECT worker_id, MIN(timestamp) AS first_checkin
    FROM checkins
    WHERE timestamp >= ? AND timestamp <= ?
    GROUP BY worker_id
  `).bind(start, end).all();

  const firstMap = {};
  for (const r of firstRes.results || []) firstMap[r.worker_id] = r.first_checkin;

  // Classify each worker
  const rows = (workersRes.results || []).map(w => {
    const fc = firstMap[w.id] || null;
    let status, badgeClass;
    if (!fc) {
      status = 'ABSENT'; badgeClass = 'badge-absent';
    } else if (fc > cutoff) {
      status = 'LATE'; badgeClass = 'badge-late';
    } else {
      status = 'ON TIME'; badgeClass = 'badge-ok';
    }
    return { w, fc, status, badgeClass };
  });

  // Sort: ABSENT first, then LATE, then ON TIME
  const order = { ABSENT: 0, LATE: 1, 'ON TIME': 2 };
  rows.sort((a, b) => order[a.status] - order[b.status]);

  const tableRows = rows.map(({ w, fc, status, badgeClass }) => `
    <tr class="${status === 'ON TIME' ? '' : 'flagged'}">
      <td>${escHtml(w.first_name)} ${escHtml(w.last_name)}</td>
      <td>${fc ? escHtml(formatSGTime(fc)) : '—'}</td>
      <td><span class="${badgeClass}">${status}</span></td>
    </tr>`).join('');

  const absentCount = rows.filter(r => r.status === 'ABSENT').length;
  const lateCount   = rows.filter(r => r.status === 'LATE').length;
  const ontimeCount = rows.filter(r => r.status === 'ON TIME').length;

  const css = ADMIN_CSS + `
    .badge-late   { background:#fee2e2; color:#991b1b; padding:.15rem .5rem;
                    border-radius:999px; font-size:.78rem; font-weight:700;
                    border:1px solid #fca5a5; }
    .badge-absent { background:#f1f5f9; color:#475569; padding:.15rem .5rem;
                    border-radius:999px; font-size:.78rem; font-weight:700;
                    border:1px solid #cbd5e1; }
    .summary-pills { display:flex; gap:.75rem; flex-wrap:wrap; margin-bottom:1.2rem; }
    .pill { padding:.4rem 1rem; border-radius:999px; font-weight:700; font-size:.9rem; }
    .pill-absent { background:#f1f5f9; color:#475569; }
    .pill-late   { background:#fee2e2; color:#991b1b; }
    .pill-ok     { background:#dcfce7; color:#166534; }
  `;

  const html = page(`Late Arrivals — ${selectedDate}`, css, `
<div class="admin-header">
  <h1>Late Arrivals</h1>
  <div style="display:flex;gap:.5rem;align-items:center;flex-wrap:wrap;">
    <a href="/admin" class="btn btn-sm btn-gray">← Attendance</a>
    <a href="/admin/logout" class="btn btn-sm btn-gray">Log Out</a>
  </div>
</div>

<div class="section">
  <div style="display:flex;gap:1rem;align-items:center;flex-wrap:wrap;margin-bottom:1rem;">
    <form method="GET" action="/admin/late" style="display:flex;gap:.5rem;align-items:center;">
      <input type="date" name="date" value="${escHtml(selectedDate)}" onchange="this.form.submit()" style="margin:0;">
    </form>
    <span style="font-size:.9rem;color:#52525b;">
      Start time: <strong>${escHtml(startTime)}</strong> SGT
      — <a href="/admin" style="font-size:.85rem;">change in Settings</a>
    </span>
  </div>
  <div class="summary-pills">
    <span class="pill pill-absent">${absentCount} Absent</span>
    <span class="pill pill-late">${lateCount} Late</span>
    <span class="pill pill-ok">${ontimeCount} On Time</span>
  </div>
  <table>
    <thead><tr><th>Worker</th><th>First Check-in (SGT)</th><th>Status</th></tr></thead>
    <tbody>${tableRows || '<tr><td colspan="3" style="color:#52525b;">No active workers.</td></tr>'}</tbody>
  </table>
</div>`);

  return new Response(html, { headers: { 'Content-Type': 'text/html' } });
}

async function handleUpdateStartTime(request, env) {
  const formData = await request.formData();
  const value = (formData.get('start_time') || '09:30').trim();
  // Validate HH:MM format
  if (!/^\d{2}:\d{2}$/.test(value)) {
    return new Response(null, { status: 302, headers: { 'Location': '/admin' } });
  }
  await env.DB.prepare(`
    INSERT INTO settings (key, value, updated_at)
    VALUES ('START_TIME', ?, CURRENT_TIMESTAMP)
    ON CONFLICT(key) DO UPDATE SET value = ?, updated_at = CURRENT_TIMESTAMP
  `).bind(value, value).run();
  return new Response(null, { status: 302, headers: { 'Location': '/admin' } });
}

async function handleUpdateAllowedIPs(request, env) {
  const formData = await request.formData();
  const value = (formData.get('allowed_ips') || '').trim();
  await env.DB.prepare(`
    INSERT INTO settings (key, value, updated_at)
    VALUES ('ALLOWED_IPS', ?, CURRENT_TIMESTAMP)
    ON CONFLICT(key) DO UPDATE SET value = ?, updated_at = CURRENT_TIMESTAMP
  `).bind(value, value).run();
  invalidateAllowedIPsCache();
  return new Response(null, { status: 302, headers: { 'Location': '/admin' } });
}

async function handleAdminLogout() {
  return new Response(null, {
    status: 302,
    headers: {
      'Location': '/admin',
      'Set-Cookie': 'admin_session=; HttpOnly; Secure; SameSite=Strict; Path=/admin; Max-Age=0'
    }
  });
}

// ─── Main fetch handler ───────────────────────────────────────────────────────

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    const path = url.pathname;
    const method = request.method;

    // Public routes
    if (path === '/myip') return handleMyIP(request);

    if (path === '/checkin') {
      if (method === 'GET')  return handleCheckinGet(request, env);
      if (method === 'POST') return handleCheckinPost(request, env);
    }

    // Admin login (public)
    if (path === '/admin/login' && method === 'POST') {
      return handleAdminLogin(request, env);
    }

    // Admin logout
    if (path === '/admin/logout') return handleAdminLogout();

    // All other /admin routes require auth
    if (path.startsWith('/admin')) {
      if (!env.ADMIN_KEY) {
        return new Response(errorPage('Config Error', 'ADMIN_KEY is not set.'),
          { status: 500, headers: { 'Content-Type': 'text/html' } });
      }
      const authed = await isAdminAuthenticated(request, env.ADMIN_KEY);
      if (!authed) {
        if (method === 'GET') {
          return new Response(loginPage(), { headers: { 'Content-Type': 'text/html' } });
        }
        return new Response(null, { status: 302, headers: { 'Location': '/admin' } });
      }

      if (path === '/admin' && method === 'GET')  return handleAdminView(request, env);

      // Worker management
      if (path === '/admin/worker/add' && method === 'POST') return handleAddWorker(request, env);

      const toggleMatch = path.match(/^\/admin\/worker\/(\d+)\/toggle$/);
      if (toggleMatch && method === 'POST') return handleToggleWorker(Number(toggleMatch[1]), env);

      const resetMatch = path.match(/^\/admin\/worker\/(\d+)\/reset-fp$/);
      if (resetMatch && method === 'POST') return handleResetFingerprint(Number(resetMatch[1]), env);

      const deleteMatch = path.match(/^\/admin\/worker\/(\d+)\/delete$/);
      if (deleteMatch && method === 'POST') return handleDeleteWorker(Number(deleteMatch[1]), env);

      if (path === '/admin/settings/allowed-ips' && method === 'POST')
        return handleUpdateAllowedIPs(request, env);

      if (path === '/admin/settings/start-time' && method === 'POST')
        return handleUpdateStartTime(request, env);

      if (path === '/admin/late' && method === 'GET')
        return handleLateView(request, env);

      return new Response(null, { status: 302, headers: { 'Location': '/admin' } });
    }

    // Root redirect
    if (path === '/') {
      return new Response(null, { status: 302, headers: { 'Location': '/admin' } });
    }

    return new Response('Not found', { status: 404 });
  }
};
