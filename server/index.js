require('dotenv').config();
const express = require('express');
const session = require('express-session');
const path = require('path');
const crypto = require('crypto');

// Initialize database (runs migrations + seed)
const db = require('./db');

// Session store backed by SQLite
const BetterSqlite3SessionStore = require('better-sqlite3-session-store');
const SqliteStore = BetterSqlite3SessionStore(session);

const app = express();
const PORT = parseInt(process.env.PORT, 10) || 8080;

// Trust first proxy (needed for correct req.ip behind nginx/load balancer & rate limiting)
app.set('trust proxy', 1);

// Parse JSON bodies
app.use(express.json());

// Session configuration
const sessionSecret = process.env.SESSION_SECRET || crypto.randomBytes(32).toString('hex');
if (!process.env.SESSION_SECRET) {
  console.warn('WARNING: SESSION_SECRET not set — using random secret. Sessions will not survive restarts.');
}
const cookieMaxAgeDays = parseInt(process.env.COOKIE_MAX_AGE_DAYS, 10) || 7;
app.use(session({
  store: new SqliteStore({
    client: db,
    expired: {
      clear: true,
      intervalMs: 900000 // 15 minutes
    }
  }),
  secret: sessionSecret,
  resave: false,
  saveUninitialized: false,
  cookie: {
    httpOnly: true,
    secure: process.env.COOKIE_SECURE === 'true',
    maxAge: cookieMaxAgeDays * 24 * 60 * 60 * 1000,
    sameSite: 'lax'
  }
}));

// Capture IP (hashed) and user-agent on every authenticated request
app.use((req, res, next) => {
  if (req.session && req.session.userId) {
    const ip = req.ip || req.connection.remoteAddress || '';
    const ipHash = crypto.createHash('sha256').update(ip).digest('hex').slice(0, 12);
    req.session.ipHash = ipHash;
    req.session.ua = (req.headers['user-agent'] || '').slice(0, 200);
    req.session.lastSeen = new Date().toISOString();
  }
  next();
});

// Serve static frontend files from parent directory
app.use(express.static(path.join(__dirname, '..')));

// Serve uploaded avatars
app.use('/uploads', express.static(path.join(__dirname, 'uploads')));

// API routes
app.use('/api/auth', require('./routes/auth'));
app.use('/api/user', require('./routes/user'));
app.use('/api/analytics', require('./routes/analytics'));
app.use('/api/oauth', require('./routes/oauth'));
app.use('/api/admin', requireAdmin, require('./routes/admin'));

// ─── RESET PASSWORD PAGE ─────────────────────────────────────
app.get('/reset-password', (req, res) => {
  const token = req.query.token || '';
  res.send(`<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Reset Password — OIL Benchmarks</title>
<link href="https://fonts.googleapis.com/css2?family=DM+Mono:wght@400;500&display=swap" rel="stylesheet">
<style>
*{margin:0;padding:0;box-sizing:border-box}
body{background:#0c0c0e;color:#e8e4dc;font-family:'DM Mono',monospace;display:flex;align-items:center;justify-content:center;min-height:100vh;padding:20px}
.card{background:#111;border:2px solid #444;border-radius:8px;width:400px;max-width:100%;padding:28px 24px;box-shadow:0 20px 60px rgba(0,0,0,0.8)}
.card h1{font-size:14px;font-weight:700;letter-spacing:1.5px;text-transform:uppercase;margin-bottom:8px;color:#c9a84c}
.card p{font-size:10px;color:#888;line-height:1.5;margin-bottom:18px}
.field{margin-bottom:12px}
.field label{display:block;font-size:9px;font-weight:700;letter-spacing:0.5px;color:#888;margin-bottom:4px;text-transform:uppercase}
.field input{width:100%;padding:9px 10px;background:#1a1a1a;border:1px solid #333;border-radius:4px;color:#e8e4dc;font-family:'DM Mono',monospace;font-size:11px;transition:border-color 0.2s}
.field input:focus{outline:none;border-color:rgba(201,168,76,0.5)}
.btn{display:block;width:100%;padding:10px;background:linear-gradient(135deg,#85783c,#c9a84c);border:none;border-radius:4px;color:#0c0c0e;font-family:'DM Mono',monospace;font-size:11px;font-weight:700;letter-spacing:1px;text-transform:uppercase;cursor:pointer;transition:filter 0.2s;margin-top:6px}
.btn:hover{filter:brightness(1.15)}
.btn:disabled{opacity:0.5;cursor:default}
.msg{font-size:10px;margin-top:12px;padding:8px 10px;border-radius:4px;display:none}
.msg.error{display:block;background:rgba(224,80,64,0.1);border:1px solid rgba(224,80,64,0.3);color:#e05040}
.msg.success{display:block;background:rgba(76,175,104,0.1);border:1px solid rgba(76,175,104,0.3);color:#4caf68}
.back{display:block;text-align:center;margin-top:16px;font-size:10px;color:rgba(201,168,76,0.7);text-decoration:none;letter-spacing:0.5px}
.back:hover{color:#c9a84c}
</style>
</head>
<body>
<div class="card">
  <h1>Reset Password</h1>
  <p>Enter your new password below.</p>
  <div class="field">
    <label>New Password</label>
    <input type="password" id="pw1" placeholder="Min. 4 characters" autocomplete="new-password">
  </div>
  <div class="field">
    <label>Confirm Password</label>
    <input type="password" id="pw2" placeholder="Re-enter password" autocomplete="new-password">
  </div>
  <button class="btn" id="submit-btn">Reset Password</button>
  <div class="msg" id="msg"></div>
  <a href="/" class="back">&larr; Back to OIL Benchmarks</a>
</div>
<script>
var token = ${JSON.stringify(token)};
var btn = document.getElementById('submit-btn');
var msg = document.getElementById('msg');
btn.addEventListener('click', function() {
  var pw1 = document.getElementById('pw1').value;
  var pw2 = document.getElementById('pw2').value;
  msg.className = 'msg'; msg.style.display = 'none';
  if (!pw1 || !pw2) { msg.textContent = 'Please fill in both fields.'; msg.className = 'msg error'; return; }
  if (pw1.length < 4) { msg.textContent = 'Password must be at least 4 characters.'; msg.className = 'msg error'; return; }
  if (pw1 !== pw2) { msg.textContent = 'Passwords do not match.'; msg.className = 'msg error'; return; }
  btn.disabled = true; btn.textContent = '...';
  fetch('/api/auth/reset', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ token: token, newPassword: pw1 })
  })
  .then(function(r) { return r.json(); })
  .then(function(data) {
    btn.disabled = false; btn.textContent = 'Reset Password';
    if (data.error) { msg.textContent = data.error; msg.className = 'msg error'; }
    else { msg.textContent = 'Password reset! You can now sign in.'; msg.className = 'msg success'; btn.style.display = 'none'; }
  })
  .catch(function() { btn.disabled = false; btn.textContent = 'Reset Password'; msg.textContent = 'Something went wrong.'; msg.className = 'msg error'; });
});
</script>
</body>
</html>`);
});

// ─── Admin authentication middleware ─────────────────────────────
function requireAdmin(req, res, next) {
  if (!req.session || !req.session.userId) {
    return res.status(401).send('<!DOCTYPE html><html><head><meta charset="utf-8"><title>Unauthorized</title><link href="https://fonts.googleapis.com/css2?family=DM+Mono:wght@400;500&display=swap" rel="stylesheet"><style>*{margin:0;padding:0;box-sizing:border-box}body{background:#0c0c0e;color:#e8e4dc;font-family:"DM Mono",monospace;display:flex;align-items:center;justify-content:center;min-height:100vh;padding:20px}.card{background:#111;border:2px solid #444;border-radius:8px;width:360px;padding:28px 24px;text-align:center}.card h1{font-size:14px;color:#e03030;letter-spacing:1.5px;text-transform:uppercase;margin-bottom:12px}.card p{font-size:11px;color:#888;line-height:1.6;margin-bottom:18px}.back{display:inline-block;padding:8px 16px;background:linear-gradient(135deg,#85783c,#c9a84c);border-radius:4px;color:#0c0c0e;font-weight:700;font-size:10px;letter-spacing:1px;text-decoration:none;text-transform:uppercase}.back:hover{filter:brightness(1.15)}</style></head><body><div class="card"><h1>401 — Unauthorized</h1><p>You must be logged in as an admin to access this page.</p><a class="back" href="/">Back to App</a></div></body></html>');
  }
  const user = db.prepare('SELECT plan FROM users WHERE id = ?').get(req.session.userId);
  if (!user || user.plan !== 'Admin') {
    return res.status(403).send('<!DOCTYPE html><html><head><meta charset="utf-8"><title>Forbidden</title><link href="https://fonts.googleapis.com/css2?family=DM+Mono:wght@400;500&display=swap" rel="stylesheet"><style>*{margin:0;padding:0;box-sizing:border-box}body{background:#0c0c0e;color:#e8e4dc;font-family:"DM Mono",monospace;display:flex;align-items:center;justify-content:center;min-height:100vh;padding:20px}.card{background:#111;border:2px solid #444;border-radius:8px;width:360px;padding:28px 24px;text-align:center}.card h1{font-size:14px;color:#e03030;letter-spacing:1.5px;text-transform:uppercase;margin-bottom:12px}.card p{font-size:11px;color:#888;line-height:1.6;margin-bottom:18px}.back{display:inline-block;padding:8px 16px;background:linear-gradient(135deg,#85783c,#c9a84c);border-radius:4px;color:#0c0c0e;font-weight:700;font-size:10px;letter-spacing:1px;text-decoration:none;text-transform:uppercase}.back:hover{filter:brightness(1.15)}</style></head><body><div class="card"><h1>403 — Forbidden</h1><p>Admin access required. Your account does not have permission to view this page.</p><a class="back" href="/">Back to App</a></div></body></html>');
  }
  next();
}

// ─── ADMIN PAGE (shell — data loaded via /api/admin endpoints) ──
app.get('/admin', requireAdmin, (req, res) => {
  const html = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Admin — Oil Benchmarks</title>
<link href="https://fonts.googleapis.com/css2?family=DM+Mono:wght@300;400;500&display=swap" rel="stylesheet">
<style>
*{margin:0;padding:0;box-sizing:border-box}
body{background:#0c0c0e;color:#e8e4dc;font-family:'DM Mono',monospace;padding:24px;font-size:13px}
h1{font-size:18px;color:#c9a84c;letter-spacing:2px;text-transform:uppercase;margin-bottom:6px}
.subtitle{font-size:10px;color:#666;letter-spacing:1px;margin-bottom:24px}
.warn{background:rgba(224,48,48,0.1);border:1px solid rgba(224,48,48,0.3);border-radius:4px;padding:8px 14px;font-size:10px;color:#e03030;margin-bottom:20px;letter-spacing:0.5px}
.stats{display:flex;gap:12px;margin-bottom:24px;flex-wrap:wrap}
.stat{background:#141418;border:1px solid #333;border-radius:6px;padding:12px 18px;min-width:120px}
.stat-val{font-size:22px;font-weight:700;color:#c9a84c}
.stat-label{font-size:9px;color:#666;text-transform:uppercase;letter-spacing:1px;margin-top:4px}
h2{font-size:12px;color:#c9a84c;letter-spacing:1.5px;text-transform:uppercase;margin:20px 0 10px;border-bottom:1px solid #282828;padding-bottom:6px}
table{width:100%;border-collapse:collapse;margin-bottom:24px}
th{text-align:left;font-size:9px;color:#666;text-transform:uppercase;letter-spacing:1px;padding:8px 12px;border-bottom:2px solid #333;font-weight:700}
td{padding:8px 12px;border-bottom:1px solid #1e1e1e;font-size:12px}
tr:hover td{background:rgba(201,168,76,0.04)}
.tag{display:inline-block;padding:2px 8px;border-radius:3px;font-size:9px;font-weight:700;letter-spacing:0.5px}
.tag-on{background:rgba(93,220,120,0.12);color:#5ddc78;border:1px solid rgba(93,220,120,0.3)}
.tag-off{background:rgba(255,82,82,0.08);color:#ff5252;border:1px solid rgba(255,82,82,0.2)}
.tag-plan{background:rgba(201,168,76,0.1);color:#c9a84c;border:1px solid rgba(201,168,76,0.3)}
.tag-admin{background:rgba(201,168,76,0.2);color:#e8c84c;border:1px solid rgba(201,168,76,0.5)}
.sid{font-size:10px;color:#555;max-width:200px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.back{display:inline-block;margin-top:16px;padding:8px 16px;background:linear-gradient(135deg,#85783c,#c9a84c);border-radius:4px;color:#0c0c0e;font-weight:700;font-size:10px;letter-spacing:1px;text-decoration:none;text-transform:uppercase}
.back:hover{filter:brightness(1.15)}
.close-btn{position:fixed;top:16px;right:16px;width:32px;height:32px;border:1px solid #444;border-radius:50%;background:#1a1a1a;color:#aaa;font-size:16px;display:flex;align-items:center;justify-content:center;cursor:pointer;transition:all 0.2s;text-decoration:none;z-index:100}
.close-btn:hover{background:#252525;color:#e8e4dc;border-color:#666}
.actions{margin-bottom:20px;display:flex;gap:8px}
.btn{padding:6px 14px;border:1px solid #444;border-radius:4px;background:#1a1a1a;color:#aaa;font-family:'DM Mono',monospace;font-size:10px;font-weight:700;cursor:pointer;text-decoration:none;letter-spacing:0.5px;transition:all 0.2s}
.btn:hover{background:#252525;color:#e8e4dc;border-color:#666}
.btn-danger{border-color:rgba(173,90,77,0.4);color:#ad5a4d}
.btn-danger:hover{background:rgba(173,90,77,0.1);color:#e05040;border-color:#ad5a4d}
.btn-sm{padding:3px 8px;font-size:9px}
.av-circle{width:22px;height:22px;border-radius:50%;display:inline-flex;align-items:center;justify-content:center;font-size:9px;font-weight:700;color:#0c0c0e;vertical-align:middle;overflow:hidden;border:1px solid #333}
.av-circle img{width:100%;height:100%;object-fit:cover}
.av-none{color:#555;font-size:9px}
dialog{background:#141418;color:#e8e4dc;border:1px solid #444;border-radius:8px;padding:20px;font-family:'DM Mono',monospace;max-width:360px}
dialog::backdrop{background:rgba(0,0,0,0.7)}
dialog h3{font-size:13px;color:#e03030;margin-bottom:8px}
dialog p{font-size:11px;color:#aaa;margin-bottom:16px;line-height:1.5}
dialog .dialog-actions{display:flex;gap:8px;justify-content:flex-end}
dialog .user-detail{color:#c9a84c;font-weight:700}
.charts-grid{display:grid;grid-template-columns:1fr 1fr;gap:16px;margin-bottom:24px}
.chart-card{background:#141418;border:1px solid #282828;border-radius:6px;padding:16px}
.chart-card h3{font-size:10px;color:#c9a84c;text-transform:uppercase;letter-spacing:1px;margin-bottom:12px;font-weight:700}
.chart-card canvas{width:100%!important;max-height:220px}
.loading{color:#555;font-size:10px;letter-spacing:1px;text-transform:uppercase;animation:pulse 1.5s ease-in-out infinite}
@keyframes pulse{0%,100%{opacity:0.4}50%{opacity:1}}
@media(max-width:768px){.charts-grid{grid-template-columns:1fr}}
</style>
</head>
<body>
<a class="close-btn" href="/" title="Back to App">&times;</a>
<h1>&#9881; Admin Panel</h1>
<p class="subtitle">Oil Benchmarks &mdash; Database Inspector</p>
<div class="warn">&#9888; This route is for development only. Remove before deploying to production.</div>

<div class="stats" id="stats-bar"><span class="loading">Loading stats...</span></div>

<div class="actions">
  <a class="btn" href="/admin" title="Refresh">&#8635; Refresh</a>
  <a class="btn btn-danger" href="/admin/clear-sessions" title="Clear all sessions">&#10005; Clear Sessions</a>
</div>

<h2>&#9776; Analytics Dashboard</h2>
<div class="charts-grid">
  <div class="chart-card"><h3>Registration Trends (Daily)</h3><canvas id="regChart"></canvas></div>
  <div class="chart-card"><h3>Cumulative Users Over Time</h3><canvas id="cumChart"></canvas></div>
  <div class="chart-card"><h3>Registrations by Week</h3><canvas id="weekChart"></canvas></div>
  <div class="chart-card"><h3>Most Used Features</h3><canvas id="featureChart"></canvas></div>
  <div class="chart-card"><h3>Plan Distribution</h3><canvas id="planChart"></canvas></div>
  <div class="chart-card"><h3>Active Sessions</h3><canvas id="sessionChart"></canvas></div>
  <div class="chart-card"><h3>Top Users by Logins</h3><canvas id="loginActivityChart"></canvas></div>
  <div class="chart-card"><h3>Login Activity (Daily)</h3><canvas id="recentLoginsChart"></canvas></div>
</div>

<h2 id="site-analytics-heading">&#128202; Site Analytics</h2>
<div class="charts-grid">
  <div class="chart-card"><h3>Page Views &amp; Visitors (Daily)</h3><canvas id="viewsChart"></canvas></div>
  <div class="chart-card"><h3>Browser Distribution</h3><canvas id="browserChart"></canvas></div>
  <div class="chart-card"><h3>Device Types</h3><canvas id="deviceChart"></canvas></div>
  <div class="chart-card"><h3>Feature Events</h3><canvas id="eventsChart"></canvas></div>
</div>
<div id="referrers-container"></div>

<h2>Users</h2>
<div id="users-table"><span class="loading">Loading users...</span></div>

<h2>User Settings</h2>
<div id="settings-table"><span class="loading">Loading settings...</span></div>

<h2>&#128337; User Activity Log</h2>
<div id="activity-table"><span class="loading">Loading activity...</span></div>

<h2>Sessions</h2>
<div id="sessions-table"><span class="loading">Loading sessions...</span></div>

<h2>Tables</h2>
<div id="tables-list"><span class="loading">Loading...</span></div>

<a class="back" href="/">&#8592; Back to App</a>

<dialog id="deleteDialog">
  <h3>&#9888; Delete User</h3>
  <p>Are you sure you want to permanently delete <span class="user-detail" id="del-user-info"></span>? This will remove all their data including settings and sessions.</p>
  <div class="dialog-actions">
    <button class="btn" onclick="document.getElementById('deleteDialog').close()">Cancel</button>
    <a class="btn btn-danger" id="del-confirm-link" href="#">&#10005; Delete</a>
  </div>
</dialog>

<script src="https://cdn.jsdelivr.net/npm/chart.js@4.4.7/dist/chart.umd.min.js"><\/script>
<script>
function confirmDelete(id, name, email) {
  document.getElementById('del-user-info').textContent = name + ' (' + email + ')';
  document.getElementById('del-confirm-link').href = '/admin/delete-user/' + id;
  document.getElementById('deleteDialog').showModal();
}
function esc(s) { var d = document.createElement('div'); d.textContent = s; return d.innerHTML; }
function escAttr(s) { return esc(s).replace(/'/g,'&#39;').replace(/"/g,'&quot;'); }
function escCss(s) { return s ? s.replace(/[;}{<>"'()\\\\]/g,'').replace(/url/gi,'').replace(/expression/gi,'') : ''; }

var gridColor = 'rgba(255,255,255,0.06)';
var tickColor = '#666';
var defOpts = {responsive:true,animation:{duration:600},plugins:{legend:{display:false}},scales:{x:{ticks:{color:tickColor,font:{size:9}},grid:{color:gridColor}},y:{ticks:{color:tickColor,font:{size:9}},grid:{color:gridColor},beginAtZero:true}}};
var legendOpts = {responsive:true,animation:{duration:600},plugins:{legend:{position:'bottom',labels:{color:tickColor,font:{size:9},padding:10}}}};

// ── Fetch summary stats ─────────────────────────────────────────
fetch('/api/admin/summary').then(function(r){return r.json()}).then(function(d){
  document.getElementById('stats-bar').innerHTML =
    '<div class="stat"><div class="stat-val">'+d.userCount+'</div><div class="stat-label">Users</div></div>'+
    '<div class="stat"><div class="stat-val">'+d.sessionCount+'</div><div class="stat-label">Active Sessions</div></div>'+
    '<div class="stat"><div class="stat-val">'+d.tableCount+'</div><div class="stat-label">Tables</div></div>'+
    '<div class="stat"><div class="stat-val">'+d.dbSizeKB+' KB</div><div class="stat-label">DB Size</div></div>';
  document.getElementById('tables-list').innerHTML =
    '<table><tr><th>Table Name</th></tr>'+d.tables.map(function(t){return '<tr><td>'+esc(t)+'</td></tr>'}).join('')+'</table>';
});

// ── Fetch user chart data ───────────────────────────────────────
fetch('/api/admin/charts/users').then(function(r){return r.json()}).then(function(CD){
  new Chart(document.getElementById('regChart'),{type:'bar',data:{labels:CD.regTrends.map(function(r){return r.day}),datasets:[{data:CD.regTrends.map(function(r){return r.count}),backgroundColor:'rgba(201,168,76,0.6)',borderColor:'#c9a84c',borderWidth:1,borderRadius:3}]},options:Object.assign({},defOpts)});
  new Chart(document.getElementById('cumChart'),{type:'line',data:{labels:CD.cumulativeData.map(function(r){return r.day}),datasets:[{data:CD.cumulativeData.map(function(r){return r.total}),borderColor:'#5ddc78',backgroundColor:'rgba(93,220,120,0.1)',fill:true,tension:0.3,pointRadius:3,pointBackgroundColor:'#5ddc78'}]},options:Object.assign({},defOpts)});
  new Chart(document.getElementById('weekChart'),{type:'bar',data:{labels:CD.regWeekly.map(function(r){return r.week}),datasets:[{data:CD.regWeekly.map(function(r){return r.count}),backgroundColor:'rgba(173,90,77,0.6)',borderColor:'#ad5a4d',borderWidth:1,borderRadius:3}]},options:Object.assign({},defOpts)});
  new Chart(document.getElementById('featureChart'),{type:'doughnut',data:{labels:['Price Alerts','Newsletter','Dark Mode','Unused'],datasets:[{data:[CD.featureUsage.priceAlerts,CD.featureUsage.newsletter,CD.featureUsage.darkMode,Math.max(0,CD.featureUsage.total-CD.featureUsage.priceAlerts)],backgroundColor:['rgba(201,168,76,0.7)','rgba(93,220,120,0.7)','rgba(100,149,237,0.7)','rgba(60,60,60,0.5)'],borderColor:'#141418',borderWidth:2}]},options:legendOpts});
  new Chart(document.getElementById('planChart'),{type:'pie',data:{labels:CD.planDist.map(function(p){return p.plan}),datasets:[{data:CD.planDist.map(function(p){return p.count}),backgroundColor:['rgba(201,168,76,0.7)','rgba(93,220,120,0.7)','rgba(173,90,77,0.7)','rgba(100,149,237,0.7)','rgba(200,200,200,0.4)'],borderColor:'#141418',borderWidth:2}]},options:legendOpts});
  new Chart(document.getElementById('sessionChart'),{type:'bar',data:{labels:['Active Now'],datasets:[{data:[CD.activeSessions],backgroundColor:'rgba(93,220,120,0.6)',borderColor:'#5ddc78',borderWidth:1,borderRadius:6,barThickness:60}]},options:{responsive:true,animation:{duration:600},indexAxis:'y',plugins:{legend:{display:false}},scales:{x:{ticks:{color:tickColor,font:{size:9}},grid:{color:gridColor},beginAtZero:true},y:{ticks:{color:tickColor,font:{size:10,weight:'bold'}},grid:{display:false}}}}});
  if(CD.loginActivity.length>0){new Chart(document.getElementById('loginActivityChart'),{type:'bar',data:{labels:CD.loginActivity.map(function(u){return u.name}),datasets:[{data:CD.loginActivity.map(function(u){return u.login_count}),backgroundColor:'rgba(201,168,76,0.6)',borderColor:'#c9a84c',borderWidth:1,borderRadius:3}]},options:{responsive:true,indexAxis:'y',animation:{duration:600},plugins:{legend:{display:false}},scales:{x:{ticks:{color:tickColor,font:{size:9}},grid:{color:gridColor},beginAtZero:true},y:{ticks:{color:tickColor,font:{size:9}},grid:{display:false}}}}});}
  if(CD.recentLogins.length>0){new Chart(document.getElementById('recentLoginsChart'),{type:'line',data:{labels:CD.recentLogins.map(function(r){return r.day}),datasets:[{label:'Logins',data:CD.recentLogins.map(function(r){return r.count}),borderColor:'#6495ed',backgroundColor:'rgba(100,149,237,0.1)',fill:true,tension:0.3,pointRadius:3,pointBackgroundColor:'#6495ed'}]},options:Object.assign({},defOpts)});}
});

// ── Fetch site analytics ────────────────────────────────────────
fetch('/api/admin/charts/analytics').then(function(r){return r.json()}).then(function(SA){
  document.getElementById('site-analytics-heading').innerHTML = '&#128202; Site Analytics <span style="font-size:10px;color:#666;font-weight:400">(last 30 days — '+SA.totalViews+' views, '+SA.uniqueVisitors+' unique visitors)</span>';
  if(SA.viewsPerDay.length>0){new Chart(document.getElementById('viewsChart'),{type:'line',data:{labels:SA.viewsPerDay.map(function(r){return r.day}),datasets:[{label:'Views',data:SA.viewsPerDay.map(function(r){return r.views}),borderColor:'#c9a84c',backgroundColor:'rgba(201,168,76,0.1)',fill:true,tension:0.3,pointRadius:3,pointBackgroundColor:'#c9a84c'},{label:'Visitors',data:SA.viewsPerDay.map(function(r){return r.visitors}),borderColor:'#5ddc78',backgroundColor:'rgba(93,220,120,0.05)',fill:true,tension:0.3,pointRadius:3,pointBackgroundColor:'#5ddc78'}]},options:{responsive:true,animation:{duration:600},plugins:{legend:{position:'top',labels:{color:tickColor,font:{size:9}}}},scales:{x:{ticks:{color:tickColor,font:{size:9}},grid:{color:gridColor}},y:{ticks:{color:tickColor,font:{size:9}},grid:{color:gridColor},beginAtZero:true}}}});}
  if(SA.browsers.length>0){new Chart(document.getElementById('browserChart'),{type:'doughnut',data:{labels:SA.browsers.map(function(b){return b.name}),datasets:[{data:SA.browsers.map(function(b){return b.count}),backgroundColor:['rgba(201,168,76,0.7)','rgba(93,220,120,0.7)','rgba(100,149,237,0.7)','rgba(173,90,77,0.7)','rgba(200,200,200,0.4)','rgba(160,120,200,0.7)'],borderColor:'#141418',borderWidth:2}]},options:legendOpts});}
  if(SA.devices.length>0){new Chart(document.getElementById('deviceChart'),{type:'pie',data:{labels:SA.devices.map(function(d){return d.name}),datasets:[{data:SA.devices.map(function(d){return d.count}),backgroundColor:['rgba(100,149,237,0.7)','rgba(201,168,76,0.7)','rgba(93,220,120,0.7)'],borderColor:'#141418',borderWidth:2}]},options:legendOpts});}
  if(SA.events.length>0){new Chart(document.getElementById('eventsChart'),{type:'bar',data:{labels:SA.events.map(function(e){return e.event}),datasets:[{data:SA.events.map(function(e){return e.count}),backgroundColor:'rgba(100,149,237,0.6)',borderColor:'#6495ed',borderWidth:1,borderRadius:3}]},options:{responsive:true,indexAxis:'y',animation:{duration:600},plugins:{legend:{display:false}},scales:{x:{ticks:{color:tickColor,font:{size:9}},grid:{color:gridColor},beginAtZero:true},y:{ticks:{color:tickColor,font:{size:8}},grid:{display:false}}}}});}
  if(SA.referrers.length>0){document.getElementById('referrers-container').innerHTML='<div class="chart-card" style="margin-bottom:24px"><h3>Top Referrers</h3><table style="width:100%"><tr><th style="text-align:left">Source</th><th>Visits</th></tr>'+SA.referrers.map(function(r){return '<tr><td style="font-size:10px;color:#aaa;word-break:break-all">'+esc(r.referrer)+'</td><td style="text-align:center;color:#c9a84c">'+r.count+'</td></tr>'}).join('')+'</table></div>';}
});

// ── Fetch users table ───────────────────────────────────────────
fetch('/api/admin/users').then(function(r){return r.json()}).then(function(d){
  var html = '<table><tr><th>ID</th><th>Avatar</th><th>Name</th><th>Email</th><th>Plan</th><th>Avatar BG</th><th>Created</th><th></th></tr>';
  d.users.forEach(function(u){
    var av = u.avatar
      ? '<div class="av-circle" style="background:'+escCss(u.avatar_bg||'linear-gradient(135deg,#85783c,#c9a84c)')+'"><img src="/uploads/'+esc(u.avatar)+'"></div>'
      : '<div class="av-circle" style="background:'+escCss(u.avatar_bg||'linear-gradient(135deg,#85783c,#c9a84c)') +'">'+esc(u.name?u.name[0].toUpperCase():'?')+'</div>';
    var planClass = u.plan==='Admin'?'tag-admin':'tag-plan';
    var bgLabel = u.avatar_bg ? '<span style="font-size:9px;color:#888">'+esc(u.avatar_bg.replace(/linear-gradient\\(135deg,/,'').replace(/\\)/,''))+'</span>' : '<span class="av-none">default</span>';
    var delBtn = u.email==='siteadmin@oil.com' ? '<span style="font-size:9px;color:#333">protected</span>' : '<button class="btn btn-danger btn-sm" onclick="confirmDelete('+u.id+',\\''+esc(u.name).replace(/'/g,"\\\\'")+'\\''+',\\''+esc(u.email).replace(/'/g,"\\\\'")+'\\''+')">&#10005; Delete</button>';
    html += '<tr><td>'+u.id+'</td><td>'+av+'</td><td>'+esc(u.name)+'</td><td>'+esc(u.email)+'</td><td><span class="tag '+planClass+'">'+esc(u.plan)+'</span></td><td>'+bgLabel+'</td><td>'+esc(u.created_at)+'</td><td>'+delBtn+'</td></tr>';
  });
  html += '</table>';
  document.getElementById('users-table').innerHTML = html;

  // Activity table reuses same data
  var act = '<table><tr><th>ID</th><th>Name</th><th>Email</th><th>Last Login</th><th>Login Count</th><th>Last Settings Change</th><th>Account Age</th></tr>';
  d.users.forEach(function(u){
    var ll = u.last_login ? esc(u.last_login) : '<span style="color:#555">never</span>';
    var lc = u.login_count || 0;
    var ls = u.last_settings_change ? esc(u.last_settings_change) : '<span style="color:#555">never</span>';
    var days = Math.floor((Date.now()-new Date(u.created_at).getTime())/(86400000));
    var age = days<1?'today':days+'d';
    var cc = lc>=10?'tag-on':lc>=1?'tag-plan':'tag-off';
    act += '<tr><td>'+u.id+'</td><td>'+esc(u.name)+'</td><td>'+esc(u.email)+'</td><td style="font-size:10px">'+ll+'</td><td><span class="tag '+cc+'">'+lc+'</span></td><td style="font-size:10px">'+ls+'</td><td style="font-size:10px;color:#888">'+age+'</td></tr>';
  });
  act += '</table>';
  document.getElementById('activity-table').innerHTML = act;
});

// ── Fetch settings table ────────────────────────────────────────
fetch('/api/admin/settings').then(function(r){return r.json()}).then(function(d){
  var html = '<table><tr><th>ID</th><th>Name</th><th>Email</th><th>Price Alerts</th><th>Newsletter</th><th>Dark Mode</th></tr>';
  d.settings.forEach(function(s){
    html += '<tr><td>'+s.id+'</td><td>'+esc(s.name)+'</td><td>'+esc(s.email)+'</td><td><span class="tag '+(s.price_alerts?'tag-on">ON':'tag-off">OFF')+'</span></td><td><span class="tag '+(s.weekly_newsletter?'tag-on">ON':'tag-off">OFF')+'</span></td><td><span class="tag '+(s.dark_mode?'tag-on">ON':'tag-off">OFF')+'</span></td></tr>';
  });
  html += '</table>';
  document.getElementById('settings-table').innerHTML = html;
});

// ── Fetch sessions table ────────────────────────────────────────
fetch('/api/admin/sessions').then(function(r){return r.json()}).then(function(d){
  var html = '<table><tr><th>SID</th><th>User</th><th>IP (hash)</th><th>User Agent</th><th>Last Seen</th><th>Expires</th><th>Status</th></tr>';
  d.sessions.forEach(function(s){
    var sid = esc(s.sid.slice(0,12))+'...';
    var usr = s.userName ? '<span style="color:#c9a84c;font-weight:700">'+esc(s.userName)+'</span><br><span style="font-size:9px;color:#666">'+esc(s.userEmail||'')+'</span>' : '<span style="color:#555;font-size:9px">anonymous</span>';
    var ip = s.ipHash ? '<span style="font-size:10px;color:#888;font-family:monospace">'+esc(s.ipHash)+'</span>' : '<span style="color:#555;font-size:9px">&mdash;</span>';
    var ua = s.ua ? '<span style="font-size:9px;color:#777;max-width:180px;display:inline-block;overflow:hidden;text-overflow:ellipsis;white-space:nowrap" title="'+esc(s.ua)+'">'+esc(s.ua.slice(0,60))+(s.ua.length>60?'...':'')+'</span>' : '<span style="color:#555;font-size:9px">&mdash;</span>';
    var ls = s.lastSeen ? '<span style="font-size:10px">'+esc(s.lastSeen.replace('T',' ').slice(0,19))+'</span>' : '<span style="color:#555;font-size:9px">&mdash;</span>';
    var exp = s.expire ? new Date(s.expire) : null;
    var tag = (exp && exp<new Date()) ? '<span class="tag tag-off">expired</span>' : '<span class="tag tag-on">active</span>';
    html += '<tr><td class="sid">'+sid+'</td><td>'+usr+'</td><td>'+ip+'</td><td>'+ua+'</td><td>'+ls+'</td><td style="font-size:10px">'+(s.expire ? esc(s.expire) : '&mdash;')+'</td><td>'+tag+'</td></tr>';
  });
  html += '</table>';
  document.getElementById('sessions-table').innerHTML = html;
});
<\/script>
</body></html>`;
  res.send(html);
});

app.get('/admin/clear-sessions', requireAdmin, (req, res) => {
  db.prepare('DELETE FROM sessions').run();
  res.redirect('/admin');
});

app.get('/admin/delete-user/:id', requireAdmin, (req, res) => {
  const userId = parseInt(req.params.id, 10);
  if (isNaN(userId)) return res.redirect('/admin');

  // Protect the siteadmin account
  const user = db.prepare('SELECT email, avatar FROM users WHERE id = ?').get(userId);
  if (!user) return res.redirect('/admin');
  if (user.email === 'siteadmin@oil.com') return res.redirect('/admin');

  // Delete avatar file if exists
  if (user.avatar) {
    const avatarPath = require('path').join(__dirname, 'uploads', user.avatar);
    if (require('fs').existsSync(avatarPath)) require('fs').unlinkSync(avatarPath);
  }

  // Delete user data (settings, then user)
  db.prepare('DELETE FROM user_settings WHERE user_id = ?').run(userId);
  db.prepare('DELETE FROM users WHERE id = ?').run(userId);

  res.redirect('/admin');
});

// ─── BACKUP API ROUTES (admin-only) ────────────────────────────
const backup = require('./backup');

// POST /admin/backup — trigger a manual backup
app.post('/admin/backup', requireAdmin, async (req, res) => {
  try {
    const result = await backup.createBackup();
    const pruned = backup.pruneBackups();
    res.json({
      message: 'Backup created successfully.',
      backup: result,
      pruned: pruned.length > 0 ? pruned : null
    });
  } catch (err) {
    console.error('Manual backup error:', err);
    res.status(500).json({ error: 'Backup failed: ' + err.message });
  }
});

// GET /admin/backups — list all backups
app.get('/admin/backups', requireAdmin, (req, res) => {
  const backups = backup.listBackups();
  res.json({ backups, retainCount: parseInt(process.env.BACKUP_RETAIN_COUNT, 10) || 10 });
});

// POST /admin/backup/restore — restore from a named backup file
app.post('/admin/backup/restore', requireAdmin, async (req, res) => {
  try {
    const { filename } = req.body;
    if (!filename) return res.status(400).json({ error: 'filename is required.' });

    const filePath = path.join(backup.BACKUP_DIR, filename);
    const result = await backup.restoreBackup(filePath);
    res.json({ message: 'Database restored. Restart the server to apply.', result });
  } catch (err) {
    console.error('Restore error:', err);
    res.status(500).json({ error: 'Restore failed: ' + err.message });
  }
});

// Fallback: serve index.html for any non-API route
app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, '..', 'index.html'));
});

if (require.main === module) {
  app.listen(PORT, () => {
    console.log(`Oil price chart server running on http://localhost:${PORT}`);

    // ── Scheduled backups ───────────────────────────────────────
    const backupIntervalHours = parseInt(process.env.BACKUP_INTERVAL_HOURS, 10) || 6;
    if (process.env.BACKUP_DISABLED !== 'true') {
      const backupModule = require('./backup');
      const runScheduledBackup = async () => {
        try {
          const result = await backupModule.createBackup();
          const pruned = backupModule.pruneBackups();
          console.log(`[auto-backup] ${result.filename} (${(result.size / 1024).toFixed(1)} KB)` +
            (pruned.length > 0 ? ` — pruned ${pruned.length} old` : ''));
        } catch (err) {
          console.error('[auto-backup] Failed:', err.message);
        }
      };
      // Initial backup on startup, then on interval
      runScheduledBackup();
      setInterval(runScheduledBackup, backupIntervalHours * 60 * 60 * 1000);
      console.log(`Auto-backup enabled: every ${backupIntervalHours}h`);
    }
  });
}

module.exports = app;
