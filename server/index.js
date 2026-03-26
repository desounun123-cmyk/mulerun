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
const PORT = 8080;

// Parse JSON bodies
app.use(express.json());

// Session configuration
const sessionSecret = crypto.randomBytes(32).toString('hex');
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
    secure: false, // set to true behind HTTPS proxy
    maxAge: 7 * 24 * 60 * 60 * 1000, // 7 days
    sameSite: 'lax'
  }
}));

// Serve static frontend files from parent directory
app.use(express.static(path.join(__dirname, '..')));

// Serve uploaded avatars
app.use('/uploads', express.static(path.join(__dirname, 'uploads')));

// API routes
app.use('/api/auth', require('./routes/auth'));
app.use('/api/user', require('./routes/user'));

// ─── ADMIN DEBUG ROUTE (temporary) ─────────────────────────────
app.get('/admin', (req, res) => {
  const users = db.prepare('SELECT id, name, email, plan, avatar, avatar_bg, created_at FROM users').all();
  const settings = db.prepare(`
    SELECT u.id, u.name, u.email, s.price_alerts, s.weekly_newsletter, s.dark_mode
    FROM users u LEFT JOIN user_settings s ON u.id = s.user_id
  `).all();
  const sessionCount = db.prepare('SELECT COUNT(*) as count FROM sessions').get();
  const sessions = db.prepare('SELECT sid, expire FROM sessions').all();
  const tables = db.prepare("SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%' ORDER BY name").all();
  const dbSize = require('fs').statSync(require('path').join(__dirname, 'data.db')).size;

  // ─── Chart data queries ───────────────────────────────────────
  // Registration trends: registrations per day (last 90 days)
  const regTrends = db.prepare(`
    SELECT date(created_at) as day, COUNT(*) as count
    FROM users
    GROUP BY date(created_at)
    ORDER BY day ASC
  `).all();

  // Active sessions per day (from session expiry data, approximate)
  // Generate daily counts for the last 30 days based on user creation
  const activeDailyRaw = db.prepare(`
    SELECT date(created_at) as day, COUNT(*) as count
    FROM users
    GROUP BY date(created_at)
    ORDER BY day ASC
  `).all();

  // Cumulative users over time
  let cumulative = 0;
  const cumulativeData = regTrends.map(r => {
    cumulative += r.count;
    return { day: r.day, total: cumulative };
  });

  // Weekly registrations
  const regWeekly = db.prepare(`
    SELECT strftime('%Y-W%W', created_at) as week, COUNT(*) as count
    FROM users
    GROUP BY strftime('%Y-W%W', created_at)
    ORDER BY week ASC
  `).all();

  // Feature usage from user_settings
  const featureUsage = db.prepare(`
    SELECT
      SUM(price_alerts) as price_alerts_on,
      SUM(weekly_newsletter) as newsletter_on,
      SUM(dark_mode) as dark_mode_on,
      COUNT(*) as total
    FROM user_settings
  `).get();

  // Plan distribution
  const planDist = db.prepare(`
    SELECT plan, COUNT(*) as count FROM users GROUP BY plan ORDER BY count DESC
  `).all();

  // Active sessions count (current)
  const activeSessionCount = sessionCount.count;

  const chartDataJSON = JSON.stringify({
    regTrends,
    cumulativeData,
    regWeekly,
    featureUsage: {
      priceAlerts: featureUsage ? featureUsage.price_alerts_on || 0 : 0,
      newsletter: featureUsage ? featureUsage.newsletter_on || 0 : 0,
      darkMode: featureUsage ? featureUsage.dark_mode_on || 0 : 0,
      total: featureUsage ? featureUsage.total || 0 : 0
    },
    planDist,
    activeSessions: activeSessionCount
  });

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
@media(max-width:768px){.charts-grid{grid-template-columns:1fr}}
</style>
</head>
<body>
<a class="close-btn" href="/" title="Back to App">&times;</a>
<h1>&#9881; Admin Panel</h1>
<p class="subtitle">Oil Benchmarks &mdash; Database Inspector</p>
<div class="warn">&#9888; This route is for development only. Remove before deploying to production.</div>

<div class="stats">
  <div class="stat"><div class="stat-val">${users.length}</div><div class="stat-label">Users</div></div>
  <div class="stat"><div class="stat-val">${sessionCount.count}</div><div class="stat-label">Active Sessions</div></div>
  <div class="stat"><div class="stat-val">${tables.length}</div><div class="stat-label">Tables</div></div>
  <div class="stat"><div class="stat-val">${(dbSize / 1024).toFixed(1)} KB</div><div class="stat-label">DB Size</div></div>
</div>

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
</div>

<script src="https://cdn.jsdelivr.net/npm/chart.js@4.4.7/dist/chart.umd.min.js"><\/script>
<script>
var CD = ${chartDataJSON};
var gridColor = 'rgba(255,255,255,0.06)';
var tickColor = '#666';
var defOpts = {responsive:true,animation:{duration:600},plugins:{legend:{display:false}},scales:{x:{ticks:{color:tickColor,font:{size:9}},grid:{color:gridColor}},y:{ticks:{color:tickColor,font:{size:9}},grid:{color:gridColor},beginAtZero:true}}};

// 1. Registration Trends (bar)
new Chart(document.getElementById('regChart'),{type:'bar',data:{labels:CD.regTrends.map(function(r){return r.day}),datasets:[{data:CD.regTrends.map(function(r){return r.count}),backgroundColor:'rgba(201,168,76,0.6)',borderColor:'#c9a84c',borderWidth:1,borderRadius:3}]},options:Object.assign({},defOpts)});

// 2. Cumulative Users (line)
new Chart(document.getElementById('cumChart'),{type:'line',data:{labels:CD.cumulativeData.map(function(r){return r.day}),datasets:[{data:CD.cumulativeData.map(function(r){return r.total}),borderColor:'#5ddc78',backgroundColor:'rgba(93,220,120,0.1)',fill:true,tension:0.3,pointRadius:3,pointBackgroundColor:'#5ddc78'}]},options:Object.assign({},defOpts)});

// 3. Weekly Registrations (bar)
new Chart(document.getElementById('weekChart'),{type:'bar',data:{labels:CD.regWeekly.map(function(r){return r.week}),datasets:[{data:CD.regWeekly.map(function(r){return r.count}),backgroundColor:'rgba(173,90,77,0.6)',borderColor:'#ad5a4d',borderWidth:1,borderRadius:3}]},options:Object.assign({},defOpts)});

// 4. Feature Usage (doughnut)
new Chart(document.getElementById('featureChart'),{type:'doughnut',data:{labels:['Price Alerts','Newsletter','Dark Mode','Unused'],datasets:[{data:[CD.featureUsage.priceAlerts,CD.featureUsage.newsletter,CD.featureUsage.darkMode,Math.max(0,CD.featureUsage.total-CD.featureUsage.priceAlerts)],backgroundColor:['rgba(201,168,76,0.7)','rgba(93,220,120,0.7)','rgba(100,149,237,0.7)','rgba(60,60,60,0.5)'],borderColor:'#141418',borderWidth:2}]},options:{responsive:true,animation:{duration:600},plugins:{legend:{position:'bottom',labels:{color:tickColor,font:{size:9},padding:10}}}}});

// 5. Plan Distribution (pie)
new Chart(document.getElementById('planChart'),{type:'pie',data:{labels:CD.planDist.map(function(p){return p.plan}),datasets:[{data:CD.planDist.map(function(p){return p.count}),backgroundColor:['rgba(201,168,76,0.7)','rgba(93,220,120,0.7)','rgba(173,90,77,0.7)','rgba(100,149,237,0.7)','rgba(200,200,200,0.4)'],borderColor:'#141418',borderWidth:2}]},options:{responsive:true,animation:{duration:600},plugins:{legend:{position:'bottom',labels:{color:tickColor,font:{size:9},padding:10}}}}});

// 6. Active Sessions gauge-style (bar with single value)
new Chart(document.getElementById('sessionChart'),{type:'bar',data:{labels:['Active Now'],datasets:[{data:[CD.activeSessions],backgroundColor:'rgba(93,220,120,0.6)',borderColor:'#5ddc78',borderWidth:1,borderRadius:6,barThickness:60}]},options:{responsive:true,animation:{duration:600},indexAxis:'y',plugins:{legend:{display:false}},scales:{x:{ticks:{color:tickColor,font:{size:9}},grid:{color:gridColor},beginAtZero:true},y:{ticks:{color:tickColor,font:{size:10,weight:'bold'}},grid:{display:false}}}}});
<\/script>

<h2>Users</h2>
<table>
<tr><th>ID</th><th>Avatar</th><th>Name</th><th>Email</th><th>Plan</th><th>Avatar BG</th><th>Created</th><th></th></tr>
${users.map(u => {
  const avatarHtml = u.avatar
    ? '<div class="av-circle" style="background:' + (u.avatar_bg || 'linear-gradient(135deg,#85783c,#c9a84c)') + '"><img src="/uploads/' + u.avatar + '"></div>'
    : '<div class="av-circle" style="background:' + (u.avatar_bg || 'linear-gradient(135deg,#85783c,#c9a84c)') + '">' + (u.name ? u.name[0].toUpperCase() : '?') + '</div>';
  const planClass = u.plan === 'Admin' ? 'tag-admin' : 'tag-plan';
  const bgLabel = u.avatar_bg ? '<span style="font-size:9px;color:#888">' + u.avatar_bg.replace(/linear-gradient\(135deg,/,'').replace(/\)/,'') + '</span>' : '<span class="av-none">default</span>';
  const deleteBtn = u.email === 'siteadmin@oil.com'
    ? '<span style="font-size:9px;color:#333">protected</span>'
    : '<button class="btn btn-danger btn-sm" onclick="confirmDelete(' + u.id + ',\'' + u.name.replace(/'/g,"\\\\'") + '\',\'' + u.email.replace(/'/g,"\\\\'") + '\')">&#10005; Delete</button>';
  return '<tr><td>' + u.id + '</td><td>' + avatarHtml + '</td><td>' + u.name + '</td><td>' + u.email + '</td><td><span class="tag ' + planClass + '">' + u.plan + '</span></td><td>' + bgLabel + '</td><td>' + u.created_at + '</td><td>' + deleteBtn + '</td></tr>';
}).join('')}
</table>

<h2>User Settings</h2>
<table>
<tr><th>ID</th><th>Name</th><th>Email</th><th>Price Alerts</th><th>Newsletter</th><th>Dark Mode</th></tr>
${settings.map(s => '<tr><td>' + s.id + '</td><td>' + s.name + '</td><td>' + s.email + '</td><td><span class="tag ' + (s.price_alerts ? 'tag-on">ON' : 'tag-off">OFF') + '</span></td><td><span class="tag ' + (s.weekly_newsletter ? 'tag-on">ON' : 'tag-off">OFF') + '</span></td><td><span class="tag ' + (s.dark_mode ? 'tag-on">ON' : 'tag-off">OFF') + '</span></td></tr>').join('')}
</table>

<h2>Sessions</h2>
<table>
<tr><th>Session ID</th><th>Expires</th></tr>
${sessions.map(s => '<tr><td class="sid">' + s.sid + '</td><td>' + (s.expire || '—') + '</td></tr>').join('')}
</table>

<h2>Tables</h2>
<table>
<tr><th>Table Name</th></tr>
${tables.map(t => '<tr><td>' + t.name + '</td></tr>').join('')}
</table>

<a class="back" href="/">&#8592; Back to App</a>

<dialog id="deleteDialog">
  <h3>&#9888; Delete User</h3>
  <p>Are you sure you want to permanently delete <span class="user-detail" id="del-user-info"></span>? This will remove all their data including settings and sessions.</p>
  <div class="dialog-actions">
    <button class="btn" onclick="document.getElementById('deleteDialog').close()">Cancel</button>
    <a class="btn btn-danger" id="del-confirm-link" href="#">&#10005; Delete</a>
  </div>
</dialog>

<script>
function confirmDelete(id, name, email) {
  document.getElementById('del-user-info').textContent = name + ' (' + email + ')';
  document.getElementById('del-confirm-link').href = '/admin/delete-user/' + id;
  document.getElementById('deleteDialog').showModal();
}
</script>
</body></html>`;
  res.send(html);
});

app.get('/admin/clear-sessions', (req, res) => {
  db.prepare('DELETE FROM sessions').run();
  res.redirect('/admin');
});

app.get('/admin/delete-user/:id', (req, res) => {
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

// Fallback: serve index.html for any non-API route
app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, '..', 'index.html'));
});

app.listen(PORT, () => {
  console.log(`Oil price chart server running on http://localhost:${PORT}`);
});
