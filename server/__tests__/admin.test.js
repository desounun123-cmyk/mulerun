const { app, request, loginAs, registerAndLogin } = require('./helpers');

describe('Admin routes', () => {
  // ── GET /admin ────────────────────────────────────────────────
  describe('GET /admin', () => {
    it('returns 401 when not logged in', async () => {
      const res = await request(app).get('/admin');
      expect(res.status).toBe(401);
      expect(res.text).toMatch(/Unauthorized/i);
    });

    it('returns 403 for non-admin user', async () => {
      const agent = await loginAs('demo@oil.com', 'oil2026');
      const res = await agent.get('/admin');
      expect(res.status).toBe(403);
      expect(res.text).toMatch(/Forbidden/i);
    });

    it('returns 200 for admin user', async () => {
      const agent = await loginAs('siteadmin@oil.com', 'nimdaetis123&');
      const res = await agent.get('/admin');
      expect(res.status).toBe(200);
      expect(res.text).toMatch(/Admin Panel/i);
    });
  });

  // ── GET /admin/clear-sessions ─────────────────────────────────
  describe('GET /admin/clear-sessions', () => {
    it('returns 401 when not logged in', async () => {
      const res = await request(app).get('/admin/clear-sessions');
      expect(res.status).toBe(401);
    });

    it('returns 403 for non-admin user', async () => {
      const agent = await loginAs('demo@oil.com', 'oil2026');
      const res = await agent.get('/admin/clear-sessions');
      expect(res.status).toBe(403);
    });

    it('clears sessions for admin and redirects', async () => {
      const agent = await loginAs('siteadmin@oil.com', 'nimdaetis123&');
      const res = await agent.get('/admin/clear-sessions');
      // Express redirects with 302
      expect(res.status).toBe(302);
      expect(res.headers.location).toBe('/admin');
    });
  });

  // ── GET /admin/delete-user/:id ────────────────────────────────
  describe('GET /admin/delete-user/:id', () => {
    it('returns 401 when not logged in', async () => {
      const res = await request(app).get('/admin/delete-user/1');
      expect(res.status).toBe(401);
    });

    it('returns 403 for non-admin user', async () => {
      const agent = await loginAs('demo@oil.com', 'oil2026');
      const res = await agent.get('/admin/delete-user/999');
      expect(res.status).toBe(403);
    });

    it('redirects when deleting a valid user', async () => {
      // Create a disposable user
      const reg = await request(app)
        .post('/api/auth/register')
        .send({ name: 'Victim', email: 'victim-admin@test.com', password: 'pass1234' });
      const victimId = reg.body.user.id;

      const agent = await loginAs('siteadmin@oil.com', 'nimdaetis123&');
      const res = await agent.get(`/admin/delete-user/${victimId}`);
      expect(res.status).toBe(302);

      // Victim should no longer be able to log in
      const login = await request(app)
        .post('/api/auth/login')
        .send({ email: 'victim-admin@test.com', password: 'pass1234' });
      expect(login.status).toBe(401);
    });

    it('refuses to delete the siteadmin account', async () => {
      const db = require('../db/db');
      const admin = db.prepare("SELECT id FROM users WHERE email = 'siteadmin@oil.com'").get();

      const agent = await loginAs('siteadmin@oil.com', 'nimdaetis123&');
      const res = await agent.get(`/admin/delete-user/${admin.id}`);
      // Should redirect without deleting
      expect(res.status).toBe(302);

      // Admin should still exist
      const login = await request(app)
        .post('/api/auth/login')
        .send({ email: 'siteadmin@oil.com', password: 'nimdaetis123&' });
      expect(login.status).toBe(200);
    });
  });

  // ── Admin data API endpoints (/api/admin/*) ───────────────────
  describe('GET /api/admin/summary', () => {
    it('returns 401 when not logged in', async () => {
      const res = await request(app).get('/api/admin/summary');
      expect(res.status).toBe(401);
    });

    it('returns 403 for non-admin user', async () => {
      const agent = await loginAs('demo@oil.com', 'oil2026');
      const res = await agent.get('/api/admin/summary');
      expect(res.status).toBe(403);
    });

    it('returns summary stats for admin', async () => {
      const agent = await loginAs('siteadmin@oil.com', 'nimdaetis123&');
      const res = await agent.get('/api/admin/summary');
      expect(res.status).toBe(200);
      expect(res.body).toHaveProperty('userCount');
      expect(res.body).toHaveProperty('sessionCount');
      expect(res.body).toHaveProperty('tableCount');
      expect(res.body).toHaveProperty('tables');
      expect(res.body).toHaveProperty('dbSizeKB');
      expect(typeof res.body.userCount).toBe('number');
    });
  });

  describe('GET /api/admin/charts/users', () => {
    it('returns user chart data for admin', async () => {
      const agent = await loginAs('siteadmin@oil.com', 'nimdaetis123&');
      const res = await agent.get('/api/admin/charts/users');
      expect(res.status).toBe(200);
      expect(res.body).toHaveProperty('regTrends');
      expect(res.body).toHaveProperty('cumulativeData');
      expect(res.body).toHaveProperty('regWeekly');
      expect(res.body).toHaveProperty('featureUsage');
      expect(res.body).toHaveProperty('planDist');
      expect(res.body).toHaveProperty('activeSessions');
      expect(res.body).toHaveProperty('loginActivity');
      expect(res.body).toHaveProperty('recentLogins');
      expect(Array.isArray(res.body.regTrends)).toBe(true);
    });
  });

  describe('GET /api/admin/charts/analytics', () => {
    it('returns site analytics for admin', async () => {
      const agent = await loginAs('siteadmin@oil.com', 'nimdaetis123&');
      const res = await agent.get('/api/admin/charts/analytics');
      expect(res.status).toBe(200);
      expect(res.body).toHaveProperty('viewsPerDay');
      expect(res.body).toHaveProperty('browsers');
      expect(res.body).toHaveProperty('devices');
      expect(res.body).toHaveProperty('referrers');
      expect(res.body).toHaveProperty('events');
      expect(res.body).toHaveProperty('totalViews');
      expect(res.body).toHaveProperty('uniqueVisitors');
    });
  });

  describe('GET /api/admin/users', () => {
    it('returns users array for admin', async () => {
      const agent = await loginAs('siteadmin@oil.com', 'nimdaetis123&');
      const res = await agent.get('/api/admin/users');
      expect(res.status).toBe(200);
      expect(Array.isArray(res.body.users)).toBe(true);
      expect(res.body.users.length).toBeGreaterThan(0);
      expect(res.body.users[0]).toHaveProperty('id');
      expect(res.body.users[0]).toHaveProperty('email');
    });
  });

  describe('GET /api/admin/settings', () => {
    it('returns settings for admin', async () => {
      const agent = await loginAs('siteadmin@oil.com', 'nimdaetis123&');
      const res = await agent.get('/api/admin/settings');
      expect(res.status).toBe(200);
      expect(Array.isArray(res.body.settings)).toBe(true);
    });
  });

  describe('GET /api/admin/sessions', () => {
    it('returns sessions for admin', async () => {
      const agent = await loginAs('siteadmin@oil.com', 'nimdaetis123&');
      const res = await agent.get('/api/admin/sessions');
      expect(res.status).toBe(200);
      expect(Array.isArray(res.body.sessions)).toBe(true);
    });
  });
});
