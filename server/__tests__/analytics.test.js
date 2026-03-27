const { app, request, loginAs } = require('./helpers');

describe('Analytics API — /api/analytics', () => {
  // ── Pageview tracking ─────────────────────────────────────────
  describe('POST /api/analytics/pageview', () => {
    it('records a pageview and returns 204', async () => {
      const res = await request(app)
        .post('/api/analytics/pageview')
        .send({ page: '/', referrer: 'https://google.com', screenW: 1920, screenH: 1080, lang: 'en-US' });

      expect(res.status).toBe(204);
    });

    it('accepts minimal payload', async () => {
      const res = await request(app)
        .post('/api/analytics/pageview')
        .send({});

      expect(res.status).toBe(204);
    });
  });

  // ── Event tracking ────────────────────────────────────────────
  describe('POST /api/analytics/event', () => {
    it('records an event and returns 204', async () => {
      const res = await request(app)
        .post('/api/analytics/event')
        .send({ event: 'theme_toggle', meta: { from: 'dark', to: 'light' } });

      expect(res.status).toBe(204);
    });

    it('returns 204 even with no event name (silent fail)', async () => {
      const res = await request(app)
        .post('/api/analytics/event')
        .send({});

      expect(res.status).toBe(204);
    });
  });

  // ── Stats (admin-only) ────────────────────────────────────────
  describe('GET /api/analytics/stats', () => {
    it('returns 401 when not logged in', async () => {
      const res = await request(app).get('/api/analytics/stats');
      expect(res.status).toBe(401);
    });

    it('returns 403 for non-admin user', async () => {
      const agent = await loginAs('demo@oil.com', 'oil2026');
      const res = await agent.get('/api/analytics/stats');
      expect(res.status).toBe(403);
    });

    it('returns stats for admin user', async () => {
      const agent = await loginAs('siteadmin@oil.com', 'nimdaetis123&');
      const res = await agent.get('/api/analytics/stats');

      expect(res.status).toBe(200);
      expect(res.body).toHaveProperty('viewsPerDay');
      expect(res.body).toHaveProperty('browsers');
      expect(res.body).toHaveProperty('devices');
      expect(res.body).toHaveProperty('totalViews');
      expect(res.body).toHaveProperty('uniqueVisitors');
    });
  });
});
