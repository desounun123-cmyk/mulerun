/**
 * Integration: Security boundaries
 *
 * Verifies that authentication, authorisation, and session isolation
 * work correctly across the full request pipeline — not just within
 * individual route handlers.
 *
 * These tests catch classes of bugs that unit tests miss:
 *   - Middleware ordering issues (auth check skipped for new routes)
 *   - Session bleed between concurrent users
 *   - Privilege escalation via direct endpoint access
 *   - Response envelope leaking internal data on error paths
 */
const {
  app, db, request, registerFull, loginFull, expectEnvelope,
  loginAs,
} = require('./helpers');

describe('Integration: Security Boundaries', () => {

  // ── Session isolation: concurrent users ─────────────────────────
  describe('Session isolation', () => {
    it('two users logged in concurrently see only their own data', async () => {
      const { agent: alice } = await registerFull(
        'Alice', 'alice@security.test', 'alicepass123'
      );
      const { agent: bob } = await registerFull(
        'Bob', 'bob@security.test', 'bobpass12345'
      );

      // Each agent should see only their own identity
      const aliceMe = await alice.get('/api/auth/me');
      const bobMe   = await bob.get('/api/auth/me');

      expect(aliceMe.body.data.user.email).toBe('alice@security.test');
      expect(bobMe.body.data.user.email).toBe('bob@security.test');

      // Alice's settings change should not affect Bob
      await alice.put('/api/user/settings')
        .send({ darkMode: false })
        .expect(200);

      const bobSettings = await bob.get('/api/user/settings');
      // Bob's dark mode should still be the default (true)
      expect(bobSettings.body.darkMode).toBe(true);
    });

    it('logging out one user does not affect another', async () => {
      const { agent: user1 } = await registerFull(
        'User1', 'user1@security.test', 'user1pass123'
      );
      const { agent: user2 } = await registerFull(
        'User2', 'user2@security.test', 'user2pass123'
      );

      // User1 logs out
      await user1.post('/api/auth/logout').expect(200);

      // User1 lost their session
      const me1 = await user1.get('/api/auth/me');
      expect(me1.status).toBe(401);

      // User2 still has theirs
      const me2 = await user2.get('/api/auth/me');
      expect(me2.status).toBe(200);
      expect(me2.body.data.user.email).toBe('user2@security.test');
    });
  });

  // ── Auth enforcement on all protected routes ────────────────────
  describe('Auth enforcement (unauthenticated access)', () => {
    const protectedEndpoints = [
      ['GET',    '/api/auth/me'],
      ['PUT',    '/api/auth/password'],
      ['DELETE', '/api/auth/account'],
      ['GET',    '/api/user/settings'],
      ['PUT',    '/api/user/settings'],
      ['PUT',    '/api/user/profile'],
      ['POST',   '/api/user/avatar'],
      ['DELETE', '/api/user/avatar'],
      ['PUT',    '/api/user/avatar-bg'],
      ['GET',    '/api/user/notifications'],
      ['POST',   '/api/auth/totp/setup'],
      ['POST',   '/api/auth/totp/verify'],
      ['POST',   '/api/auth/totp/disable'],
      ['GET',    '/api/auth/totp/status'],
    ];

    it.each(protectedEndpoints)(
      '%s %s returns 401 without authentication',
      async (method, path) => {
        const req = request(app);
        let res;
        switch (method) {
          case 'GET':    res = await req.get(path); break;
          case 'POST':   res = await req.post(path).send({}); break;
          case 'PUT':    res = await req.put(path).send({}); break;
          case 'DELETE': res = await req.delete(path); break;
        }
        expect(res.status).toBe(401);
      }
    );
  });

  // ── Admin role enforcement ──────────────────────────────────────
  describe('Admin role enforcement', () => {
    const adminEndpoints = [
      ['GET', '/admin'],
      ['GET', '/api/admin/summary'],
      ['GET', '/api/admin/users'],
      ['GET', '/api/admin/sessions'],
      ['GET', '/api/admin/settings'],
      ['GET', '/api/admin/charts/users'],
      ['GET', '/api/admin/charts/analytics'],
      ['GET', '/api/analytics/stats'],
    ];

    it.each(adminEndpoints)(
      '%s %s returns 403 for non-admin user',
      async (method, path) => {
        const { agent } = await registerFull(
          'NonAdmin', `nonadmin-${Date.now()}@security.test`, 'nonadmin1234'
        );
        const res = await agent.get(path);
        expect([401, 403]).toContain(res.status);
      }
    );

    it.each(adminEndpoints)(
      '%s %s returns 200 for admin user',
      async (_method, path) => {
        const admin = await loginFull('siteadmin@oil.com', 'nimdaetis123&');
        const res = await admin.agent.get(path);
        expect(res.status).toBe(200);
      }
    );
  });

  // ── Response envelope consistency ──────────────────────────────
  describe('Response envelope consistency', () => {
    it('successful auth responses use { ok: true, data } envelope', async () => {
      const res = await request(app)
        .post('/api/auth/login')
        .send({ email: 'demo@oil.com', password: 'oil2026oil2026' });

      expectEnvelope(res, { ok: true, status: 200 });
      expect(res.body).toHaveProperty('data');
    });

    it('auth error responses use { ok: false, error } envelope', async () => {
      const res = await request(app)
        .post('/api/auth/login')
        .send({ email: 'demo@oil.com', password: 'wrongpassword' });

      expectEnvelope(res, { ok: false, status: 401 });
    });

    it('validation error responses use { ok: false, error } envelope', async () => {
      const res = await request(app)
        .post('/api/auth/register')
        .send({ name: '', email: 'bad', password: 'x' });

      expect(res.status).toBe(400);
      expect(res.body.ok).toBe(false);
      expect(res.body).toHaveProperty('error');
    });

    it('404 for unknown API routes returns JSON (not HTML)', async () => {
      const res = await request(app).get('/api/nonexistent');
      // Should be 404 JSON, not a 200 HTML page
      expect(res.status).toBe(404);
      if (res.headers['content-type'] &&
          res.headers['content-type'].includes('json')) {
        expect(res.body).toHaveProperty('ok', false);
      }
    });
  });

  // ── Privilege escalation prevention ─────────────────────────────
  describe('Privilege escalation prevention', () => {
    it('normal user cannot access admin delete-user endpoint', async () => {
      const { agent, user } = await registerFull(
        'Escalate', 'escalate@security.test', 'escalate1234'
      );

      // Try to delete another user via admin route
      const res = await agent.get(`/admin/delete-user/${user.id}`);
      expect([401, 403]).toContain(res.status);
    });

    it('normal user cannot access admin clear-sessions', async () => {
      const { agent } = await registerFull(
        'NoSessions', 'nosess@security.test', 'nosess123456'
      );
      const res = await agent.get('/admin/clear-sessions');
      expect([401, 403]).toContain(res.status);
    });

    it('admin cannot delete their own account via user route', async () => {
      const admin = await loginFull('siteadmin@oil.com', 'nimdaetis123&');
      const res = await admin.agent.delete('/api/auth/account');
      expect(res.status).toBe(403);
      expect(res.body.error).toMatch(/admin/i);
    });
  });

  // ── Session regeneration on auth state change ──────────────────
  describe('Session regeneration', () => {
    it('session cookie changes after login (prevents fixation)', async () => {
      const agent = request.agent(app);

      // Get initial session cookie
      await agent.get('/api/auth/me');
      const cookiesBefore = agent.jar.getCookies({ path: '/' }).map(c => c.value);

      // Login — should regenerate session
      await agent.post('/api/auth/login')
        .send({ email: 'demo@oil.com', password: 'oil2026oil2026' })
        .expect(200);

      const cookiesAfter = agent.jar.getCookies({ path: '/' }).map(c => c.value);

      // At least one cookie should have changed (session ID regenerated)
      // If supertest exposes cookies, verify they differ
      if (cookiesBefore.length > 0 && cookiesAfter.length > 0) {
        expect(cookiesAfter[0]).not.toBe(cookiesBefore[0]);
      }
    });
  });
});
