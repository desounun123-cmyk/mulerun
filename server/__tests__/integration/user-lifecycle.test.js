/**
 * Integration: Full user lifecycle
 *
 * Tests the complete journey from registration through account deletion,
 * verifying that each step correctly affects downstream state.
 *
 * These are TRUE integration tests — each test case exercises multiple
 * route modules (auth, user, notifications) in a single sequential flow,
 * validating cross-cutting data consistency that unit tests miss.
 */
const {
  app, db, request, registerFull, loginFull, expectEnvelope,
} = require('./helpers');

describe('Integration: User Lifecycle', () => {

  // ── Register → Session → Profile → Settings → Password → Delete ──
  describe('Full account lifecycle', () => {
    const EMAIL = 'lifecycle@integration.test';
    const PASS  = 'lifecycle1234';
    let agent, userId;

    it('registers a new account and receives a session', async () => {
      const { agent: a, user } = await registerFull('Lifecycle User', EMAIL, PASS);
      agent = a;
      userId = user.id;

      expect(user.email).toBe(EMAIL);
      expect(user.name).toBe('Lifecycle User');
      expect(user.plan).toBe('Free');

      // Session should be active immediately after registration
      const me = await agent.get('/api/auth/me');
      expectEnvelope(me, { ok: true, status: 200 });
      expect(me.body.data.user.id).toBe(userId);
    });

    it('can read default settings after registration', async () => {
      const res = await agent.get('/api/user/settings');
      expect(res.status).toBe(200);
      // New accounts get default settings (set in registration handler)
      expect(res.body).toHaveProperty('priceAlerts');
      expect(res.body).toHaveProperty('darkMode');
    });

    it('can update profile name', async () => {
      const res = await agent
        .put('/api/user/profile')
        .send({ name: 'Updated Name' });

      expect(res.status).toBe(200);
      expect(res.body.user.name).toBe('Updated Name');

      // Verify /me reflects the new name
      const me = await agent.get('/api/auth/me');
      expect(me.body.data.user.name).toBe('Updated Name');
    });

    it('can update settings and verify persistence', async () => {
      const res = await agent
        .put('/api/user/settings')
        .send({ priceAlerts: false, weeklyNewsletter: true, darkMode: false });

      expect(res.status).toBe(200);

      const get = await agent.get('/api/user/settings');
      expect(get.body.priceAlerts).toBe(false);
      expect(get.body.weeklyNewsletter).toBe(true);
      expect(get.body.darkMode).toBe(false);
    });

    it('can change password and login with new credentials', async () => {
      const change = await agent
        .put('/api/auth/password')
        .send({ currentPassword: PASS, newPassword: 'newLifecycle99' });

      expect(change.status).toBe(200);

      // Old password should fail
      const oldLogin = await request(app)
        .post('/api/auth/login')
        .send({ email: EMAIL, password: PASS });
      expect(oldLogin.status).toBe(401);

      // New password should work
      const newLogin = await request(app)
        .post('/api/auth/login')
        .send({ email: EMAIL, password: 'newLifecycle99' });
      expect(newLogin.status).toBe(200);
    });

    it('receives a security notification after password change', async () => {
      const res = await agent.get('/api/user/notifications');
      expect(res.status).toBe(200);

      const notes = res.body.data || res.body.notifications || [];
      const pwNote = notes.find(n =>
        n.type === 'security' && /password/i.test(n.title)
      );
      expect(pwNote).toBeDefined();
    });

    it('can delete the account', async () => {
      const del = await agent.delete('/api/auth/account');
      expect(del.status).toBe(200);

      // Session should be destroyed
      const me = await agent.get('/api/auth/me');
      expect(me.status).toBe(401);

      // Login should fail — account no longer exists
      const login = await request(app)
        .post('/api/auth/login')
        .send({ email: EMAIL, password: 'newLifecycle99' });
      expect(login.status).toBe(401);
    });

    it('account data is fully erased from the database', async () => {
      const user = db.prepare('SELECT id FROM users WHERE email = ?').get(EMAIL);
      expect(user).toBeUndefined();

      const settings = db.prepare('SELECT * FROM user_settings WHERE user_id = ?').get(userId);
      expect(settings).toBeUndefined();

      const notifications = db.prepare('SELECT * FROM notifications WHERE user_id = ?').all(userId);
      expect(notifications.length).toBe(0);
    });
  });

  // ── Registration creates a welcome notification ──────────────────
  describe('Registration side effects', () => {
    it('creates a welcome notification on registration', async () => {
      const { agent } = await registerFull('WelcomeUser', 'welcome@integration.test', 'welcome1234');

      const res = await agent.get('/api/user/notifications');
      expect(res.status).toBe(200);

      const notes = res.body.data || res.body.notifications || [];
      const welcome = notes.find(n => /welcome/i.test(n.title));
      expect(welcome).toBeDefined();
      expect(welcome.type).toBe('info');
    });
  });

  // ── Logout destroys session but preserves account ────────────────
  describe('Logout and re-login', () => {
    it('logout destroys session, re-login restores access', async () => {
      const EMAIL = 'relogin@integration.test';
      const { agent } = await registerFull('ReLogin', EMAIL, 'relogin1234');

      // Logout
      const logout = await agent.post('/api/auth/logout');
      expect(logout.status).toBe(200);

      // Session is gone
      const me = await agent.get('/api/auth/me');
      expect(me.status).toBe(401);

      // Re-login works
      const { agent: agent2 } = await loginFull(EMAIL, 'relogin1234');
      const me2 = await agent2.get('/api/auth/me');
      expect(me2.status).toBe(200);
      expect(me2.body.data.user.email).toBe(EMAIL);
    });
  });
});
