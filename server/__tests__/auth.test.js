const { app, db, request, loginAs, registerAndLogin } = require('./helpers');

describe('Auth API — /api/auth', () => {
  // ── Registration ──────────────────────────────────────────────
  describe('POST /api/auth/register', () => {
    it('creates a new account via registerAndLogin helper', async () => {
      const agent = await registerAndLogin('Test User', 'test-reg@example.com', 'pass1234pass');
      const res = await agent.get('/api/auth/me');

      expect(res.status).toBe(200);
      expect(res.body.user).toMatchObject({
        name: 'Test User',
        email: 'test-reg@example.com',
        plan: 'Free',
      });
    });

    it('rejects duplicate email', async () => {
      // demo@oil.com is seeded by db.js
      const res = await request(app)
        .post('/api/auth/register')
        .send({ name: 'Dup', email: 'demo@oil.com', password: 'anything1234' });

      expect(res.status).toBe(409);
      expect(res.body.error).toMatch(/already exists/i);
    });

    it('rejects missing fields', async () => {
      const res = await request(app)
        .post('/api/auth/register')
        .send({ name: 'No Email' });

      expect(res.status).toBe(400);
    });

    it('rejects password shorter than 8 characters', async () => {
      const res = await request(app)
        .post('/api/auth/register')
        .send({ name: 'Short', email: 'short@example.com', password: 'ab' });

      expect(res.status).toBe(400);
      expect(res.body.error).toMatch(/at least 8/i);
    });
  });

  // ── Login ─────────────────────────────────────────────────────
  describe('POST /api/auth/login', () => {
    it('logs in with valid credentials (seeded demo user)', async () => {
      const res = await request(app)
        .post('/api/auth/login')
        .send({ email: 'demo@oil.com', password: 'oil2026oil2026' });

      expect(res.status).toBe(200);
      expect(res.body.message).toMatch(/logged in/i);
      expect(res.body.user.email).toBe('demo@oil.com');
    });

    it('rejects invalid password', async () => {
      const res = await request(app)
        .post('/api/auth/login')
        .send({ email: 'demo@oil.com', password: 'wrong' });

      expect(res.status).toBe(401);
      expect(res.body.error).toMatch(/invalid/i);
    });

    it('rejects non-existent email', async () => {
      const res = await request(app)
        .post('/api/auth/login')
        .send({ email: 'nobody@example.com', password: 'x' });

      expect(res.status).toBe(401);
    });

    it('rejects missing fields', async () => {
      const res = await request(app)
        .post('/api/auth/login')
        .send({});

      expect(res.status).toBe(400);
    });
  });

  // ── Session — /api/auth/me ────────────────────────────────────
  describe('GET /api/auth/me', () => {
    it('returns 401 when not logged in', async () => {
      const res = await request(app).get('/api/auth/me');
      expect(res.status).toBe(401);
    });

    it('returns user info when logged in', async () => {
      const agent = await loginAs('demo@oil.com', 'oil2026oil2026');
      const res = await agent.get('/api/auth/me');

      expect(res.status).toBe(200);
      expect(res.body.user.email).toBe('demo@oil.com');
    });
  });

  // ── Logout ────────────────────────────────────────────────────
  describe('POST /api/auth/logout', () => {
    it('destroys the session', async () => {
      const agent = await loginAs('demo@oil.com', 'oil2026oil2026');

      const logoutRes = await agent.post('/api/auth/logout');
      expect(logoutRes.status).toBe(200);

      // Session should be gone
      const meRes = await agent.get('/api/auth/me');
      expect(meRes.status).toBe(401);
    });
  });

  // ── Password change ───────────────────────────────────────────
  describe('PUT /api/auth/password', () => {
    it('returns 401 when not logged in', async () => {
      const res = await request(app)
        .put('/api/auth/password')
        .send({ currentPassword: 'x', newPassword: 'y' });

      expect(res.status).toBe(401);
    });

    it('rejects wrong current password', async () => {
      const agent = await registerAndLogin('PwUser', 'pwuser@test.com', 'oldpass1234');
      const res = await agent
        .put('/api/auth/password')
        .send({ currentPassword: 'WRONGWRONG', newPassword: 'newpass1234' });

      expect(res.status).toBe(403);
    });

    it('changes password successfully', async () => {
      const agent = await registerAndLogin('PwChange', 'pwchange@test.com', 'original1234');
      const res = await agent
        .put('/api/auth/password')
        .send({ currentPassword: 'original1234', newPassword: 'updated1234' });

      expect(res.status).toBe(200);

      // Verify new password works
      const login = await request(app)
        .post('/api/auth/login')
        .send({ email: 'pwchange@test.com', password: 'updated1234' });
      expect(login.status).toBe(200);
    });
  });

  // ── Account deletion ──────────────────────────────────────────
  describe('DELETE /api/auth/account', () => {
    it('returns 401 when not logged in', async () => {
      const res = await request(app).delete('/api/auth/account');
      expect(res.status).toBe(401);
    });

    it('deletes own account', async () => {
      const agent = await registerAndLogin('ToDelete', 'del@test.com', 'pass1234pass');
      const res = await agent.delete('/api/auth/account');
      expect(res.status).toBe(200);

      // Login should fail now
      const login = await request(app)
        .post('/api/auth/login')
        .send({ email: 'del@test.com', password: 'pass1234pass' });
      expect(login.status).toBe(401);
    });

    it('prevents admin from self-deleting', async () => {
      const agent = await loginAs('siteadmin@oil.com', 'nimdaetis123&');
      const res = await agent.delete('/api/auth/account');
      expect(res.status).toBe(403);
    });
  });
});
