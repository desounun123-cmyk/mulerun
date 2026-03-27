const { app, request, loginAs, registerAndLogin } = require('./helpers');

describe('User API — /api/user', () => {
  // ── Settings ──────────────────────────────────────────────────
  describe('GET /api/user/settings', () => {
    it('returns 401 when not logged in', async () => {
      const res = await request(app).get('/api/user/settings');
      expect(res.status).toBe(401);
    });

    it('returns default settings for logged-in user', async () => {
      const agent = await loginAs('demo@oil.com', 'oil2026');
      const res = await agent.get('/api/user/settings');

      expect(res.status).toBe(200);
      expect(res.body).toHaveProperty('priceAlerts');
      expect(res.body).toHaveProperty('weeklyNewsletter');
      expect(res.body).toHaveProperty('darkMode');
    });
  });

  describe('PUT /api/user/settings', () => {
    it('returns 401 when not logged in', async () => {
      const res = await request(app)
        .put('/api/user/settings')
        .send({ darkMode: false });
      expect(res.status).toBe(401);
    });

    it('updates settings', async () => {
      const agent = await registerAndLogin('SettingsUser', 'settings@test.com', 'pass1234');

      const res = await agent
        .put('/api/user/settings')
        .send({ priceAlerts: false, weeklyNewsletter: true, darkMode: false });

      expect(res.status).toBe(200);
      expect(res.body.priceAlerts).toBe(false);
      expect(res.body.weeklyNewsletter).toBe(true);
      expect(res.body.darkMode).toBe(false);

      // Verify persistence
      const get = await agent.get('/api/user/settings');
      expect(get.body.priceAlerts).toBe(false);
      expect(get.body.weeklyNewsletter).toBe(true);
    });

    it('supports partial updates', async () => {
      const agent = await registerAndLogin('Partial', 'partial@test.com', 'pass1234');

      // Set initial state
      await agent
        .put('/api/user/settings')
        .send({ priceAlerts: true, weeklyNewsletter: false, darkMode: true });

      // Update only one field
      const res = await agent
        .put('/api/user/settings')
        .send({ weeklyNewsletter: true });

      expect(res.status).toBe(200);
      expect(res.body.weeklyNewsletter).toBe(true);
      // Others should remain unchanged
      expect(res.body.priceAlerts).toBe(true);
      expect(res.body.darkMode).toBe(true);
    });
  });

  // ── Profile ───────────────────────────────────────────────────
  describe('PUT /api/user/profile', () => {
    it('returns 401 when not logged in', async () => {
      const res = await request(app)
        .put('/api/user/profile')
        .send({ name: 'Hacker' });
      expect(res.status).toBe(401);
    });

    it('updates the user name', async () => {
      const agent = await registerAndLogin('OldName', 'profile@test.com', 'pass1234');
      const res = await agent
        .put('/api/user/profile')
        .send({ name: 'NewName' });

      expect(res.status).toBe(200);
      expect(res.body.user.name).toBe('NewName');
    });

    it('rejects empty name', async () => {
      const agent = await registerAndLogin('Valid', 'emptyname@test.com', 'pass1234');
      const res = await agent
        .put('/api/user/profile')
        .send({ name: '' });

      expect(res.status).toBe(400);
    });

    it('rejects name longer than 100 characters', async () => {
      const agent = await registerAndLogin('Long', 'longname@test.com', 'pass1234');
      const res = await agent
        .put('/api/user/profile')
        .send({ name: 'A'.repeat(101) });

      expect(res.status).toBe(400);
    });
  });

  // ── Avatar background ─────────────────────────────────────────
  describe('PUT /api/user/avatar-bg', () => {
    it('returns 401 when not logged in', async () => {
      const res = await request(app)
        .put('/api/user/avatar-bg')
        .send({ avatarBg: '#ff0000' });
      expect(res.status).toBe(401);
    });

    it('updates avatar background', async () => {
      const agent = await registerAndLogin('BgUser', 'bg@test.com', 'pass1234');
      const res = await agent
        .put('/api/user/avatar-bg')
        .send({ avatarBg: 'linear-gradient(135deg,#ff0000,#00ff00)' });

      expect(res.status).toBe(200);
      expect(res.body.avatarBg).toMatch(/gradient/);
    });

    it('clears avatar background with null', async () => {
      const agent = await registerAndLogin('BgClear', 'bgclear@test.com', 'pass1234');
      await agent
        .put('/api/user/avatar-bg')
        .send({ avatarBg: '#ff0000' });

      const res = await agent
        .put('/api/user/avatar-bg')
        .send({ avatarBg: null });

      expect(res.status).toBe(200);
      expect(res.body.avatarBg).toBeNull();
    });
  });

  // ── Avatar upload / delete ────────────────────────────────────
  describe('POST /api/user/avatar', () => {
    it('returns 401 when not logged in', async () => {
      const res = await request(app).post('/api/user/avatar');
      expect(res.status).toBe(401);
    });

    it('rejects request with no file', async () => {
      const agent = await registerAndLogin('NoFile', 'nofile@test.com', 'pass1234');
      const res = await agent.post('/api/user/avatar');
      expect(res.status).toBe(400);
    });
  });

  describe('DELETE /api/user/avatar', () => {
    it('returns 401 when not logged in', async () => {
      const res = await request(app).delete('/api/user/avatar');
      expect(res.status).toBe(401);
    });

    it('succeeds even when no avatar is set', async () => {
      const agent = await registerAndLogin('NoAvatar', 'noavatar@test.com', 'pass1234');
      const res = await agent.delete('/api/user/avatar');
      expect(res.status).toBe(200);
    });
  });
});
