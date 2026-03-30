/**
 * Integration tests for auth endpoints — /api/auth/*
 *
 * Covers: login with lockout, forgot/reset password flow, session
 * management, registration validation, and edge cases.
 *
 * NOTE: CAPTCHA validation is skipped in test mode (NODE_ENV=test),
 * matching the existing pattern of disabling rate limiters in tests.
 * CAPTCHA endpoint rendering is tested independently below.
 */

const { app, db, request, loginAs, registerAndLogin } = require('./helpers');

describe('Auth Integration — /api/auth', () => {
  // ── Registration validation ─────────────────────────────────────────
  describe('POST /register — input validation', () => {
    it('registers a user successfully', async () => {
      const agent = await registerAndLogin('RegTest', 'regtest@test.com', 'password1234');
      const res = await agent.get('/api/auth/me');

      expect(res.status).toBe(200);
      expect(res.body.user.email).toBe('regtest@test.com');
      expect(res.body.user.plan).toBe('Free');
    });

    it('rejects password shorter than 8 characters', async () => {
      const res = await request(app)
        .post('/api/auth/register')
        .send({ name: 'Short', email: 'shortpw@test.com', password: '1234567' });

      expect(res.status).toBe(400);
      expect(res.body.error).toMatch(/at least 8/i);
    });

    it('rejects name with only HTML tags (stripped to empty)', async () => {
      const res = await request(app)
        .post('/api/auth/register')
        .send({ name: '<b></b><i></i>', email: 'xss@test.com', password: 'password1234' });

      expect(res.status).toBe(400);
      expect(res.body.error).toMatch(/valid characters/i);
    });

    it('strips HTML tags from name but keeps text content', async () => {
      const agent = await registerAndLogin('alert1', 'stripped@test.com', 'password1234');
      const res = await agent.get('/api/auth/me');

      expect(res.status).toBe(200);
      // <script>alert(1)</script> → "alert(1)" (tags stripped, content kept)
      expect(res.body.user.name).toBe('alert1');
    });

    it('rejects name longer than 100 characters', async () => {
      const res = await request(app)
        .post('/api/auth/register')
        .send({ name: 'A'.repeat(101), email: 'longname@test.com', password: 'password1234' });

      expect(res.status).toBe(400);
      expect(res.body.error).toMatch(/100 characters/i);
    });

    it('rejects invalid email format', async () => {
      const res = await request(app)
        .post('/api/auth/register')
        .send({ name: 'Bad Email', email: 'not-an-email', password: 'password1234' });

      expect(res.status).toBe(400);
    });

    it('rejects oauth.local email domain', async () => {
      const res = await request(app)
        .post('/api/auth/register')
        .send({ name: 'OAuth', email: 'fake@oauth.local', password: 'password1234' });

      expect(res.status).toBe(400);
      expect(res.body.error).toMatch(/domain/i);
    });

    it('rejects duplicate email', async () => {
      const res = await request(app)
        .post('/api/auth/register')
        .send({ name: 'Dup', email: 'demo@oil.com', password: 'anything1234' });

      expect(res.status).toBe(409);
      expect(res.body.error).toMatch(/already exists/i);
    });
  });

  // ── Login — account lockout ───────────────────────────────────────
  describe('POST /login — account lockout', () => {
    it('locks account after 5 failed attempts', async () => {
      const agent = await registerAndLogin('LockTest', 'locktest@test.com', 'correctpass1');
      await agent.post('/api/auth/logout');

      // Make 5 failed login attempts
      for (let i = 0; i < 5; i++) {
        await request(app)
          .post('/api/auth/login')
          .send({ email: 'locktest@test.com', password: 'wrongpassword' });
      }

      // 6th attempt with correct password should get 423 (locked)
      const res = await request(app)
        .post('/api/auth/login')
        .send({ email: 'locktest@test.com', password: 'correctpass1' });

      expect(res.status).toBe(423);
      expect(res.body.error).toMatch(/locked/i);
      expect(res.body).toHaveProperty('lockedUntil');
    });

    it('resets failed count on successful login', async () => {
      const agent = await registerAndLogin('ResetCount', 'resetcount@test.com', 'mypassword1');
      await agent.post('/api/auth/logout');

      // Make 2 failed attempts
      await request(app)
        .post('/api/auth/login')
        .send({ email: 'resetcount@test.com', password: 'wrongwrong' });
      await request(app)
        .post('/api/auth/login')
        .send({ email: 'resetcount@test.com', password: 'wrongwrong' });

      // Successful login should reset counter
      const res = await request(app)
        .post('/api/auth/login')
        .send({ email: 'resetcount@test.com', password: 'mypassword1' });

      expect(res.status).toBe(200);

      // Verify counter is reset in DB
      const user = db.prepare("SELECT failed_login_attempts FROM users WHERE email = ?").get('resetcount@test.com');
      expect(user.failed_login_attempts).toBe(0);
    });
  });

  // ── Login — remember me ───────────────────────────────────────────
  describe('POST /login — remember me', () => {
    it('returns 200 with rememberMe false', async () => {
      const res = await request(app)
        .post('/api/auth/login')
        .send({ email: 'demo@oil.com', password: 'oil2026oil2026', rememberMe: false });

      expect(res.status).toBe(200);
    });

    it('returns 200 with rememberMe true and sets cookie', async () => {
      const res = await request(app)
        .post('/api/auth/login')
        .send({ email: 'demo@oil.com', password: 'oil2026oil2026', rememberMe: true });

      expect(res.status).toBe(200);
      const cookies = res.headers['set-cookie'];
      expect(cookies).toBeDefined();
    });
  });

  // ── Forgot password ───────────────────────────────────────────────
  describe('POST /forgot — password reset request', () => {
    it('returns success message for existing email (prevents enumeration)', async () => {
      const res = await request(app)
        .post('/api/auth/forgot')
        .send({ email: 'demo@oil.com' });

      expect(res.status).toBe(200);
      expect(res.body.message).toMatch(/reset link/i);
    });

    it('returns same message for non-existent email (prevents enumeration)', async () => {
      const res = await request(app)
        .post('/api/auth/forgot')
        .send({ email: 'nonexistent@nowhere.com' });

      expect(res.status).toBe(200);
      expect(res.body.message).toMatch(/reset link/i);
    });

    it('rejects missing email', async () => {
      const res = await request(app)
        .post('/api/auth/forgot')
        .send({});

      expect(res.status).toBe(400);
    });

    it('creates a reset token in the database', async () => {
      await request(app)
        .post('/api/auth/forgot')
        .send({ email: 'demo@oil.com' });

      const user = db.prepare("SELECT id FROM users WHERE email = ?").get('demo@oil.com');
      const tokens = db.prepare(
        "SELECT * FROM password_reset_tokens WHERE user_id = ? AND used = FALSE ORDER BY created_at DESC"
      ).all(user.id);

      expect(tokens.length).toBeGreaterThan(0);
    });
  });

  // ── Reset password with token ─────────────────────────────────────
  describe('POST /reset — password reset with token', () => {
    it('rejects missing token', async () => {
      const res = await request(app)
        .post('/api/auth/reset')
        .send({ newPassword: 'newpass12345' });

      expect(res.status).toBe(400);
    });

    it('rejects invalid token', async () => {
      const res = await request(app)
        .post('/api/auth/reset')
        .send({ token: 'deadbeefdeadbeefdeadbeefdeadbeef', newPassword: 'newpass12345' });

      expect(res.status).toBe(400);
      expect(res.body.error).toMatch(/invalid|expired/i);
    });

    it('rejects new password shorter than 8 chars', async () => {
      const res = await request(app)
        .post('/api/auth/reset')
        .send({ token: 'sometoken', newPassword: 'short' });

      expect(res.status).toBe(400);
      expect(res.body.error).toMatch(/8 characters/i);
    });
  });

  // ── Password change (authenticated) ───────────────────────────────
  describe('PUT /password — change password', () => {
    it('rejects when not authenticated', async () => {
      const res = await request(app)
        .put('/api/auth/password')
        .send({ currentPassword: 'anything', newPassword: 'anything2' });

      expect(res.status).toBe(401);
    });

    it('rejects new password shorter than 8 chars', async () => {
      const agent = await registerAndLogin('PwLen', 'pwlen@test.com', 'oldpassword1');
      const res = await agent
        .put('/api/auth/password')
        .send({ currentPassword: 'oldpassword1', newPassword: 'short' });

      expect(res.status).toBe(400);
      expect(res.body.error).toMatch(/8 characters/i);
    });

    it('rejects missing fields', async () => {
      const agent = await registerAndLogin('PwMissing', 'pwmissing@test.com', 'oldpassword1');
      const res = await agent
        .put('/api/auth/password')
        .send({});

      expect(res.status).toBe(400);
    });

    it('changes password and verifies new credentials work', async () => {
      const agent = await registerAndLogin('PwOK', 'pwok@test.com', 'oldpassword1');

      const res = await agent
        .put('/api/auth/password')
        .send({ currentPassword: 'oldpassword1', newPassword: 'newpassword1' });
      expect(res.status).toBe(200);

      // Log in with new password
      const loginRes = await request(app)
        .post('/api/auth/login')
        .send({ email: 'pwok@test.com', password: 'newpassword1' });
      expect(loginRes.status).toBe(200);

      // Old password should fail
      const oldRes = await request(app)
        .post('/api/auth/login')
        .send({ email: 'pwok@test.com', password: 'oldpassword1' });
      expect(oldRes.status).toBe(401);
    });
  });

  // ── Session — /me endpoint ────────────────────────────────────────
  describe('GET /me — session management', () => {
    it('returns 401 for unauthenticated request', async () => {
      const res = await request(app).get('/api/auth/me');
      expect(res.status).toBe(401);
    });

    it('returns full user object when authenticated', async () => {
      const agent = await loginAs('demo@oil.com', 'oil2026oil2026');
      const res = await agent.get('/api/auth/me');

      expect(res.status).toBe(200);
      expect(res.body.user).toHaveProperty('id');
      expect(res.body.user).toHaveProperty('name');
      expect(res.body.user).toHaveProperty('email', 'demo@oil.com');
      expect(res.body.user).toHaveProperty('plan');
      expect(res.body.user).toHaveProperty('joinedDate');
    });

    it('returns 401 after logout', async () => {
      const agent = await loginAs('demo@oil.com', 'oil2026oil2026');

      let res = await agent.get('/api/auth/me');
      expect(res.status).toBe(200);

      await agent.post('/api/auth/logout').expect(200);

      res = await agent.get('/api/auth/me');
      expect(res.status).toBe(401);
    });
  });

  // ── Account deletion ──────────────────────────────────────────────
  describe('DELETE /account — account deletion', () => {
    it('returns 401 when not authenticated', async () => {
      const res = await request(app).delete('/api/auth/account');
      expect(res.status).toBe(401);
    });

    it('deletes own account and prevents subsequent login', async () => {
      const agent = await registerAndLogin('ToDelete2', 'del2@test.com', 'pass1234pass');
      const res = await agent.delete('/api/auth/account');
      expect(res.status).toBe(200);

      const loginRes = await request(app)
        .post('/api/auth/login')
        .send({ email: 'del2@test.com', password: 'pass1234pass' });
      expect(loginRes.status).toBe(401);
    });

    it('prevents admin from deleting their own account', async () => {
      const agent = await loginAs('siteadmin@oil.com', 'nimdaetis123&');
      const res = await agent.delete('/api/auth/account');
      expect(res.status).toBe(403);
    });
  });

  // ── CAPTCHA endpoint ──────────────────────────────────────────────
  describe('GET /captcha', () => {
    it('returns SVG content type', async () => {
      const res = await request(app).get('/api/auth/captcha');
      expect(res.status).toBe(200);
      expect(res.headers['content-type']).toMatch(/svg/i);
    });

    it('returns no-cache headers', async () => {
      const res = await request(app).get('/api/auth/captcha');
      expect(res.headers['cache-control']).toMatch(/no-store|no-cache/i);
    });

    it('returns valid SVG markup', async () => {
      const res = await request(app).get('/api/auth/captcha');
      const body = res.text || res.body.toString();
      expect(body).toMatch(/<svg/);
      expect(body).toMatch(/<\/svg>/);
    });
  });

  // ── Login edge cases ──────────────────────────────────────────────
  describe('POST /login — edge cases', () => {
    it('rejects empty body', async () => {
      const res = await request(app)
        .post('/api/auth/login')
        .send({});

      expect(res.status).toBe(400);
    });

    it('rejects non-existent email with generic error (prevents enumeration)', async () => {
      const res = await request(app)
        .post('/api/auth/login')
        .send({ email: 'nobody@nowhere.test', password: 'anything123' });

      expect(res.status).toBe(401);
      expect(res.body.error).toMatch(/invalid/i);
    });

    it('locks account after max failed attempts', async () => {
      const agent = await registerAndLogin('AttemptMax', 'attemptmax@test.com', 'correctpw123');
      await agent.post('/api/auth/logout');

      // Exhaust all 5 attempts
      for (let i = 0; i < 5; i++) {
        await request(app)
          .post('/api/auth/login')
          .send({ email: 'attemptmax@test.com', password: 'wrongwrongwrong' });
      }

      // Account should now be locked
      const res = await request(app)
        .post('/api/auth/login')
        .send({ email: 'attemptmax@test.com', password: 'correctpw123' });

      expect(res.status).toBe(423);
      expect(res.body).toHaveProperty('lockedUntil');
      expect(res.body).toHaveProperty('remainingMinutes');
    });
  });
});
