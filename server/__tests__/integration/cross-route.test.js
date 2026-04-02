/**
 * Integration: Cross-route data flow
 *
 * Tests that span multiple route modules, verifying that data written
 * by one route is correctly visible to another. These catch bugs where
 * individual routes pass their own unit tests but the data contract
 * between them is broken.
 */
const {
  app, db, request, registerFull, loginFull, expectEnvelope,
  loginAs,
} = require('./helpers');

describe('Integration: Cross-Route Data Flow', () => {

  // ── Admin sees newly-registered users ──────────────────────────
  describe('Admin ↔ Auth: user visibility', () => {
    it('admin user list reflects new registrations', async () => {
      const admin = await loginFull('siteadmin@oil.com', 'nimdaetis123&');

      // Snapshot current user count
      const before = await admin.agent.get('/api/admin/users');
      expect(before.status).toBe(200);
      const countBefore = before.body.users.length;

      // Register a new user (separate session)
      await registerFull('Visible', 'visible@cross.test', 'visible1234');

      // Admin should now see one more user
      const after = await admin.agent.get('/api/admin/users');
      expect(after.body.users.length).toBe(countBefore + 1);
      const found = after.body.users.find(u => u.email === 'visible@cross.test');
      expect(found).toBeDefined();
    });

    it('admin summary userCount increases after registration', async () => {
      const admin = await loginFull('siteadmin@oil.com', 'nimdaetis123&');

      const before = await admin.agent.get('/api/admin/summary');
      const countBefore = before.body.userCount;

      await registerFull('CountUp', 'countup@cross.test', 'countup1234');

      const after = await admin.agent.get('/api/admin/summary');
      expect(after.body.userCount).toBe(countBefore + 1);
    });
  });

  // ── Admin delete ↔ user session ────────────────────────────────
  describe('Admin delete → user session invalidation', () => {
    it('admin-deleted user can no longer access protected routes', async () => {
      // Register a victim
      const { agent: victimAgent, user: victim } =
        await registerFull('Victim', 'victim@cross.test', 'victim1234');

      // Victim's session works
      const meBefore = await victimAgent.get('/api/auth/me');
      expect(meBefore.status).toBe(200);

      // Admin deletes the victim
      const admin = await loginFull('siteadmin@oil.com', 'nimdaetis123&');
      const del = await admin.agent.get(`/admin/delete-user/${victim.id}`);
      expect(del.status).toBe(302);

      // Victim's next request should fail — user no longer exists
      // The session still has userId but the DB lookup in /me returns 401
      const meAfter = await victimAgent.get('/api/auth/me');
      expect(meAfter.status).toBe(401);
    });
  });

  // ── Auth → Notifications ───────────────────────────────────────
  describe('Auth events → notification creation', () => {
    it('password change creates a security notification visible via user route', async () => {
      const { agent } = await registerFull(
        'NotifTest', 'notif@cross.test', 'notifpass1234'
      );

      await agent
        .put('/api/auth/password')
        .send({ currentPassword: 'notifpass1234', newPassword: 'changed1234!' })
        .expect(200);

      // Notification should be readable via /api/user/notifications
      const res = await agent.get('/api/user/notifications');
      expect(res.status).toBe(200);

      const notes = res.body.data || res.body.notifications || [];
      const secNote = notes.find(n =>
        n.type === 'security' && /password/i.test(n.title)
      );
      expect(secNote).toBeDefined();
      expect(secNote.message).toMatch(/changed/i);
    });
  });

  // ── Settings persistence across sessions ───────────────────────
  describe('Settings survive logout/login cycle', () => {
    it('settings written in one session are read back in a new session', async () => {
      const EMAIL = 'persist@cross.test';
      const PASS  = 'persist1234!';

      // Session 1: register and set custom settings
      const { agent: s1 } = await registerFull('Persist', EMAIL, PASS);
      await s1.put('/api/user/settings')
        .send({ priceAlerts: false, weeklyNewsletter: true, darkMode: false })
        .expect(200);
      await s1.post('/api/auth/logout').expect(200);

      // Session 2: login and read settings
      const { agent: s2 } = await loginFull(EMAIL, PASS);
      const res = await s2.get('/api/user/settings');
      expect(res.status).toBe(200);
      expect(res.body.priceAlerts).toBe(false);
      expect(res.body.weeklyNewsletter).toBe(true);
      expect(res.body.darkMode).toBe(false);
    });
  });

  // ── Analytics tracking works for unauthenticated visitors ──────
  describe('Analytics ↔ Admin charts', () => {
    it('pageview recorded by analytics appears in admin chart data', async () => {
      // Track a pageview (no auth required)
      await request(app)
        .post('/api/analytics/pageview')
        .send({ page: '/integration-test-page', referrer: 'https://test.com' })
        .expect(204);

      // Admin should see it in analytics data
      const admin = await loginFull('siteadmin@oil.com', 'nimdaetis123&');
      const res = await admin.agent.get('/api/admin/charts/analytics');
      expect(res.status).toBe(200);
      expect(res.body.totalViews).toBeGreaterThan(0);
    });
  });
});
