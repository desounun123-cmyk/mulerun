const { app, request, loginAs } = require('./helpers');
const path = require('path');
const fs = require('fs');
const backup = require('../utils/backup');

describe('Database backup', () => {
  // ── Core backup functions ───────────────────────────────────────
  describe('createBackup()', () => {
    it('creates a backup file', async () => {
      const result = await backup.createBackup();

      expect(result.filename).toMatch(/^data-backup-.*\.db$/);
      expect(result.size).toBeGreaterThan(0);
      expect(fs.existsSync(result.path)).toBe(true);

      // Clean up
      fs.unlinkSync(result.path);
    });
  });

  describe('listBackups()', () => {
    it('returns an array of backups sorted newest first', async () => {
      const b1 = await backup.createBackup();
      const b2 = await backup.createBackup();

      const list = backup.listBackups();
      expect(list.length).toBeGreaterThanOrEqual(2);
      // Newest first
      expect(list[0].created >= list[1].created).toBe(true);

      // Clean up
      fs.unlinkSync(b1.path);
      fs.unlinkSync(b2.path);
    });
  });

  describe('pruneBackups()', () => {
    it('deletes backups beyond the retain count', async () => {
      // Create 4 backups
      const backups = [];
      for (let i = 0; i < 4; i++) {
        backups.push(await backup.createBackup());
      }

      // Prune keeping only 2
      const deleted = backup.pruneBackups(2);
      expect(deleted.length).toBe(2);

      const remaining = backup.listBackups();
      expect(remaining.length).toBe(2);

      // Clean up remaining
      for (const b of remaining) {
        fs.unlinkSync(path.join(backup.BACKUP_DIR, b.filename));
      }
    });
  });

  describe('restoreBackup()', () => {
    it('restores from a backup file', async () => {
      const b = await backup.createBackup();
      const result = await backup.restoreBackup(b.path);

      expect(result.restored).toBe(b.path);

      // Clean up
      fs.unlinkSync(b.path);
    });

    it('throws for non-existent file', async () => {
      await expect(backup.restoreBackup('/tmp/does-not-exist.db'))
        .rejects.toThrow(/not found/i);
    });
  });

  // ── Admin API endpoints ─────────────────────────────────────────
  describe('POST /admin/backup', () => {
    it('returns 401 when not logged in', async () => {
      const res = await request(app).post('/admin/backup');
      expect(res.status).toBe(401);
    });

    it('returns 403 for non-admin user', async () => {
      const agent = await loginAs('demo@oil.com', 'oil2026');
      const res = await agent.post('/admin/backup');
      expect(res.status).toBe(403);
    });

    it('creates a backup for admin', async () => {
      const agent = await loginAs('siteadmin@oil.com', 'nimdaetis123&');
      const res = await agent.post('/admin/backup');

      expect(res.status).toBe(200);
      expect(res.body.backup.filename).toMatch(/^data-backup-/);
      expect(res.body.backup.size).toBeGreaterThan(0);

      // Clean up
      fs.unlinkSync(res.body.backup.path);
    });
  });

  describe('GET /admin/backups', () => {
    it('returns 401 when not logged in', async () => {
      const res = await request(app).get('/admin/backups');
      expect(res.status).toBe(401);
    });

    it('returns backup list for admin', async () => {
      const agent = await loginAs('siteadmin@oil.com', 'nimdaetis123&');
      const res = await agent.get('/admin/backups');

      expect(res.status).toBe(200);
      expect(Array.isArray(res.body.backups)).toBe(true);
      expect(res.body).toHaveProperty('retainCount');
    });
  });
});
