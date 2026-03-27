/**
 * SQLite database backup utility.
 *
 * Uses better-sqlite3's `.backup()` API for safe, online backups that
 * don't block reads/writes on the live database.
 *
 * Usage:
 *   node backup.js                  # one-off backup
 *   node backup.js --prune          # backup + delete old files
 *   node backup.js --restore <file> # restore from a backup file
 *
 * Environment variables:
 *   BACKUP_DIR          — directory for backup files  (default: ./backups)
 *   BACKUP_RETAIN_COUNT — how many backups to keep    (default: 10)
 */
const path = require('path');
const fs = require('fs');
const log = require('./logger').child({ module: 'backup' });

const BACKUP_DIR = process.env.BACKUP_DIR
  ? path.resolve(process.env.BACKUP_DIR)
  : path.join(__dirname, 'backups');

const RETAIN_COUNT = parseInt(process.env.BACKUP_RETAIN_COUNT, 10) || 10;

const DB_PATH = process.env.DB_PATH
  ? path.resolve(process.env.DB_PATH)
  : path.join(__dirname, 'data.db');

/**
 * Create a timestamped backup of the database.
 * Returns the absolute path of the new backup file.
 */
async function createBackup() {
  if (!fs.existsSync(BACKUP_DIR)) {
    fs.mkdirSync(BACKUP_DIR, { recursive: true });
  }

  const timestamp = new Date().toISOString().replace(/[:.]/g, '-');
  const filename = `data-backup-${timestamp}.db`;
  const dest = path.join(BACKUP_DIR, filename);

  // Use better-sqlite3's backup API — safe with concurrent readers/writers.
  // Falls back to file copy if backup() fails (e.g. WAL-mode edge cases).
  const Database = require('better-sqlite3');
  try {
    const source = new Database(DB_PATH, { readonly: true });
    try {
      await source.backup(dest);
    } finally {
      source.close();
    }
  } catch (_) {
    // Fallback: checkpoint WAL then copy the file
    try {
      const tmp = new Database(DB_PATH);
      tmp.pragma('wal_checkpoint(TRUNCATE)');
      tmp.close();
    } catch (__) { /* ignore — may already be closed or readonly */ }
    fs.copyFileSync(DB_PATH, dest);
  }

  const stats = fs.statSync(dest);
  return {
    path: dest,
    filename,
    size: stats.size,
    timestamp: new Date().toISOString(),
  };
}

/**
 * List existing backups sorted by date (newest first).
 */
function listBackups() {
  if (!fs.existsSync(BACKUP_DIR)) return [];

  return fs.readdirSync(BACKUP_DIR)
    .filter(f => f.startsWith('data-backup-') && f.endsWith('.db'))
    .map(f => {
      const stats = fs.statSync(path.join(BACKUP_DIR, f));
      return { filename: f, size: stats.size, created: stats.mtime };
    })
    .sort((a, b) => b.created - a.created);
}

/**
 * Delete old backups, keeping only the most recent `count`.
 * Returns the list of deleted filenames.
 */
function pruneBackups(count) {
  const keep = count !== undefined ? count : RETAIN_COUNT;
  const backups = listBackups();
  const deleted = [];

  if (backups.length <= keep) return deleted;

  const toDelete = backups.slice(keep);
  for (const b of toDelete) {
    fs.unlinkSync(path.join(BACKUP_DIR, b.filename));
    deleted.push(b.filename);
  }

  return deleted;
}

/**
 * Restore the live database from a backup file.
 * DANGER: This overwrites the current data.db.
 */
async function restoreBackup(backupFilePath) {
  const resolved = path.resolve(backupFilePath);
  if (!fs.existsSync(resolved)) {
    throw new Error(`Backup file not found: ${resolved}`);
  }

  // Verify the backup is a valid SQLite database
  const Database = require('better-sqlite3');
  const check = new Database(resolved, { readonly: true });
  try {
    check.pragma('integrity_check');
  } finally {
    check.close();
  }

  // Copy backup over live database
  fs.copyFileSync(resolved, DB_PATH);

  // Remove WAL/SHM files so the restored DB starts clean
  for (const suffix of ['-wal', '-shm']) {
    const f = DB_PATH + suffix;
    if (fs.existsSync(f)) fs.unlinkSync(f);
  }

  return { restored: resolved, target: DB_PATH };
}

// ─── CLI mode ───────────────────────────────────────────────────
if (require.main === module) {
  const args = process.argv.slice(2);

  if (args.includes('--restore')) {
    const idx = args.indexOf('--restore');
    const file = args[idx + 1];
    if (!file) {
      console.error('Usage: node backup.js --restore <backup-file>');
      process.exit(1);
    }
    restoreBackup(file)
      .then(r => console.log(`Restored ${r.restored} → ${r.target}`))
      .catch(e => { console.error('Restore failed:', e.message); process.exit(1); });
  } else {
    createBackup()
      .then(result => {
        console.log(`Backup created: ${result.filename} (${(result.size / 1024).toFixed(1)} KB)`);
        if (args.includes('--prune')) {
          const deleted = pruneBackups();
          if (deleted.length > 0) {
            console.log(`Pruned ${deleted.length} old backup(s): ${deleted.join(', ')}`);
          } else {
            console.log(`No old backups to prune (keeping ${RETAIN_COUNT}).`);
          }
        }
      })
      .catch(e => { console.error('Backup failed:', e.message); process.exit(1); });
  }
}

module.exports = { createBackup, listBackups, pruneBackups, restoreBackup, BACKUP_DIR };
