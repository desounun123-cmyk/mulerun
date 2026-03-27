/**
 * Shared test setup — provides a fresh app instance backed by an
 * in-memory SQLite database so tests never touch production data.
 */
const path = require('path');

// Signal test environment — disables rate limiters
process.env.NODE_ENV = 'test';

// Point DB_PATH to a per-worker temp file so each jest worker is isolated.
const os = require('os');
const fs = require('fs');
const tmpDb = path.join(os.tmpdir(), `oil-test-${process.pid}-${Date.now()}.db`);
process.env.DB_PATH = tmpDb;

// Require app *after* setting DB_PATH so db.js picks it up.
const app = require('../index');
const request = require('supertest');
const db = require('../db');

/** Helper: register + login and return the supertest agent (cookie jar). */
async function loginAs(email, password) {
  const agent = request.agent(app);
  await agent
    .post('/api/auth/login')
    .send({ email, password })
    .expect(200);
  return agent;
}

/** Helper: register a new user and return the agent. */
async function registerAndLogin(name, email, password) {
  const agent = request.agent(app);
  await agent
    .post('/api/auth/register')
    .send({ name, email, password })
    .expect(201);
  return agent;
}

afterAll(() => {
  // Clean up temp database files
  try {
    db.close();
    for (const suffix of ['', '-wal', '-shm']) {
      const f = tmpDb + suffix;
      if (fs.existsSync(f)) fs.unlinkSync(f);
    }
  } catch (_) { /* ignore */ }
});

module.exports = { app, db, request, loginAs, registerAndLogin };
