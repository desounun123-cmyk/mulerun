/**
 * Integration test helpers.
 *
 * Re-exports the shared helpers from the parent directory and adds
 * integration-specific utilities for multi-step workflow tests.
 *
 * Tests in this directory exercise cross-cutting concerns:
 *   - Full user lifecycle (register → verify → settings → delete)
 *   - Cross-route data flow (auth → user → notifications → admin)
 *   - Session isolation between concurrent users
 *   - Response envelope consistency across all endpoints
 */
const base = require('../helpers');

/**
 * Register a user and return { agent, user } with the full user object.
 * Unlike the base registerAndLogin which only returns the agent, this
 * captures the response body so tests can reference user.id, etc.
 */
async function registerFull(name, email, password) {
  const agent = base.request.agent(base.app);
  const res = await agent
    .post('/api/auth/register')
    .send({ name, email, password })
    .expect(201);
  return { agent, user: res.body.data.user, body: res.body };
}

/**
 * Login and return { agent, user } with the full user object.
 */
async function loginFull(email, password) {
  const agent = base.request.agent(base.app);
  const res = await agent
    .post('/api/auth/login')
    .send({ email, password })
    .expect(200);
  return { agent, user: res.body.data.user, body: res.body };
}

/**
 * Assert that a response conforms to the standard API envelope.
 * Success: { ok: true, data?, message? }
 * Error:   { ok: false, error }
 */
function expectEnvelope(res, { ok = true, status = 200 } = {}) {
  expect(res.status).toBe(status);
  expect(res.body).toHaveProperty('ok', ok);
  if (ok) {
    expect(res.body).not.toHaveProperty('error');
  } else {
    expect(res.body).toHaveProperty('error');
    expect(typeof res.body.error).toBe('string');
  }
}

module.exports = {
  ...base,
  registerFull,
  loginFull,
  expectEnvelope,
};
