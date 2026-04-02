# Security Policy

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 1.x     | :white_check_mark: |

## Reporting a Vulnerability

**Do not open a public GitHub issue for security vulnerabilities.**

If you discover a security issue in this project, please report it
responsibly so we can address it before it is publicly disclosed.

### How to report

Send an email to **security@oilbenchmarks.com** with:

- A description of the vulnerability and its potential impact.
- Steps to reproduce or a proof-of-concept (the simpler, the better).
- The affected file(s) and line numbers, if known.
- Any suggested fix, if you have one.

### What to expect

| Step | Timeframe |
| ---- | --------- |
| Acknowledgement of your report | 2 business days |
| Initial triage and severity assessment | 5 business days |
| Status update with remediation plan | 10 business days |
| Fix deployed (critical/high severity) | 30 days or sooner |

We will keep you informed throughout the process. If the issue qualifies
for a CVE, we will coordinate disclosure with you before publishing.

### Scope

The following are in scope:

- The Node.js/Express backend (`server/`)
- The service worker and client-side PWA code (`sw.js`, `index.html`)
- Authentication, session management, and access control
- Data storage and encryption (SQLite, PostgreSQL adapter, VAPID keys)
- Input validation and output encoding
- Rate limiting and abuse prevention
- Dependencies with known CVEs that are reachable in our code paths

The following are out of scope:

- Denial-of-service attacks that require excessive resources to execute
- Social engineering or phishing attacks against project maintainers
- Vulnerabilities in third-party services we integrate with (report those to the respective vendor)
- Issues that require physical access to the server

### Safe Harbor

We consider security research conducted in accordance with this policy
to be authorized and will not pursue legal action against researchers
who:

- Act in good faith and avoid privacy violations, data destruction,
  and disruption of service.
- Only interact with accounts they own or with explicit permission.
- Report findings promptly and do not disclose them publicly before
  a fix is available.

### Recognition

We maintain a list of researchers who have responsibly disclosed
vulnerabilities. If you would like to be credited, let us know in
your report and we will add you to the acknowledgements section below.

## Security Controls

This project implements the following security measures:

- **Authentication**: bcrypt password hashing (cost 10), session
  regeneration on login/logout, TOTP two-factor authentication.
- **Session management**: express-session with SQLite/PostgreSQL
  store, httpOnly + secure + sameSite cookies, configurable expiry.
- **Rate limiting**: per-IP rate limits on login, registration,
  CAPTCHA, password reset, and password change endpoints.
- **Account lockout**: progressive lockout after failed login
  attempts with configurable threshold and duration.
- **Input validation**: Zod schemas on all mutation endpoints,
  HTML tag stripping, CSV formula injection prevention.
- **CSRF protection**: same-origin session cookies with sameSite
  attribute; honeypot fields on public forms.
- **Encryption at rest**: VAPID push keys encrypted with
  AES-256-GCM, key derived from SESSION_SECRET via PBKDF2.
- **Idempotency**: Idempotency-Key header support on all mutation
  endpoints to prevent duplicate side-effects from retries.
- **Push notification throttling**: per-user sliding-window rate
  limiter on web push sends.
- **Cache hygiene**: service worker purges session-sensitive cached
  data on logout; offline fallbacks include page context without
  leaking user data.
- **Helmet**: HTTP security headers (CSP, HSTS, X-Frame-Options,
  etc.) via helmet middleware.
- **Dependency auditing**: `npm audit` run as part of CI.

## Acknowledgements

We thank the following researchers for responsibly disclosing
vulnerabilities:

- *(Your name here — be the first!)*
