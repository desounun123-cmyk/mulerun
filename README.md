# Oil Price Benchmark Platform

A full-stack web application for tracking WTI Crude Oil benchmark prices, with real-time alerts, market news aggregation, and analytical tools.

## Tech Stack

| Layer | Technology |
|-------|-----------|
| Backend | Express.js (Node.js 20) |
| Database | SQLite via better-sqlite3 (WAL mode) |
| Auth | bcryptjs + express-session with CAPTCHA |
| Frontend | Vanilla HTML/CSS/JS (SPA) |
| PWA | Service worker + Web Push notifications |

## Prerequisites

- **Node.js 20.x** (see `.nvmrc`)
- npm 10+

## Quick Start

```bash
# Clone
git clone https://github.com/desounun123-cmyk/mulerun.git
cd mulerun/server

# Install dependencies
npm install

# Configure environment
cp .env.example .env
# Edit .env with your settings (SMTP, API keys, etc.)

# Start the server
npm start
```

The app serves on `http://localhost:8080` by default.

## Project Structure

```
mulerun/
├── index.html              # Main SPA entry point
├── market-data.html        # Market data page
├── offline.html            # Offline fallback (PWA)
├── sw.js                   # Service worker
├── manifest.json           # PWA manifest
├── robots.txt              # Crawler rules
├── 404.html                # Custom 404 page (i18n)
├── icons/                  # App icons & favicons
├── .well-known/            # security.txt
└── server/
    ├── index.js            # Express app & server entry point
    ├── db.js               # SQLite setup, migrations, seed data
    ├── db-postgres.js       # PostgreSQL adapter (optional)
    ├── backup.js           # Automated backup & PITR system
    ├── routes/
    │   ├── auth.js         # Registration, login, password reset, CAPTCHA
    │   ├── user.js         # Profile, avatar, preferences, 2FA
    │   ├── analytics.js    # Price data, charts, exports
    │   ├── oauth.js        # OAuth providers
    │   ├── news.js         # News feed aggregation
    │   └── admin.js        # Admin dashboard & management
    ├── utils/
    │   ├── logger.js       # Pino logger configuration
    │   ├── email.js        # SMTP transport (Nodemailer)
    │   └── web-push.js     # Push notification service
    ├── scripts/
    │   └── check-prices.js # Scheduled EIA API price checker
    └── __tests__/
        ├── helpers.js              # Test setup (in-memory DB)
        ├── auth.test.js            # Auth unit tests
        ├── auth-integration.test.js # Auth integration tests
        └── translate-sql.test.js   # SQL translator tests
```

## Available Scripts

From the `server/` directory:

| Command | Description |
|---------|-------------|
| `npm start` | Start the production server |
| `npm run dev` | Start in development mode |
| `npm test` | Run the test suite (Jest) |
| `npm run backup` | Run backup with pruning |
| `npm run backup:list` | List available backups |
| `npm run backup:restore` | Restore from backup |

## Configuration

Copy `server/.env.example` to `server/.env` and configure:

- **PORT** — Server port (default: 8080)
- **NODE_ENV** — `production` or `development`
- **SESSION_SECRET** — Secret for session cookies
- **SMTP_*/** — Email credentials for password resets and alerts
- **EIA_API_KEY** — U.S. Energy Information Administration API key
- **NEWS_API_KEY** / **MEDIASTACK_KEY** — News feed providers
- **VAPID_*/** — Web Push notification keys

See `.env.example` for the full list with descriptions.

## Testing

```bash
cd server
npm test
```

Tests run against an isolated in-memory SQLite database. CAPTCHA and rate limiters are bypassed in test mode (`NODE_ENV=test`).

## Security

- CSRF protection via double-submit cookie pattern
- Account lockout after 5 failed login attempts (15-minute window)
- CAPTCHA challenge on registration and after repeated login failures
- Helmet security headers (CSP, HSTS, X-Frame-Options, etc.)
- Rate limiting on auth and API endpoints
- HTML sanitization on user inputs
- Vulnerability reports: see [.well-known/security.txt](.well-known/security.txt)

## License

See [LICENSE](LICENSE).
