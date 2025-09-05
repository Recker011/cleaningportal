# Availability Tracking System

Node.js/Express availability tracking app with MySQL (mysql2) and minimal UI:
- Roles: manager and employee
- Employees set weekly availability (morning/afternoon + notes)
- Managers view and edit employee availability
- Health endpoint for deployment checks

## Deploy on Koyeb

- Run command: `npm start`
- Health path: `/healthz`
- Environment variables to configure in Koyeb:
  - SESSION_SECRET
  - DB_HOST
  - DB_PORT
  - DB_USER
  - DB_PASSWORD
  - DB_NAME
  - DB_SSL_CA_PATH (defaults to `certs/aiven_dev_ca.pem` if not provided)

Notes:
- Networking: the app binds to `0.0.0.0` and respects `process.env.PORT`. `trust proxy` is enabled.
- Set `NODE_ENV=production` in Koyeb.
- Filesystem is ephemeral on Koyeb; this app does not persist files locally.

## Local Development

- Copy `.env.example` to `.env` and fill in values as needed
- Install dependencies: `npm i`
- Start dev server: `npm run dev` (listens on http://localhost:3000 by default)
- Health check: `curl http://localhost:3000/healthz` returns `{"ok":true,...}`