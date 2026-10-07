# M/S ANDE HI ANDE Contractor Workforce Portal

The portal is mounted at `/portal` for local development. Its dedicated Render service serves only the contractor portal; `/` redirects to `/portal`, and the existing G TEC storefront is not part of that service. It uses PostgreSQL for workforce data and server-side sessions. No role passwords are stored in source code. Do not put production secrets in GitHub.

## Database setup

1. Create a PostgreSQL database in Neon or another PostgreSQL provider.
2. Copy its pooled connection string into `DATABASE_URL` (include SSL settings as required by the provider).
3. From the repository root, run `npm install`, then `npm run contractor:migrate`.
4. Set the four `INITIAL_*_PASSWORD` variables in a private local shell, then run `npm run contractor:seed`. The seed command hashes passwords with bcrypt, upserts the four role accounts and forces a password change at first sign in. The portal requires a new password of at least 12 characters.
5. Clear those local seed variables after seeding. Never add initial passwords to Vercel or commit a populated `.env` file.

The migration creates users, database sessions, workers, one-use joining codes, attendance, progress reports, file metadata, ID cards, login rate limits, and audit logs. Employee IDs are assigned by a database sequence when the MD approves a worker.

## Free trial hosting

`render.yaml` describes a free-tier trial: the portal runs on Render Free, while PostgreSQL and private photo/document storage use a separate Supabase Free project. Free services can sleep or pause after inactivity and do not provide automatic database backups, so this trial setup is not suitable for sensitive employee records. The first visit after sleep may take about a minute. Domain registration is separate from hosting.

1. Push the `contractor-portal-live` branch and create a Blueprint on Render from its `render.yaml`. The service starts the dedicated portal server, not the storefront server.
2. Use a separate Supabase project for contractor records. Configure `DATABASE_URL` with its PostgreSQL session-pooler connection string, `SUPABASE_URL` with its project URL, and `SUPABASE_SERVICE_ROLE_KEY` with its service-role key. The startup command creates a private `contractor-private` bucket (5 MB per file) if it does not exist. Never put these secrets in GitHub or chat; keep the service-role key private.
3. Set four different initial account passwords in Render's private environment. Use unique passwords of at least 12 characters. The app applies its idempotent schema migration at startup and creates only missing accounts. Each account must change its initial password at first sign-in.
4. When deployment finishes, the Render service root redirects to `/portal`. Test the Render address before pointing the purchased domain at it.

The free service's local disk is temporary. Uploaded files therefore use the private Supabase bucket. Do not use this trial setup for sensitive worker information unless a backed-up, reliable paid hosting plan is in place. The joining-code registration and ID-card QR verification pages remain separate limited public flows.

## Role behavior

- **MASTER:** dashboard, workers, joining codes and approvals, attendance, monthly reports, progress, ID cards, user access.
- **MD:** dashboard, worker list and profile completion, final approval and ID cards.
- **MANAGER:** dashboard, joining codes and manager verification.
- **SUPERVISOR:** dashboard, worker lookup, attendance, monthly reports and progress.

The API enforces these roles server side. Sessions use random opaque tokens in HttpOnly, Secure-in-production, SameSite=Strict cookies. State-changing requests require a session CSRF token and same-origin checks. Login attempts and joining-code attempts are rate limited in PostgreSQL. Public employee verification returns only name, employee ID, designation, department, company and active status.

## Local development

Run `npm run start:local` from the repository root. This starts a persistent local PostgreSQL-compatible database in `contractor-portal/local-data`, applies the schema, seeds the role accounts only the first time, and serves the portal at `http://127.0.0.1:3100/portal` when `PORT=3100` is set. Without Supabase storage settings, uploaded photos and report attachments are stored locally in `contractor-portal/local-data/uploads`. Local database and upload files are ignored by Git. This local setup is for this computer only.
## Current implementation notes

- Attendance exports and monthly CSV download run in the browser. CSV is available; XLSX export is not included yet.
- ID cards have a print layout, worker photo, QR verification URL, regenerate action and revoke action. Photos and report attachments are served only to signed-in portal roles; hosted deployments store them on persistent private storage.
- ID card printing places one standard 85.6 × 53.98 mm card in the center of A4 paper for printing and cutting.
- Admin user creation, disable/enable and the audit log viewer are supported. Audit records are stored in `cp_audit_logs`.
- The repository contains an unrelated G TEC storefront. The dedicated contractor deployment uses `contractor-portal/server.js` and returns no storefront pages or APIs.
