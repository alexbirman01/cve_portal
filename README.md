# CVE Portal (Jira + NVD)

Local development (v1):

1. Ensure `.env` contains Jira credentials.
2. Start stack (API, worker, DB, Redis, UI):
   - `docker compose up --build`
3. Optional — UI with Vite hot reload (dev only):
   - `cd ui && npm install && npm run dev` (uses Vite’s `/api` → `localhost:8000` proxy)

Services:
- API: `http://localhost:8000`
- UI (container, nginx + static build): `http://localhost:8080`
- UI (Vite dev): `http://localhost:5173` (or next free port)
- Postgres: `localhost:5432`
- Redis: `localhost:6379`

