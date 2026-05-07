# CVE Portal (Jira + NVD)

Local development (v1):

1. Ensure `.env` contains Jira credentials.
2. Start backend + dependencies:
   - `docker compose up --build`
3. UI:
   - `cd ui && npm install && npm run dev`

Services:
- API: `http://localhost:8000`
- UI: `http://localhost:5173`
- Postgres: `localhost:5432`
- Redis: `localhost:6379`

