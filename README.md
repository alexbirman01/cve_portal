# CVE Portal (Jira + NVD)

## What’s in the box (PM view)

- **Single place to see risk** — Pull a Jira security ticket, extract CVEs from description and attachments, enrich with NVD, and correlate existing **PLAT** work (bugs + Security Vulnerability tickets).
- **Results that match how you work** — Clear results layout, filters, Excel export, suggested internal comment, and **bulk “create all” PLAT CVE** actions where the data supports it.
- **Dashboard as a status board** — One row per issue (latest run) with per-CVE badges. **Workflow status**: *Done* = pipeline finished and no missing PLAT CVE slots for creatable rows; *In progress* = still missing required PLAT CVEs; plus Processing / Failed when runs are in flight or broke.
- **Find work fast** — Search by **PLATFORM** parent key, **PLAT-** ticket, **CVE** id, or paste a Jira URL; filter the board by workflow status.
- **Re-run when reality changes** — **Re-process ticket** from results kicks off a full analysis pass (with confirmation), not just a refresh of old JSON.

**Configuration** — Set Jira + optional NVD/Aqua in `.env`. **Postgres** user, password, host, port, and database name are also read from `.env`; Compose wires the API/worker DSN from those values (defaults suit local Docker). For **Jira Service Management** parent tickets (e.g. `PLATFORM-*`), set **`JIRA_USE_JSM_INTERNAL_COMMENTS=true`** so “Push to Jira as comment” uses the Service Desk API with `public: false` (customer-internal). If this is unset, the portal uses the standard issue comment API, which does not apply that visibility and comments may appear public to the customer.

---

Local development (v1):

1. Copy or create `.env` with Jira credentials and, if you use Docker Postgres overrides, **`POSTGRES_*`** / `POSTGRES_DSN` (see `.env` comments).
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

