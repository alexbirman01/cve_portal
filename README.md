# CVE Portal (Jira + NVD)

**Full documentation**: [docs/CVE-Portal.md](docs/CVE-Portal.md) — covers Product Manager design, architecture, and deployment perspectives.

## What's in the box (PM view)

- **Single place to see risk** — Pull a Jira security ticket, extract CVEs from description and attachments, enrich with NVD, and correlate existing **PLAT** work (bugs + Security Vulnerability tickets).
- **Results that match how you work** — Clear results layout, filters, Excel export, suggested internal comment, and **bulk "create all" PLAT CVE** actions where the data supports it.
- **Dashboard as a status board** — One row per issue (latest run) with per-CVE badges. **Workflow status**: *Done* = pipeline finished and no missing PLAT CVE slots for creatable rows; *In progress* = still missing required PLAT CVEs; plus Processing / Failed when runs are in flight or broke.
- **Find work fast** — Search by **PLATFORM** parent key, **PLAT-** ticket, **CVE** id, or paste a Jira URL; filter the board by workflow status.
- **Re-run when reality changes** — **Re-process ticket** from results kicks off a full analysis pass (with confirmation), not just a refresh of old JSON.

**Configuration** — Set Jira + optional NVD/Aqua in `.env`. **Postgres** user, password, host, port, and database name are also read from `.env`; Compose wires the API/worker DSN from those values (defaults suit local Docker). For **Jira Service Management** parent tickets (e.g. `PLATFORM-*`), set **`JIRA_USE_JSM_INTERNAL_COMMENTS=true`** so "Push to Jira as comment" uses the Service Desk API with `public: false` (customer-internal). If this is unset, the portal uses the standard issue comment API, which does not apply that visibility and comments may appear public to the customer. Additional Jira write behaviour can be tuned via: **`JIRA_PLAT_BUG_COMPONENT_NAME`** (default `Security`) sets the Jira component stamped on new PLAT Bugs; **`JIRA_PLAT_LINK_TO_PARENT_ON_CREATE`** (default `true`) controls whether PLAT tickets are automatically linked back to the PLATFORM parent; **`JIRA_PLAT_PARENT_LINK_TYPE_NAME`** (default `Relates`) is the Jira link type used for that relationship. The portal also works with external Postgres (e.g. AWS RDS) out of the box — no extra connection string flags needed.

---

## What's new

**PLAT Sync — Sync summary modal**
After a PLAT sync completes, a pop-up table breaks down each phase of the run: *Refresh CVEs from Jira*, *Read fix version & tag*, *Sync CVE label & due date*, and *Link to PLATFORM*. Each row shows how many items were checked and how many were actually changed. Any non-fatal warnings (e.g. a link that could not be created) appear in an amber section at the bottom so nothing is silently swallowed.

**PLAT Sync — Phase-aware live progress**
The in-flight sync progress pill now shows the current phase name (*Refreshing CVEs / Reading fix/tag / Label & due date / Linking to PLATFORM*) alongside a per-phase counter, replacing the single cumulative number. This makes it easier to tell at a glance which stage is running and how far along it is.

**Auto-link PLAT tickets to the PLATFORM parent**
When a PLAT Security Vulnerability or PLAT Bug ticket is created — either manually from the results table or automatically during a sync — the portal now creates a "Relates" issue link from the PLATFORM parent to the PLAT ticket in Jira. This keeps the relationship visible in Jira without any manual step. The behaviour is on by default and can be disabled or pointed at a different link type via `JIRA_PLAT_LINK_TO_PARENT_ON_CREATE` and `JIRA_PLAT_PARENT_LINK_TYPE_NAME`.

**PLAT Bug — Component auto-assign**
Newly created PLAT Bug tickets are automatically stamped with a Jira component (default: `Security`). The component name is configurable via `JIRA_PLAT_BUG_COMPONENT_NAME`.

**About / Health dialog**
A new **About** link in the top navigation bar opens a dialog that shows the running portal version, Python version, key package versions (FastAPI, Celery, SQLAlchemy, etc.), and live health probes for Postgres, Redis, and the Celery worker — useful for quick ops checks without leaving the browser.

**External Postgres / AWS RDS support**
The portal now explicitly pins the Postgres `search_path` to `public` on every connection, making it compatible with RDS instances (or any shared Postgres) where the database-level or user-level default differs. Standard `POSTGRES_*` environment variables are all that is needed; no extra DSN flags required.

**UI — CVE table column alignment**
Column headers in the CVE findings table (*Affected Image*, *PLAT Bug*, *PLAT CVE*) now align precisely with the cell content below them.

---

Local development (v1):

1. Copy or create `.env` with Jira credentials and, if you use Docker Postgres overrides, **`POSTGRES_*`** / `POSTGRES_DSN` (see `.env` comments).
2. Start stack (API, worker, DB, Redis, UI):
   - `docker compose up --build`
3. Optional — UI with Vite hot reload (dev only):
   - `cd ui && npm install && npm run dev` (uses Vite's `/api` → `localhost:8000` proxy)

Services:
- API: `http://localhost:8000`
- UI (container, nginx + static build): `http://localhost:8080`
- UI (Vite dev): `http://localhost:5173` (or next free port)
- Postgres: `localhost:5432`
- Redis: `localhost:6379`
