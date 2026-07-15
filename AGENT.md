# CVE Portal — Agent Handoff

**Last updated:** 2026-05-28  
**Prod version:** `1.2622.6` (`5e56e24`)  
**Prod URL:** https://cve.ps-cluster.plainid.net  
**Branch:** `main` (clean, pushed)

---

## PLAT lookup/create audit (stdout)

Structured JSON lines on portal/worker pod stdout (not in UI):

```bash
kubectl logs -n cve deploy/cve-cve-portal-portal -f | rg plat_create_audit
kubectl logs -n cve deploy/cve-cve-portal-worker -f | rg plat_lookup_audit
```

Create path: initial Jira search → pre-create search (if no match) → create only if both empty. Search failures fail closed (503 on create, failed run on process). Multiple existing PLAT keys for same CVE+image → 409 block.

---

## Current status (shipped in 1.2622.6)

### PLAT sync & UX
- **Sync activity log** (`_plat_sync_log`) in findings UI + worker stdout
- **Stuck “Syncing” UI fix:** poll while `syncing_plat*`; clear `_plat_sync_progress` on completion in worker merge
- **Sync PLAT** allowed on `cancelled`/`failed` runs that still have `cve_rows`
- **Sequential auto-sync:** dedicated `plat_sync` queue, `plat-sync-worker` concurrency=1 (local + Helm)
- **Beat interval:** 1 hour (`3600s`)

### Customer status / findings display
- **Invalid PLAT status** → Expected release date + Tag numbers = `N/A`
- **Pending Vendor Fix** → Expected release date = `Pending Vendor Fix`, Tag numbers = `N/A`
- Column renamed: **PLAT fix version** → **Expected release date**
- **Suggested comment:** package column shows NVD name; `Package not found` only on Expected release date when **Invalid**; fix/tag use PLAT values when status is not Invalid
- **ADF tables** in Jira customer status comments (aligned columns, no extra blank intro lines)

### Aqua
- **Optional Aqua processing** (portal setting `aqua_processing_enabled`, **default off**)
- Checkbox in **Aqua Packages** admin; rewrite Package Name on Sync PLAT disabled unless Aqua processing is on
- Pipeline step shows **Aqua package check (off)** as skipped when disabled

### Package / NVD
- NVD is source of truth for primary package; attachment name stored as `attachment_product` hint only (not `attachment_primary` override in Aqua path)
- `attachment_primary` still used when building `cve_rows` primary resource (see open tasks)

### Image source of truth (strict gating — shipped)
- **CVE↔image pairs come only from Excel/JSON structured attachment facts** (`cve_image_facts`). Description text and PDF free-text are no longer used for PLAT image slots.
- **PLAT create is hard-blocked** unless `image_basename` resolves (via alias map) to a name in the `allowed_images` catalog. `POST /api/plat` returns HTTP 400 with a clear message for unknown images.
- **UI gates Create CVE / Create All** on `isAllowedImageBasename` — unknown images show the "Unknown image" badge but no create button.
- `plainid_image_patterns` config is no longer used for PLAT inclusion (still in config but deprecated for this purpose).

---

## Known issue (not fixed)

### Two instances + shared RDS → duplicate auto-sync
If **local docker compose** and **prod K8s** both use the **same Postgres** (RDS):
- Each environment runs its own **Celery Beat** (`run_due_plat_syncs` every hour)
- Each reads the same `issue_sync_schedules` and enqueues `sync_plat_for_run` on **separate Redis**
- Result: same tickets synced twice, extra Jira load

**Immediate workaround:** stop local beat when pointing at prod DB:
```bash
docker compose stop beat
# or: docker compose up -d portal worker plat-sync-worker   # no beat
```

**Proper fix (recommended):** atomic claim on `last_auto_sync_at`, skip if run already syncing, env gate (`AUTO_SYNC_ENABLED` prod-only), or single beat per DB.

---

## Open tasks

| Priority | Task | Notes |
|----------|------|--------|
| High | **Auto-sync dedupe across environments** | See known issue above |
| Medium | **`attachment_primary` guard in `cve_rows` build** | `worker/app/tasks.py` ~593–595 still prefers `attachment_primary` over NVD; pending `nvd_has_versions` guard from earlier discussion |
| Low | **Aqua: scan correct image tag before latest fallback** | Discussed for cases like `openjdk21-jre` in cache but not in Aqua UI for ticket tag |
| Ops | **Local dev: use local Postgres** | Avoid sharing RDS with prod to prevent schedule/sync collisions |

---

## Commands run (2026-05-28 session)

### Git
```bash
git add VERSION api/ worker/ ui/ docker-compose.yml docs/CVE-Portal.md infra/helm/cve-portal/
git commit -m "feat: #PLAT-24605 optional Aqua, PLAT sync UX, and customer status improvements"
git push origin main
```

### Local deploy
```bash
docker compose build portal worker plat-sync-worker beat
docker compose up -d
docker compose build portal && docker compose up -d portal   # UI-only iterations
curl http://localhost:8080/health
```

### Prod deploy (`1.2622.6`)
```bash
VERSION=$(cat VERSION)   # 1.2622.6
GIT_COMMIT=$(git rev-parse --short HEAD)

docker build --platform linux/amd64 \
  --build-arg GIT_COMMIT=$GIT_COMMIT --build-arg APP_VERSION=$VERSION \
  -t psplainid/cve-portal:$VERSION -t psplainid/cve-portal:latest \
  -f api/Dockerfile .

docker build --platform linux/amd64 \
  --build-arg GIT_COMMIT=$GIT_COMMIT --build-arg APP_VERSION=$VERSION \
  -t psplainid/cve-worker:$VERSION -t psplainid/cve-worker:latest \
  -f worker/Dockerfile .

docker push psplainid/cve-portal:$VERSION && docker push psplainid/cve-portal:latest
docker push psplainid/cve-worker:$VERSION && docker push psplainid/cve-worker:latest

helm upgrade cve infra/helm/cve-portal \
  --namespace cve \
  -f infra/helm/cve-portal/values.secret.yaml \
  --set image.portal.tag=$VERSION \
  --set image.worker.tag=$VERSION

kubectl get pods -n cve
curl -s -u "admin:…" https://cve.ps-cluster.plainid.net/health
```

**Prod verify:** Helm revision 16; all pods Running including `plat-sync-worker`; health `{"ok":true}`.

---

## Architecture quick reference

| Component | Role |
|-----------|------|
| `portal` | FastAPI + React SPA |
| `worker` (`-Q celery`) | `process_issue`, `run_due_plat_syncs` |
| `plat-sync-worker` (`-Q plat_sync`, concurrency=1) | `sync_plat_for_run` sequential |
| `beat` | Hourly `run_due_plat_syncs` — **only one should run per shared DB** |
| Redis | Celery broker (local vs prod are separate) |
| Postgres | Shared RDS in prod + often local dev → schedule collision risk |

---

## Next recommended step

1. **Stop local `beat`** (or disable via compose profile) while using prod RDS — quick relief for duplicate auto-sync.
2. **Implement auto-sync claim** in `run_due_plat_syncs` (`worker/app/tasks.py`):
   - Atomic `UPDATE … SET last_auto_sync_at = now() WHERE … AND due`
   - Skip enqueue if `ProcessingRun.status` in `syncing_plat` / `syncing_plat_rewrite`
   - Optional: `AUTO_SYNC_ENABLED` env, true only in K8s
3. **Local compose:** add `BEAT_ENABLED=false` or use local Postgres in `.env` for dev.

Ticket: **PLAT-24605**
