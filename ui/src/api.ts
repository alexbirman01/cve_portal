export type JiraAttachment = {
  id: string
  filename: string
  mimeType?: string | null
  size?: number | null
  content?: string | null
}

export type OrgRef = {
  id?: string | null
  name?: string | null
}

export type IssueResponse = {
  key: string
  summary?: string | null
  issuetype?: string | null
  project?: string | null
  reporter?: string | null
  organizations?: string[] | null
  /** From Jira Organizations field — prefer for PLAT create (id). */
  organization_refs?: OrgRef[] | null
  description_raw?: unknown
  description_text?: string | null
  attachments: JiraAttachment[]
  created?: string | null
}

export type ProcessResponse = {
  run_id: string
  task_id: string
}

export type AffectedPackage = {
  vendor: string
  product: string
  version_start?: string | null
  fixed_version?: string | null
}

export type PlatTicket = {
  key: string
  issue_type: string   // "Security Vulnerability" or "Bug"
  summary?: string | null
}

export type AffectedImage = {
  image: string
  tag?: string | null
}

export type PlatSecurityFieldSyncEntry = {
  fix_versions: string
  tag_numbers: string
  /** Jira workflow status.name after Sync PLAT (e.g. Invalid). */
  issue_status?: string
  package_name?: string
  package_vuln_version?: string
  vendor_fix_version?: string
}

export type CveRow = {
  cve_id: string
  severity?: string | null
  score?: string | null
  nvd_state?: string
  affected_images?: AffectedImage[]   // all matched PlainID images
  affected_image?: string | null       // legacy: first image only
  affected_tag?: string | null
  affected_resource?: string | null
  affected_version?: string | null
  fixed_version?: string | null
  all_packages?: AffectedPackage[]
  plat_security_keys?: string[]
  /** Sec-Vuln PLAT keys per image basename (imagename in correlation / summary). */
  plat_security_for_images?: Record<string, string[]>
  plat_tickets?: PlatTicket[]   // new: typed list
  plat_ticket?: string | null   // legacy: backward compat with old cached runs
  sources?: string[]
  sla_due_date?: string | null
  /**
   * Per Security PLAT key (uppercase): Jira fixVersions + tag numbers field after last Sync.
   * Empty Jira values stored as "None". Only keys with a successful GET are present.
   */
  plat_security_field_sync?: Record<string, PlatSecurityFieldSyncEntry>
  /**
   * @deprecated Legacy rollup from older sync — prefer plat_security_field_sync.
   */
  plat_app_fix_versions?: string | null
  /**
   * @deprecated Legacy rollup from older sync — prefer plat_security_field_sync.
   */
  plat_tag_numbers?: string | null
  /** True when Aqua confirmed package name; false = block PLAT CVE create; null/undefined = Aqua not configured. */
  aqua_pkg_found?: boolean | null
  aqua_package_name?: string | null
  aqua_candidates?: AquaPackageCandidate[]
  /** @deprecated Replaced by package_by_image — kept for backward compat with cached runs. */
  aqua_pkg_by_image?: Record<string, AquaPkgByImageEntry>
  /** Per-image package + Aqua status. Prefer this over aqua_pkg_by_image. */
  package_by_image?: Record<string, PackageByImageEntry>
}

export type AquaPackageCandidate = {
  name: string
  version?: string | null
  source: 'customer' | 'nvd' | 'aqua' | string
}

export type AquaPkgByImageEntry = {
  found: boolean
  aqua_package_name?: string | null
  aqua_package_version?: string | null
  candidates?: AquaPackageCandidate[]
  aqua_checked?: boolean
}

export type PackageByImageEntry = {
  /** Package name used for this image's Aqua lookup. */
  affected_resource: string | null
  aqua_pkg_found?: boolean | null
  aqua_package_name?: string | null
  aqua_package_version?: string | null
  aqua_candidates?: AquaPackageCandidate[]
  aqua_checked?: boolean
  /** Jira tag when catalog came from another Aqua tag (e.g. latest). */
  aqua_tag_requested?: string | null
  aqua_tag_used?: string | null
}

export type PlatSyncLogEntry = {
  ts: string
  level: 'info' | 'warn' | 'error' | string
  msg: string
}

export type JobResult = {
  issue_key: string
  cves: string[]
  cve_rows: CveRow[]
  nvd: any[]
  attachments: any[]
  images: any[]
  sla_anchor_created?: string | null
  sla_anchor_issue_key?: string | null
  /** Set when some Jira writes during PLAT sync fail (partial success). */
  _plat_sync_errors?: string[] | null
  /** Append-only activity log during/after Sync PLAT (polled from result_json). */
  _plat_sync_log?: PlatSyncLogEntry[] | null
  /** In-flight progress while status is syncing_plat (polled from result_json). */
  _plat_sync_progress?: {
    phase: string
    phase_current?: number
    phase_total?: number
    phase_index?: number
    phase_count?: number
    /** @deprecated Legacy cumulative counter — prefer phase_current/phase_total */
    current?: number
    /** @deprecated Legacy cumulative counter — prefer phase_current/phase_total */
    total?: number
  } | null
  /** Whether Aqua cross-check ran for this run (portal setting at processing time). */
  _aqua_processing_enabled?: boolean | null
  /** Counters from the last Sync PLAT run. */
  _plat_sync_stats?: {
    tickets_refreshed: number
    fields_read: number
    label_date_checked?: number
    label_date_updated?: number
    labels_added?: number
    duedates_updated?: number
    links_checked?: number
    links_created?: number
    package_names_rewritten?: number
    aqua_rows_rechecked?: number
    packages_checked?: number
    packages_updated?: number
    // legacy (pre-accurate-stats) — may be present on old stored runs
    label_date_pushed?: number
    linked?: number
  } | null
  /** Cumulative link counters from process_issue. */
  _plat_link_counts?: { links_checked?: number; links_created?: number; errors: string[] } | null
  error?: string | null
  traceback?: string | null
}

export type JobResponse = {
  run_id: string
  issue_key: string
  status: string
  task_id?: string | null
  updated_at?: string | null
  result?: JobResult | null
}

export type CustomerSlaRecord = {
  id: string
  customer_name: string
  sla_critical?: string | null
  sla_high?: string | null
  sla_medium?: string | null
  sla_low?: string | null
  created_at?: string | null
  updated_at?: string | null
}

export async function apiListCustomerSlas(): Promise<CustomerSlaRecord[]> {
  return apiGet('/api/sla/customers')
}

export async function apiCreateCustomerSla(body: {
  customer_name: string
  sla_critical?: string | null
  sla_high?: string | null
  sla_medium?: string | null
  sla_low?: string | null
}): Promise<CustomerSlaRecord> {
  return apiPost('/api/sla/customers', body)
}

export async function apiUpdateCustomerSla(
  id: string,
  body: Partial<{
    customer_name: string
    sla_critical: string | null
    sla_high: string | null
    sla_medium: string | null
    sla_low: string | null
  }>,
): Promise<CustomerSlaRecord> {
  return apiPut(`/api/sla/customers/${encodeURIComponent(id)}`, body)
}

export async function apiDeleteCustomerSla(id: string): Promise<void> {
  return apiDelete(`/api/sla/customers/${encodeURIComponent(id)}`)
}

export type AllowedImageRecord = {
  id: string
  name: string
  aliases?: string
  created_at?: string | null
  updated_at?: string | null
}

export async function apiListAllowedImages(): Promise<AllowedImageRecord[]> {
  return apiGet('/api/allowed-images')
}

export async function apiCreateAllowedImage(body: { name: string; aliases?: string }): Promise<AllowedImageRecord> {
  return apiPost('/api/allowed-images', body)
}

export async function apiUpdateAllowedImage(
  id: string,
  body: { name: string; aliases?: string },
): Promise<AllowedImageRecord> {
  return apiPut(`/api/allowed-images/${encodeURIComponent(id)}`, body)
}

export async function apiDeleteAllowedImage(id: string): Promise<void> {
  return apiDelete(`/api/allowed-images/${encodeURIComponent(id)}`)
}

export function isAllowedImageBasename(basename: string, allowed: Set<string>): boolean {
  return allowed.has(basename.toLowerCase())
}

export type AquaCachedImageSummary = {
  registry: string
  repository: string
  tag: string
  display: string
  package_count: number
  fetched_at: string | null
  fresh: boolean
}

export type AquaCachedPackage = {
  name: string
  version?: string | null
  fix_version?: string | null
}

export type AquaPackagesCatalogResponse = {
  aqua_configured: boolean
  ttl_hours: number
  default_ttl_hours: number
  images: AquaCachedImageSummary[]
}

export type AquaPackageEntryResponse = AquaCachedImageSummary & {
  packages: AquaCachedPackage[]
}

export type AquaPackagesSettingsResponse = {
  ttl_hours: number
  default_ttl_hours: number
  aqua_configured: boolean
  /** When true, CVE processing cross-checks packages against Aqua (default off). */
  aqua_processing_enabled: boolean
  rewrite_plat_package_name_on_sync: boolean
  /** @deprecated Legacy alias — same as rewrite_plat_package_name_on_sync */
  recheck_on_sync: boolean
  preferred_registry: string
  default_preferred_registry: string
  default_image_tag: string
  default_default_image_tag: string
}

export type AquaPackagesSettingsPatch = {
  ttl_hours?: number
  aqua_processing_enabled?: boolean
  rewrite_plat_package_name_on_sync?: boolean
  recheck_on_sync?: boolean
  preferred_registry?: string
  default_image_tag?: string
}

export async function apiListAquaPackages(): Promise<AquaPackagesCatalogResponse> {
  return apiGet('/api/aqua-packages')
}

export async function apiGetAquaPackagesSettings(): Promise<AquaPackagesSettingsResponse> {
  return apiGet('/api/aqua-packages/settings')
}

export async function apiPatchAquaPackagesSettings(patch: AquaPackagesSettingsPatch): Promise<AquaPackagesSettingsResponse> {
  const res = await fetch('/api/aqua-packages/settings', {
    method: 'PATCH',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(patch),
  })
  if (!res.ok) throw new Error(await res.text())
  return (await res.json()) as AquaPackagesSettingsResponse
}

export async function apiGetAquaPackageEntry(
  registry: string,
  repository: string,
  tag: string,
): Promise<AquaPackageEntryResponse> {
  const q = new URLSearchParams({ registry, repository, tag })
  return apiGet(`/api/aqua-packages/entry?${q}`)
}

export async function apiDeleteAquaPackageEntry(
  registry: string,
  repository: string,
  tag: string,
): Promise<void> {
  const q = new URLSearchParams({ registry, repository, tag })
  return apiDelete(`/api/aqua-packages/entry?${q}`)
}

export async function apiRefreshAquaPackageEntry(
  registry: string,
  repository: string,
  tag: string,
): Promise<AquaCachedImageSummary> {
  return apiPost('/api/aqua-packages/refresh', { registry, repository, tag })
}

export type HistoryRun = {
  run_id: string
  issue_key: string
  status: string
  created_at?: string | null
  cve_count?: number | null
}

export type DashboardCveState =
  | 'pipeline_running'
  | 'pipeline_failed'
  | 'nvd_error'
  | 'no_image'
  | 'needs_plat_cve'
  | 'needs_version'
  | 'plat_complete'

export type IssueCveStatusEntry = {
  cve_id: string
  severity?: string | null
  cve_state: DashboardCveState | string
}

export type DashboardTicketStatus = 'processing' | 'failed' | 'in_progress' | 'done'

export type DashboardRemediationStatus =
  | 'error'
  | 'processing'
  | 'package_not_matched'
  | 'needs_plat'
  | 'initialized'
  | 'waiting_release_date'
  | 'waiting_tags'
  | 'done'

export type IssueCveStatusSummary = {
  issue_key: string
  /** Parent security ticket (e.g. PLATFORM-1234); may mirror issue_key */
  parent_issue_key?: string
  /** Jira project prefix of parent ticket, e.g. PLATFORM */
  issue_project?: string
  run_id: string
  run_status: string
  /** PLAT workflow: done = all CVE PLAT tickets created; in_progress = some still missing. */
  ticket_status?: DashboardTicketStatus | string
  /** Richer remediation readiness status from the API (preferred over ticket_status). */
  remediation_status?: DashboardRemediationStatus | string
  created_at?: string | null
  updated_at?: string | null
  cve_count?: number | null
  needs_plat_cve_count?: number
  /** JSM Organization / customer names from the parent ticket */
  customer_names?: string[]
  /** Dashboard checkbox: run Sync PLAT automatically once every 24 hours */
  daily_sync_enabled?: boolean
  last_auto_sync_at?: string | null
  /** PLAT-xxx keys from linked Jira tickets in the last run result */
  plat_keys?: string[]
  cves: IssueCveStatusEntry[]
}

export function dashboardCveStateLabel(state: string): string {
  const map: Record<string, string> = {
    pipeline_running: 'Pipeline running',
    pipeline_failed: 'Pipeline failed',
    nvd_error: 'NVD error',
    no_image: 'No image',
    needs_plat_cve: 'Needs PLAT CVE',
    needs_version: 'Needs version',
    plat_complete: 'PLAT complete',
  }
  return map[state] ?? state
}

export function dashboardTicketStatusLabel(status: string): string {
  const map: Record<string, string> = {
    processing: 'Processing',
    failed: 'Failed',
    in_progress: 'In progress',
    done: 'Done',
    cancelled: 'Cancelled',
  }
  return map[status] ?? status
}

export function ticketStatusForSummary(s: IssueCveStatusSummary): DashboardTicketStatus {
  const ts = s.ticket_status
  if (ts === 'processing' || ts === 'failed' || ts === 'in_progress' || ts === 'done') {
    return ts
  }
  if (s.run_status.startsWith('failed')) return 'failed'
  if (s.run_status !== 'done') return 'processing'
  if ((s.needs_plat_cve_count ?? 0) > 0) return 'in_progress'
  return 'done'
}

export function remediationStatusForSummary(s: IssueCveStatusSummary): DashboardRemediationStatus {
  const rs = s.remediation_status
  if (
    rs === 'error' || rs === 'processing' || rs === 'package_not_matched' || rs === 'needs_plat' ||
    rs === 'initialized' || rs === 'waiting_release_date' || rs === 'waiting_tags' || rs === 'done'
  ) return rs
  // Fallback for old cached API responses that only have ticket_status
  const ts = ticketStatusForSummary(s)
  if (ts === 'failed') return 'error'
  if (ts === 'processing') return 'processing'
  if (ts === 'in_progress') return 'needs_plat'
  return 'done'
}

export function dashboardRemediationStatusLabel(status: DashboardRemediationStatus | string): string {
  const map: Record<string, string> = {
    error: 'Error',
    processing: 'Processing',
    package_not_matched: 'Package not matched',
    needs_plat: 'Needs PLAT',
    initialized: 'Initialized',
    waiting_release_date: 'Waiting for release date',
    waiting_tags: 'Waiting for tags',
    done: 'Done',
  }
  return map[status] ?? status
}

export type CreatePlatResponse =
  | { exists: true; keys: string[]; link_warnings?: string[] }
  | { exists: false; key: string; summary?: string; link_warnings?: string[] }

export function jobIsSyncingPlat(status?: string | null): boolean {
  return (
    status === 'syncing_plat' ||
    status === 'syncing_plat_rewrite' ||
    status === 'syncing_aqua'
  )
}

export function formatStatus(status?: string | null): string {
  if (!status) return ''
  const map: Record<string, string> = {
    queued: 'Queued',
    fetching_issue: 'Fetching Jira issue',
    extracting_from_description: 'Extracting from description',
    downloading_attachments: 'Downloading attachments',
    parsing_attachments: 'Parsing attachments',
    enriching_nvd: 'Validating/enriching via NVD',
    enriching_alpine: 'Enriching via Alpine secdb (OSV)',
    enriching_rh: 'Enriching via Red Hat Security',
    enriching_cve5: 'Enriching via MITRE CVE 5.0',
    looking_up_plat_tickets: 'Looking up PLAT tickets',
    building_results: 'Building results',
    enriching_aqua: 'Cross-checking packages in Aqua',
    skipping_aqua: 'Skipping Aqua (disabled)',
    done: 'Done',
    syncing_plat: 'Syncing PLAT with Jira',
    syncing_plat_rewrite: 'Rewriting PLAT Package Name in Jira',
    syncing_aqua: 'Rewriting PLAT Package Name in Jira',
    // Legacy (removed Aqua phase)
    querying_aqua: 'Building results',
  }
  if (status.startsWith('failed')) return `Failed`
  return map[status] ?? status
}

/** Map deprecated / DB statuses to the step list we render (keeps old runs readable). */
function normalizeStatusForSteps(status?: string | null): string | undefined | null {
  if (!status) return status
  if (status === 'querying_aqua') return 'building_results'
  if (status === 'syncing_plat') return 'syncing_plat'
  return status
}

export type StatusStepState = 'done' | 'current' | 'todo' | 'failed' | 'skipped'

export function statusSteps(
  status?: string | null,
  opts?: { aquaProcessingEnabled?: boolean },
): Array<{ id: string; label: string; state: StatusStepState }> {
  const aquaOn = opts?.aquaProcessingEnabled ?? false
  const steps = [
    { id: 'fetching_issue', label: 'Fetch issue' },
    { id: 'extracting_from_description', label: 'Extract description' },
    { id: 'downloading_attachments', label: 'Download attachments' },
    { id: 'parsing_attachments', label: 'Parse attachments' },
    { id: 'enriching_nvd', label: 'NVD enrichment' },
    { id: 'enriching_alpine', label: 'Alpine package lookup' },
    { id: 'looking_up_plat_tickets', label: 'Look up PLAT tickets' },
    { id: 'enriching_aqua', label: aquaOn ? 'Aqua package check' : 'Aqua package check (off)' },
    { id: 'building_results', label: 'Build results' },
    { id: 'syncing_plat', label: 'Sync PLAT (Jira)' },
    { id: 'done', label: 'Done' },
  ]
  const norm = normalizeStatusForSteps(status)
  const aquaIdx = steps.findIndex((s) => s.id === 'enriching_aqua')
  const idx = steps.findIndex((s) => s.id === norm)

  return steps.map((s, i) => {
    if (s.id === 'enriching_aqua' && !aquaOn) {
      const pastAqua =
        norm === 'building_results' ||
        norm === 'syncing_plat' ||
        norm === 'syncing_plat_rewrite' ||
        norm === 'syncing_aqua' ||
        norm === 'done' ||
        (idx >= 0 && idx > aquaIdx)
      return {
        ...s,
        state: (pastAqua ? 'skipped' : 'todo') as StatusStepState,
      }
    }

    let state: StatusStepState = 'todo'
    if (status?.startsWith('failed')) {
      state = 'failed'
    } else if (idx >= 0) {
      if (i < idx) state = 'done'
      else if (i === idx) state = 'current'
    }

    return { ...s, state }
  })
}

export async function apiGet<T>(path: string): Promise<T> {
  const res = await fetch(path)
  if (!res.ok) throw new Error(await res.text())
  return (await res.json()) as T
}

export async function apiPut<T>(path: string, body: unknown): Promise<T> {
  const res = await fetch(path, {
    method: 'PUT',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body),
  })
  if (!res.ok) throw new Error(await res.text())
  return (await res.json()) as T
}

export async function apiDelete(path: string): Promise<void> {
  const res = await fetch(path, { method: 'DELETE' })
  if (!res.ok) throw new Error(await res.text())
}

/** Browser-safe config from the API (no secrets). */
export type ClientConfig = {
  jira_browse_url: string
}

export async function apiGetClientConfig(): Promise<ClientConfig> {
  return apiGet<ClientConfig>('/api/config/client')
}

export type ComponentHealth = { status: 'ok' | 'error' | 'no_workers'; host?: string; detail?: string; workers?: string[] }

export type AboutInfo = {
  portal_version: string
  git_commit: string
  python_version: string
  packages: Record<string, string>
  components: {
    postgres: ComponentHealth
    redis: ComponentHealth
    celery_worker: ComponentHealth
  }
}

export async function apiGetAbout(): Promise<AboutInfo> {
  return apiGet<AboutInfo>('/api/about')
}

/** Remove all `processing_runs` rows for this Jira key from the database. */
export async function apiDeleteProcessingRunsForIssue(
  issueKey: string,
): Promise<{ ok: boolean; deleted_count: number }> {
  const res = await fetch(`/api/jobs/issue/${encodeURIComponent(issueKey.trim())}`, { method: 'DELETE' })
  if (!res.ok) throw new Error(await res.text())
  return (await res.json()) as { ok: boolean; deleted_count: number }
}

export async function apiPost<T>(path: string, body: unknown): Promise<T> {
  const res = await fetch(path, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body),
  })
  if (!res.ok) throw new Error(await res.text())
  return (await res.json()) as T
}

export async function apiCreatePlat(body: {
  cve_id: string
  image_basename: string
  package_name: string
  package_version: string
  severity?: string | null
  organizations?: OrgRef[] | null
  /** Jira parent issue key — used to copy organization IDs when the payload has no numeric ids */
  source_issue_key?: string | null
  /** SLA due date YYYY-MM-DD; sent as Jira `duedate` on create */
  sla_due_date?: string | null
  /** Run whose result_json will be updated with the new key so it survives remount */
  run_id?: string | null
}): Promise<CreatePlatResponse> {
  const res = await fetch('/api/plat', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body),
  })
  const text = await res.text()
  if (!res.ok) throw new Error(text || res.statusText)
  return JSON.parse(text) as CreatePlatResponse
}

/** Per-image package entry — reads new package_by_image first, falls back to aqua_pkg_by_image. */
export function packageEntryForImage(
  r: CveRow,
  imageBasename: string,
): PackageByImageEntry | undefined {
  const fold = imageBasename.toLowerCase()
  const pbi = r.package_by_image
  if (pbi) {
    if (pbi[imageBasename]) return pbi[imageBasename]
    for (const [k, v] of Object.entries(pbi)) {
      if (k.toLowerCase() === fold) return v
    }
  }
  // Fallback: convert legacy aqua_pkg_by_image entry to PackageByImageEntry shape
  const m = r.aqua_pkg_by_image
  if (m) {
    const legacy = m[imageBasename] ?? Object.entries(m).find(([k]) => k.toLowerCase() === fold)?.[1]
    if (legacy) {
      return {
        affected_resource: r.affected_resource ?? null,
        aqua_pkg_found: legacy.found,
        aqua_package_name: legacy.aqua_package_name,
        aqua_package_version: legacy.aqua_package_version,
        aqua_candidates: legacy.candidates,
        aqua_checked: legacy.aqua_checked,
      }
    }
  }
  return undefined
}

/** @deprecated Use packageEntryForImage instead. */
export function aquaPkgEntryForImage(
  r: CveRow,
  imageBasename: string,
): AquaPkgByImageEntry | undefined {
  const e = packageEntryForImage(r, imageBasename)
  if (!e) return undefined
  return {
    found: e.aqua_pkg_found === true,
    aqua_package_name: e.aqua_package_name,
    aqua_package_version: e.aqua_package_version,
    candidates: e.aqua_candidates,
    aqua_checked: e.aqua_checked,
  }
}

/** Whether PLAT CVE create is allowed for this image (Aqua must confirm when checked). */
export function aquaAllowsPlatCreate(r: CveRow, imageBasename: string): boolean {
  const entry = packageEntryForImage(r, imageBasename)
  if (entry?.aqua_checked) return entry.aqua_pkg_found === true
  if (r.aqua_pkg_found === true || r.aqua_pkg_found === false) return r.aqua_pkg_found === true
  return true
}

export function aquaCandidateSourceLabel(source: string): string {
  if (source === 'customer') return 'Customer report'
  if (source === 'nvd') return 'NVD'
  if (source === 'aqua') return 'Aqua'
  return source
}

export type PackagePickOption = {
  source: 'aqua' | 'customer' | 'nvd'
  value: string
  label: string
}

/** True when any NVD package in the row has vendor 'golang'. */
export function isNvdGoRow(row: CveRow): boolean {
  return (row.all_packages ?? []).some(
    (p) => (p.vendor ?? '').trim().toLowerCase() === 'golang',
  )
}

/** Fixed-order pick list when Aqua did not confirm the package (aqua / customer / nvd). */
export function packagePickOptions(
  row: CveRow,
  candidates: AquaPackageCandidate[],
  entry?: PackageByImageEntry,
): PackagePickOption[] {
  const nameFor = (source: string) =>
    candidates.find((c) => c.source === source)?.name?.trim() ?? ''
  const customer =
    nameFor('customer') ||
    canonicalSinglePackageName(entry?.affected_resource ?? row.affected_resource)
  const nvd =
    nameFor('nvd') ||
    (row.all_packages?.map((p) => canonicalSinglePackageName(p.product)).find(Boolean) ?? '')

  if (isNvdGoRow(row)) {
    return [
      { source: 'aqua', value: 'stdlib', label: 'aqua — stdlib' },
      { source: 'customer', value: customer, label: customer ? `customer — ${customer}` : 'customer — none' },
      { source: 'nvd', value: nvd, label: nvd ? `nvd — ${nvd}` : 'nvd — none' },
    ]
  }

  const aqua = nameFor('aqua')
  const label = (source: string, name: string) => {
    if (name) return `${source} — ${name}`
    if (source === 'aqua') return 'aqua — not found'
    return `${source} — none`
  }
  return [
    { source: 'aqua', value: aqua, label: label('aqua', aqua) },
    { source: 'customer', value: customer, label: label('customer', customer) },
    { source: 'nvd', value: nvd, label: label('nvd', nvd) },
  ]
}

/** First token when scanners join packages (libssl3,libcrypto3) — mirrors api/app/package_name.py */
export function canonicalSinglePackageName(name: string | null | undefined): string {
  const s = (name ?? '').trim()
  if (!s) return ''
  const parts = s.split(/[,;]+/).map((p) => p.trim()).filter(Boolean)
  return parts[0] ?? ''
}

/** Best-effort package / component name for PLAT “Package Name” field. */
export function platPackageNameForRow(r: CveRow, imageBasename?: string): string {
  if (imageBasename) {
    const entry = packageEntryForImage(r, imageBasename)
    if (entry?.aqua_pkg_found && entry.aqua_package_name) {
      return canonicalSinglePackageName(entry.aqua_package_name)
    }
    if (isNvdGoRow(r)) return 'stdlib'
    if (entry?.affected_resource) return canonicalSinglePackageName(entry.affected_resource)
  }
  if (r.aqua_pkg_found && r.aqua_package_name?.trim()) {
    return canonicalSinglePackageName(r.aqua_package_name)
  }
  if (isNvdGoRow(r)) return 'stdlib'
  if (r.aqua_package_name?.trim()) return canonicalSinglePackageName(r.aqua_package_name)
  const res = canonicalSinglePackageName(r.affected_resource)
  if (res) return res
  const product = r.all_packages
    ?.map((p) => canonicalSinglePackageName(p.product))
    .find(Boolean)
  if (product) return product
  return r.cve_id
}

/** Organizations payload for /api/plat — prefers Jira `organization_refs` (with id). */
export function platOrgRefsFromIssue(issue: Pick<IssueResponse, 'organization_refs' | 'organizations'>): OrgRef[] {
  const refs = issue.organization_refs?.filter(
    (r) => (r.id != null && String(r.id).trim() !== '') || (r.name != null && String(r.name).trim() !== ''),
  )
  if (refs?.length) return refs
  return (issue.organizations ?? []).filter(Boolean).map((name) => ({ name }))
}

const SEV_ORDER: Record<string, number> = { CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3 }

export function sortCveRows(rows: CveRow[]): CveRow[] {
  return [...rows].sort((a, b) => {
    const sa = SEV_ORDER[a.severity?.toUpperCase() ?? ''] ?? 99
    const sb = SEV_ORDER[b.severity?.toUpperCase() ?? ''] ?? 99
    if (sa !== sb) return sa - sb
    return a.cve_id.localeCompare(b.cve_id)
  })
}

/** Security Vulnerability PLAT keys for this row (explicit or derived from plat_tickets). */
export function platSecurityKeys(r: CveRow): string[] {
  if (r.plat_security_keys?.length) return r.plat_security_keys
  return (r.plat_tickets ?? [])
    .filter((t) => t.issue_type === 'Security Vulnerability')
    .map((t) => t.key)
}

/** True when PLAT Security workflow status is Invalid (case-insensitive). */
export function isPlatIssueStatusInvalid(status: string | null | undefined): boolean {
  return (status ?? '').trim().toLowerCase() === 'invalid'
}

/** Any scoped Security PLAT key on this row has Invalid workflow status. */
export function platIssueStatusInvalidForKeys(r: CveRow, secKeys: string[]): boolean {
  const m = r.plat_security_field_sync
  if (!m) return false
  for (const k of secKeys) {
    const pk = k.trim().toUpperCase()
    if (!pk) continue
    if (isPlatIssueStatusInvalid(m[pk]?.issue_status)) return true
  }
  return false
}

/** True when PLAT Security workflow status is Pending Vendor Fix (case-insensitive). */
export function isPlatIssueStatusPendingVendorFix(status: string | null | undefined): boolean {
  return (status ?? '').trim().toLowerCase() === 'pending vendor fix'
}

/** Any scoped Security PLAT key on this row has Pending Vendor Fix workflow status. */
export function platIssueStatusPendingVendorFixForKeys(r: CveRow, secKeys: string[]): boolean {
  const m = r.plat_security_field_sync
  if (!m) return false
  for (const k of secKeys) {
    const pk = k.trim().toUpperCase()
    if (!pk) continue
    if (isPlatIssueStatusPendingVendorFix(m[pk]?.issue_status)) return true
  }
  return false
}

/** Jira app fields for one Security PLAT key after Sync (keys stored uppercase). */
export function platSecuritySyncForKey(r: CveRow, issueKey: string): PlatSecurityFieldSyncEntry | null {
  const m = r.plat_security_field_sync
  if (!m) return null
  const k = issueKey.trim().toUpperCase()
  return m[k] ?? null
}

/** Multiline text for PLAT fix column (one line per key: `KEY · fix`). */
export function platSecuritySyncFixColumnText(r: CveRow): string {
  const m = r.plat_security_field_sync
  if (m && Object.keys(m).length > 0) {
    return [...Object.keys(m)]
      .sort()
      .map((k) => `${k} · ${m[k].fix_versions}`)
      .join('\n')
  }
  return (r.plat_app_fix_versions ?? '').trim()
}

/** `fix_versions` for these Security PLAT keys (single value if one key; else KEY · lines). */
export function platSecuritySyncFixForKeys(r: CveRow, keys: string[]): string {
  const upper = [...new Set(keys.map((k) => k.trim().toUpperCase()).filter(Boolean))].sort()
  if (!upper.length) return ''
  const m = r.plat_security_field_sync
  if (!m || !Object.keys(m).length) return ''
  if (upper.length === 1) return normalizePlatSyncFieldValue(m[upper[0]]?.fix_versions)
  return upper
    .map((k) => {
      const fix = normalizePlatSyncFieldValue(m[k]?.fix_versions)
      return `${k} · ${fix || '—'}`
    })
    .join('\n')
}

/** `tag_numbers` for these Security PLAT keys. */
export function platSecuritySyncTagForKeys(r: CveRow, keys: string[]): string {
  const upper = [...new Set(keys.map((k) => k.trim().toUpperCase()).filter(Boolean))].sort()
  if (!upper.length) return ''
  const m = r.plat_security_field_sync
  if (!m || !Object.keys(m).length) return ''
  if (upper.length === 1) return normalizePlatSyncFieldValue(m[upper[0]]?.tag_numbers)
  return upper
    .map((k) => {
      const tag = normalizePlatSyncFieldValue(m[k]?.tag_numbers)
      return `${k} · ${tag || '—'}`
    })
    .join('\n')
}

/** Multiline text for Tag numbers column (one line per key: `KEY · tag`). */
export function platSecuritySyncTagColumnText(r: CveRow): string {
  const m = r.plat_security_field_sync
  if (m && Object.keys(m).length > 0) {
    return [...Object.keys(m)]
      .sort()
      .map((k) => `${k} · ${m[k].tag_numbers}`)
      .join('\n')
  }
  return (r.plat_tag_numbers ?? '').trim()
}

/** Lowercase search fragment for per-key PLAT sync fields. */
export function platSecuritySyncSearchBlob(r: CveRow): string {
  const a = platSecuritySyncFixColumnText(r)
  const b = platSecuritySyncTagColumnText(r)
  return [a, b].filter(Boolean).join('\n')
}

export function imagePathBasename(imagePath: string): string {
  return imagePath.replace(/^plainid\//i, '').split('/').pop()?.trim() ?? ''
}

/**
 * Aqua ECR transactional tags use `{version}_{Service}_{DDMonYYYY}`.
 * UI shows the release version only; the full tag is kept in row data for Aqua lookups.
 */
const AQUA_TRANSACTIONAL_TAG_RE = /^([\d.]+)_.+_\d{2}[A-Za-z]{3}\d{4}$/

export function imageTagForDisplay(tag: string | null | undefined): string {
  const t = (tag ?? '').trim()
  if (!t) return ''
  const m = AQUA_TRANSACTIONAL_TAG_RE.exec(t)
  return m ? m[1] : t
}

/** `basename:displayTag` or basename alone. */
export function imageBasenameTagLabel(basename: string, tag: string | null | undefined): string {
  const bn = basename.trim()
  if (!bn) return ''
  const dt = imageTagForDisplay(tag)
  return dt ? `${bn}:${dt}` : bn
}

/** Distinct image basenames for this CVE row (from affected_images or legacy single). */
export function imageBasenamesForCveRow(r: CveRow): string[] {
  const imgs = (r.affected_images ?? []).filter((i) => i.image && i.image !== 'NA')
  const names = imgs.length
    ? imgs.map((i) => imagePathBasename(i.image))
    : r.affected_image && r.affected_image !== 'NA'
      ? [imagePathBasename(r.affected_image)]
      : []
  const seen = new Set<string>()
  const out: string[] = []
  for (const n of names) {
    if (!n) continue
    const k = n.toLowerCase()
    if (seen.has(k)) continue
    seen.add(k)
    out.push(n)
  }
  return out
}

/** Label for PLAT rows: `basename:tag` when tag exists, else basename (or `:affected_version` as fallback). */
export function platDisplayLabelForImage(r: CveRow, imageBasename: string): string {
  const fold = imageBasename.toLowerCase()
  const imgs = (r.affected_images ?? []).filter((i) => i.image && i.image !== 'NA')
  for (const i of imgs) {
    if (imagePathBasename(i.image).toLowerCase() === fold) {
      return imageBasenameTagLabel(imageBasename, i.tag)
    }
  }
  if (r.affected_image && r.affected_image !== 'NA' && imagePathBasename(r.affected_image).toLowerCase() === fold) {
    return imageBasenameTagLabel(imageBasename, r.affected_tag)
  }
  const v = (r.affected_version ?? '').trim()
  return v ? `${imageBasename}:${v}` : imageBasename
}

/** Short `image:tag` line for compact PLAT panel (basename:tag per image). */
export function platDisplaySketchSummary(r: CveRow): string {
  const basenames = imageBasenamesForCveRow(r)
  if (basenames.length > 0) {
    return basenames.map((b) => platDisplayLabelForImage(r, b)).join('; ')
  }
  if (r.affected_image && r.affected_image !== 'NA') {
    const bn = imagePathBasename(r.affected_image)
    if (bn) return platDisplayLabelForImage(r, bn)
    const tail = r.affected_image.replace(/^plainid\//i, '').trim()
    const dt = imageTagForDisplay(r.affected_tag)
    return dt ? `${tail}:${dt}` : tail
  }
  return ''
}

/** Full image ref for PLAT row label: repo path (no `plainid/` prefix) + optional `:tag` — same shape as former “Affected Image : Tag” column. */
export function platDisplayFullImageForRow(r: CveRow, imageBasename: string): string {
  const path = imagePathForBasename(r, imageBasename)
  if (!path) {
    return platDisplayLabelForImage(r, imageBasename)
  }
  const normalized = path.replace(/^plainid\//i, '').trim()
  const fold = imageBasename.toLowerCase()
  const imgs = (r.affected_images ?? []).filter((i) => i.image && i.image !== 'NA')
  for (const i of imgs) {
    if (imagePathBasename(i.image).toLowerCase() === fold) {
      const dt = imageTagForDisplay(i.tag)
      return dt ? `${normalized}:${dt}` : normalized
    }
  }
  if (r.affected_image && r.affected_image !== 'NA' && imagePathBasename(r.affected_image).toLowerCase() === fold) {
    const dt = imageTagForDisplay(r.affected_tag)
    return dt ? `${normalized}:${dt}` : normalized
  }
  const v = (r.affected_version ?? '').trim()
  return v ? `${normalized}:${v}` : normalized
}

/** All affected images as `path:tag` (same rules as the old table column), joined for fallback rows. */
export function platDisplayFullImagesSummary(r: CveRow): string {
  const imgs = (r.affected_images ?? []).filter((i) => i.image && i.image !== 'NA')
  if (imgs.length > 0) {
    return imgs
      .map((i) => {
        const path = i.image.replace(/^plainid\//i, '').trim()
        const dt = imageTagForDisplay(i.tag)
        return dt ? `${path}:${dt}` : path
      })
      .filter(Boolean)
      .join('; ')
  }
  if (r.affected_image && r.affected_image !== 'NA') {
    const path = r.affected_image.replace(/^plainid\//i, '').trim()
    const dt = imageTagForDisplay(r.affected_tag)
    return dt ? `${path}:${dt}` : path
  }
  return ''
}

/** Tokens derived from an image basename (aligned with worker `_img_tokens`); only len > 2. */
export function imageTokensForBasename(basename: string): string[] {
  const name = basename.trim().toLowerCase()
  if (!name) return []
  const parts = name.split(/[-_]/g)
  return _uniqueImageTokens([name, ...parts])
}

/** Full image path for a basename on this row (first match). */
export function imagePathForBasename(r: CveRow, imageBasename: string): string | null {
  const fold = imageBasename.toLowerCase()
  const imgs = (r.affected_images ?? []).filter((i) => i.image && i.image !== 'NA')
  for (const i of imgs) {
    if (imagePathBasename(i.image).toLowerCase() === fold) return i.image
  }
  if (r.affected_image && r.affected_image !== 'NA' && imagePathBasename(r.affected_image).toLowerCase() === fold) {
    return r.affected_image
  }
  return null
}

/**
 * Tokens from a registry image path (aligned with worker `_img_tokens`: strip plainid/, lower,
 * whole path plus [-_] parts, optional tag stem, and `/` path segments e.g. rclone/rclone → rclone).
 */
export function imageTokensForImagePath(imagePath: string): string[] {
  const name = imagePath.replace(/^plainid\//i, '').trim().toLowerCase()
  if (!name) return []
  const parts = name.split(/[-_]/g)
  const raw: string[] = [name, ...parts]
  const stem = name.includes(':') ? name.split(':', 1)[0].trim() : name
  if (stem && !raw.includes(stem)) raw.push(stem)
  for (const seg of stem.split('/')) {
    const s = seg.trim()
    if (s && !raw.includes(s)) raw.push(s)
  }
  return _uniqueImageTokens(raw)
}

function _uniqueImageTokens(raw: string[]): string[] {
  const seen = new Set<string>()
  const out: string[] = []
  for (const t of raw) {
    const s = t.trim()
    if (s.length <= 2) continue
    if (seen.has(s)) continue
    seen.add(s)
    out.push(s)
  }
  return out
}

/** Sec-Vuln keys not assigned to any image in `plat_security_for_images` (multi-image rows). */
export function platOrphanSecKeys(r: CveRow): string[] {
  const allSec = platSecurityKeys(r)
  if (!allSec.length) return []
  const imgs = imageBasenamesForCveRow(r)
  const m = r.plat_security_for_images
  if (!m || Object.keys(m).length === 0) {
    if (imgs.length > 1) return [...allSec]
    return []
  }
  const mapped = new Set<string>()
  for (const keys of Object.values(m)) {
    for (const k of keys) mapped.add(k)
  }
  return allSec.filter((k) => !mapped.has(k))
}

/** Sec-Vuln PLAT keys already linked to this image for the CVE row. */
export function platSecKeysForImage(r: CveRow, imageBasename: string): string[] {
  const m = r.plat_security_for_images
  if (m && Object.keys(m).length) {
    if (m[imageBasename]?.length) return m[imageBasename]
    const fold = imageBasename.toLowerCase()
    for (const [k, v] of Object.entries(m)) {
      if (k.toLowerCase() === fold && v.length) return v
    }
  }
  const imgs = imageBasenamesForCveRow(r)
  if (imgs.length === 1 && imgs[0].toLowerCase() === imageBasename.toLowerCase()) {
    const all = platSecurityKeys(r)
    if (all.length === 1) return all
  }
  return []
}

export function imageBasenameForPlat(r: CveRow): string | null {
  const all = imageBasenamesForCveRow(r)
  return all[0] ?? null
}

/** Apply a PLAT Security create (new or already-existing) onto the CVE table row list. */
export function mergePlatCreateIntoRows(
  rows: CveRow[],
  cveId: string,
  imageBasename: string,
  out: CreatePlatResponse,
): CveRow[] {
  return rows.map((r) => {
    if (r.cve_id !== cveId) return r
    const mergeKeys = out.exists ? out.keys : [out.key]
    const m = { ...(r.plat_security_for_images ?? {}) }
    const cur = new Set(m[imageBasename] ?? [])
    for (const k of mergeKeys) cur.add(k)
    m[imageBasename] = [...cur]

    const byKey = new Map((r.plat_tickets ?? []).map((t) => [t.key, t]))
    for (const k of mergeKeys) {
      if (!byKey.has(k)) byKey.set(k, { key: k, issue_type: 'Security Vulnerability' })
    }
    const allSec = new Set([...(r.plat_security_keys ?? []), ...mergeKeys])
    return {
      ...r,
      plat_security_for_images: m,
      plat_security_keys: [...allSec],
      plat_tickets: [...byKey.values()],
    }
  })
}

export async function apiEnqueuePlatSync(runId: string): Promise<{ task_id: string }> {
  return apiPost<{ task_id: string }>(`/api/jobs/${encodeURIComponent(runId)}/sync-plat`, {})
}

export async function apiCancelRun(runId: string): Promise<void> {
  const res = await fetch(`/api/jobs/${encodeURIComponent(runId)}/cancel`, { method: 'POST' })
  if (!res.ok) throw new Error(await res.text())
}

export type IssueSyncScheduleResponse = {
  issue_key: string
  daily_sync_enabled: boolean
  last_auto_sync_at?: string | null
}

export async function apiPatchIssueSyncSchedule(
  issueKey: string,
  body: { daily_sync_enabled: boolean },
): Promise<IssueSyncScheduleResponse> {
  const res = await fetch(`/api/issues/${encodeURIComponent(issueKey)}/sync-schedule`, {
    method: 'PATCH',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body),
  })
  if (!res.ok) throw new Error(await res.text())
  return (await res.json()) as IssueSyncScheduleResponse
}

export type CveRowPatchResponse = {
  ok: boolean
  aqua_pkg_found?: boolean | null
  aqua_package_name?: string | null
  aqua_candidates?: AquaPackageCandidate[]
  affected_resource?: string | null
  /** Updated per-image entry for the patched image_basename. */
  package_by_image_entry?: PackageByImageEntry | null
  /** Full updated package_by_image map. */
  package_by_image?: Record<string, PackageByImageEntry>
}

export async function apiPatchCveRow(
  runId: string,
  cveId: string,
  patch: {
    affected_version?: string | null
    affected_resource?: string | null
    image_basename?: string | null
    force_refresh_aqua?: boolean
  },
): Promise<CveRowPatchResponse> {
  const res = await fetch(`/api/jobs/${encodeURIComponent(runId)}/cve-row`, {
    method: 'PATCH',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ cve_id: cveId, ...patch }),
  })
  if (!res.ok) throw new Error(await res.text())
  return (await res.json()) as CveRowPatchResponse
}

export type PlatMissingCveSlot = { cve_id: string; image_basename: string }

/** Row/image pairs that show “Create CVE” (image in Allowed Images catalog, no Sec-Vuln PLAT yet). */
export function platMissingCveCreateSlots(rows: CveRow[], allowedImageNames?: Set<string>): PlatMissingCveSlot[] {
  const out: PlatMissingCveSlot[] = []
  for (const r of rows) {
    for (const imageBasename of imageBasenamesForCveRow(r)) {
      if (platSecKeysForImage(r, imageBasename).length === 0) {
        if (!allowedImageNames || allowedImageNames.size === 0 || isAllowedImageBasename(imageBasename, allowedImageNames)) {
          out.push({ cve_id: r.cve_id, image_basename: imageBasename })
        }
      }
    }
  }
  return out
}

/** Empty Jira sync placeholder and other non-values → blank for display. */
export function normalizePlatSyncFieldValue(raw: string | null | undefined): string {
  const s = (raw ?? '').trim()
  if (!s || s.toLowerCase() === 'none') return ''
  return s
}

/**
 * Parse any version week codes (e.g. `5.2627.x`, `5.2622.2`) from a PLAT fix/tag string and
 * translate each to the calendar Monday that starts that ISO week (e.g. `June 29, 2026`).
 * Returns null if no parseable week code is found.
 */
export function translateFixVersionToReleaseDate(fixVersion: string): string | null {
  if (!fixVersion) return null
  const regex = /\b\d\.(\d{2})(\d{2})\.[xX\d]+\b/gi
  const months = [
    'January', 'February', 'March', 'April', 'May', 'June',
    'July', 'August', 'September', 'October', 'November', 'December',
  ]
  let match
  const dates: string[] = []
  const seenDates = new Set<string>()
  while ((match = regex.exec(fixVersion)) !== null) {
    const yy = parseInt(match[1], 10)
    const ww = parseInt(match[2], 10)
    if (isNaN(yy) || isNaN(ww) || ww < 1 || ww > 53) continue
    const year = 2000 + yy
    // ISO Week 1 is the week containing Jan 4; find its Monday.
    const jan4 = new Date(year, 0, 4)
    const dow = jan4.getDay() === 0 ? 7 : jan4.getDay()
    const week1Monday = new Date(year, 0, 4 - dow + 1)
    const monday = new Date(week1Monday.getTime() + (ww - 1) * 7 * 86400000)
    const formatted = `${months[monday.getMonth()]} ${monday.getDate()}, ${monday.getFullYear()}`
    if (!seenDates.has(formatted)) {
      seenDates.add(formatted)
      dates.push(formatted)
    }
  }
  return dates.length > 0 ? dates.join(' and ') : null
}

/**
 * Resolve PLAT fix column / comment text: prefer week code in fixVersions name, else tag number.
 * Returns translated date when possible; otherwise the raw fix name.
 */
export function resolvePlatFixReleaseDateDisplay(
  fixRaw: string,
  tagRaw = '',
): { display: string; title?: string } {
  const fix = normalizePlatSyncFieldValue(fixRaw)
  const tag = normalizePlatSyncFieldValue(tagRaw)
  const fromFix = fix ? translateFixVersionToReleaseDate(fix) : null
  if (fromFix) {
    return { display: fromFix, title: fix }
  }
  const fromTag = tag ? translateFixVersionToReleaseDate(tag) : null
  if (fromTag) {
    const titleParts = [fix, tag ? `Tag: ${tag}` : ''].filter(Boolean)
    return { display: fromTag, title: titleParts.join('\n') || undefined }
  }
  if (fix) return { display: fix }
  return { display: '' }
}

export const CUSTOMER_STATUS_COMMENT_MARKER = '<!-- CVE-Portal-Customer-Status v1 -->'

export const CUSTOMER_STATUS_IN_PROGRESS = 'In progress'

export const CUSTOMER_STATUS_NOTE =
  'Note: The "Expected Release Date" is an estimate and may be subject to change.'

/** Bullet lines under "Status definitions:" in the Jira customer status comment. */
export const CUSTOMER_STATUS_DEFINITIONS = [
  'In progress: CVE is under evaluation or no vendor fix is available yet',
  'Pending Vendor Fix: Awaiting an upstream vendor patch; no PlainID fix date available yet',
  'Package not found: Package not present in this image when PLAT CVE is Invalid (Expected release date column)',
  'N/A: PLAT CVE marked Invalid',
] as const

function formatCustomerStatusReportDate(d: Date = new Date()): string {
  return d.toLocaleDateString('en-US', { year: 'numeric', month: 'long', day: 'numeric' })
}

/** Title, note, and status definitions included before the CVE table in the comment. */
export function formatCustomerStatusCommentIntro(reportDate: Date = new Date()): string[] {
  return [
    `CVE Status Report - ${formatCustomerStatusReportDate(reportDate)}`,
    '',
    CUSTOMER_STATUS_NOTE,
    '',
    'Status definitions:',
    ...CUSTOMER_STATUS_DEFINITIONS.map((line) => `- ${line}`),
    '',
  ]
}

function isPlatSyncUnavailableValue(raw: string): boolean {
  const s = (raw ?? '').trim()
  if (!s || s === '—') return true
  if (s.startsWith('— (sync PLAT')) return true
  return false
}

/** PlainID release date — same translation as findings PLAT fix version column. */
export function plainIdExpectedReleaseDate(fix: string, tag: string): string {
  const fixIn = isPlatSyncUnavailableValue(fix) ? '' : fix
  const tagIn = isPlatSyncUnavailableValue(tag) ? '' : tag
  const { display } = resolvePlatFixReleaseDateDisplay(fixIn, tagIn)
  return display || CUSTOMER_STATUS_IN_PROGRESS
}

/** PlainID release version — same as findings Tag numbers column (raw tag, not translated). */
export function plainIdReleaseVersion(tag: string): string {
  if (isPlatSyncUnavailableValue(tag)) return CUSTOMER_STATUS_IN_PROGRESS
  const v = normalizePlatSyncFieldValue(tag)
  return v || CUSTOMER_STATUS_IN_PROGRESS
}

/** Raw PLAT sync fields for customer table (no pending-hint placeholders). */
function commentPlatRawForKeys(r: CveRow, secKeys: string[]): { fix: string; tag: string } {
  let fix = platSecuritySyncFixForKeys(r, secKeys).trim()
  let tag = platSecuritySyncTagForKeys(r, secKeys).trim()
  const hasMap = !!(r.plat_security_field_sync && Object.keys(r.plat_security_field_sync).length > 0)
  if (!hasMap && secKeys.length === 0) {
    const lf = normalizePlatSyncFieldValue(r.plat_app_fix_versions)
    const lt = normalizePlatSyncFieldValue(r.plat_tag_numbers)
    if (!fix && lf) fix = lf
    if (!tag && lt) tag = lt
  }
  return { fix, tag }
}

export type UpsertCustomerStatusCommentResponse = {
  ok: boolean
  action: 'created' | 'updated'
  comment_id: string
}

export async function apiUpsertCustomerStatusComment(
  issueKey: string,
  body: string,
): Promise<UpsertCustomerStatusCommentResponse> {
  const res = await fetch(`/api/issues/${encodeURIComponent(issueKey)}/comment/status`, {
    method: 'PUT',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ body, internal: true }),
  })
  if (!res.ok) throw new Error(await res.text())
  return (await res.json()) as UpsertCustomerStatusCommentResponse
}

type CustomerStatusTableRow = {
  cve: string
  severity: string
  image: string
  packageName: string
  expectedRelease: string
  fixVersion: string
}

/** Package label for an image (findings table, comment, PLAT fix/tag N/A gate). */
export function packageDisplayForImage(r: CveRow, imageBasename: string): string {
  const entry = packageEntryForImage(r, imageBasename)
  const checked =
    entry?.aqua_checked === true ||
    entry?.aqua_checked === false ||
    r.aqua_pkg_found === true ||
    r.aqua_pkg_found === false

  if (checked) {
    const found =
      entry?.aqua_checked != null
        ? entry.aqua_pkg_found === true
        : r.aqua_pkg_found === true
    if (found) {
      return (
        canonicalSinglePackageName(
          entry?.aqua_package_name ||
            entry?.affected_resource ||
            r.affected_resource,
        ) || '—'
      )
    }
    return 'Package not found'
  }

  const name = canonicalSinglePackageName(entry?.affected_resource ?? r.affected_resource)
  return name || '—'
}

export function isPackageNotFoundForImage(r: CveRow, imageBasename: string): boolean {
  return packageDisplayForImage(r, imageBasename) === 'Package not found'
}

/** Package name for customer comment (NVD/Aqua name; never the "Package not found" label). */
export function packageNameForComment(r: CveRow, imageBasename: string): string {
  const entry = packageEntryForImage(r, imageBasename)
  const name = canonicalSinglePackageName(
    entry?.aqua_package_name ||
      entry?.affected_resource ||
      r.affected_resource,
  )
  return name || '—'
}

function formatCveSeverityForComment(r: CveRow): string {
  const sevRaw = (r.severity ?? '').trim()
  if (!sevRaw) return 'Unknown'
  const score = r.score != null && String(r.score).trim() !== '' ? ` (${String(r.score).trim()})` : ''
  return `${sevRaw.toUpperCase()}${score}`
}

function collectCustomerStatusRows(result: JobResult): CustomerStatusTableRow[] {
  const out: CustomerStatusTableRow[] = []
  const rows = sortCveRows(result.cve_rows ?? [])

  for (const r of rows) {
    const severity = formatCveSeverityForComment(r)
    const basenames = imageBasenamesForCveRow(r)

    const pushRow = (imageLabel: string, secKeys: string[], imageBasename?: string) => {
      const { fix, tag } = commentPlatRawForKeys(r, secKeys)
      const bn = imageBasename ?? ''
      const packageMissing = bn ? isPackageNotFoundForImage(r, bn) : false
      const packageName = bn ? packageNameForComment(r, bn) : '—'
      const platInvalid = platIssueStatusInvalidForKeys(r, secKeys)
      const platPendingVendorFix = platIssueStatusPendingVendorFixForKeys(r, secKeys)
      out.push({
        cve: r.cve_id,
        severity,
        image: imageLabel,
        packageName,
        expectedRelease: platInvalid
          ? packageMissing
            ? 'Package not found'
            : 'N/A'
          : platPendingVendorFix
            ? 'Pending Vendor Fix'
            : plainIdExpectedReleaseDate(fix, tag),
        fixVersion:
          platInvalid || platPendingVendorFix ? 'N/A' : plainIdReleaseVersion(tag),
      })
    }

    if (basenames.length > 0) {
      for (const bn of basenames) {
        pushRow(platDisplayLabelForImage(r, bn), platSecKeysForImage(r, bn), bn)
      }
      const orphan = platOrphanSecKeys(r)
      if (orphan.length) {
        pushRow('Unmapped Security PLAT', orphan)
      }
      continue
    }

    const imgs = (r.affected_images ?? []).filter((i) => i.image && i.image !== 'NA')
    if (!imgs.length && r.affected_image && r.affected_image !== 'NA') {
      const legacyBn = imageBasenamesForCveRow(r)[0]
      pushRow(
        legacyBn ? platDisplayLabelForImage(r, legacyBn) : platDisplayFullImagesSummary(r),
        platSecurityKeys(r),
        legacyBn,
      )
    } else if (imgs.length) {
      for (const img of imgs) {
        const bn = imagePathBasename(img.image)
        pushRow(
          bn ? platDisplayLabelForImage(r, bn) : platDisplayFullImagesSummary(r),
          platSecurityKeys(r),
          bn || undefined,
        )
      }
    } else {
      pushRow('—', platSecurityKeys(r))
    }
  }

  return out
}

// ─── Comment column visibility ────────────────────────────────────────────────

export type CustomerStatusCommentColumnKey =
  | 'cve'
  | 'severity'
  | 'image'
  | 'package'
  | 'expectedRelease'
  | 'fixVersion'

export type CustomerStatusCommentColumnVisibility = Record<CustomerStatusCommentColumnKey, boolean>

export const CUSTOMER_STATUS_COMMENT_COLUMN_LABELS: Record<CustomerStatusCommentColumnKey, string> = {
  cve: 'CVE',
  severity: 'Severity',
  image: 'Image',
  package: 'Package',
  expectedRelease: 'Expected release date',
  fixVersion: 'Fix Version',
}

export const CUSTOMER_STATUS_COMMENT_COLUMN_KEYS: CustomerStatusCommentColumnKey[] = [
  'cve',
  'severity',
  'image',
  'package',
  'expectedRelease',
  'fixVersion',
]

export const DEFAULT_CUSTOMER_STATUS_COMMENT_COLUMN_VISIBILITY: CustomerStatusCommentColumnVisibility = {
  cve: true,
  severity: true,
  image: true,
  package: true,
  expectedRelease: true,
  fixVersion: true,
}

/** Merge a partial visibility override with defaults; CVE is always forced on. */
export function resolveCustomerStatusCommentColumns(
  partial?: Partial<CustomerStatusCommentColumnVisibility>,
): CustomerStatusCommentColumnVisibility {
  const resolved = { ...DEFAULT_CUSTOMER_STATUS_COMMENT_COLUMN_VISIBILITY, ...partial, cve: true }
  return resolved
}

// ─── Comment table formatting ─────────────────────────────────────────────────

function padTableCell(value: string, width: number): string {
  return (value.trim() || '—').padEnd(width)
}

type ColSpec = {
  key: CustomerStatusCommentColumnKey
  header: string
  minW: number
  getValue: (row: CustomerStatusTableRow) => string
}

const COMMENT_COL_SPECS: ColSpec[] = [
  { key: 'cve',           header: 'CVE',                  minW: 12, getValue: (r) => r.cve },
  { key: 'severity',      header: 'Severity',             minW: 8,  getValue: (r) => r.severity },
  { key: 'image',         header: 'Image',                minW: 5,  getValue: (r) => r.image },
  { key: 'package',       header: 'Package',              minW: 7,  getValue: (r) => r.packageName },
  { key: 'expectedRelease', header: 'Expected release date', minW: 22, getValue: (r) => r.expectedRelease },
  { key: 'fixVersion',    header: 'Fix Version',          minW: 10, getValue: (r) => r.fixVersion },
]

function formatCustomerStatusTable(
  tableRows: CustomerStatusTableRow[],
  columns: CustomerStatusCommentColumnVisibility,
): string[] {
  const visibleSpecs = COMMENT_COL_SPECS.filter((s) => columns[s.key])
  if (visibleSpecs.length === 0) return []

  const widths = visibleSpecs.map((s) =>
    Math.max(s.minW, s.header.length, ...tableRows.map((r) => s.getValue(r).length)),
  )

  const header = visibleSpecs.map((s, i) => padTableCell(s.header, widths[i])).join(' | ')
  const rule = widths.map((w) => '-'.repeat(w)).join('-+-')
  const body = tableRows.map((row) =>
    visibleSpecs.map((s, i) => padTableCell(s.getValue(row), widths[i])).join(' | '),
  )
  return [header, rule, ...body]
}

export function buildCustomerStatusComment(
  result: JobResult,
  columns?: Partial<CustomerStatusCommentColumnVisibility>,
): string {
  const vis = resolveCustomerStatusCommentColumns(columns)
  const lines: string[] = [CUSTOMER_STATUS_COMMENT_MARKER, '']
  lines.push(...formatCustomerStatusCommentIntro())

  const tableRows = collectCustomerStatusRows(result)
  if (tableRows.length === 0) {
    lines.push('No CVE rows to display.')
  } else {
    lines.push(...formatCustomerStatusTable(tableRows, vis))
  }

  return lines.join('\n').trimEnd()
}

/** @deprecated Use buildCustomerStatusComment — kept for existing imports. */
export function buildSuggestedComment(result: JobResult): string {
  return buildCustomerStatusComment(result)
}

// ─── Excel export ─────────────────────────────────────────────────────────────

const CUSTOMER_STATUS_EXCEL_HEADERS = [
  'CVE',
  'Severity',
  'Image',
  'Expected release date',
  'Fix Version',
] as const

function customerStatusRowsFromCveRows(rows: CveRow[]): CustomerStatusTableRow[] {
  return collectCustomerStatusRows({
    issue_key: '',
    cve_rows: rows,
    cves: [],
    nvd: [],
    attachments: [],
    images: [],
  })
}

export function exportCvesToExcel(rows: CveRow[], filename = 'cve-findings.xlsx') {
  import('xlsx').then((XLSX) => {
    const tableRows = customerStatusRowsFromCveRows(rows)
    const data = tableRows.map((r) => ({
      CVE: r.cve,
      Severity: r.severity,
      Image: r.image,
      'Expected release date': r.expectedRelease,
      'Fix Version': r.fixVersion,
    }))

    const ws =
      data.length > 0
        ? XLSX.utils.json_to_sheet(data)
        : XLSX.utils.aoa_to_sheet([[...CUSTOMER_STATUS_EXCEL_HEADERS]])

    const colWidths = CUSTOMER_STATUS_EXCEL_HEADERS.map((key) => ({
      wch: Math.max(
        key.length,
        ...data.map((row) => String(row[key as keyof typeof row] ?? '').length),
      ) + 2,
    }))
    ws['!cols'] = colWidths

    const wb = XLSX.utils.book_new()
    XLSX.utils.book_append_sheet(wb, ws, 'Customer Status')
    XLSX.writeFile(wb, filename)
  })
}
