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
    // legacy (pre-accurate-stats) — may be present on old stored runs
    label_date_pushed?: number
    linked?: number
  } | null
  /** Cumulative link counters from process_issue. */
  _plat_link_counts?: { links_checked?: number; links_created?: number; errors: string[] } | null
}

export type JobResponse = {
  run_id: string
  issue_key: string
  status: string
  task_id?: string | null
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
  created_at?: string | null
  cve_count?: number | null
  needs_plat_cve_count?: number
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

export type CreatePlatResponse =
  | { exists: true; keys: string[]; link_warnings?: string[] }
  | { exists: false; key: string; summary?: string; link_warnings?: string[] }

export function formatStatus(status?: string | null): string {
  if (!status) return ''
  const map: Record<string, string> = {
    queued: 'Queued',
    fetching_issue: 'Fetching Jira issue',
    extracting_from_description: 'Extracting from description',
    downloading_attachments: 'Downloading attachments',
    parsing_attachments: 'Parsing attachments',
    enriching_nvd: 'Validating/enriching via NVD',
    looking_up_plat_tickets: 'Looking up PLAT tickets',
    building_results: 'Building results',
    done: 'Done',
    syncing_plat: 'Syncing PLAT with Jira',
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

export function statusSteps(status?: string | null) {
  const steps = [
    { id: 'fetching_issue', label: 'Fetch issue' },
    { id: 'extracting_from_description', label: 'Extract description' },
    { id: 'downloading_attachments', label: 'Download attachments' },
    { id: 'parsing_attachments', label: 'Parse attachments' },
    { id: 'enriching_nvd', label: 'NVD enrichment' },
    { id: 'looking_up_plat_tickets', label: 'Look up PLAT tickets' },
    { id: 'building_results', label: 'Build results' },
    { id: 'syncing_plat', label: 'Sync PLAT (Jira)' },
    { id: 'done', label: 'Done' },
  ]
  const norm = normalizeStatusForSteps(status)
  const idx = steps.findIndex((s) => s.id === norm)
  return steps.map((s, i) => ({
    ...s,
    state: status?.startsWith('failed')
      ? 'failed'
      : i < idx
        ? 'done'
        : i === idx
          ? 'current'
          : 'todo',
  }))
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

export type ComponentHealth = { status: 'ok' | 'error' | 'no_workers'; detail?: string; workers?: string[] }

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

export async function apiCreatePlatBug(body: {
  cve_id: string
  image_basename: string
  package_name: string
  package_version: string
  severity?: string | null
  organizations?: OrgRef[] | null
  source_issue_key?: string | null
  /** Label shown in UI / Jira description Image line (e.g. pip-operator:tag) */
  image_display?: string | null
  /** Resource column — component/package name */
  resource_label?: string | null
  vendor_fix_version?: string | null
  /** SLA due date YYYY-MM-DD; sent as Jira `duedate` on create */
  sla_due_date?: string | null
}): Promise<CreatePlatResponse> {
  const res = await fetch('/api/plat/bug', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body),
  })
  const text = await res.text()
  if (!res.ok) throw new Error(text || res.statusText)
  return JSON.parse(text) as CreatePlatResponse
}

/** Best-effort package / component name for PLAT “Package Name” field. */
export function platPackageNameForRow(r: CveRow): string {
  const res = (r.affected_resource ?? '').trim()
  if (res) return res
  const product = r.all_packages?.map((p) => (p.product ?? '').trim()).find(Boolean)
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
  if (upper.length === 1) return m[upper[0]]?.fix_versions ?? ''
  return upper.map((k) => `${k} · ${m[k]?.fix_versions ?? '—'}`).join('\n')
}

/** `tag_numbers` for these Security PLAT keys. */
export function platSecuritySyncTagForKeys(r: CveRow, keys: string[]): string {
  const upper = [...new Set(keys.map((k) => k.trim().toUpperCase()).filter(Boolean))].sort()
  if (!upper.length) return ''
  const m = r.plat_security_field_sync
  if (!m || !Object.keys(m).length) return ''
  if (upper.length === 1) return m[upper[0]]?.tag_numbers ?? ''
  return upper.map((k) => `${k} · ${m[k]?.tag_numbers ?? '—'}`).join('\n')
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
      const t = (i.tag ?? '').trim()
      return t ? `${imageBasename}:${t}` : imageBasename
    }
  }
  if (r.affected_image && r.affected_image !== 'NA' && imagePathBasename(r.affected_image).toLowerCase() === fold) {
    const t = (r.affected_tag ?? '').trim()
    return t ? `${imageBasename}:${t}` : imageBasename
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
    return r.affected_tag ? `${tail}:${String(r.affected_tag).trim()}` : tail
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
      const t = (i.tag ?? '').trim()
      return t ? `${normalized}:${t}` : normalized
    }
  }
  if (r.affected_image && r.affected_image !== 'NA' && imagePathBasename(r.affected_image).toLowerCase() === fold) {
    const t = (r.affected_tag ?? '').trim()
    return t ? `${normalized}:${t}` : normalized
  }
  const v = (r.affected_version ?? '').trim()
  return v ? `${normalized}:${v}` : normalized
}

/** All affected images as `path:tag` (same rules as the old table column), joined for fallback rows. */
export function platDisplayFullImagesSummary(r: CveRow): string {
  const imgs = (r.affected_images ?? []).filter((i) => i.image && i.image !== 'NA')
  if (imgs.length > 0) {
    return imgs
      .map((i) => `${i.image.replace(/^plainid\//i, '').trim()}${i.tag ? `:${i.tag.trim()}` : ''}`)
      .filter(Boolean)
      .join('; ')
  }
  if (r.affected_image && r.affected_image !== 'NA') {
    return `${r.affected_image.replace(/^plainid\//i, '').trim()}${r.affected_tag ? `:${String(r.affected_tag).trim()}` : ''}`
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

function escapeRegExp(s: string): string {
  return s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')
}

/** Match token as a whole segment (aligned with worker `_token_in_summary`). */
export function tokenInSummaryForPlatBug(token: string, summaryLower: string): boolean {
  if (token.length <= 2) return false
  const re = new RegExp(`(?<![a-zA-Z0-9\\-_])${escapeRegExp(token)}(?![a-zA-Z0-9\\-_])`, 'i')
  return re.test(summaryLower)
}

export function bugSummaryMatchesTokens(
  summary: string | null | undefined,
  tokens: string[],
): boolean {
  const summaryLower = (summary ?? '').toLowerCase()
  if (!tokens.length) return false
  return tokens.some((tok) => tokenInSummaryForPlatBug(tok, summaryLower))
}

export function bugSummaryMatchesImageBasename(
  summary: string | null | undefined,
  imageBasename: string,
): boolean {
  return bugSummaryMatchesTokens(summary, imageTokensForBasename(imageBasename))
}

/** Bug PLAT tickets whose summary matches this image (worker-style tokens on full path when known). */
export function platBugTicketsForImage(r: CveRow, imageBasename: string): PlatTicket[] {
  const path = imagePathForBasename(r, imageBasename)
  const tokens = path ? imageTokensForImagePath(path) : imageTokensForBasename(imageBasename)
  const bugs = (r.plat_tickets ?? []).filter((t) => t.issue_type === 'Bug')
  const matched = bugs.filter((t) => bugSummaryMatchesTokens(t.summary, tokens))
  matched.sort((a, b) => a.key.localeCompare(b.key))
  return matched
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

/** Apply a PLAT Bug create (new or already-existing) onto the CVE table row list. */
export function mergePlatBugCreateIntoRows(
  rows: CveRow[],
  cveId: string,
  imageBasename: string,
  out: CreatePlatResponse,
): CveRow[] {
  const fallbackSummary = `[${cveId}] - [${imageBasename}]`
  const summaryTemplate =
    !out.exists && out.summary != null && out.summary.trim() !== ''
      ? out.summary
      : fallbackSummary
  return rows.map((r) => {
    if (r.cve_id !== cveId) return r
    const mergeKeys = out.exists ? out.keys : [out.key]
    const byKey = new Map((r.plat_tickets ?? []).map((t) => [t.key, t]))
    for (const k of mergeKeys) {
      const prev = byKey.get(k)
      const summary =
        prev?.issue_type === 'Bug' && prev.summary?.trim()
          ? prev.summary
          : summaryTemplate
      byKey.set(k, { key: k, issue_type: 'Bug', summary })
    }
    return {
      ...r,
      plat_tickets: [...byKey.values()],
    }
  })
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

export type PlatMissingCveSlot = { cve_id: string; image_basename: string }

/** Row/image pairs that show “Create CVE” (version present, image known, no Sec-Vuln PLAT yet). */
export function platMissingCveCreateSlots(rows: CveRow[]): PlatMissingCveSlot[] {
  const out: PlatMissingCveSlot[] = []
  for (const r of rows) {
    const verOk = !!(r.affected_version && String(r.affected_version).trim())
    if (!verOk) continue
    for (const imageBasename of imageBasenamesForCveRow(r)) {
      if (platSecKeysForImage(r, imageBasename).length === 0) {
        out.push({ cve_id: r.cve_id, image_basename: imageBasename })
      }
    }
  }
  return out
}

export function platMissingBugCreateSlots(rows: CveRow[]): PlatMissingCveSlot[] {
  const out: PlatMissingCveSlot[] = []
  for (const r of rows) {
    const verOk = !!(r.affected_version && String(r.affected_version).trim())
    if (!verOk) continue
    for (const imageBasename of imageBasenamesForCveRow(r)) {
      if (platBugTicketsForImage(r, imageBasename).length === 0) {
        out.push({ cve_id: r.cve_id, image_basename: imageBasename })
      }
    }
  }
  return out
}

/** PLAT fix / tag text for suggested Jira comment (per-image Security keys or row rollup). */
function commentPlatMetaForKeys(r: CveRow, secKeys: string[]): { fix: string; tag: string } {
  const hasMap = !!(r.plat_security_field_sync && Object.keys(r.plat_security_field_sync).length > 0)
  let fix = platSecuritySyncFixForKeys(r, secKeys).trim()
  let tag = platSecuritySyncTagForKeys(r, secKeys).trim()
  if (!hasMap && secKeys.length === 0) {
    const lf = (r.plat_app_fix_versions ?? '').trim()
    const lt = (r.plat_tag_numbers ?? '').trim()
    if (!fix && lf) fix = lf
    if (!tag && lt) tag = lt
  }
  const pendingHint = '— (sync PLAT in CVE portal)'
  if (!fix) fix = secKeys.length > 0 && !hasMap ? pendingHint : '—'
  if (!tag) tag = secKeys.length > 0 && !hasMap ? pendingHint : '—'
  return { fix, tag }
}

function pushSuggestedPackageLines(lines: string[], r: CveRow): void {
  const pkgs = r.all_packages ?? []
  if (pkgs.length > 0) {
    for (const p of pkgs) {
      const product = (p.product ?? '').trim() || '—'
      const affected = (p.version_start ?? '').trim() || '—'
      const fv = (p.fixed_version ?? '').trim()
      lines.push(
        fv
          ? `Package:  ${product} affected: ${affected} → fix: ${fv}`
          : `Package:  ${product} affected: ${affected}`,
      )
    }
    return
  }
  const res = (r.affected_resource ?? '').trim()
  if (res) {
    const av = (r.affected_version ?? '').trim() || '—'
    const fv = (r.fixed_version ?? '').trim()
    lines.push(
      fv ? `Package:  ${res} affected: ${av} → fix: ${fv}` : `Package:  ${res} affected: ${av}`,
    )
  }
}

export function buildSuggestedComment(result: JobResult): string {
  const lines: string[] = []
  const key = (result.issue_key ?? '').trim()
  if (key) {
    lines.push(`${key} — CVE review (auto-generated draft)`)
    lines.push('—'.repeat(56))
    lines.push('')
  }

  const rows = sortCveRows(result.cve_rows ?? [])
  for (const r of rows) {
    const sevRaw = (r.severity ?? '').trim()
    const sev = sevRaw
      ? `${sevRaw.toUpperCase()}${r.score != null && String(r.score).trim() !== '' ? ` (${String(r.score).trim()})` : ''}`
      : 'Unknown'
    lines.push(`${r.cve_id}  [${sev}]`)
    pushSuggestedPackageLines(lines, r)

    const basenames = imageBasenamesForCveRow(r)
    for (const bn of basenames) {
      const label = platDisplayLabelForImage(r, bn)
      const keys = platSecKeysForImage(r, bn)
      const { fix, tag } = commentPlatMetaForKeys(r, keys)
      lines.push(
        `  Image:    ${label} -> Expected fix release date: ${fix}. Release tag: ${tag}`,
      )
    }

    const orphan = platOrphanSecKeys(r)
    if (orphan.length) {
      const { fix, tag } = commentPlatMetaForKeys(r, orphan)
      lines.push(
        `  Image:    Unmapped Security PLAT -> Expected fix release date: ${fix}. Release tag: ${tag}`,
      )
    }

    if (!basenames.length) {
      const imgs = (r.affected_images ?? []).filter((i) => i.image && i.image !== 'NA')
      const legacyPath =
        !imgs.length && r.affected_image && r.affected_image !== 'NA'
          ? `${r.affected_image.replace(/^plainid\//i, '')}${r.affected_tag ? `:${String(r.affected_tag).trim()}` : ''}`
          : ''
      if (legacyPath) {
        const keys = platSecurityKeys(r)
        const { fix, tag } = commentPlatMetaForKeys(r, keys)
        lines.push(
          `  Image:    ${legacyPath} -> Expected fix release date: ${fix}. Release tag: ${tag}`,
        )
      }
    }

    lines.push('')
  }

  const attachments: any[] = result?.attachments ?? []
  if (attachments.length) {
    lines.push('Attachments parsed:')
    for (const a of attachments) lines.push(`  • ${a.filename} (${a.status})`)
    lines.push('')
  }

  return lines.join('\n').trimEnd()
}

// ─── Excel export ─────────────────────────────────────────────────────────────

export function exportCvesToExcel(rows: CveRow[], filename = 'cve-findings.xlsx') {
  import('xlsx').then((XLSX) => {
    const data = rows.map((r) => {
      const secByImage = r.plat_security_for_images && Object.keys(r.plat_security_for_images).length
        ? Object.entries(r.plat_security_for_images)
            .map(([img, keys]) => `${img}: ${keys.join(', ')}`)
            .join('\n')
        : platSecurityKeys(r).join(', ') || '—'

      const tickets = (r.plat_tickets ?? (r.plat_ticket ? [{ key: r.plat_ticket, issue_type: 'Security Vulnerability' }] : []))
        .map(t => `${t.key} (${t.issue_type})`)
        .join(', ')

      const imgs = (r.affected_images ?? []).filter(i => i.image && i.image !== 'NA')
      const imgList = imgs.length > 0
        ? imgs.map(i => `${i.image.replace(/^plainid\//i, '')}${i.tag ? `:${i.tag}` : ''}`).join('\n')
        : (r.affected_image && r.affected_image !== 'NA'
            ? `${r.affected_image}${r.affected_tag ? `:${r.affected_tag}` : ''}`
            : '')

      return {
        'CVE ID':          r.cve_id,
        'PLAT Sec / image': secByImage,
        'PLAT (all)':      tickets || '—',
        'Severity':        r.severity ?? '—',
        'CVSS Score':      r.score ?? '—',
        'Affected Image':  imgList || '—',
        'Resource':        r.affected_resource ?? '—',
        'Affected Ver.':   r.affected_version ?? '—',
        'Vendor Fix':      r.fixed_version ?? '—',
        'Due Date':        r.sla_due_date ?? '—',
        'PLAT fix version': platSecuritySyncFixColumnText(r) || '—',
        'Tag numbers':      platSecuritySyncTagColumnText(r) || '—',
        'NVD URL':         `https://nvd.nist.gov/vuln/detail/${r.cve_id}`,
      }
    })

    const ws = XLSX.utils.json_to_sheet(data)
    // Auto-width columns
    const colWidths = Object.keys(data[0] ?? {}).map((key) => ({
      wch: Math.max(key.length, ...data.map(row => String((row as Record<string,string>)[key] ?? '').split('\n')[0].length)) + 2,
    }))
    ws['!cols'] = colWidths

    const wb = XLSX.utils.book_new()
    XLSX.utils.book_append_sheet(wb, ws, 'CVE Findings')
    XLSX.writeFile(wb, filename)
  })
}
