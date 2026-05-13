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
}

export type JobResult = {
  issue_key: string
  cves: string[]
  cve_rows: CveRow[]
  nvd: any[]
  attachments: any[]
  images: any[]
}

export type JobResponse = {
  run_id: string
  issue_key: string
  status: string
  task_id?: string | null
  result?: JobResult | null
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
  | { exists: true; keys: string[] }
  | { exists: false; key: string; summary?: string }

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
 * whole path plus segments split on - and _).
 */
export function imageTokensForImagePath(imagePath: string): string[] {
  const name = imagePath.replace(/^plainid\//i, '').trim().toLowerCase()
  if (!name) return []
  const parts = name.split(/[-_]/g)
  return _uniqueImageTokens([name, ...parts])
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

/** Apply a PLAT create (new or already-existing) response onto the CVE table row list. */
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

export function buildSuggestedComment(result: JobResult): string {
  const lines: string[] = [
    'CVE Enrichment Summary (auto-generated)',
    '='.repeat(44),
    '',
  ]

  const rows = sortCveRows(result.cve_rows ?? [])
  for (const r of rows) {
    const sev = r.severity ? `${r.severity}${r.score ? ` (${r.score})` : ''}` : 'Unknown'
    const platList = (r.plat_tickets ?? (r.plat_ticket ? [{ key: r.plat_ticket, issue_type: 'Security Vulnerability' }] : []))
    const platStr = platList.length ? `  [${platList.map(t => `${t.key} (${t.issue_type})`).join(', ')}]` : ''
    lines.push(`▸ ${r.cve_id}  [${sev}]${platStr}`)
    const imgs = (r.affected_images ?? []).filter(i => i.image && i.image !== 'NA')
    if (imgs.length) {
      for (const i of imgs) lines.push(`  Image:    ${i.image.replace(/^plainid\//i, '')}${i.tag ? `:${i.tag}` : ''}`)
    } else if (r.affected_image && r.affected_image !== 'NA') {
      lines.push(`  Image:    ${r.affected_image}${r.affected_tag ? `:${r.affected_tag}` : ''}`)
    }
    // List all affected packages from NVD
    const pkgs = r.all_packages ?? []
    if (pkgs.length) {
      for (const p of pkgs) {
        const fix = p.fixed_version ? ` → fix: ${p.fixed_version}` : ''
        lines.push(`  Package:  ${p.product}${fix}`)
      }
    } else if (r.affected_resource) {
      lines.push(`  Resource: ${r.affected_resource}${r.affected_version ? ` >= ${r.affected_version}` : ''}`)
      if (r.fixed_version) lines.push(`  Fix:      ${r.fixed_version}`)
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
