export type JiraAttachment = {
  id: string
  filename: string
  mimeType?: string | null
  size?: number | null
  content?: string | null
}

export type IssueResponse = {
  key: string
  summary?: string | null
  issuetype?: string | null
  project?: string | null
  reporter?: string | null
  organizations?: string[] | null
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

export type CveRow = {
  cve_id: string
  severity?: string | null
  score?: string | null
  nvd_state?: string
  affected_image?: string | null
  affected_tag?: string | null
  affected_resource?: string | null
  affected_version?: string | null
  fixed_version?: string | null
  all_packages?: AffectedPackage[]
  confidence?: 'high' | 'medium' | 'low' | string | null
  plat_ticket?: string | null
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
    done: 'Done',
  }
  if (status.startsWith('failed')) return `Failed`
  return map[status] ?? status
}

export function statusSteps(status?: string | null) {
  const steps = [
    { id: 'fetching_issue', label: 'Fetch issue' },
    { id: 'extracting_from_description', label: 'Extract description' },
    { id: 'downloading_attachments', label: 'Download attachments' },
    { id: 'parsing_attachments', label: 'Parse attachments' },
    { id: 'enriching_nvd', label: 'NVD enrichment' },
    { id: 'looking_up_plat_tickets', label: 'Look up PLAT tickets' },
    { id: 'done', label: 'Done' },
  ]
  const idx = steps.findIndex((s) => s.id === status)
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

const SEV_ORDER: Record<string, number> = { CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3 }

export function sortCveRows(rows: CveRow[]): CveRow[] {
  return [...rows].sort((a, b) => {
    const sa = SEV_ORDER[a.severity?.toUpperCase() ?? ''] ?? 99
    const sb = SEV_ORDER[b.severity?.toUpperCase() ?? ''] ?? 99
    if (sa !== sb) return sa - sb
    return a.cve_id.localeCompare(b.cve_id)
  })
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
    lines.push(`▸ ${r.cve_id}  [${sev}]`)
    if (r.affected_image && r.affected_image !== 'NA') lines.push(`  Image:    ${r.affected_image}${r.affected_tag ? `:${r.affected_tag}` : ''}`)
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
