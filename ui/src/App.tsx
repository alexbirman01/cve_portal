import { useEffect, useMemo, useRef, useState } from 'react'
import './App.css'
import {
  apiCreatePlat,
  apiGet,
  apiPost,
  buildSuggestedComment,
  exportCvesToExcel,
  formatStatus,
  imageBasenamesForCveRow,
  mergePlatCreateIntoRows,
  platBugTicketsForImage,
  platMissingCveCreateSlots,
  platOrphanSecKeys,
  platSecKeysForImage,
  platDisplayFullImageForRow,
  platDisplayFullImagesSummary,
  platDisplayLabelForImage,
  platDisplaySketchSummary,
  platOrgRefsFromIssue,
  platPackageNameForRow,
  platSecurityKeys,
  sortCveRows,
  statusSteps,
  dashboardCveStateLabel,
  dashboardTicketStatusLabel,
  ticketStatusForSummary,
  type CreatePlatResponse,
  type CveRow,
  type DashboardTicketStatus,
  type IssueCveStatusSummary,
  type IssueResponse,
  type JobResponse,
  type OrgRef,
  type ProcessResponse,
} from './api'

// ─── helpers ────────────────────────────────────────────────────────────────

function SevBadge({ sev, score }: { sev?: string | null; score?: string | null }) {
  const s = sev?.toUpperCase()
  const cls =
    s === 'CRITICAL' ? 'sevCritical' :
    s === 'HIGH'     ? 'sevHigh'     :
    s === 'MEDIUM'   ? 'sevMedium'   :
    s === 'LOW'      ? 'sevLow'      : 'sevUnknown'
  return (
    <span className={`sevBadge ${cls}`}>
      {sev ?? 'Unknown'}{score ? ` ${score}` : ''}
    </span>
  )
}


function StepList({ status }: { status?: string | null }) {
  const steps = statusSteps(status)
  return (
    <div className="steps">
      {steps.map((s) => (
        <div
          key={s.id}
          className={`step ${s.state === 'done' ? 'stepDone' : s.state === 'current' ? 'stepCurrent' : s.state === 'failed' ? 'stepFailed' : ''}`}
        >
          <span className="stepDot" />
          {s.label}
        </div>
      ))}
    </div>
  )
}

function StatusBadge({ status }: { status?: string | null }) {
  if (!status) return null
  const isDone    = status === 'done'
  const isFailed  = status.startsWith('failed')
  const isRunning = !isDone && !isFailed && status !== 'queued'
  const cls = isDone ? 'statusDone' : isFailed ? 'statusFailed' : isRunning ? 'statusRunning' : 'statusQueued'
  return <span className={`statusBadge ${cls}`}>{formatStatus(status)}</span>
}

function Dash() {
  return <span className="dash">—</span>
}

/** Lowercase blob for CVE row text search */
function cveRowSearchText(r: CveRow): string {
  const tickets = [
    ...(r.plat_tickets ?? []),
    ...(r.plat_ticket ? [{ key: r.plat_ticket, issue_type: '' as const }] : []),
  ]
  const keys = tickets.map((t) => t.key).join(' ')
  return [
    r.cve_id,
    r.affected_resource,
    r.affected_version,
    r.fixed_version,
    platDisplaySketchSummary(r),
    platDisplayFullImagesSummary(r),
    keys,
  ]
    .filter(Boolean)
    .join(' ')
    .toLowerCase()
}

function rowMatchesCveFilters(
  r: CveRow,
  q: string,
  sev: string,
  res: string,
): boolean {
  const needle = q.trim().toLowerCase()
  if (needle && !cveRowSearchText(r).includes(needle)) return false
  if (sev && (r.severity ?? '').toUpperCase() !== sev.toUpperCase()) return false
  if (res && (r.affected_resource ?? '') !== res) return false
  return true
}

function severitySortKey(s: string): number {
  const u = s.toUpperCase()
  const order = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'UNKNOWN']
  const i = order.indexOf(u)
  return i >= 0 ? i : 99
}

/** Worst (highest) severity among findings for ticket-level summary chip */
function aggregateSeverityLabel(rows: CveRow[]): string {
  if (!rows.length) return ''
  const order = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']
  let bestIdx = -1
  for (const r of rows) {
    const u = (r.severity ?? '').toUpperCase().trim()
    const i = order.indexOf(u)
    if (i >= 0) bestIdx = bestIdx === -1 ? i : Math.min(bestIdx, i)
  }
  return bestIdx < 0 ? '' : order[bestIdx]
}

function severityMetaChipClass(label: string): string {
  const u = label.toUpperCase()
  if (u === 'CRITICAL') return 'attrChipMetaBox attrChipSevCritical'
  if (u === 'HIGH') return 'attrChipMetaBox attrChipSevHigh'
  if (u === 'MEDIUM') return 'attrChipMetaBox attrChipSevMedium'
  if (u === 'LOW') return 'attrChipMetaBox attrChipSevLow'
  return 'attrChipMetaBox attrChipSevUnknown'
}

function formatSeverityTitleCase(label: string): string {
  if (!label) return '—'
  return label.charAt(0) + label.slice(1).toLowerCase()
}

// ─── CVE table ───────────────────────────────────────────────────────────────

function CveTable({
  rows,
  issueKey,
  platOrganizationRefs,
  onPlatCreated,
  hideBuiltInToolbar,
  sourceRowCount,
  onClearFilters,
}: {
  rows: CveRow[]
  issueKey?: string
  platOrganizationRefs?: OrgRef[] | null
  onPlatCreated?: (cveId: string, imageBasename: string, out: CreatePlatResponse) => void
  hideBuiltInToolbar?: boolean
  /** When filters hide all rows but source had rows, show clear action */
  sourceRowCount?: number
  onClearFilters?: () => void
}) {
  const sorted = useMemo(() => sortCveRows(rows), [rows])
  const [platBusy, setPlatBusy] = useState<string | null>(null)
  const [platErrRow, setPlatErrRow] = useState<string | null>(null)
  const [platErrMsg, setPlatErrMsg] = useState<string | null>(null)
  if (!sorted.length) {
    const hadSource = (sourceRowCount ?? 0) > 0
    if (hadSource && onClearFilters) {
      return (
        <div className="cveTableWrap cveTableWrapEmpty">
          <p className="muted small cveTableEmptyMsg">
            No CVEs match filters.{' '}
            <button type="button" className="resultsClearFiltersLink" onClick={onClearFilters}>
              Clear filters
            </button>
          </p>
        </div>
      )
    }
    return <div className="muted small">No CVEs found.</div>
  }
  const filename = issueKey ? `${issueKey}-cve-findings.xlsx` : 'cve-findings.xlsx'
  return (
    <div className="cveTableWrap">
      {!hideBuiltInToolbar && (
        <div className="cveTableToolbar">
          <button
            className="btnExport"
            onClick={() => exportCvesToExcel(sorted, filename)}
            title="Export to Excel"
          >
            ↓ Export Excel
          </button>
        </div>
      )}
      <table className="cveTable">
        <colgroup>
          <col className="cveColCve" />
          <col className="cveColPlat" />
          <col className="cveColSev" />
          <col className="cveColRes" />
          <col className="cveColVer" />
          <col className="cveColFix" />
        </colgroup>
        <thead>
          <tr>
            <th>CVE ID</th>
            <th>Affected image PLAT ticket</th>
            <th>Severity</th>
            <th>Resource</th>
            <th>Affected Ver.</th>
            <th>Vendor Fix</th>
          </tr>
        </thead>
        <tbody>
          {sorted.map((r) => (
            <tr key={r.cve_id}>
              <td>
                <a
                  className="cveId"
                  href={`https://nvd.nist.gov/vuln/detail/${r.cve_id}`}
                  target="_blank"
                  rel="noreferrer"
                >
                  {r.cve_id}
                </a>
              </td>
              <td className="platTicketCell">
                {(() => {
                  const tickets = [
                    ...(r.plat_tickets ?? (r.plat_ticket ? [{ key: r.plat_ticket, issue_type: 'Security Vulnerability' }] : [])),
                  ]
                  const bugTickets = tickets.filter((t) => t.issue_type === 'Bug')
                  bugTickets.sort((a, b) => a.key.localeCompare(b.key))

                  const perImages = imageBasenamesForCveRow(r)
                  const verOk = !!(r.affected_version && String(r.affected_version).trim())
                  const orphanSec = platOrphanSecKeys(r)
                  const allSecKeys = platSecurityKeys(r)

                  return (
                    <div className="platCell platCellSketchBoard">
                      {perImages.length > 0 ? (
                        <>
                          {perImages.map((imgBasename) => {
                            const bugsForImg = platBugTicketsForImage(r, imgBasename)
                            const secKeys = platSecKeysForImage(r, imgBasename)
                            const busyKey = `${r.cve_id}|${imgBasename}`
                            const canCreateThis =
                              onPlatCreated && verOk && secKeys.length === 0
                            const showDash =
                              !bugsForImg.length && !secKeys.length && !canCreateThis
                            return (
                              <div key={imgBasename} className="platPerImage">
                                <span
                                  className="platPerImageLabel mono"
                                  title={platDisplayFullImageForRow(r, imgBasename)}
                                >
                                  {platDisplayLabelForImage(r, imgBasename)}
                                </span>
                                <div className="platPerImageActions platSketchActions">
                                  {bugsForImg.map((t) => (
                                    <a
                                      key={t.key}
                                      className="platTicketPill platTicketFound"
                                      href={`https://plainid.atlassian.net/browse/${t.key}`}
                                      target="_blank"
                                      rel="noreferrer"
                                      title={t.issue_type}
                                    >
                                      {t.key}
                                      <span className="platTicketType">bug</span>
                                    </a>
                                  ))}
                                  {secKeys.map((pk) => (
                                    <a
                                      key={pk}
                                      className="platTicketPill platTicketFound"
                                      href={`https://plainid.atlassian.net/browse/${pk}`}
                                      target="_blank"
                                      rel="noreferrer"
                                      title="Security Vulnerability"
                                    >
                                      {pk}
                                      <span className="platTicketType">cve</span>
                                    </a>
                                  ))}
                                  {!secKeys.length && canCreateThis && (
                                    <button
                                      type="button"
                                      className="platTicketPill platTicketCreate platCreatePill"
                                      disabled={platBusy === busyKey}
                                      title={`Create Security Vulnerability (CVE) PLAT for ${imgBasename}`}
                                      onClick={async () => {
                                        const ver = (r.affected_version ?? '').trim()
                                        if (!ver || !onPlatCreated) return
                                        setPlatBusy(busyKey)
                                        setPlatErrRow(null)
                                        setPlatErrMsg(null)
                                        try {
                                          const out = await apiCreatePlat({
                                            cve_id: r.cve_id,
                                            image_basename: imgBasename,
                                            package_name: platPackageNameForRow(r),
                                            package_version: ver,
                                            severity: r.severity,
                                            organizations: platOrganizationRefs ?? [],
                                            source_issue_key: issueKey,
                                          })
                                          onPlatCreated(r.cve_id, imgBasename, out)
                                        } catch (e) {
                                          setPlatErrRow(r.cve_id)
                                          setPlatErrMsg(e instanceof Error ? e.message : String(e))
                                        } finally {
                                          setPlatBusy(null)
                                        }
                                      }}
                                    >
                                      {platBusy === busyKey ? 'Creating…' : 'Create CVE'}
                                    </button>
                                  )}
                                  {showDash && (
                                    <span className="muted small platPerImageNA">—</span>
                                  )}
                                </div>
                              </div>
                            )
                          })}
                          {orphanSec.length > 0 && (
                            <div className="platPerImage platPerImageOrphan">
                              <span
                                className="platPerImageLabel"
                                title="Security PLAT not linked to a specific image in Jira data"
                              >
                                Unmapped Sec
                              </span>
                              <div className="platPerImageActions platSketchActions">
                                {orphanSec.map((pk) => (
                                  <a
                                    key={pk}
                                    className="platTicketPill platTicketFound"
                                    href={`https://plainid.atlassian.net/browse/${pk}`}
                                    target="_blank"
                                    rel="noreferrer"
                                    title="Security Vulnerability—unmapped to image"
                                  >
                                    {pk}
                                    <span className="platTicketType">cve</span>
                                  </a>
                                ))}
                              </div>
                            </div>
                          )}
                        </>
                      ) : (
                        <>
                          {(bugTickets.length > 0 ||
                            allSecKeys.length > 0 ||
                            platDisplayFullImagesSummary(r) ||
                            platDisplaySketchSummary(r)) && (
                            <div className="platPerImage platPerImageAggregated">
                              <span
                                className="platPerImageLabel mono"
                                title={
                                  platDisplayFullImagesSummary(r) ||
                                  platDisplaySketchSummary(r) ||
                                  undefined
                                }
                              >
                                {platDisplaySketchSummary(r) ||
                                  platDisplayFullImagesSummary(r) ||
                                  '—'}
                              </span>
                              <div className="platPerImageActions platSketchActions">
                                {bugTickets.map((t) => (
                                  <a
                                    key={t.key}
                                    className="platTicketPill platTicketFound"
                                    href={`https://plainid.atlassian.net/browse/${t.key}`}
                                    target="_blank"
                                    rel="noreferrer"
                                    title={t.issue_type}
                                  >
                                    {t.key}
                                    <span className="platTicketType">bug</span>
                                  </a>
                                ))}
                                {allSecKeys.map((pk) => (
                                  <a
                                    key={pk}
                                    className="platTicketPill platTicketFound"
                                    href={`https://plainid.atlassian.net/browse/${pk}`}
                                    target="_blank"
                                    rel="noreferrer"
                                    title="Security Vulnerability"
                                  >
                                    {pk}
                                    <span className="platTicketType">cve</span>
                                  </a>
                                ))}
                                {bugTickets.length === 0 &&
                                  allSecKeys.length === 0 && (
                                    <span className="muted small platPerImageNA">—</span>
                                  )}
                              </div>
                            </div>
                          )}
                          {bugTickets.length === 0 &&
                            allSecKeys.length === 0 &&
                            !platDisplayFullImagesSummary(r) &&
                            !platDisplaySketchSummary(r) && (
                              <div className="platFallbackRow">
                                <Dash />
                              </div>
                            )}
                        </>
                      )}

                      {platErrRow === r.cve_id && platErrMsg && (
                        <div className="platCreateErr small">{platErrMsg}</div>
                      )}
                    </div>
                  )
                })()}
              </td>
              <td>
                <SevBadge sev={r.severity} score={r.score} />
              </td>
              <td>
                {r.affected_resource
                  ? <span className="mono">{r.affected_resource}</span>
                  : <Dash />}
              </td>
              <td>
                {r.affected_version
                  ? <span className="mono">{r.affected_version}</span>
                  : <Dash />}
              </td>
              <td>
                {r.fixed_version
                  ? <span className="mono fixedVer">{r.fixed_version}</span>
                  : <Dash />}
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  )
}

// ─── ticket info panel ───────────────────────────────────────────────────────

function TicketPanel({
  issue,
  job,
  loading,
  onStartProcessing,
  onViewResults,
}: {
  issue: IssueResponse
  job: JobResponse | null
  loading: boolean
  onStartProcessing: () => void
  onViewResults: () => void
}) {
  const isDone = job?.status === 'done'
  const isActive = !!job?.status && !isDone && !job.status.startsWith('failed')

  return (
    <div className="card">
      <div className="ticketHeader">
        <div className="ticketKey">{issue.key}</div>
        <div className="ticketTitleRow">
          <div className="ticketSummary">{issue.summary ?? '—'}</div>
          <div className="ticketActions">
            {!isDone && (
              <button className="btn btnPrimary" disabled={loading || isActive} onClick={onStartProcessing}>
                {isActive ? 'Processing…' : 'Start processing'}
              </button>
            )}
            {isDone && (
              <button className="btn btnPrimary" onClick={onViewResults}>View results</button>
            )}
            {isDone && (
              <button className="btn btnSecondary" onClick={onStartProcessing} disabled={loading}>Re-run</button>
            )}
            {job?.status && <StatusBadge status={job.status} />}
          </div>
        </div>
        <div className="ticketMeta">
          <div className="attrChip attrChipProject">
            <span className="attrChipLabel">Project</span>
            <span className="attrChipValue mono">{issue.project ?? '—'}</span>
          </div>
          <div className="attrChip attrChipType">
            <span className="attrChipLabel">Type</span>
            <span className="attrChipValue">{issue.issuetype ?? '—'}</span>
          </div>
          <div className="attrChip attrChipAttach">
            <span className="attrChipLabel">Attachments</span>
            <span className="attrChipValue">{issue.attachments?.length ?? 0}</span>
          </div>
          {issue.reporter && (
            <div className="attrChip attrChipReporter">
              <span className="attrChipLabel">Reporter</span>
              <span className="attrChipValue">{issue.reporter}</span>
            </div>
          )}
          {(issue.organizations?.length ?? 0) > 0 && (
            <div className="attrChip attrChipOrg">
              <span className="attrChipLabel">Organizations</span>
              <span className="attrChipValue">{issue.organizations!.join(', ')}</span>
            </div>
          )}
        </div>
      </div>

      {job?.status && <StepList status={job.status} />}

      {/* Description */}
      <div className="card">
        <div className="cardHeader">
          <span className="cardTitle">Description</span>
        </div>
        <pre className="descPre">{(issue.description_text ?? '').trim() || '—'}</pre>
      </div>

      {/* Attachments */}
      {issue.attachments.length > 0 && (
        <div className="card">
          <div className="cardHeader">
            <span className="cardTitle">Attachments ({issue.attachments.length})</span>
          </div>
          <table className="attachTable">
            <thead>
              <tr>
                <th>File</th>
                <th>Type</th>
                <th>Size (bytes)</th>
              </tr>
            </thead>
            <tbody>
              {issue.attachments.map((a) => (
                <tr key={a.id}>
                  <td>{a.filename}</td>
                  <td>{a.mimeType ?? '—'}</td>
                  <td>{a.size ?? '—'}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  )
}

function ResultsOverflowMenu({ issueKey }: { issueKey: string }) {
  const [open, setOpen] = useState(false)
  const ref = useRef<HTMLDivElement>(null)
  useEffect(() => {
    if (!open) return
    const fn = (e: MouseEvent) => {
      if (ref.current && !ref.current.contains(e.target as Node)) setOpen(false)
    }
    document.addEventListener('mousedown', fn)
    return () => document.removeEventListener('mousedown', fn)
  }, [open])

  const jiraUrl = `https://plainid.atlassian.net/browse/${encodeURIComponent(issueKey)}`

  return (
    <div className="resultsOverflowWrap" ref={ref}>
      <button
        type="button"
        className="resultsOverflowBtn"
        aria-expanded={open}
        aria-label="More actions"
        onClick={() => setOpen(!open)}
      >
        ⋮
      </button>
      {open && (
        <ul className="resultsOverflowMenu" role="menu">
          <li role="none">
            <button
              type="button"
              role="menuitem"
              className="resultsOverflowMenuItem"
              onClick={() => {
                void navigator.clipboard.writeText(issueKey)
                setOpen(false)
              }}
            >
              Copy issue key
            </button>
          </li>
          <li role="none">
            <a
              className="resultsOverflowMenuItem"
              role="menuitem"
              href={jiraUrl}
              target="_blank"
              rel="noreferrer"
              onClick={() => setOpen(false)}
            >
              Open in Jira
            </a>
          </li>
        </ul>
      )}
    </div>
  )
}

// ─── results panel ───────────────────────────────────────────────────────────

function ResultsPanel({
  issue,
  job,
  loading,
  commentBody,
  onCommentChange,
  onPushComment,
  onBack,
  onReprocessTicket,
  commentPosted,
}: {
  issue: IssueResponse
  job: JobResponse
  loading: boolean
  commentBody: string
  onCommentChange: (v: string) => void
  onPushComment: () => void
  onBack: () => void
  onReprocessTicket: () => void | Promise<void>
  commentPosted: boolean
}) {
  const [rows, setRows] = useState<CveRow[]>([])
  const [filterText, setFilterText] = useState('')
  const [severityFilter, setSeverityFilter] = useState('')
  const [resourceFilter, setResourceFilter] = useState('')
  const [platBulkBusy, setPlatBulkBusy] = useState(false)
  const [platBulkProgress, setPlatBulkProgress] = useState<{ done: number; total: number } | null>(null)
  const [platBulkErr, setPlatBulkErr] = useState<string | null>(null)

  useEffect(() => {
    if (job.status === 'done' && job.result?.cve_rows) {
      setRows(job.result.cve_rows)
    } else {
      setRows([])
    }
  }, [job])

  const onPlatCreated = (cveId: string, imageBasename: string, out: CreatePlatResponse) => {
    setRows((prev) => mergePlatCreateIntoRows(prev, cveId, imageBasename, out))
  }

  const severityOptions = useMemo(() => {
    const s = new Set<string>()
    for (const r of rows) {
      if (r.severity?.trim()) s.add(r.severity.trim().toUpperCase())
    }
    return [...s].sort((a, b) => severitySortKey(a) - severitySortKey(b) || a.localeCompare(b))
  }, [rows])

  const resourceOptions = useMemo(() => {
    const s = new Set<string>()
    for (const r of rows) {
      if (r.affected_resource?.trim()) s.add(r.affected_resource.trim())
    }
    return [...s].sort((a, b) => a.localeCompare(b))
  }, [rows])

  const findingsSeveritySummary = useMemo(() => aggregateSeverityLabel(rows), [rows])

  const filteredRows = useMemo(
    () => rows.filter((r) => rowMatchesCveFilters(r, filterText, severityFilter, resourceFilter)),
    [rows, filterText, severityFilter, resourceFilter],
  )

  const missingCveSlots = useMemo(
    () => platMissingCveCreateSlots(filteredRows),
    [filteredRows],
  )

  async function createAllMissingPlatCves() {
    const slots = [...missingCveSlots]
    if (!issue.key || slots.length === 0) return
    setPlatBulkBusy(true)
    setPlatBulkErr(null)
    setPlatBulkProgress({ done: 0, total: slots.length })
    const orgRefs = platOrgRefsFromIssue(issue)
    let acc = rows
    const failures: string[] = []
    try {
      for (let i = 0; i < slots.length; i++) {
        const slot = slots[i]
        const r = acc.find((x) => x.cve_id === slot.cve_id)
        if (!r) continue
        const ver = (r.affected_version ?? '').trim()
        if (!ver) continue
        try {
          const out = await apiCreatePlat({
            cve_id: r.cve_id,
            image_basename: slot.image_basename,
            package_name: platPackageNameForRow(r),
            package_version: ver,
            severity: r.severity,
            organizations: orgRefs,
            source_issue_key: issue.key,
          })
          acc = mergePlatCreateIntoRows(acc, slot.cve_id, slot.image_basename, out)
          setRows(acc)
        } catch (e) {
          const msg = e instanceof Error ? e.message : String(e)
          failures.push(`${r.cve_id} / ${slot.image_basename}: ${msg}`)
        }
        setPlatBulkProgress({ done: i + 1, total: slots.length })
      }
      if (failures.length) {
        setPlatBulkErr(
          failures.length === slots.length
            ? `All ${failures.length} failed. ${failures[0]}`
            : `${failures.length} of ${slots.length} failed. ${failures.slice(0, 3).join(' · ')}${failures.length > 3 ? ' …' : ''}`,
        )
      }
    } finally {
      setPlatBulkBusy(false)
      setPlatBulkProgress(null)
    }
  }

  function clearAllFilters() {
    setFilterText('')
    setSeverityFilter('')
    setResourceFilter('')
  }

  const findingsDone = job.status === 'done'
  const exportFilename = issue.key ? `${issue.key}-cve-findings.xlsx` : 'cve-findings.xlsx'

  return (
    <div className="resultsStack">
      <div className="resultsBarWrap">
        <div className="resultsBarGrid">
          <div className="resultsBarLeft">
            <button type="button" className="resultsBarBack" onClick={onBack}>
              ←
            </button>
            <span className="resultsMonoKey">{issue.key}</span>
          </div>
          <h1 className="resultsBarTitleMain">{issue.summary ?? '—'}</h1>
          <div className="resultsBarRight">
            {job.status === 'done' ? (
              <span className="resultsDonePill">✓ Done</span>
            ) : (
              <StatusBadge status={job.status} />
            )}
            <ResultsOverflowMenu issueKey={issue.key} />
          </div>
        </div>
        <div className="resultsAttrRow resultsAttrRowMeta">
          <div className="attrChip attrChipMetaBox attrChipProject">
            <span className="attrChipLabel">Project</span>
            <span className="attrChipValuePill">
              <span className="mono">{issue.project ?? '—'}</span>
            </span>
          </div>
          <div className={`attrChip ${severityMetaChipClass(findingsSeveritySummary)}`}>
            <span className="attrChipLabel">Severity</span>
            <span className="attrChipValuePill">{formatSeverityTitleCase(findingsSeveritySummary)}</span>
          </div>
          <div className="attrChip attrChipMetaBox attrChipType">
            <span className="attrChipLabel">Type</span>
            <span className="attrChipValuePill">{issue.issuetype ?? '—'}</span>
          </div>
          <div className="attrChip attrChipMetaBox attrChipAttach">
            <span className="attrChipLabel">Attachments</span>
            <span className="attrChipValuePill">
              {issue.attachments.length} file{issue.attachments.length !== 1 ? 's' : ''}
            </span>
          </div>
          {issue.reporter && (
            <div className="attrChip attrChipMetaBox attrChipReporter">
              <span className="attrChipLabel">Reporter</span>
              <span className="attrChipValuePill">{issue.reporter}</span>
            </div>
          )}
          {(issue.organizations?.length ?? 0) > 0 && (
            <div className="attrChip attrChipMetaBox attrChipOrg">
              <span className="attrChipLabel">Organization</span>
              <span className="attrChipValuePill">{issue.organizations!.join(', ')}</span>
            </div>
          )}
        </div>
      </div>

      {/* CVE table */}
      <div className="card resultsFindingsCard">
        <div className="cardHeader resultsFindingsCardHeader">
          <span className="cardTitle">
            CVE Findings ({filteredRows.length}
            {filteredRows.length !== rows.length ? ` of ${rows.length}` : ''})
          </span>
        </div>
        {findingsDone && (
          <div className="resultsFindingsToolbar">
            <div className="resultsFindingsToolbarMain">
              <label className="resultsFilterSearchWrap">
                <input
                  type="search"
                  className="resultsFilterSearch"
                  placeholder="Filter by CVE ID, resource, image, etc…"
                  value={filterText}
                  onChange={(e) => setFilterText(e.target.value)}
                  autoComplete="off"
                />
              </label>
              <select
                className="resultsFilterSelect"
                value={severityFilter}
                onChange={(e) => setSeverityFilter(e.target.value)}
                aria-label="Severity filter"
              >
                <option value="">Severity</option>
                {severityOptions.map((s) => (
                  <option key={s} value={s}>{s}</option>
                ))}
              </select>
              <select
                className="resultsFilterSelect"
                value={resourceFilter}
                onChange={(e) => setResourceFilter(e.target.value)}
                aria-label="Resource filter"
              >
                <option value="">Resource</option>
                {resourceOptions.map((res) => (
                  <option key={res} value={res}>{res}</option>
                ))}
              </select>
              <button
                type="button"
                className="resultsFiltersResetBtn"
                onClick={clearAllFilters}
                title="Reset all filters"
              >
                Filters
              </button>
            </div>
            <div className="resultsFindingsToolbarActions">
              <button
                type="button"
                className="btnReprocessTicket"
                disabled={loading || platBulkBusy}
                title="Re-run full analysis: Jira, attachments, NVD, and PLAT lookup"
                onClick={() => void onReprocessTicket()}
              >
                ⟳ Re-process ticket
              </button>
              <button
                type="button"
                className="btnCreateAllPlat"
                disabled={loading || platBulkBusy || missingCveSlots.length === 0}
                title={
                  missingCveSlots.length === 0
                    ? 'No filtered findings need a new CVE PLAT ticket (requires affected version and image)'
                    : `Create Security Vulnerability PLAT tickets for ${missingCveSlots.length} filtered image/CVE pair(s) missing a CVE ticket`
                }
                onClick={() => void createAllMissingPlatCves()}
              >
                {platBulkBusy && platBulkProgress
                  ? `Creating… ${platBulkProgress.done}/${platBulkProgress.total}`
                  : `＋ Create all CVE tickets${missingCveSlots.length ? ` (${missingCveSlots.length})` : ''}`}
              </button>
              <button
                type="button"
                className="btnExport"
                onClick={() => exportCvesToExcel(filteredRows, exportFilename)}
                title="Export filtered rows to Excel"
              >
                ↓ Export Excel
              </button>
            </div>
          </div>
        )}
        {findingsDone && platBulkErr && (
          <div className="resultsPlatBulkErr small" role="alert">
            {platBulkErr}
          </div>
        )}
        <CveTable
          rows={filteredRows}
          issueKey={issue.key}
          platOrganizationRefs={platOrgRefsFromIssue(issue)}
          onPlatCreated={onPlatCreated}
          hideBuiltInToolbar={findingsDone}
          sourceRowCount={rows.length}
          onClearFilters={findingsDone && rows.length > 0 ? clearAllFilters : undefined}
        />
      </div>

      {/* Suggested comment */}
      <div className="card">
        <div className="cardHeader">
          <span className="cardTitle">Suggested internal comment</span>
          {commentPosted && <span className="statusBadge statusDone" style={{ fontSize: 11 }}>Posted to Jira</span>}
        </div>
        <textarea
          className="commentTextarea"
          value={commentBody}
          onChange={(e) => onCommentChange(e.target.value)}
        />
        <div className="btnRow">
          <button
            className="btn btnPrimary"
            disabled={loading || !commentBody.trim() || commentPosted}
            onClick={onPushComment}
          >
            Push to Jira as internal comment
          </button>
          {loading && <span className="muted small">Posting…</span>}
        </div>
      </div>
    </div>
  )
}

// ─── dashboard ───────────────────────────────────────────────────────────────

const DASH_PAGE_SIZE = 8

function dashCveStatePillClass(state: string): string {
  if (state === 'plat_complete') return 'dashCveState dashCveStateOk'
  if (state === 'needs_plat_cve') return 'dashCveState dashCveStateAction'
  if (state === 'needs_version' || state === 'no_image') return 'dashCveState dashCveStateWarn'
  if (state === 'nvd_error' || state === 'pipeline_failed') return 'dashCveState dashCveStateBad'
  if (state === 'pipeline_running') return 'dashCveState dashCveStateRun'
  return 'dashCveState'
}

function dashTicketWorkflowPillClass(status: DashboardTicketStatus): string {
  if (status === 'done') return 'dashTicketWorkflow dashTicketWorkflowDone'
  if (status === 'in_progress') return 'dashTicketWorkflow dashTicketWorkflowProgress'
  if (status === 'processing') return 'dashTicketWorkflow dashTicketWorkflowProcessing'
  return 'dashTicketWorkflow dashTicketWorkflowFailed'
}

/** Normalize dashboard search: lowercase, extract key from pasted Jira /browse/ URL. */
function normalizeDashboardSearchQuery(raw: string): string {
  const t = raw.trim().toLowerCase()
  if (!t) return ''
  const m = t.match(/\/browse\/([a-z][a-z0-9]*-\d+)/i)
  if (m) return m[1].toLowerCase()
  return t
}

function DashboardView({
  onOpen,
  onNew,
}: {
  onOpen: (issueKey: string, runId: string) => void
  onNew: () => void
}) {
  const [summaries, setSummaries] = useState<IssueCveStatusSummary[]>([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)
  const [page, setPage] = useState(1)
  const [dashSearch, setDashSearch] = useState('')
  const [dashStatusFilter, setDashStatusFilter] = useState<DashboardTicketStatus | ''>('')

  useEffect(() => {
    let alive = true
    apiGet<IssueCveStatusSummary[]>('/api/jobs/cve-status')
      .then((data) => { if (alive) setSummaries(data) })
      .catch((e) => { if (alive) setError(e?.message ?? String(e)) })
      .finally(() => { if (alive) setLoading(false) })
    return () => { alive = false }
  }, [])

  useEffect(() => {
    setPage(1)
  }, [dashSearch, dashStatusFilter])

  function relativeTime(iso?: string | null) {
    if (!iso) return '—'
    const diff = Date.now() - new Date(iso).getTime()
    const m = Math.floor(diff / 60000)
    if (m < 1) return 'just now'
    if (m < 60) return `${m}m ago`
    const h = Math.floor(m / 60)
    if (h < 24) return `${h}h ago`
    return `${Math.floor(h / 24)}d ago`
  }

  const totalIssues = summaries.length
  const totalCves = summaries.reduce((s, x) => s + (x.cve_count ?? x.cves.length ?? 0), 0)
  const wfInProgress = summaries.filter((x) => ticketStatusForSummary(x) === 'in_progress').length
  const wfDone = summaries.filter((x) => ticketStatusForSummary(x) === 'done').length
  const wfProcessing = summaries.filter((x) => ticketStatusForSummary(x) === 'processing').length
  const wfFailed = summaries.filter((x) => ticketStatusForSummary(x) === 'failed').length

  const filteredSummaries = useMemo(() => {
    const q = normalizeDashboardSearchQuery(dashSearch)
    return summaries.filter((s) => {
      const ts = ticketStatusForSummary(s)
      if (dashStatusFilter && ts !== dashStatusFilter) return false
      if (!q) return true
      const parent = (s.parent_issue_key ?? s.issue_key).toLowerCase()
      const proj = (s.issue_project ?? '').toLowerCase()
      if (parent.includes(q)) return true
      if (proj && proj === q) return true
      if (s.plat_keys?.some((k) => k.toLowerCase().includes(q))) return true
      return s.cves.some((c) => c.cve_id.toLowerCase().includes(q))
    })
  }, [summaries, dashSearch, dashStatusFilter])

  const totalPages = Math.max(1, Math.ceil(filteredSummaries.length / DASH_PAGE_SIZE))
  const pageSlice = filteredSummaries.slice((page - 1) * DASH_PAGE_SIZE, page * DASH_PAGE_SIZE)

  return (
    <div className="dashboard">
      <div className="dashGreeting">
        <div>
          <div className="dashTitle">CVE Security Dashboard</div>
          <div className="dashSub">Latest analysis per ticket and CVE state from the last run</div>
        </div>
        <button className="btn btnPrimary" onClick={onNew}>＋ Process new ticket</button>
      </div>

      {!loading && !error && (
        <div className="dashStats dashStatsWorkflow">
          <div className="statCard">
            <div className="statValue">{totalIssues}</div>
            <div className="statLabel">Issues</div>
          </div>
          <div className="statCard">
            <div className="statValue statValueGreen">{totalCves}</div>
            <div className="statLabel">CVEs</div>
          </div>
          <div className="statCard">
            <div className="statValue statValueAmber">{wfInProgress}</div>
            <div className="statLabel">In progress</div>
          </div>
          <div className="statCard">
            <div className="statValue statValueGreen">{wfDone}</div>
            <div className="statLabel">Done</div>
          </div>
          <div className="statCard">
            <div className="statValue">{wfProcessing}</div>
            <div className="statLabel">Processing</div>
          </div>
          <div className="statCard">
            <div className="statValue statValueRed">{wfFailed}</div>
            <div className="statLabel">Failed</div>
          </div>
        </div>
      )}

      <div className="card dashBoardCard">
        <div className="cardHeader dashBoardCardHeader">
          <span className="cardTitle">Tickets and CVE state</span>
          {!loading && (
            <span className="muted small">
              {filteredSummaries.length === summaries.length
                ? `${summaries.length} issues`
                : `${filteredSummaries.length} of ${summaries.length} issues`}
            </span>
          )}
        </div>

        {!loading && !error && summaries.length > 0 && (
          <div className="dashToolbar">
            <label className="dashSearchWrap">
              <input
                type="search"
                className="dashSearchInput"
                placeholder="Search PLATFORM parent, PLAT-…, CVE… (or paste Jira URL)"
                value={dashSearch}
                onChange={(e) => setDashSearch(e.target.value)}
                autoComplete="off"
              />
            </label>
            <select
              className="dashFilterSelect"
              value={dashStatusFilter}
              onChange={(e) => setDashStatusFilter(e.target.value as DashboardTicketStatus | '')}
              aria-label="Filter by ticket status"
            >
              <option value="">All statuses</option>
              <option value="in_progress">In progress</option>
              <option value="done">Done</option>
              <option value="processing">Processing</option>
              <option value="failed">Failed</option>
            </select>
          </div>
        )}

        {loading && <div className="muted small">Loading…</div>}
        {error && <div className="errorBox">{error}</div>}

        {!loading && !error && summaries.length === 0 && (
          <div className="muted small">No runs yet — process your first ticket to get started.</div>
        )}

        {!loading && !error && summaries.length > 0 && filteredSummaries.length === 0 && (
          <div className="muted small dashFilterEmpty">
            No issues match search or status filter.
            {' '}
            <button type="button" className="resultsClearFiltersLink" onClick={() => { setDashSearch(''); setDashStatusFilter('') }}>
              Clear filters
            </button>
          </div>
        )}

        {!loading && summaries.length > 0 && filteredSummaries.length > 0 && (
          <>
            <div className="dashIssueList">
              {pageSlice.map((s) => {
                const wf = ticketStatusForSummary(s)
                return (
                <details key={s.issue_key} className="dashIssueDetails">
                  <summary className="dashIssueSummary">
                    <span className="dashIssueSummaryMain">
                      <span className="dashIssueKey mono">{s.issue_key}</span>
                      <span className={dashTicketWorkflowPillClass(wf)} title="PLAT ticket workflow (last run)">
                        {dashboardTicketStatusLabel(wf)}
                      </span>
                      {wf === 'processing' && (
                        <StatusBadge status={s.run_status} />
                      )}
                      {s.cve_count != null && (
                        <span className="cvePill">{s.cve_count} CVE{s.cve_count !== 1 ? 's' : ''}</span>
                      )}
                      {(s.needs_plat_cve_count ?? 0) > 0 && (
                        <span className="dashNeedsPlatPill">{s.needs_plat_cve_count} need PLAT</span>
                      )}
                    </span>
                    <span className="dashIssueSummaryAside">
                      <span className="muted small">{relativeTime(s.created_at)}</span>
                      <button
                        type="button"
                        className="btn btnSecondary dashIssueOpenBtn"
                        onClick={(e) => {
                          e.preventDefault()
                          e.stopPropagation()
                          onOpen(s.issue_key, s.run_id)
                        }}
                      >
                        Open
                      </button>
                    </span>
                  </summary>
                  <div className="dashIssueBody">
                    {s.run_status !== 'done' && !s.run_status.startsWith('failed') && (
                      <p className="muted small">Pipeline still running — open the ticket to watch progress.</p>
                    )}
                    {s.cves.length > 0 ? (
                      <table className="dashCveTable">
                        <thead>
                          <tr>
                            <th>CVE</th>
                            <th>Severity</th>
                            <th>State</th>
                          </tr>
                        </thead>
                        <tbody>
                          {s.cves.map((c) => (
                            <tr key={c.cve_id}>
                              <td>
                                <a
                                  className="cveId"
                                  href={`https://nvd.nist.gov/vuln/detail/${encodeURIComponent(c.cve_id)}`}
                                  target="_blank"
                                  rel="noreferrer"
                                >
                                  {c.cve_id}
                                </a>
                              </td>
                              <td>
                                {c.severity
                                  ? <span className="mono">{c.severity}</span>
                                  : <span className="dash">—</span>}
                              </td>
                              <td>
                                <span className={dashCveStatePillClass(String(c.cve_state))}>
                                  {dashboardCveStateLabel(String(c.cve_state))}
                                </span>
                              </td>
                            </tr>
                          ))}
                        </tbody>
                      </table>
                    ) : (
                      s.run_status === 'done' && (
                        <p className="muted small">No CVE rows in the saved result.</p>
                      )
                    )}
                  </div>
                </details>
                )
              })}
            </div>

            {totalPages > 1 && (
              <div className="pagination">
                <button
                  type="button"
                  className="pageBtn"
                  disabled={page === 1}
                  onClick={() => setPage((p) => p - 1)}
                >
                  ← Prev
                </button>
                {Array.from({ length: totalPages }, (_, i) => i + 1).map((p) => (
                  <button
                    key={p}
                    type="button"
                    className={`pageBtn ${p === page ? 'pageBtnActive' : ''}`}
                    onClick={() => setPage(p)}
                  >
                    {p}
                  </button>
                ))}
                <button
                  type="button"
                  className="pageBtn"
                  disabled={page === totalPages}
                  onClick={() => setPage((p) => p + 1)}
                >
                  Next →
                </button>
              </div>
            )}
          </>
        )}
      </div>
    </div>
  )
}

// ─── main app ────────────────────────────────────────────────────────────────

type Page = 'dashboard' | 'new'

function App() {
  const [page, setPage]               = useState<Page>('dashboard')
  const [issueKey, setIssueKey]       = useState('')
  const [loading, setLoading]         = useState(false)
  const [error, setError]             = useState<string | null>(null)
  const [issue, setIssue]             = useState<IssueResponse | null>(null)
  const [runId, setRunId]             = useState<string | null>(null)
  const [job, setJob]                 = useState<JobResponse | null>(null)
  const [commentBody, setCommentBody] = useState('')
  const [commentPosted, setCommentPosted] = useState(false)
  const [viewMode, setViewMode]       = useState<'ticket' | 'results'>('ticket')

  const suggested = useMemo(
    () => (job?.result ? buildSuggestedComment(job.result) : ''),
    // eslint-disable-next-line react-hooks/exhaustive-deps
    [job?.result],
  )

  useEffect(() => {
    if (suggested) setCommentBody(suggested)
  }, [suggested])

  useEffect(() => {
    if (!runId) return
    let alive = true
    const t = setInterval(async () => {
      try {
        const j = await apiGet<JobResponse>(`/api/jobs/${runId}`)
        if (!alive) return
        setJob(j)
        if (j.status === 'done') {
          setViewMode('results')
          clearInterval(t)
        }
        if (j.status.startsWith('failed')) clearInterval(t)
      } catch (e: any) {
        if (!alive) return
        setError(e?.message ?? String(e))
      }
    }, 2000)
    return () => { alive = false; clearInterval(t) }
  }, [runId])

  function normalizeIssueKey(raw: string): string {
    const trimmed = raw.trim()
    // Accept full Jira URLs like https://....atlassian.net/browse/PLATFORM-1875
    const m = trimmed.match(/\/browse\/([A-Z][A-Z0-9]+-\d+)/i)
    return m ? m[1].toUpperCase() : trimmed.toUpperCase()
  }

  async function fetchIssue() {
    const key = normalizeIssueKey(issueKey)
    setIssueKey(key)
    setError(null)
    setLoading(true)
    setIssue(null)
    setRunId(null)
    setJob(null)
    setViewMode('ticket')
    setCommentPosted(false)
    try {
      const data = await apiGet<IssueResponse>(`/api/issues/${key}`)
      setIssue(data)
    } catch (e: any) {
      setError(e?.message ?? String(e))
    } finally {
      setLoading(false)
    }
  }

  async function startProcessingForIssue(issueRow: IssueResponse) {
    setError(null)
    setLoading(true)
    setRunId(null)
    setJob(null)
    setViewMode('ticket')
    setCommentPosted(false)
    try {
      const res = await apiPost<ProcessResponse>(`/api/issues/${issueRow.key}/process`, {})
      setRunId(res.run_id)
    } catch (e: any) {
      setError(e?.message ?? String(e))
    } finally {
      setLoading(false)
    }
  }

  async function startProcessing() {
    if (!issue) return
    await startProcessingForIssue(issue)
  }

  async function reprocessTicket() {
    if (!issue) return
    const ok = window.confirm(
      'Start a full analysis run again? This re-fetches the Jira issue, attachments, NVD, and PLAT data. In-memory changes in the results table are replaced when the run finishes.',
    )
    if (!ok) return
    await startProcessingForIssue(issue)
  }

  async function pushComment() {
    if (!issue) return
    setError(null)
    setLoading(true)
    try {
      await apiPost(`/api/issues/${issue.key}/comment`, { body: commentBody, internal: true })
      setCommentPosted(true)
    } catch (e: any) {
      setError(e?.message ?? String(e))
    } finally {
      setLoading(false)
    }
  }

  async function openFromHistory(key: string, rid: string) {
    setPage('new')
    setError(null)
    setIssueKey(key)
    setCommentPosted(false)
    setLoading(true)
    try {
      const [issueData, jobData] = await Promise.all([
        apiGet<IssueResponse>(`/api/issues/${key}`),
        apiGet<JobResponse>(`/api/jobs/${rid}`),
      ])
      setIssue(issueData)
      setJob(jobData)
      setRunId(rid)
      setViewMode('results')
    } catch (e: any) {
      setError(e?.message ?? String(e))
    } finally {
      setLoading(false)
    }
  }

  const showResults = issue && job && viewMode === 'results'
  const showTicket  = issue && viewMode === 'ticket'

  return (
    <div className="appShell">
      {/* ── Top nav ── */}
      <header className="topNav">
        <button className="topNavBrand" onClick={() => setPage('dashboard')}>
          <img src="/plainid-logo.svg" alt="PlainID" className="topNavLogoImg" />
          <span className="topNavSub">CVE Portal · Global Services</span>
        </button>

        <div className="topNavItems">
          <button
            className={`topNavItem ${page === 'dashboard' ? 'topNavItemActive' : ''}`}
            onClick={() => setPage('dashboard')}
          >
            ⊞ Dashboard
          </button>
          <button
            className={`topNavItem ${page === 'new' ? 'topNavItemActive' : ''}`}
            onClick={() => {
              setPage('new')
              setIssue(null)
              setIssueKey('')
              setRunId(null)
              setJob(null)
              setViewMode('ticket')
              setCommentBody('')
              setCommentPosted(false)
              setError(null)
            }}
          >
            ＋ New
          </button>
        </div>

        <div className="topNavLinks">
          <a className="topNavLink" href="https://nvd.nist.gov/" target="_blank" rel="noreferrer">NVD ↗</a>
          <a className="topNavLink" href="https://plainid.atlassian.net/jira/projects" target="_blank" rel="noreferrer">Jira ↗</a>
        </div>
      </header>

      {/* ── Main content ── */}
      <main className="mainContent">
        {/* ── NEW page ── */}
        {page === 'new' && (
          <>
            {/* Lookup bar */}
            {!issue && (
              <div className="heroSearch">
                <div className="heroTitle">Process a security ticket</div>
                <div className="heroSub">Enter a PLATFORM ticket number to fetch and analyze its CVEs</div>
                <div className="heroInputRow">
                  <input
                    className="lookupInput heroInput"
                    placeholder="PLATFORM-1234"
                    value={issueKey}
                    onChange={(e) => setIssueKey(e.target.value)}
                    onKeyDown={(e) => e.key === 'Enter' && issueKey.trim() && !loading && fetchIssue()}
                    autoFocus
                  />
                  <button className="btn btnPrimary" disabled={!issueKey.trim() || loading} onClick={fetchIssue}>
                    {loading ? 'Fetching…' : 'Fetch'}
                  </button>
                </div>
                {error && <div className="errorBox" style={{ marginTop: 16 }}>{error}</div>}
              </div>
            )}

            {issue && (
              <div className="pageHeader">
                <div className="lookupCard">
                  <input
                    className="lookupInput"
                    placeholder="PLATFORM-1234"
                    value={issueKey}
                    onChange={(e) => setIssueKey(e.target.value)}
                    onKeyDown={(e) => e.key === 'Enter' && issueKey.trim() && !loading && fetchIssue()}
                  />
                  <button className="btn btnPrimary" disabled={!issueKey.trim() || loading} onClick={fetchIssue}>
                    {loading && !job ? 'Fetching…' : 'Fetch'}
                  </button>
                  {loading && job && <span className="muted small">Working…</span>}
                </div>
                {error && <div className="errorBox">{error}</div>}
              </div>
            )}

            {showResults && (
              <ResultsPanel
                issue={issue}
                job={job}
                loading={loading}
                commentBody={commentBody}
                onCommentChange={setCommentBody}
                onPushComment={pushComment}
                onBack={() => setViewMode('ticket')}
                onReprocessTicket={reprocessTicket}
                commentPosted={commentPosted}
              />
            )}

            {showTicket && (
              <TicketPanel
                issue={issue}
                job={job}
                loading={loading}
                onStartProcessing={startProcessing}
                onViewResults={() => setViewMode('results')}
              />
            )}
          </>
        )}

        {/* ── DASHBOARD page ── */}
        {page === 'dashboard' && (
          <DashboardView
            onOpen={openFromHistory}
            onNew={() => {
              setIssue(null)
              setIssueKey('')
              setRunId(null)
              setJob(null)
              setViewMode('ticket')
              setCommentBody('')
              setCommentPosted(false)
              setError(null)
              setPage('new')
            }}
          />
        )}
      </main>
    </div>
  )
}

export default App
