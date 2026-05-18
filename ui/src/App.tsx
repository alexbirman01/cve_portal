import { useCallback, useEffect, useMemo, useRef, useState } from 'react'
import './App.css'
import type { ComponentHealth } from './api'
import {
  apiCreateCustomerSla,
  apiCreatePlat,
  apiCreatePlatBug,
  apiDeleteCustomerSla,
  apiDeleteProcessingRunsForIssue,
  apiEnqueuePlatSync,
  apiGet,
  apiGetAbout,
  apiGetClientConfig,
  apiListCustomerSlas,
  apiPost,
  apiUpdateCustomerSla,
  buildSuggestedComment,
  exportCvesToExcel,
  formatStatus,
  imageBasenamesForCveRow,
  mergePlatBugCreateIntoRows,
  mergePlatCreateIntoRows,
  platBugTicketsForImage,
  platMissingBugCreateSlots,
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
  platSecuritySyncFixForKeys,
  platSecuritySyncTagForKeys,
  platSecuritySyncSearchBlob,
  sortCveRows,
  statusSteps,
  dashboardCveStateLabel,
  dashboardTicketStatusLabel,
  ticketStatusForSummary,
  type AboutInfo,
  type CreatePlatResponse,
  type CustomerSlaRecord,
  type CveRow,
  type DashboardTicketStatus,
  type IssueCveStatusSummary,
  type IssueResponse,
  type JobResponse,
  type JobResult,
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
    r.sla_due_date,
    platSecuritySyncSearchBlob(r),
    keys,
  ]
    .filter(Boolean)
    .join(' ')
    .toLowerCase()
}

function rowMatchesCveSearch(r: CveRow, q: string): boolean {
  const needle = q.trim().toLowerCase()
  if (!needle) return true
  return cveRowSearchText(r).includes(needle)
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

type PlatSyncStrip = { fix: string; tag: string; secKeyCount: number }

function rowHasPlatSecuritySyncMap(r: CveRow): boolean {
  const m = r.plat_security_field_sync
  return !!m && Object.keys(m).length > 0
}

/** Fix/tag text for a set of Security PLAT keys (one sketch row). */
function platSyncStripForKeys(r: CveRow, secKeys: string[], legacyRowFallback = false): PlatSyncStrip {
  let fix = platSecuritySyncFixForKeys(r, secKeys)
  let tag = platSecuritySyncTagForKeys(r, secKeys)
  if (legacyRowFallback) {
    const m = r.plat_security_field_sync
    if (!m || !Object.keys(m).length) {
      const lf = (r.plat_app_fix_versions ?? '').trim()
      const lt = (r.plat_tag_numbers ?? '').trim()
      if (!fix && lf) fix = lf
      if (!tag && lt) tag = lt
    }
  }
  return { fix, tag, secKeyCount: secKeys.length }
}

/** One strip per PLAT sketch row (same order: each image, then orphan if any; else aggregated). */
function platSyncStripsForRow(r: CveRow): PlatSyncStrip[] | null {
  const tickets = [
    ...(r.plat_tickets ?? (r.plat_ticket ? [{ key: r.plat_ticket, issue_type: 'Security Vulnerability' }] : [])),
  ]
  const bugTickets = tickets.filter((t) => t.issue_type === 'Bug')
  const perImages = imageBasenamesForCveRow(r)
  const orphanSec = platOrphanSecKeys(r)
  const allSecKeys = platSecurityKeys(r)

  if (perImages.length > 0) {
    const out: PlatSyncStrip[] = []
    for (const img of perImages) {
      out.push(platSyncStripForKeys(r, platSecKeysForImage(r, img), false))
    }
    if (orphanSec.length) {
      out.push(platSyncStripForKeys(r, orphanSec, false))
    }
    return out
  }

  const showAggregated =
    bugTickets.length > 0 ||
    allSecKeys.length > 0 ||
    !!platDisplayFullImagesSummary(r) ||
    !!platDisplaySketchSummary(r)

  if (showAggregated) {
    return [platSyncStripForKeys(r, allSecKeys, true)]
  }

  return null
}

/** Single cell line for fix or tag strip (value, sync hint, or em dash). */
function PlatSyncStripCell({
  strip,
  field,
  hasSyncMap,
}: {
  strip: PlatSyncStrip
  field: 'fix' | 'tag'
  hasSyncMap: boolean
}) {
  const raw = (field === 'fix' ? strip.fix : strip.tag).trim()
  if (raw) {
    return <span className="platSyncStripText mono platAppMeta">{field === 'fix' ? strip.fix : strip.tag}</span>
  }
  if (strip.secKeyCount > 0 && !hasSyncMap) {
    return (
      <span className="platSyncPendingHint muted small" title="Run Actions → Sync PLAT (Jira) to load fix versions and tag field">
        Sync PLAT…
      </span>
    )
  }
  return <Dash />
}

const CVE_TABLE_COLUMN_KEYS = [
  'cve',
  'platImage',
  'platBug',
  'platCve',
  'platFix',
  'platTags',
  'severity',
  'resource',
  'affectedVer',
  'vendorFix',
  'dueDate',
] as const
type CveTableColumnKey = (typeof CVE_TABLE_COLUMN_KEYS)[number]

const CVE_TABLE_COLUMN_LABELS: Record<CveTableColumnKey, string> = {
  cve: 'CVE ID',
  platImage: 'Affected image',
  platBug: 'PLAT bug',
  platCve: 'PLAT CVE',
  platFix: 'PLAT fix version',
  platTags: 'Tag numbers',
  severity: 'Severity',
  resource: 'Resource',
  affectedVer: 'Affected Ver.',
  vendorFix: 'Vendor Fix',
  dueDate: 'Due Date',
}

const CVE_TABLE_COL_CLASS: Record<CveTableColumnKey, string> = {
  cve: 'cveColCve',
  platImage: 'cveColPlatImg',
  platBug: 'cveColPlatBug',
  platCve: 'cveColPlatCve',
  platFix: 'cveColPlatFix',
  platTags: 'cveColPlatTag',
  severity: 'cveColSev',
  resource: 'cveColRes',
  affectedVer: 'cveColVer',
  vendorFix: 'cveColFix',
  dueDate: 'cveColDue',
}

const DEFAULT_CVE_TABLE_COLUMN_VISIBILITY: Record<CveTableColumnKey, boolean> = {
  cve: true,
  platImage: true,
  platBug: true,
  platCve: true,
  severity: true,
  resource: true,
  affectedVer: true,
  vendorFix: true,
  dueDate: true,
  platFix: true,
  platTags: true,
}

type CveTableColumnVisibility = Record<CveTableColumnKey, boolean>

// ─── CVE table ───────────────────────────────────────────────────────────────

function CveTable({
  rows,
  issueKey,
  platOrganizationRefs,
  onPlatCreated,
  onPlatBugCreated,
  hideBuiltInToolbar,
  sourceRowCount,
  onClearSearch,
  columnVisibility: columnVisibilityProp,
}: {
  rows: CveRow[]
  issueKey?: string
  platOrganizationRefs?: OrgRef[] | null
  onPlatCreated?: (cveId: string, imageBasename: string, out: CreatePlatResponse) => void
  onPlatBugCreated?: (cveId: string, imageBasename: string, out: CreatePlatResponse) => void
  hideBuiltInToolbar?: boolean
  /** When search hides all rows but source had rows, show clear action */
  sourceRowCount?: number
  onClearSearch?: () => void
  columnVisibility?: CveTableColumnVisibility
}) {
  const sorted = useMemo(() => sortCveRows(rows), [rows])
  const [platBusy, setPlatBusy] = useState<string | null>(null)
  const [platErrRow, setPlatErrRow] = useState<string | null>(null)
  const [platErrMsg, setPlatErrMsg] = useState<string | null>(null)
  const [platLinkWarnings, setPlatLinkWarnings] = useState<string[] | null>(null)
  const vis = useMemo(() => {
    const m: CveTableColumnVisibility = { ...DEFAULT_CVE_TABLE_COLUMN_VISIBILITY, ...columnVisibilityProp }
    m.cve = true
    return m
  }, [columnVisibilityProp])
  if (!sorted.length) {
    const hadSource = (sourceRowCount ?? 0) > 0
    if (hadSource && onClearSearch) {
      return (
        <div className="cveTableWrap cveTableWrapEmpty">
          <p className="muted small cveTableEmptyMsg">
            No CVEs match search.{' '}
            <button type="button" className="resultsClearFiltersLink" onClick={onClearSearch}>
              Clear search
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
          {CVE_TABLE_COLUMN_KEYS.filter((k) => vis[k]).map((k) => (
            <col key={k} className={CVE_TABLE_COL_CLASS[k]} />
          ))}
        </colgroup>
        <thead>
          <tr>
            {CVE_TABLE_COLUMN_KEYS.filter((k) => vis[k]).map((k) => (
              <th key={k}>{CVE_TABLE_COLUMN_LABELS[k]}</th>
            ))}
          </tr>
        </thead>
        <tbody>
          {sorted.map((r) => {
            const syncStrips = platSyncStripsForRow(r)
            const hasSyncMap = rowHasPlatSecuritySyncMap(r)
            return (
            <tr key={r.cve_id}>
              {vis.cve ? (
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
              ) : null}
              {(vis.platImage || vis.platBug || vis.platCve) ? (() => {
                  const tickets = [
                    ...(r.plat_tickets ?? (r.plat_ticket ? [{ key: r.plat_ticket, issue_type: 'Security Vulnerability' }] : [])),
                  ]
                  const bugTickets = tickets.filter((t) => t.issue_type === 'Bug')
                  bugTickets.sort((a, b) => a.key.localeCompare(b.key))

                  const perImages = imageBasenamesForCveRow(r)
                  const verOk = !!(r.affected_version && String(r.affected_version).trim())
                  const orphanSec = platOrphanSecKeys(r)
                  const allSecKeys = platSecurityKeys(r)

                  const platErrBlock =
                    platErrRow === r.cve_id && (platErrMsg || platLinkWarnings?.length) ? (
                      <div className="platCreateErr small">
                        {platErrMsg && <div>{platErrMsg}</div>}
                        {platLinkWarnings?.map((w, i) => (
                          <div key={i} className="platLinkWarning">{w}</div>
                        ))}
                      </div>
                    ) : null

                  const errInImage = vis.platImage ? platErrBlock : null
                  const errInBug = !vis.platImage && vis.platBug ? platErrBlock : null
                  const errInCve = !vis.platImage && !vis.platBug && vis.platCve ? platErrBlock : null

                  return (
                    <>
                      {vis.platImage ? (
              <td className="platTicketCell platColCell">
                <div className="platColStack">
                      {perImages.length > 0 ? (
                        <>
                          {perImages.map((imgBasename) => (
                            <div key={imgBasename} className="platColStrip">
                              <span
                                className="platPerImageLabel mono platColImageLabel"
                                title={platDisplayFullImageForRow(r, imgBasename)}
                              >
                                {platDisplayLabelForImage(r, imgBasename)}
                              </span>
                            </div>
                          ))}
                          {orphanSec.length > 0 && (
                            <div className="platColStrip platPerImageOrphan">
                              <span
                                className="platPerImageLabel platColImageLabel"
                                title="Security PLAT not linked to a specific image in Jira data"
                              >
                                Unmapped Sec
                              </span>
                            </div>
                          )}
                        </>
                      ) : (
                        <>
                          {(bugTickets.length > 0 ||
                            allSecKeys.length > 0 ||
                            platDisplayFullImagesSummary(r) ||
                            platDisplaySketchSummary(r)) && (
                            <div className="platColStrip">
                              <span
                                className="platPerImageLabel mono platColImageLabel"
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
                            </div>
                          )}
                          {bugTickets.length === 0 &&
                            allSecKeys.length === 0 &&
                            !platDisplayFullImagesSummary(r) &&
                            !platDisplaySketchSummary(r) && (
                              <div className="platColStrip">
                                <Dash />
                              </div>
                            )}
                        </>
                      )}
                      {errInImage}
                </div>
              </td>
                      ) : null}
                      {vis.platBug ? (
              <td className="platTicketCell platColCell">
                <div className="platColStack">
                      {perImages.length > 0 ? (
                        <>
                          {perImages.map((imgBasename) => {
                            const bugsForImg = platBugTicketsForImage(r, imgBasename)
                            const busyKeyBug = `${r.cve_id}|${imgBasename}|bug`
                            const canCreateBug =
                              onPlatBugCreated && verOk && bugsForImg.length === 0
                            const bugEmpty = !bugsForImg.length && !canCreateBug
                            return (
                              <div key={imgBasename} className="platColStrip">
                                <div
                                  className={
                                    bugEmpty ? 'platColPills platColPillsEmpty' : 'platColPills'
                                  }
                                >
                                  {bugEmpty ? (
                                    <span className="muted small platPerImageNA">—</span>
                                  ) : (
                                    <>
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
                                        </a>
                                      ))}
                                      {canCreateBug && (
                                        <button
                                          type="button"
                                          className="platTicketPill platTicketCreate platTicketCreateBug platCreatePill platCreateBugPill"
                                          disabled={platBusy === busyKeyBug}
                                          title={`Create Bug PLAT for ${imgBasename}`}
                                          onClick={async () => {
                                            const ver = (r.affected_version ?? '').trim()
                                            if (!ver || !onPlatBugCreated) return
                                            setPlatBusy(busyKeyBug)
                                            setPlatErrRow(null)
                                            setPlatErrMsg(null)
                                            setPlatLinkWarnings(null)
                                            try {
                                              const out = await apiCreatePlatBug({
                                                cve_id: r.cve_id,
                                                image_basename: imgBasename,
                                                package_name: platPackageNameForRow(r),
                                                package_version: ver,
                                                severity: r.severity,
                                                organizations: platOrganizationRefs ?? [],
                                                source_issue_key: issueKey,
                                                image_display: platDisplayLabelForImage(r, imgBasename),
                                                resource_label:
                                                  (r.affected_resource ?? '').trim() ||
                                                  platPackageNameForRow(r),
                                                vendor_fix_version: (r.fixed_version ?? '').trim() || null,
                                                sla_due_date: r.sla_due_date ?? null,
                                              })
                                              if (out.link_warnings?.length) {
                                                setPlatErrRow(r.cve_id)
                                                setPlatLinkWarnings(out.link_warnings)
                                              }
                                              onPlatBugCreated(r.cve_id, imgBasename, out)
                                            } catch (e) {
                                              setPlatErrRow(r.cve_id)
                                              setPlatErrMsg(e instanceof Error ? e.message : String(e))
                                            } finally {
                                              setPlatBusy(null)
                                            }
                                          }}
                                        >
                                          {platBusy === busyKeyBug ? 'Creating…' : 'Create BUG'}
                                        </button>
                                      )}
                                    </>
                                  )}
                                </div>
                              </div>
                            )
                          })}
                          {orphanSec.length > 0 && (
                            <div className="platColStrip">
                              <div className="platColPills platColPillsEmpty">
                                <span className="muted small platPerImageNA">—</span>
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
                            <div className="platColStrip">
                              <div
                                className={
                                  bugTickets.length === 0
                                    ? 'platColPills platColPillsEmpty'
                                    : 'platColPills'
                                }
                              >
                                {bugTickets.length === 0 ? (
                                  <span className="muted small platPerImageNA">—</span>
                                ) : (
                                  bugTickets.map((t) => (
                                    <a
                                      key={t.key}
                                      className="platTicketPill platTicketFound"
                                      href={`https://plainid.atlassian.net/browse/${t.key}`}
                                      target="_blank"
                                      rel="noreferrer"
                                      title={t.issue_type}
                                    >
                                      {t.key}
                                    </a>
                                  ))
                                )}
                              </div>
                            </div>
                          )}
                          {bugTickets.length === 0 &&
                            allSecKeys.length === 0 &&
                            !platDisplayFullImagesSummary(r) &&
                            !platDisplaySketchSummary(r) && (
                              <div className="platColStrip">
                                <Dash />
                              </div>
                            )}
                        </>
                      )}
                      {errInBug}
                </div>
              </td>
                      ) : null}
                      {vis.platCve ? (
              <td className="platTicketCell platColCell">
                <div className="platColStack">
                      {perImages.length > 0 ? (
                        <>
                          {perImages.map((imgBasename) => {
                            const secKeys = platSecKeysForImage(r, imgBasename)
                            const busyKeyCve = `${r.cve_id}|${imgBasename}|cve`
                            const canCreateThis =
                              onPlatCreated && verOk && secKeys.length === 0
                            const cveEmpty = !secKeys.length && !canCreateThis
                            return (
                              <div key={imgBasename} className="platColStrip">
                                <div
                                  className={
                                    cveEmpty ? 'platColPills platColPillsEmpty' : 'platColPills'
                                  }
                                >
                                  {cveEmpty ? (
                                    <span className="muted small platPerImageNA">—</span>
                                  ) : (
                                    <>
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
                                        </a>
                                      ))}
                                      {!secKeys.length && canCreateThis && (
                                        <button
                                          type="button"
                                          className="platTicketPill platTicketCreate platCreatePill"
                                          disabled={platBusy === busyKeyCve}
                                          title={`Create Security Vulnerability (CVE) PLAT for ${imgBasename}`}
                                          onClick={async () => {
                                            const ver = (r.affected_version ?? '').trim()
                                            if (!ver || !onPlatCreated) return
                                            setPlatBusy(busyKeyCve)
                                            setPlatErrRow(null)
                                            setPlatErrMsg(null)
                                            setPlatLinkWarnings(null)
                                            try {
                                              const out = await apiCreatePlat({
                                                cve_id: r.cve_id,
                                                image_basename: imgBasename,
                                                package_name: platPackageNameForRow(r),
                                                package_version: ver,
                                                severity: r.severity,
                                                organizations: platOrganizationRefs ?? [],
                                                source_issue_key: issueKey,
                                                sla_due_date: r.sla_due_date ?? null,
                                              })
                                              if (out.link_warnings?.length) {
                                                setPlatErrRow(r.cve_id)
                                                setPlatLinkWarnings(out.link_warnings)
                                              }
                                              onPlatCreated(r.cve_id, imgBasename, out)
                                            } catch (e) {
                                              setPlatErrRow(r.cve_id)
                                              setPlatErrMsg(e instanceof Error ? e.message : String(e))
                                            } finally {
                                              setPlatBusy(null)
                                            }
                                          }}
                                        >
                                          {platBusy === busyKeyCve ? 'Creating…' : 'Create CVE'}
                                        </button>
                                      )}
                                    </>
                                  )}
                                </div>
                              </div>
                            )
                          })}
                          {orphanSec.length > 0 && (
                            <div className="platColStrip">
                              <div className="platColPills">
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
                            <div className="platColStrip">
                              <div
                                className={
                                  allSecKeys.length === 0
                                    ? 'platColPills platColPillsEmpty'
                                    : 'platColPills'
                                }
                              >
                                {allSecKeys.length === 0 ? (
                                  <span className="muted small platPerImageNA">—</span>
                                ) : (
                                  allSecKeys.map((pk) => (
                                    <a
                                      key={pk}
                                      className="platTicketPill platTicketFound"
                                      href={`https://plainid.atlassian.net/browse/${pk}`}
                                      target="_blank"
                                      rel="noreferrer"
                                      title="Security Vulnerability"
                                    >
                                      {pk}
                                    </a>
                                  ))
                                )}
                              </div>
                            </div>
                          )}
                          {bugTickets.length === 0 &&
                            allSecKeys.length === 0 &&
                            !platDisplayFullImagesSummary(r) &&
                            !platDisplaySketchSummary(r) && (
                              <div className="platColStrip">
                                <Dash />
                              </div>
                            )}
                        </>
                      )}
                      {errInCve}
                </div>
              </td>
                      ) : null}
                    </>
                  )
                })()
              : null}
              {vis.platFix ? (
              <td className="platSyncStackCell">
                {syncStrips == null ? (
                  <Dash />
                ) : (
                  <div className="platSyncStack">
                    {syncStrips.map((s, i) => (
                      <div key={i} className="platSyncStrip">
                        <div className="platSyncStripMetaRow">
                          <PlatSyncStripCell strip={s} field="fix" hasSyncMap={hasSyncMap} />
                        </div>
                      </div>
                    ))}
                  </div>
                )}
              </td>
              ) : null}
              {vis.platTags ? (
              <td className="platSyncStackCell">
                {syncStrips == null ? (
                  <Dash />
                ) : (
                  <div className="platSyncStack">
                    {syncStrips.map((s, i) => (
                      <div key={i} className="platSyncStrip">
                        <div className="platSyncStripMetaRow">
                          <PlatSyncStripCell strip={s} field="tag" hasSyncMap={hasSyncMap} />
                        </div>
                      </div>
                    ))}
                  </div>
                )}
              </td>
              ) : null}
              {vis.severity ? (
              <td>
                <SevBadge sev={r.severity} score={r.score} />
              </td>
              ) : null}
              {vis.resource ? (
              <td>
                {r.affected_resource
                  ? <span className="mono">{r.affected_resource}</span>
                  : <Dash />}
              </td>
              ) : null}
              {vis.affectedVer ? (
              <td>
                {r.affected_version
                  ? <span className="mono">{r.affected_version}</span>
                  : <Dash />}
              </td>
              ) : null}
              {vis.vendorFix ? (
              <td>
                {r.fixed_version
                  ? <span className="mono fixedVer">{r.fixed_version}</span>
                  : <Dash />}
              </td>
              ) : null}
              {vis.dueDate ? (
              <td>
                {r.sla_due_date
                  ? (
                    <span className="mono slaDueDate" title="Strictest SLA due (orgs on ticket + severity; anchor = ticket created)">
                      {r.sla_due_date}
                    </span>
                  )
                  : <Dash />}
              </td>
              ) : null}
            </tr>
            )
          })}
        </tbody>
      </table>
    </div>
  )
}

// ─── customer SLA admin ─────────────────────────────────────────────────────

function SlaAdminPanelBody() {
  const [rows, setRows] = useState<CustomerSlaRecord[]>([])
  const [loading, setLoading] = useState(true)
  const [err, setErr] = useState<string | null>(null)
  const [savingId, setSavingId] = useState<string | null>(null)
  const [createBusy, setCreateBusy] = useState(false)
  const [draft, setDraft] = useState({
    customer_name: '',
    sla_critical: '',
    sla_high: '',
    sla_medium: '',
    sla_low: '',
  })

  const load = useCallback(async () => {
    setErr(null)
    setLoading(true)
    try {
      const list = await apiListCustomerSlas()
      setRows([...list].sort((a, b) => a.customer_name.localeCompare(b.customer_name)))
    } catch (e: any) {
      setErr(e?.message ?? String(e))
    } finally {
      setLoading(false)
    }
  }, [])

  useEffect(() => { void load() }, [load])

  function patchRow(id: string, patch: Partial<CustomerSlaRecord>) {
    setRows((prev) => prev.map((r) => (r.id === id ? { ...r, ...patch } : r)))
  }

  async function saveRow(r: CustomerSlaRecord) {
    setErr(null)
    setSavingId(r.id)
    try {
      const updated = await apiUpdateCustomerSla(r.id, {
        customer_name: r.customer_name,
        sla_critical: r.sla_critical ?? null,
        sla_high: r.sla_high ?? null,
        sla_medium: r.sla_medium ?? null,
        sla_low: r.sla_low ?? null,
      })
      setRows((prev) =>
        [...prev.map((x) => (x.id === r.id ? updated : x))].sort((a, b) =>
          a.customer_name.localeCompare(b.customer_name)),
      )
    } catch (e: any) {
      setErr(e?.message ?? String(e))
    } finally {
      setSavingId(null)
    }
  }

  async function removeRow(r: CustomerSlaRecord) {
    const ok = window.confirm(`Delete SLA row for “${r.customer_name}”?`)
    if (!ok) return
    setErr(null)
    setSavingId(r.id)
    try {
      await apiDeleteCustomerSla(r.id)
      setRows((prev) => prev.filter((x) => x.id !== r.id))
    } catch (e: any) {
      setErr(e?.message ?? String(e))
    } finally {
      setSavingId(null)
    }
  }

  async function createRow() {
    const name = draft.customer_name.trim()
    if (!name) {
      setErr('Customer name is required.')
      return
    }
    setErr(null)
    setCreateBusy(true)
    try {
      const created = await apiCreateCustomerSla({
        customer_name: name,
        sla_critical: draft.sla_critical.trim() || undefined,
        sla_high: draft.sla_high.trim() || undefined,
        sla_medium: draft.sla_medium.trim() || undefined,
        sla_low: draft.sla_low.trim() || undefined,
      })
      setRows((prev) =>
        [...prev, created].sort((a, b) => a.customer_name.localeCompare(b.customer_name)),
      )
      setDraft({ customer_name: '', sla_critical: '', sla_high: '', sla_medium: '', sla_low: '' })
    } catch (e: any) {
      setErr(e?.message ?? String(e))
    } finally {
      setCreateBusy(false)
    }
  }

  if (loading) return <p className="muted small">Loading customer SLA table…</p>

  return (
    <div className="slaAdminBody">
      <p className="muted small slaAdminHint">
        Values are free text parsed by the worker (e.g. <code>14 days</code>,{' '}
        <code>30 business days</code>, <code>N/A</code>). Due dates use the Jira ticket{' '}
        <strong>created</strong> timestamp as anchor.
      </p>
      {err && <div className="errorBox slaAdminErr">{err}</div>}
      <div className="slaAdminToolbar">
        <button type="button" className="btn btnSecondary btnSm" onClick={() => void load()} disabled={!!savingId || createBusy}>
          Refresh
        </button>
      </div>
      <div className="slaTableWrap">
        <table className="slaTable">
          <thead>
            <tr>
              <th>Customer</th>
              <th>Critical</th>
              <th>High</th>
              <th>Medium</th>
              <th>Low</th>
              <th />
            </tr>
          </thead>
          <tbody>
            {rows.map((r) => (
              <tr key={r.id}>
                <td>
                  <input
                    className="slaInput"
                    value={r.customer_name}
                    onChange={(e) => patchRow(r.id, { customer_name: e.target.value })}
                    aria-label={`Customer name for ${r.id}`}
                  />
                </td>
                {(['sla_critical', 'sla_high', 'sla_medium', 'sla_low'] as const).map((field) => (
                  <td key={field}>
                    <input
                      className="slaInput"
                      value={r[field] ?? ''}
                      onChange={(e) => patchRow(r.id, { [field]: e.target.value })}
                      aria-label={`${field} for ${r.customer_name}`}
                    />
                  </td>
                ))}
                <td className="slaRowActions">
                  <button
                    type="button"
                    className="btn btnSm"
                    disabled={savingId === r.id || createBusy}
                    onClick={() => void saveRow(r)}
                  >
                    Save
                  </button>
                  <button
                    type="button"
                    className="btn btnSm btnDangerGhost"
                    disabled={savingId === r.id || createBusy}
                    onClick={() => void removeRow(r)}
                  >
                    Delete
                  </button>
                </td>
              </tr>
            ))}
            <tr className="slaTableAddRow">
              <td>
                <input
                  className="slaInput"
                  placeholder="New customer"
                  value={draft.customer_name}
                  onChange={(e) => setDraft((d) => ({ ...d, customer_name: e.target.value }))}
                />
              </td>
              <td>
                <input
                  className="slaInput"
                  placeholder="Critical"
                  value={draft.sla_critical}
                  onChange={(e) => setDraft((d) => ({ ...d, sla_critical: e.target.value }))}
                />
              </td>
              <td>
                <input
                  className="slaInput"
                  placeholder="High"
                  value={draft.sla_high}
                  onChange={(e) => setDraft((d) => ({ ...d, sla_high: e.target.value }))}
                />
              </td>
              <td>
                <input
                  className="slaInput"
                  placeholder="Medium"
                  value={draft.sla_medium}
                  onChange={(e) => setDraft((d) => ({ ...d, sla_medium: e.target.value }))}
                />
              </td>
              <td>
                <input
                  className="slaInput"
                  placeholder="Low"
                  value={draft.sla_low}
                  onChange={(e) => setDraft((d) => ({ ...d, sla_low: e.target.value }))}
                />
              </td>
              <td className="slaRowActions">
                <button
                  type="button"
                  className="btn btnSm btnPrimary"
                  disabled={createBusy || !!savingId}
                  onClick={() => void createRow()}
                >
                  Add
                </button>
              </td>
            </tr>
          </tbody>
        </table>
      </div>
    </div>
  )
}

function ToolbarSlaModal({ open, onClose }: { open: boolean; onClose: () => void }) {
  useEffect(() => {
    if (!open) return
    function onKey(e: KeyboardEvent) {
      if (e.key === 'Escape') onClose()
    }
    window.addEventListener('keydown', onKey)
    return () => window.removeEventListener('keydown', onKey)
  }, [open, onClose])

  if (!open) return null
  return (
    <div className="slaModalBackdrop" role="presentation" onClick={onClose}>
      <div
        className="slaModalPanel"
        role="dialog"
        aria-modal="true"
        aria-labelledby="slaModalTitle"
        onClick={(e) => e.stopPropagation()}
      >
        <div className="slaModalHeader">
          <h2 id="slaModalTitle">Customer SLA</h2>
          <button type="button" className="slaModalClose" onClick={onClose} aria-label="Close">
            ×
          </button>
        </div>
        <div className="slaModalBody">
          <SlaAdminPanelBody />
        </div>
      </div>
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

function FindingsColumnsMenu({
  visibility,
  onChange,
}: {
  visibility: CveTableColumnVisibility
  onChange: (v: CveTableColumnVisibility) => void
}) {
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

  function toggle(key: CveTableColumnKey) {
    if (key === 'cve') return
    onChange({ ...visibility, [key]: !visibility[key] })
  }

  return (
    <div className="findingsColumnsWrap" ref={ref}>
      <button
        type="button"
        className="findingsColumnsBtn"
        aria-expanded={open}
        aria-haspopup="true"
        onClick={() => setOpen(!open)}
      >
        Columns <span className="findingsColumnsChev" aria-hidden>▾</span>
      </button>
      {open && (
        <div className="findingsColumnsPopover" role="menu" aria-label="Visible columns">
          {CVE_TABLE_COLUMN_KEYS.map((key) => (
            <label key={key} className="findingsColumnsRow">
              <input
                type="checkbox"
                checked={visibility[key]}
                disabled={key === 'cve'}
                onChange={() => toggle(key)}
              />
              <span>{CVE_TABLE_COLUMN_LABELS[key]}</span>
            </label>
          ))}
        </div>
      )}
    </div>
  )
}

function ResultsActionsMenu({
  disabled,
  onReprocess,
  onCreateAllCve,
  onCreateAllBug,
  onSync,
  missingCveCount,
  missingBugCount,
}: {
  disabled: boolean
  onReprocess: () => void
  onCreateAllCve: () => void
  onCreateAllBug: () => void
  onSync: () => void
  missingCveCount: number
  missingBugCount: number
}) {
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

  return (
    <div className="resultsActionsWrap" ref={ref}>
      <button
        type="button"
        className="resultsActionsBtn"
        aria-expanded={open}
        aria-haspopup="true"
        disabled={disabled}
        onClick={() => setOpen(!open)}
      >
        Actions <span className="resultsActionsChev" aria-hidden>▾</span>
      </button>
      {open && (
        <ul className="resultsActionsMenu" role="menu">
          <li role="none">
            <button
              type="button"
              role="menuitem"
              className="resultsActionsMenuItem"
              disabled={disabled}
              onClick={() => {
                setOpen(false)
                onReprocess()
              }}
            >
              Re-process ticket
            </button>
          </li>
          <li role="none">
            <button
              type="button"
              role="menuitem"
              className="resultsActionsMenuItem"
              disabled={disabled || missingCveCount === 0}
              title={
                missingCveCount === 0
                  ? 'No filtered rows need a new Security Vulnerability PLAT ticket'
                  : undefined
              }
              onClick={() => {
                setOpen(false)
                onCreateAllCve()
              }}
            >
              Create all CVE tickets{missingCveCount > 0 ? ` (${missingCveCount})` : ''}
            </button>
          </li>
          <li role="none">
            <button
              type="button"
              role="menuitem"
              className="resultsActionsMenuItem"
              disabled={disabled || missingBugCount === 0}
              title={
                missingBugCount === 0
                  ? 'No filtered rows need a new Bug PLAT ticket (per image)'
                  : undefined
              }
              onClick={() => {
                setOpen(false)
                onCreateAllBug()
              }}
            >
              Create all bug tickets{missingBugCount > 0 ? ` (${missingBugCount})` : ''}
            </button>
          </li>
          <li role="none">
            <button
              type="button"
              role="menuitem"
              className="resultsActionsMenuItem"
              disabled={disabled}
              title="Sync PLAT Security fields into the table; add missing CVE label and SLA due date on Jira"
              onClick={() => {
                setOpen(false)
                onSync()
              }}
            >
              Sync PLAT (Jira)
            </button>
          </li>
        </ul>
      )}
    </div>
  )
}

function platSyncProgressCounter(p: NonNullable<JobResult['_plat_sync_progress']>): string {
  const cur = p.phase_current ?? p.current
  const tot = p.phase_total ?? p.total
  if (cur != null && tot != null) {
    return `${cur}/${tot}`
  }
  return ''
}

function platSyncProgressPhaseLabel(p: NonNullable<JobResult['_plat_sync_progress']>): string {
  const phase = p.phase || ''
  if (phase.includes('Refreshing')) return 'Refreshing CVEs'
  if (phase.includes('Reading fix')) return 'Reading fix/tag'
  if (phase.includes('label')) return 'Label & due date'
  if (phase.includes('Linking')) return 'Linking to PLATFORM'
  return phase
}

function PlatSyncSummaryModal({
  open,
  stats,
  issueKey,
  warnings,
  onClose,
}: {
  open: boolean
  stats: NonNullable<JobResult['_plat_sync_stats']>
  issueKey?: string
  warnings?: string[]
  onClose: () => void
}) {
  useEffect(() => {
    if (!open) return
    const handler = (e: KeyboardEvent) => { if (e.key === 'Escape') onClose() }
    window.addEventListener('keydown', handler)
    return () => window.removeEventListener('keydown', handler)
  }, [open, onClose])

  if (!open) return null

  const ldChecked = stats.label_date_checked ?? stats.label_date_pushed ?? 0
  const ldUpdated = stats.label_date_updated ?? 0
  const labelsAdded = stats.labels_added ?? 0
  const duedatesUpdated = stats.duedates_updated ?? 0
  const lkChecked = stats.links_checked ?? 0
  const lkCreated = stats.links_created ?? stats.linked ?? 0
  const refreshed = stats.tickets_refreshed ?? 0
  const fieldsRead = stats.fields_read ?? 0

  const rows: { step: number; operation: string; checked: string; changed: string; details: string }[] = [
    {
      step: 1,
      operation: 'Refresh CVEs from Jira',
      checked: '—',
      changed: `${refreshed}`,
      details: 'PLAT tickets re-queried per CVE row',
    },
    {
      step: 2,
      operation: 'Read fix version & tag',
      checked: `${fieldsRead}`,
      changed: `${fieldsRead}`,
      details: 'Security Vuln fields fetched',
    },
    {
      step: 3,
      operation: 'Sync CVE label & due date',
      checked: `${ldChecked}`,
      changed: `${ldUpdated}`,
      details: `${labelsAdded} label${labelsAdded !== 1 ? 's' : ''} added · ${duedatesUpdated} due date${duedatesUpdated !== 1 ? 's' : ''} changed`,
    },
    {
      step: 4,
      operation: issueKey ? `Link to ${issueKey}` : 'Link to PLATFORM',
      checked: `${lkChecked}`,
      changed: `${lkCreated}`,
      details: 'PLATFORM parent link ensured',
    },
  ]

  return (
    <div className="modalOverlay" onClick={onClose} role="presentation">
      <div
        className="modalBox platSyncModalBox"
        onClick={(e) => e.stopPropagation()}
        role="dialog"
        aria-modal="true"
        aria-labelledby="platSyncModalTitle"
      >
        <div className="modalHeader">
          <span className="modalTitle" id="platSyncModalTitle">
            PLAT sync complete
            {issueKey ? <span className="platSyncModalIssueKey"> · {issueKey}</span> : null}
          </span>
          <button className="modalClose" onClick={onClose} aria-label="Close">✕</button>
        </div>
        <div className="platSyncModalBody">
          <table className="platSyncModalTable">
            <thead>
              <tr>
                <th>#</th>
                <th>Operation</th>
                <th>Checked</th>
                <th>Changed</th>
                <th>Details</th>
              </tr>
            </thead>
            <tbody>
              {rows.map((row) => (
                <tr key={row.step}>
                  <td className="platSyncModalStep">{row.step}</td>
                  <td className="platSyncModalOperation">{row.operation}</td>
                  <td className="platSyncModalNum">{row.checked}</td>
                  <td className={`platSyncModalNum${row.changed !== '0' && row.changed !== '—' ? ' platSyncModalChanged' : ''}`}>{row.changed}</td>
                  <td className="platSyncModalDetails">{row.details}</td>
                </tr>
              ))}
            </tbody>
          </table>
          {warnings && warnings.length > 0 && (
            <div className="platSyncModalWarnings">
              <span className="platSyncModalWarningsTitle">
                {warnings.length} warning{warnings.length !== 1 ? 's' : ''}
              </span>
              <ul className="platSyncModalWarningsList">
                {warnings.slice(0, 3).map((w, i) => (
                  <li key={i}>{w}</li>
                ))}
                {warnings.length > 3 && (
                  <li className="muted">…and {warnings.length - 3} more</li>
                )}
              </ul>
            </div>
          )}
        </div>
        <div className="platSyncModalFooter">
          <button type="button" className="btn btnSecondary btnSm" onClick={onClose}>
            Close
          </button>
        </div>
      </div>
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
  onJobRefresh,
  onRefreshSuggestedComment,
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
  onJobRefresh: () => Promise<JobResponse>
  /** Re-fetch saved run from the server and rebuild the suggested comment (e.g. after Sync PLAT). */
  onRefreshSuggestedComment: () => Promise<void>
  commentPosted: boolean
}) {
  const [rows, setRows] = useState<CveRow[]>([])
  const [filterText, setFilterText] = useState('')
  const [columnVisibility, setColumnVisibility] = useState<CveTableColumnVisibility>(() => ({
    ...DEFAULT_CVE_TABLE_COLUMN_VISIBILITY,
  }))
  const [platBulkBusy, setPlatBulkBusy] = useState(false)
  const [platBulkProgress, setPlatBulkProgress] = useState<{ done: number; total: number } | null>(null)
  const [platBulkErr, setPlatBulkErr] = useState<string | null>(null)
  const [platBulkErrIsWarn, setPlatBulkErrIsWarn] = useState(false)
  const [platSyncSummary, setPlatSyncSummary] = useState<JobResult['_plat_sync_stats'] | null>(null)
  const [platSyncModalOpen, setPlatSyncModalOpen] = useState(false)
  const [platSyncWarnings, setPlatSyncWarnings] = useState<string[]>([])
  const [platSyncProgress, setPlatSyncProgress] = useState<JobResult['_plat_sync_progress'] | null>(null)
  const [suggestedCommentRefreshing, setSuggestedCommentRefreshing] = useState(false)

  useEffect(() => {
    const rs = job.result?.cve_rows
    if (rs && Array.isArray(rs) && !job.status.startsWith('failed')) {
      setRows(rs)
    } else if (!job.status.startsWith('failed')) {
      setRows([])
    }
  }, [job])

  const onPlatCreated = (cveId: string, imageBasename: string, out: CreatePlatResponse) => {
    setRows((prev) => mergePlatCreateIntoRows(prev, cveId, imageBasename, out))
  }

  const onPlatBugCreated = (cveId: string, imageBasename: string, out: CreatePlatResponse) => {
    setRows((prev) => mergePlatBugCreateIntoRows(prev, cveId, imageBasename, out))
  }

  const findingsSeveritySummary = useMemo(() => aggregateSeverityLabel(rows), [rows])

  const filteredRows = useMemo(
    () => rows.filter((r) => rowMatchesCveSearch(r, filterText)),
    [rows, filterText],
  )

  const missingCveSlots = useMemo(
    () => platMissingCveCreateSlots(filteredRows),
    [filteredRows],
  )

  const missingBugSlots = useMemo(
    () => platMissingBugCreateSlots(filteredRows),
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
            sla_due_date: r.sla_due_date ?? null,
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

  async function createAllMissingPlatBugs() {
    const slots = [...missingBugSlots]
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
          const out = await apiCreatePlatBug({
            cve_id: r.cve_id,
            image_basename: slot.image_basename,
            package_name: platPackageNameForRow(r),
            package_version: ver,
            severity: r.severity,
            organizations: orgRefs,
            source_issue_key: issue.key,
            image_display: platDisplayLabelForImage(r, slot.image_basename),
            resource_label:
              (r.affected_resource ?? '').trim() ||
              platPackageNameForRow(r),
            vendor_fix_version: (r.fixed_version ?? '').trim() || null,
            sla_due_date: r.sla_due_date ?? null,
          })
          acc = mergePlatBugCreateIntoRows(acc, slot.cve_id, slot.image_basename, out)
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

  async function runPlatSync() {
    if (!job.run_id) return
    setPlatBulkErr(null)
    setPlatBulkErrIsWarn(false)
    setPlatSyncSummary(null)
    setPlatSyncModalOpen(false)
    setPlatSyncWarnings([])
    setPlatSyncProgress(null)
    setPlatBulkBusy(true)
    try {
      await apiEnqueuePlatSync(job.run_id)
      for (let attempt = 0; attempt < 120; attempt++) {
        await new Promise((r) => setTimeout(r, 1500))
        const j = await onJobRefresh()
        if (j.status === 'syncing_plat') {
          setPlatSyncProgress(j.result?._plat_sync_progress ?? null)
          continue
        }
        setPlatSyncProgress(null)
        if (j.status === 'done') {
          const pe = j.result?._plat_sync_errors
          const ss = j.result?._plat_sync_stats
          if (ss) {
            setPlatSyncSummary(ss)
            setPlatSyncWarnings(pe ?? [])
            setPlatSyncModalOpen(true)
          }
          void onRefreshSuggestedComment()
          if (pe?.length) {
            setPlatBulkErrIsWarn(true)
          }
          break
        }
        if (j.status.startsWith('failed')) {
          throw new Error(j.status)
        }
      }
    } catch (e) {
      setPlatBulkErr(e instanceof Error ? e.message : String(e))
      setPlatSyncProgress(null)
    } finally {
      setPlatBulkBusy(false)
    }
  }

  function clearCveSearch() {
    setFilterText('')
  }

  async function handleRefreshSuggestedComment() {
    if (!job.run_id || !job.result) return
    setSuggestedCommentRefreshing(true)
    try {
      await onRefreshSuggestedComment()
    } finally {
      setSuggestedCommentRefreshing(false)
    }
  }

  const findingsReady =
    !!job.result && Array.isArray(job.result.cve_rows) && !job.status.startsWith('failed')
  const exportFilename = issue.key ? `${issue.key}-cve-findings.xlsx` : 'cve-findings.xlsx'

  return (
    <div className="resultsStack">
      {platSyncSummary && (
        <PlatSyncSummaryModal
          open={platSyncModalOpen}
          stats={platSyncSummary}
          issueKey={issue.key}
          warnings={platSyncWarnings}
          onClose={() => setPlatSyncModalOpen(false)}
        />
      )}
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
        {findingsReady && (
          <div className="resultsFindingsToolbar">
            <div className="resultsFindingsToolbarMain">
              <label className="resultsFilterSearchWrap">
                <input
                  type="search"
                  className="resultsFilterSearch"
                  placeholder="Search CVE ID, resource, image, etc…"
                  value={filterText}
                  onChange={(e) => setFilterText(e.target.value)}
                  autoComplete="off"
                />
              </label>
              <FindingsColumnsMenu visibility={columnVisibility} onChange={setColumnVisibility} />
            </div>
            <div className="resultsFindingsToolbarActions">
              <ResultsActionsMenu
                disabled={loading || platBulkBusy || job.status === 'syncing_plat'}
                onReprocess={() => { void onReprocessTicket() }}
                onCreateAllCve={() => { void createAllMissingPlatCves() }}
                onCreateAllBug={() => { void createAllMissingPlatBugs() }}
                onSync={() => { void runPlatSync() }}
                missingCveCount={missingCveSlots.length}
                missingBugCount={missingBugSlots.length}
              />
              {platBulkBusy && platBulkProgress && (
                <span className="muted small">
                  Creating… {platBulkProgress.done}/{platBulkProgress.total}
                </span>
              )}
              {(platBulkBusy || job.status === 'syncing_plat') && !platBulkProgress && (
                <span className="platSyncProgressPill" role="status">
                  Syncing PLAT
                  {platSyncProgress ? (
                    <>
                      {' · '}
                      {platSyncProgressPhaseLabel(platSyncProgress)}
                      {platSyncProgressCounter(platSyncProgress)
                        ? ` ${platSyncProgressCounter(platSyncProgress)}`
                        : ''}
                    </>
                  ) : (
                    ' in Jira…'
                  )}
                </span>
              )}
              <button
                type="button"
                className="btnExport"
                onClick={() => exportCvesToExcel(filteredRows, exportFilename)}
                title="Export rows matching search to Excel"
              >
                ↓ Export Excel
              </button>
            </div>
          </div>
        )}
        {findingsReady && platBulkErr && (
          <div className={`resultsPlatBulkErr small${platBulkErrIsWarn ? '' : ' resultsPlatBulkInfo'}`} role="status">
            {platBulkErr}
          </div>
        )}
        <CveTable
          rows={filteredRows}
          issueKey={issue.key}
          platOrganizationRefs={platOrgRefsFromIssue(issue)}
          onPlatCreated={onPlatCreated}
          onPlatBugCreated={onPlatBugCreated}
          hideBuiltInToolbar={findingsReady}
          sourceRowCount={rows.length}
          onClearSearch={findingsReady && rows.length > 0 ? clearCveSearch : undefined}
          columnVisibility={columnVisibility}
        />
      </div>

      {/* Suggested comment */}
      <div className="card">
        <div className="cardHeader suggestedCommentCardHeader">
          <div className="suggestedCommentHeaderLeft">
            <span className="cardTitle">Suggested comment</span>
            {commentPosted && (
              <span className="statusBadge statusDone" style={{ fontSize: 11 }}>
                Posted to Jira
              </span>
            )}
          </div>
          <button
            type="button"
            className="btn btnSecondary btnSm"
            disabled={
              loading ||
              suggestedCommentRefreshing ||
              !job.result ||
              job.status.startsWith('failed')
            }
            title="Reload the saved analysis run from the server and rebuild this draft (includes latest PLAT sync fields)."
            onClick={() => void handleRefreshSuggestedComment()}
          >
            {suggestedCommentRefreshing ? 'Refreshing…' : 'Refresh draft'}
          </button>
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
            Push to Jira as comment
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
  const [jiraBrowseUrl, setJiraBrowseUrl] = useState('')
  const [removeBusyKey, setRemoveBusyKey] = useState<string | null>(null)

  const loadSummaries = useCallback(async () => {
    setError(null)
    setLoading(true)
    try {
      const data = await apiGet<IssueCveStatusSummary[]>('/api/jobs/cve-status')
      setSummaries(data)
    } catch (e: unknown) {
      setError(e instanceof Error ? e.message : String(e))
    } finally {
      setLoading(false)
    }
  }, [])

  useEffect(() => {
    void loadSummaries()
  }, [loadSummaries])

  useEffect(() => {
    let alive = true
    apiGetClientConfig()
      .then((c) => {
        if (!alive) return
        setJiraBrowseUrl((c.jira_browse_url ?? '').trim().replace(/\/$/, ''))
      })
      .catch(() => {
        if (!alive) return
        setJiraBrowseUrl('')
      })
    return () => {
      alive = false
    }
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
                      <span className="dashIssueActionBtns">
                        <button
                          type="button"
                          className="btn btnSecondary btnSm dashIssueOpenBtn"
                          onClick={(e) => {
                            e.preventDefault()
                            e.stopPropagation()
                            onOpen(s.issue_key, s.run_id)
                          }}
                        >
                          Open
                        </button>
                        {jiraBrowseUrl ? (
                          <a
                            className="btn btnSecondary btnSm dashIssueOpenBtn"
                            href={`${jiraBrowseUrl}/${encodeURIComponent(s.issue_key)}`}
                            target="_blank"
                            rel="noreferrer"
                            title="Open in Jira"
                            onClick={(e) => e.stopPropagation()}
                          >
                            Open on Jira
                          </a>
                        ) : (
                          <button
                            type="button"
                            className="btn btnSecondary btnSm dashIssueOpenBtn"
                            disabled
                            title="Jira URL not configured on server"
                          >
                            Open on Jira
                          </button>
                        )}
                        <button
                          type="button"
                          className="btn btnDangerGhost btnSm dashIssueOpenBtn"
                          disabled={removeBusyKey !== null}
                          title="Remove saved runs for this ticket from the CVE portal database"
                          onClick={(e) => {
                            e.preventDefault()
                            e.stopPropagation()
                            const msg =
                              `Remove all saved analysis runs for ${s.issue_key} from the portal database? ` +
                              'This does not change Jira. This cannot be undone.'
                            if (!window.confirm(msg)) return
                            setRemoveBusyKey(s.issue_key)
                            setError(null)
                            apiDeleteProcessingRunsForIssue(s.issue_key)
                              .then(() => loadSummaries())
                              .catch((err: unknown) =>
                                setError(err instanceof Error ? err.message : String(err)),
                              )
                              .finally(() => setRemoveBusyKey(null))
                          }}
                        >
                          {removeBusyKey === s.issue_key ? 'Removing…' : 'Remove'}
                        </button>
                      </span>
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

function HealthDot({ h }: { h: ComponentHealth }) {
  const ok = h.status === 'ok'
  const warn = h.status === 'no_workers'
  const cls = ok ? 'healthDotOk' : warn ? 'healthDotWarn' : 'healthDotErr'
  const label = ok ? 'OK' : warn ? 'No workers' : 'Error'
  return (
    <span className={`healthDot ${cls}`} title={h.detail ?? label}>
      {label}
      {h.workers && h.workers.length > 0 && (
        <span className="healthWorkerCount"> ({h.workers.length})</span>
      )}
    </span>
  )
}

function AboutModal({ open, onClose, info, loading }: {
  open: boolean
  onClose: () => void
  info: AboutInfo | null
  loading: boolean
}) {
  if (!open) return null
  const backendPkgs = info?.packages ?? {}
  const buildTime = __UI_BUILD_TIME__
  const commitShort = info?.git_commit ? info.git_commit.slice(0, 8) : null
  const components = info?.components
  return (
    <div className="modalOverlay" onClick={onClose}>
      <div className="modalBox aboutModalBox" onClick={(e) => e.stopPropagation()}>
        <div className="modalHeader">
          <span className="modalTitle">About CVE Portal</span>
          <button className="modalClose" onClick={onClose} aria-label="Close">✕</button>
        </div>
        <div className="aboutBody">
          {loading && <p className="muted small">Loading…</p>}

          {/* ── Version hero ── */}
          <div className="aboutVersionHero">
            <span className="aboutVersionNumber">v{info?.portal_version ?? __UI_VERSION__}</span>
            {commitShort && (
              <code className="aboutCommitBadge">{commitShort}</code>
            )}
          </div>

          {/* ── Component health ── */}
          {components && (
            <section className="aboutSection">
              <h4 className="aboutSectionTitle">Components</h4>
              <table className="aboutTable">
                <tbody>
                  <tr><td>PostgreSQL</td><td><HealthDot h={components.postgres} /></td></tr>
                  <tr><td>Redis</td><td><HealthDot h={components.redis} /></td></tr>
                  <tr><td>Celery worker</td><td><HealthDot h={components.celery_worker} /></td></tr>
                </tbody>
              </table>
            </section>
          )}

          {/* ── Frontend ── */}
          <section className="aboutSection">
            <h4 className="aboutSectionTitle">Frontend</h4>
            <table className="aboutTable">
              <tbody>
                <tr><td>Build time</td><td>{new Date(buildTime).toLocaleString()}</td></tr>
                <tr><td>React</td><td>{__REACT_VERSION__}</td></tr>
                <tr><td>TypeScript</td><td>{__TS_VERSION__}</td></tr>
                <tr><td>Vite</td><td>{__VITE_VERSION__}</td></tr>
              </tbody>
            </table>
          </section>

          {/* ── Backend packages ── */}
          {info && (
            <section className="aboutSection">
              <h4 className="aboutSectionTitle">Backend (Python {info.python_version})</h4>
              <table className="aboutTable">
                <tbody>
                  {Object.entries(backendPkgs).map(([name, ver]) => (
                    <tr key={name}><td>{name}</td><td>{ver}</td></tr>
                  ))}
                </tbody>
              </table>
            </section>
          )}
        </div>
      </div>
    </div>
  )
}

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
  const [slaToolbarOpen, setSlaToolbarOpen] = useState(false)
  const [aboutOpen, setAboutOpen]     = useState(false)
  const [aboutInfo, setAboutInfo]     = useState<AboutInfo | null>(null)
  const [aboutLoading, setAboutLoading] = useState(false)

  const openAbout = useCallback(async () => {
    setAboutOpen(true)
    if (aboutInfo) return
    setAboutLoading(true)
    try {
      setAboutInfo(await apiGetAbout())
    } catch {
      // non-fatal
    } finally {
      setAboutLoading(false)
    }
  }, [aboutInfo])

  const closeSlaModal = useCallback(() => setSlaToolbarOpen(false), [])

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

  const refreshJob = useCallback(async () => {
    if (!runId) throw new Error('No run id')
    const j = await apiGet<JobResponse>(`/api/jobs/${runId}`)
    setJob(j)
    return j
  }, [runId])

  const refreshSuggestedComment = useCallback(async () => {
    if (!runId) return
    setError(null)
    try {
      const j = await refreshJob()
      setCommentPosted(false)
      if (j.result) setCommentBody(buildSuggestedComment(j.result))
    } catch (e: any) {
      setError(e?.message ?? String(e))
    }
  }, [runId, refreshJob])

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
            type="button"
            className="topNavItem"
            onClick={() => setSlaToolbarOpen(true)}
          >
            Customer SLA
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
          <button type="button" className="topNavLink topNavLinkBtn" onClick={() => void openAbout()}>About</button>
        </div>
      </header>

      <ToolbarSlaModal open={slaToolbarOpen} onClose={closeSlaModal} />
      <AboutModal open={aboutOpen} onClose={() => setAboutOpen(false)} info={aboutInfo} loading={aboutLoading} />

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

            {issue && !showResults && (
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
                onJobRefresh={refreshJob}
                onRefreshSuggestedComment={refreshSuggestedComment}
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
