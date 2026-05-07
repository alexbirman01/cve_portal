import { useEffect, useMemo, useState } from 'react'
import './App.css'
import {
  apiGet,
  apiPost,
  buildSuggestedComment,
  formatStatus,
  sortCveRows,
  statusSteps,
  type CveRow,
  type HistoryRun,
  type IssueResponse,
  type JobResponse,
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

function ConfBadge({ conf }: { conf?: string | null }) {
  const c = conf?.toLowerCase()
  const cls = c === 'high' ? 'confHigh' : c === 'medium' ? 'confMedium' : 'confLow'
  return <span className={`confBadge ${cls}`}>{conf ?? 'low'}</span>
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

// ─── CVE table ───────────────────────────────────────────────────────────────

function CveTable({ rows }: { rows: CveRow[] }) {
  const sorted = useMemo(() => sortCveRows(rows), [rows])
  if (!sorted.length) return <div className="muted small">No CVEs found.</div>
  return (
    <div className="cveTableWrap">
      <table className="cveTable">
          <thead>
          <tr>
            <th style={{ minWidth: 160 }}>CVE ID</th>
            <th style={{ minWidth: 110 }}>PLAT Ticket</th>
            <th style={{ minWidth: 100 }}>Severity</th>
            <th style={{ minWidth: 190 }}>Affected Image : Tag</th>
            <th style={{ minWidth: 140 }}>Resource</th>
            <th style={{ minWidth: 110 }}>Affected Ver.</th>
            <th style={{ minWidth: 110 }}>Fixed Version</th>
            <th style={{ minWidth: 90 }}>Confidence</th>
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
              <td>
                {r.plat_ticket
                  ? <a className="platTicketPill" href={`https://plainid.atlassian.net/browse/${r.plat_ticket}`} target="_blank" rel="noreferrer">{r.plat_ticket}</a>
                  : <Dash />}
              </td>
              <td><SevBadge sev={r.severity} score={r.score} /></td>
              <td>
                {r.affected_image && r.affected_image !== 'NA'
                  ? <span className="mono">{r.affected_image.replace(/^plainid\//i, '')}{r.affected_tag ? `:${r.affected_tag}` : ''}</span>
                  : <Dash />}
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
              <td><ConfBadge conf={r.confidence} /></td>
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
          <div className="metaItem">Project <span>{issue.project ?? '—'}</span></div>
          <div className="metaItem">Type <span>{issue.issuetype ?? '—'}</span></div>
          <div className="metaItem">Attachments <span>{issue.attachments?.length ?? 0}</span></div>
          {issue.reporter && (
            <div className="metaItem">Reporter <span>{issue.reporter}</span></div>
          )}
          {(issue.organizations?.length ?? 0) > 0 && (
            <div className="metaItem">Organizations <span>{issue.organizations!.join(', ')}</span></div>
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

// ─── results panel ───────────────────────────────────────────────────────────

function ResultsPanel({
  issue,
  job,
  loading,
  commentBody,
  onCommentChange,
  onPushComment,
  onBack,
  commentPosted,
}: {
  issue: IssueResponse
  job: JobResponse
  loading: boolean
  commentBody: string
  onCommentChange: (v: string) => void
  onPushComment: () => void
  onBack: () => void
  commentPosted: boolean
}) {
  const rows: CveRow[] = job.result?.cve_rows ?? []
  return (
    <div className="resultsStack">
      {/* Results header — compact single row */}
      <div className="resultsBar">
        <button className="resultsBarBack" onClick={onBack}>←</button>
        <span className="resultsBarKey">{issue.key}</span>
        <span className="resultsBarSep">·</span>
        <span className="resultsBarTitle">{issue.summary ?? '—'}</span>
        <span className="resultsBarMeta">
          <span>{issue.issuetype}</span>
          <span className="resultsBarDot">·</span>
          <span>{issue.project}</span>
          {(issue.attachments?.length ?? 0) > 0 && (
            <><span className="resultsBarDot">·</span><span>{issue.attachments.length} attachment{issue.attachments.length !== 1 ? 's' : ''}</span></>
          )}
        </span>
        <StatusBadge status={job.status} />
      </div>

      {/* CVE table */}
      <div className="card">
        <div className="cardHeader">
          <span className="cardTitle">CVE Findings ({rows.length})</span>
        </div>
        <CveTable rows={rows} />
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

// ─── history view ────────────────────────────────────────────────────────────

function HistoryView({ onOpen }: { onOpen: (issueKey: string, runId: string) => void }) {
  const [runs, setRuns] = useState<HistoryRun[]>([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)

  useEffect(() => {
    let alive = true
    apiGet<HistoryRun[]>('/api/jobs')
      .then((data) => { if (alive) setRuns(data) })
      .catch((e) => { if (alive) setError(e?.message ?? String(e)) })
      .finally(() => { if (alive) setLoading(false) })
    return () => { alive = false }
  }, [])

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

  return (
    <div className="card historyCard">
      <div className="cardHeader">
        <span className="cardTitle">Recent processing runs</span>
        {!loading && <span className="muted small">{runs.length} runs</span>}
      </div>

      {loading && <div className="muted small">Loading…</div>}
      {error && <div className="errorBox">{error}</div>}

      {!loading && !error && runs.length === 0 && (
        <div className="muted small">No runs yet. Fetch a ticket and start processing.</div>
      )}

      {!loading && runs.length > 0 && (
        <table className="historyTable">
          <thead>
            <tr>
              <th>Ticket</th>
              <th>Status</th>
              <th>CVEs</th>
              <th>When</th>
              <th></th>
            </tr>
          </thead>
          <tbody>
            {runs.map((r) => (
              <tr key={r.run_id}>
                <td>
                  <span className="mono" style={{ color: 'rgba(99,130,241,1)', fontWeight: 700 }}>
                    {r.issue_key}
                  </span>
                </td>
                <td><StatusBadge status={r.status} /></td>
                <td>
                  {r.cve_count != null
                    ? <span className="cvePill">{r.cve_count} CVE{r.cve_count !== 1 ? 's' : ''}</span>
                    : <span className="dash">—</span>}
                </td>
                <td><span className="muted small">{relativeTime(r.created_at)}</span></td>
                <td>
                  {r.status === 'done' && (
                    <button
                      className="btn btnSecondary"
                      style={{ padding: '4px 12px', fontSize: 12 }}
                      onClick={() => onOpen(r.issue_key, r.run_id)}
                    >
                      Open
                    </button>
                  )}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </div>
  )
}

// ─── main app ────────────────────────────────────────────────────────────────

type Page = 'new' | 'history'

function App() {
  const [page, setPage]               = useState<Page>('new')
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

  async function fetchIssue() {
    setError(null)
    setLoading(true)
    setIssue(null)
    setRunId(null)
    setJob(null)
    setViewMode('ticket')
    setCommentPosted(false)
    try {
      const data = await apiGet<IssueResponse>(`/api/issues/${issueKey.trim()}`)
      setIssue(data)
    } catch (e: any) {
      setError(e?.message ?? String(e))
    } finally {
      setLoading(false)
    }
  }

  async function startProcessing() {
    if (!issue) return
    setError(null)
    setLoading(true)
    setRunId(null)
    setJob(null)
    setViewMode('ticket')
    setCommentPosted(false)
    try {
      const res = await apiPost<ProcessResponse>(`/api/issues/${issue.key}/process`, {})
      setRunId(res.run_id)
    } catch (e: any) {
      setError(e?.message ?? String(e))
    } finally {
      setLoading(false)
    }
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
      {/* ── Side nav ── */}
      <nav className="sideNav">
        <div className="sideNavLogo">
          <div>
            <img src="/plainid-logo.svg" alt="PlainID" className="sideNavLogoImg" />
            <div className="sideNavLogoSub">CVE Portal · Security Team</div>
          </div>
        </div>

        <div className="sideNavItems">
          <button
            className={`sideNavItem ${page === 'new' ? 'sideNavItemActive' : ''}`}
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
            <span className="sideNavIcon">＋</span> New
          </button>
          <button
            className={`sideNavItem ${page === 'history' ? 'sideNavItemActive' : ''}`}
            onClick={() => setPage('history')}
          >
            <span className="sideNavIcon">⏱</span> History
          </button>
        </div>

        <div className="sideNavFooter">
          <a
            className="sideNavFooterLink"
            href="https://nvd.nist.gov/"
            target="_blank"
            rel="noreferrer"
          >
            NVD ↗
          </a>
          <a
            className="sideNavFooterLink"
            href="https://plainid.atlassian.net/jira/projects"
            target="_blank"
            rel="noreferrer"
          >
            Jira ↗
          </a>
        </div>
      </nav>

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

        {/* ── HISTORY page ── */}
        {page === 'history' && (
          <HistoryView onOpen={openFromHistory} />
        )}
      </main>
    </div>
  )
}

export default App
