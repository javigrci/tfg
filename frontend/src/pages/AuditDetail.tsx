import { useState } from 'react'
import { useParams, useNavigate } from 'react-router-dom'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import {
  ArrowLeft, Play, Loader2, Shield, Terminal,
  ChevronDown, ChevronRight, AlertTriangle, Info, FileDown,
} from 'lucide-react'
import { toast } from 'sonner'
import api from '@/lib/api'
import type { Audit, Finding, FindingStatus, SeverityLevel, RiskLevel } from '@/types'

// ── Severity helpers ──────────────────────────────────────────────────────────

const SEV_STYLES: Record<SeverityLevel | RiskLevel, string> = {
  critical: 'bg-red-500/10 text-red-400 border border-red-500/20',
  high:     'bg-orange-500/10 text-orange-400 border border-orange-500/20',
  medium:   'bg-yellow-500/10 text-yellow-400 border border-yellow-500/20',
  low:      'bg-blue-500/10 text-blue-400 border border-blue-500/20',
  info:     'bg-slate-500/10 text-slate-400 border border-slate-500/20',
}

const SEV_DOT: Record<SeverityLevel | RiskLevel, string> = {
  critical: 'bg-red-400',
  high:     'bg-orange-400',
  medium:   'bg-yellow-400',
  low:      'bg-blue-400',
  info:     'bg-slate-400',
}

const STATUS_STYLES: Record<string, string> = {
  completed: 'bg-green-500/10 text-green-400 border border-green-500/20',
  running:   'bg-blue-500/10 text-blue-400 border border-blue-500/20',
  failed:    'bg-red-500/10 text-red-400 border border-red-500/20',
  pending:   'bg-slate-500/10 text-slate-400 border border-slate-500/20',
  draft:     'bg-slate-500/10 text-slate-400 border border-slate-500/20',
}

const FINDING_STATUS_STYLES: Record<FindingStatus, string> = {
  open:           'bg-slate-500/10 text-slate-400 border border-slate-500/20',
  in_progress:    'bg-blue-500/10 text-blue-400 border border-blue-500/20',
  resolved:       'bg-green-500/10 text-green-400 border border-green-500/20',
  false_positive: 'bg-yellow-500/10 text-yellow-400 border border-yellow-500/20',
}

const FINDING_STATUS_LABELS: Record<FindingStatus, string> = {
  open:           'Open',
  in_progress:    'In Progress',
  resolved:       'Resolved',
  false_positive: 'False Positive',
}

const TOOL_COLORS: Record<string, string> = {
  nmap:    'bg-purple-500/10 text-purple-400 border border-purple-500/20',
  wapiti:  'bg-cyan-500/10 text-cyan-400 border border-cyan-500/20',
  nuclei:  'bg-pink-500/10 text-pink-400 border border-pink-500/20',
  nikto:   'bg-orange-500/10 text-orange-400 border border-orange-500/20',
  bash:    'bg-slate-500/10 text-slate-400 border border-slate-500/20',
}

function StatusBadge({ status }: { status: FindingStatus }) {
  return (
    <span className={`inline-flex items-center rounded-full px-2.5 py-0.5 text-xs font-medium ${FINDING_STATUS_STYLES[status]}`}>
      {FINDING_STATUS_LABELS[status]}
    </span>
  )
}

function SeverityBadge({ severity }: { severity: SeverityLevel | RiskLevel }) {
  return (
    <span className={`inline-flex items-center gap-1.5 rounded-full px-2.5 py-0.5 text-xs font-medium capitalize ${SEV_STYLES[severity]}`}>
      <span className={`h-1.5 w-1.5 rounded-full ${SEV_DOT[severity]}`} />
      {severity}
    </span>
  )
}

function KpiCard({ label, value, sub }: { label: string; value: string | number; sub?: string }) {
  return (
    <div className="rounded-xl border border-border bg-card p-4 space-y-1">
      <p className="text-xs font-medium uppercase tracking-wider text-muted-foreground">{label}</p>
      <p className="text-2xl font-bold text-foreground">{value}</p>
      {sub && <p className="text-xs text-muted-foreground">{sub}</p>}
    </div>
  )
}

// ── FindingRow ────────────────────────────────────────────────────────────────

function FindingRow({ finding, auditId }: { finding: Finding; auditId: string | undefined }) {
  const [open, setOpen] = useState(false)
  const qc = useQueryClient()

  const statusMutation = useMutation({
    mutationFn: (newStatus: FindingStatus) =>
      api.patch(`/findings/${finding.id}/status`, { status: newStatus }).then(r => r.data),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['audit', auditId] })
      toast.success('Status updated')
    },
    onError: () => toast.error('Failed to update status'),
  })

  return (
    <>
      <tr
        className="cursor-pointer hover:bg-muted/20 transition-colors"
        onClick={() => setOpen(v => !v)}
      >
        <td className="px-4 py-3">
          {open
            ? <ChevronDown className="h-3.5 w-3.5 text-muted-foreground" />
            : <ChevronRight className="h-3.5 w-3.5 text-muted-foreground" />}
        </td>
        <td className="px-4 py-3 font-medium text-foreground text-sm">{finding.title}</td>
        <td className="px-4 py-3"><SeverityBadge severity={finding.severity} /></td>
        <td className="px-4 py-3 text-xs text-muted-foreground capitalize">{finding.category.replace(/_/g, ' ')}</td>
        <td className="px-4 py-3" onClick={e => e.stopPropagation()}>
          <StatusBadge status={finding.status} />
        </td>
      </tr>
      {open && (
        <tr className="bg-muted/10">
          <td colSpan={5} className="px-6 py-4">
            <div className="space-y-3 text-sm">
              <div>
                <p className="text-xs font-medium uppercase tracking-wider text-muted-foreground mb-1">Description</p>
                <p className="text-foreground">{finding.description}</p>
              </div>
              {finding.evidence && (
                <div>
                  <p className="text-xs font-medium uppercase tracking-wider text-muted-foreground mb-1">Evidence</p>
                  <pre className="rounded-lg bg-background border border-border px-3 py-2 text-xs font-mono text-muted-foreground whitespace-pre-wrap">{finding.evidence}</pre>
                </div>
              )}
              <div>
                <p className="text-xs font-medium uppercase tracking-wider text-muted-foreground mb-1">Recommendation</p>
                <p className="text-foreground">{finding.recommendation}</p>
              </div>
              {finding.notes && (
                <div>
                  <p className="text-xs font-medium uppercase tracking-wider text-muted-foreground mb-1">Analyst Notes</p>
                  <p className="text-foreground">{finding.notes}</p>
                </div>
              )}
              {/* Status control */}
              <div className="flex items-center gap-3 pt-1 border-t border-border">
                <p className="text-xs font-medium uppercase tracking-wider text-muted-foreground">Status</p>
                <select
                  value={finding.status}
                  disabled={statusMutation.isPending}
                  onChange={e => statusMutation.mutate(e.target.value as FindingStatus)}
                  className="rounded-md border border-border bg-background px-2 py-1 text-xs text-foreground focus:outline-none focus:ring-1 focus:ring-blue-500 disabled:opacity-50"
                >
                  {(['open', 'in_progress', 'resolved', 'false_positive'] as FindingStatus[]).map(s => (
                    <option key={s} value={s}>{FINDING_STATUS_LABELS[s]}</option>
                  ))}
                </select>
                {statusMutation.isPending && <Loader2 className="h-3.5 w-3.5 animate-spin text-muted-foreground" />}
              </div>
            </div>
          </td>
        </tr>
      )}
    </>
  )
}

// ── Main component ────────────────────────────────────────────────────────────

export default function AuditDetail() {
  const { id } = useParams<{ id: string }>()
  const navigate = useNavigate()
  const qc = useQueryClient()

  const { data: audit, isLoading, isError } = useQuery<Audit>({
    queryKey: ['audit', id],
    queryFn: () => api.get(`/audits/${id}`).then(r => r.data),
  })

  const runMutation = useMutation({
    mutationFn: () => api.post(`/audits/${id}/run`).then(r => r.data),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['audit', id] })
      qc.invalidateQueries({ queryKey: ['audits'] })
      toast.success('Audit completed successfully')
    },
    onError: () => toast.error('Audit execution failed'),
  })

  const [pdfLoading, setPdfLoading] = useState(false)

  const handleDownloadPdf = async () => {
    if (pdfLoading) return
    setPdfLoading(true)
    try {
      const response = await api.get(`/audits/${id}/report/pdf`, { responseType: 'blob' })
      const blob = new Blob([response.data], { type: 'application/pdf' })
      const url  = URL.createObjectURL(blob)
      const a    = document.createElement('a')
      a.href     = url
      a.download = `audit_report_${id}.pdf`
      document.body.appendChild(a)
      a.click()
      document.body.removeChild(a)
      URL.revokeObjectURL(url)
      toast.success('PDF downloaded')
    } catch {
      toast.error('Failed to generate PDF')
    } finally {
      setPdfLoading(false)
    }
  }

  if (isLoading) {
    return (
      <div className="flex items-center justify-center py-24 text-muted-foreground">
        <Loader2 className="h-5 w-5 animate-spin mr-2" />
        Loading audit…
      </div>
    )
  }

  if (isError || !audit) {
    return (
      <div className="flex flex-col items-center justify-center py-24 gap-3 text-muted-foreground">
        <AlertTriangle className="h-8 w-8 text-destructive" />
        <p className="text-sm">Audit not found or failed to load.</p>
        <button onClick={() => navigate('/audits')} className="text-sm text-blue-400 hover:underline">
          Back to audits
        </button>
      </div>
    )
  }

  const allFindings = audit.scans.flatMap(s => s.findings)
  const report = audit.report
  const canRun = audit.status !== 'running'

  return (
    <div className="space-y-6">

      {/* Header */}
      <div className="flex items-start justify-between gap-4">
        <div className="flex items-start gap-3">
          <button
            onClick={() => navigate('/audits')}
            className="mt-1 rounded-md p-1.5 text-muted-foreground hover:text-foreground hover:bg-muted/40 transition-colors"
          >
            <ArrowLeft className="h-4 w-4" />
          </button>
          <div>
            <div className="flex items-center gap-3">
              <h1 className="text-2xl font-semibold text-foreground">{audit.name}</h1>
              <span className={`inline-flex items-center rounded-full px-2.5 py-0.5 text-xs font-medium capitalize ${STATUS_STYLES[audit.status]}`}>
                {audit.status}
              </span>
            </div>
            {audit.description && (
              <p className="text-sm text-muted-foreground mt-1">{audit.description}</p>
            )}
            <p className="text-xs text-muted-foreground mt-1">
              Target: <span className="font-medium text-foreground font-mono">{audit.target.address}</span>
              {' · '}Tools: <span className="font-medium text-foreground">{audit.selected_modules.join(', ')}</span>
            </p>
          </div>
        </div>
        <div className="flex items-center gap-2 shrink-0">
          {report && (
            <button
              onClick={handleDownloadPdf}
              disabled={pdfLoading}
              className="flex items-center gap-2 rounded-lg border border-border bg-card px-4 py-2 text-sm font-medium text-foreground hover:bg-muted/40 transition-colors disabled:opacity-50 disabled:cursor-not-allowed"
            >
              {pdfLoading
                ? <Loader2 className="h-4 w-4 animate-spin" />
                : <FileDown className="h-4 w-4" />}
              Export PDF
            </button>
          )}
          <button
            onClick={() => runMutation.mutate()}
            disabled={!canRun || runMutation.isPending}
            className="flex items-center gap-2 rounded-lg bg-blue-500 px-4 py-2 text-sm font-medium text-white hover:bg-blue-600 transition-colors disabled:opacity-50 disabled:cursor-not-allowed"
          >
            {runMutation.isPending
              ? <Loader2 className="h-4 w-4 animate-spin" />
              : <Play className="h-4 w-4" />}
            Run Audit
          </button>
        </div>
      </div>

      {/* KPIs */}
      <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-6 gap-3">
        <div className="col-span-2 sm:col-span-1">
          {report
            ? <KpiCard label="Risk Level" value={report.risk_level.toUpperCase()} />
            : <KpiCard label="Risk Level" value="—" sub="Not run yet" />}
        </div>
        <KpiCard label="Total" value={report?.total_findings ?? 0} sub="findings" />
        <KpiCard label="Critical" value={report?.critical_count ?? 0} />
        <KpiCard label="High" value={report?.high_count ?? 0} />
        <KpiCard label="Medium" value={report?.medium_count ?? 0} />
        <KpiCard label="Low" value={report?.low_count ?? 0} />
      </div>

      {/* Body */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">

        {/* Left — Findings */}
        <div className="lg:col-span-2 space-y-6">

          {/* Scans timeline */}
          <div className="rounded-xl border border-border bg-card overflow-hidden">
            <div className="px-4 py-3 border-b border-border">
              <h2 className="text-sm font-semibold text-foreground flex items-center gap-2">
                <Terminal className="h-4 w-4 text-muted-foreground" />
                Execution Timeline
              </h2>
            </div>
            {audit.scans.length === 0 ? (
              <div className="px-4 py-8 text-center text-sm text-muted-foreground">
                No scans yet. Run the audit to start scanning.
              </div>
            ) : (
              <div className="divide-y divide-border">
                {audit.scans.map(scan => (
                  <div key={scan.id} className="px-4 py-3 flex items-center gap-3">
                    <span className={`inline-flex items-center rounded-md px-2 py-0.5 text-xs font-medium uppercase ${TOOL_COLORS[scan.tool] ?? TOOL_COLORS.bash}`}>
                      {scan.tool}
                    </span>
                    <span className={`inline-flex items-center rounded-full px-2 py-0.5 text-xs capitalize ${STATUS_STYLES[scan.status]}`}>
                      {scan.status}
                    </span>
                    <span className="text-xs font-mono text-muted-foreground truncate flex-1">
                      {scan.command ?? '—'}
                    </span>
                    <span className="text-xs text-muted-foreground shrink-0">
                      {scan.findings.length} finding{scan.findings.length !== 1 ? 's' : ''}
                    </span>
                  </div>
                ))}
              </div>
            )}
          </div>

          {/* Findings table */}
          <div className="rounded-xl border border-border bg-card overflow-hidden">
            <div className="px-4 py-3 border-b border-border flex items-center justify-between">
              <h2 className="text-sm font-semibold text-foreground flex items-center gap-2">
                <Shield className="h-4 w-4 text-muted-foreground" />
                Findings
                {allFindings.length > 0 && (
                  <span className="ml-1 rounded-full bg-muted px-2 py-0.5 text-xs text-muted-foreground">
                    {allFindings.length}
                  </span>
                )}
              </h2>
              {/* Severity summary */}
              {report && allFindings.length > 0 && (
                <div className="flex items-center gap-2">
                  {(['critical', 'high', 'medium', 'low'] as SeverityLevel[]).map(sev => {
                    const count = allFindings.filter(f => f.severity === sev).length
                    if (count === 0) return null
                    return <SeverityBadge key={sev} severity={sev} />
                  })}
                </div>
              )}
            </div>
            {allFindings.length === 0 ? (
              <div className="px-4 py-8 text-center text-sm text-muted-foreground">
                No findings yet.
              </div>
            ) : (
              <table className="w-full text-sm">
                <thead>
                  <tr className="border-b border-border bg-muted/30 text-xs uppercase tracking-wider text-muted-foreground">
                    <th className="px-4 py-2 w-8" />
                    <th className="px-4 py-2 text-left">Title</th>
                    <th className="px-4 py-2 text-left">Severity</th>
                    <th className="px-4 py-2 text-left">Category</th>
                    <th className="px-4 py-2 text-left">Status</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-border">
                  {allFindings.map(finding => (
                    <FindingRow key={finding.id} finding={finding} auditId={id} />
                  ))}
                </tbody>
              </table>
            )}
          </div>
        </div>

        {/* Right — Target info + Report */}
        <div className="space-y-4">

          {/* Target info */}
          <div className="rounded-xl border border-border bg-card p-4 space-y-3">
            <h2 className="text-sm font-semibold text-foreground">System Information</h2>
            <div className="space-y-2 text-sm">
              <div className="flex justify-between">
                <span className="text-muted-foreground">Name</span>
                <span className="font-medium text-foreground">{audit.target.name}</span>
              </div>
              <div className="flex justify-between">
                <span className="text-muted-foreground">Address</span>
                <span className="font-mono text-foreground">{audit.target.address}</span>
              </div>
              <div className="flex justify-between">
                <span className="text-muted-foreground">Environment</span>
                <span className="capitalize text-foreground">{audit.target.environment}</span>
              </div>
              <div className="flex justify-between">
                <span className="text-muted-foreground">Status</span>
                <span className="capitalize text-foreground">{audit.target.status}</span>
              </div>
            </div>
            {Object.keys(audit.target.details).length > 0 && (
              <div>
                <p className="text-xs font-medium uppercase tracking-wider text-muted-foreground mb-2">Metadata</p>
                <pre className="rounded-lg bg-background border border-border px-3 py-2 text-xs font-mono text-muted-foreground whitespace-pre-wrap">
                  {JSON.stringify(audit.target.details, null, 2)}
                </pre>
              </div>
            )}
          </div>

          {/* Report */}
          {report ? (
            <div className="rounded-xl border border-border bg-card p-4 space-y-3">
              <div className="flex items-center justify-between">
                <h2 className="text-sm font-semibold text-foreground">Report</h2>
                <SeverityBadge severity={report.risk_level} />
              </div>
              {report.summary && (
                <p className="text-sm text-muted-foreground">{report.summary}</p>
              )}
              <div className="grid grid-cols-2 gap-2">
                {([
                  ['Critical', report.critical_count, 'text-red-400'],
                  ['High',     report.high_count,     'text-orange-400'],
                  ['Medium',   report.medium_count,   'text-yellow-400'],
                  ['Low',      report.low_count,       'text-blue-400'],
                ] as [string, number, string][]).map(([label, count, color]) => (
                  <div key={label} className="rounded-lg bg-muted/30 px-3 py-2">
                    <p className={`text-lg font-bold ${color}`}>{count}</p>
                    <p className="text-xs text-muted-foreground">{label}</p>
                  </div>
                ))}
              </div>
              <p className="text-xs text-muted-foreground">
                Generated {new Date(report.created_at).toLocaleDateString('en-GB', {
                  day: '2-digit', month: 'short', year: 'numeric',
                })}
              </p>
            </div>
          ) : (
            <div className="rounded-xl border border-border bg-card p-4 flex items-start gap-3">
              <Info className="h-4 w-4 text-muted-foreground shrink-0 mt-0.5" />
              <p className="text-sm text-muted-foreground">
                No report yet. Run the audit to generate one.
              </p>
            </div>
          )}

          {/* Audit metadata */}
          <div className="rounded-xl border border-border bg-card p-4 space-y-2 text-sm">
            <h2 className="text-sm font-semibold text-foreground mb-3">Audit Info</h2>
            <div className="flex justify-between">
              <span className="text-muted-foreground">Created by</span>
              <span className="text-foreground">{audit.created_by.username}</span>
            </div>
            <div className="flex justify-between">
              <span className="text-muted-foreground">Type</span>
              <span className="capitalize text-foreground">{audit.audit_type.replace(/_/g, ' ')}</span>
            </div>
            <div className="flex justify-between">
              <span className="text-muted-foreground">Created</span>
              <span className="text-foreground">
                {new Date(audit.created_at).toLocaleDateString('en-GB', { day: '2-digit', month: 'short', year: 'numeric' })}
              </span>
            </div>
            {audit.started_at && (
              <div className="flex justify-between">
                <span className="text-muted-foreground">Last run</span>
                <span className="text-foreground">
                  {new Date(audit.started_at).toLocaleDateString('en-GB', { day: '2-digit', month: 'short', year: 'numeric' })}
                </span>
              </div>
            )}
          </div>
        </div>
      </div>
    </div>
  )
}
