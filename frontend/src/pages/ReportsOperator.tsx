import { useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import { useNavigate } from 'react-router-dom'
import { ChevronDown, ChevronRight, ExternalLink, Loader2 } from 'lucide-react'
import api from '@/lib/api'
import type { SeverityLevel } from '@/types'

interface ReportEntry {
  id: number
  audit_id: number
  audit_name: string
  target_address: string
  risk_level: string
  total_findings: number
  critical_count: number
  high_count: number
  medium_count: number
  low_count: number
  created_at: string | null
}

interface FindingWithContext {
  id: number
  title: string
  severity: SeverityLevel
  category: string
  recommendation: string
  scan_tool: string
  audit_id: number
  audit_name: string
}

const RISK_LEVELS = ['critical', 'high', 'medium', 'low'] as const
type RiskLevel = typeof RISK_LEVELS[number]

const RISK_STYLES: Record<string, string> = {
  critical: 'bg-red-500/10 text-red-400 border border-red-500/20',
  high:     'bg-orange-500/10 text-orange-400 border border-orange-500/20',
  medium:   'bg-yellow-500/10 text-yellow-400 border border-yellow-500/20',
  low:      'bg-green-500/10 text-green-400 border border-green-500/20',
  info:     'bg-slate-500/10 text-slate-400 border border-slate-500/20',
}

const SEV_STYLES: Record<string, string> = {
  critical: 'bg-red-500/10 text-red-400 border border-red-500/20',
  high:     'bg-orange-500/10 text-orange-400 border border-orange-500/20',
  medium:   'bg-yellow-500/10 text-yellow-400 border border-yellow-500/20',
  low:      'bg-blue-500/10 text-blue-400 border border-blue-500/20',
  info:     'bg-slate-500/10 text-slate-400 border border-slate-500/20',
}

const CHIP_FILTER: Record<string, string> = {
  critical: 'border-red-500/40 text-red-400 hover:bg-red-500/10',
  high:     'border-orange-500/40 text-orange-400 hover:bg-orange-500/10',
  medium:   'border-yellow-500/40 text-yellow-400 hover:bg-yellow-500/10',
  low:      'border-green-500/40 text-green-400 hover:bg-green-500/10',
}

function RiskBadge({ level }: { level: string }) {
  return (
    <span className={`inline-flex items-center rounded-full px-2.5 py-0.5 text-xs font-medium uppercase border ${RISK_STYLES[level] ?? RISK_STYLES.info}`}>
      {level} risk
    </span>
  )
}

function ReportCard({ report }: { report: ReportEntry }) {
  const navigate = useNavigate()
  const [open, setOpen] = useState(false)

  const { data: findings = [], isFetching } = useQuery<FindingWithContext[]>({
    queryKey: ['findings-for-audit', report.audit_id],
    queryFn: () => api.get('/findings').then(r =>
      (r.data as FindingWithContext[]).filter(f => f.audit_id === report.audit_id)
    ),
    enabled: open,
  })

  return (
    <div className="rounded-xl border border-border bg-card overflow-hidden">
      <button
        className="w-full text-left px-5 py-4 hover:bg-muted/10 transition-colors"
        onClick={() => setOpen(v => !v)}
      >
        <div className="flex items-start justify-between gap-4">
          <div className="flex items-center gap-3 min-w-0">
            {open
              ? <ChevronDown className="h-4 w-4 text-muted-foreground shrink-0 mt-0.5" />
              : <ChevronRight className="h-4 w-4 text-muted-foreground shrink-0 mt-0.5" />}
            <div className="min-w-0">
              <p className="font-semibold text-foreground text-sm">{report.audit_name}</p>
              <p className="text-xs text-muted-foreground mt-0.5">{report.target_address}</p>
            </div>
          </div>
          <div className="flex items-center gap-3 shrink-0">
            <RiskBadge level={report.risk_level} />
            {report.created_at && (
              <span className="text-xs text-muted-foreground hidden sm:block">
                {new Date(report.created_at).toLocaleDateString()}
              </span>
            )}
            <button
              onClick={e => { e.stopPropagation(); navigate(`/audits/${report.audit_id}`) }}
              className="flex items-center gap-1 text-xs text-blue-400 hover:underline"
            >
              View audit
              <ExternalLink className="h-3 w-3" />
            </button>
          </div>
        </div>

        {/* Metrics row */}
        <div className="flex items-center gap-4 mt-3 ml-7 text-xs">
          <span className="text-muted-foreground">
            FINDINGS <span className="font-semibold text-foreground ml-1">{report.total_findings}</span>
          </span>
          {report.critical_count > 0 && (
            <span className="text-muted-foreground">
              CRITICAL <span className="font-semibold text-red-400 ml-1">{report.critical_count}</span>
            </span>
          )}
          {report.high_count > 0 && (
            <span className="text-muted-foreground">
              HIGH <span className="font-semibold text-orange-400 ml-1">{report.high_count}</span>
            </span>
          )}
          {report.medium_count > 0 && (
            <span className="text-muted-foreground">
              MEDIUM <span className="font-semibold text-yellow-400 ml-1">{report.medium_count}</span>
            </span>
          )}
        </div>
      </button>

      {open && (
        <div className="border-t border-border">
          {isFetching ? (
            <div className="flex items-center justify-center py-8 text-muted-foreground">
              <Loader2 className="h-4 w-4 animate-spin mr-2" /> Loading findings…
            </div>
          ) : findings.length === 0 ? (
            <div className="py-8 text-center text-sm text-muted-foreground">No findings for this audit</div>
          ) : (
            <table className="w-full text-sm">
              <thead>
                <tr className="bg-muted/20 text-xs uppercase tracking-wider text-muted-foreground">
                  <th className="px-5 py-3 text-left">Finding Title</th>
                  <th className="px-5 py-3 text-left">Severity</th>
                  <th className="px-5 py-3 text-left">Category</th>
                  <th className="px-5 py-3 text-left">Tool</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-border">
                {findings.map(f => (
                  <tr key={f.id} className="hover:bg-muted/10 transition-colors">
                    <td className="px-5 py-3 font-medium text-foreground">{f.title}</td>
                    <td className="px-5 py-3">
                      <span className={`inline-flex items-center rounded-full px-2.5 py-0.5 text-xs font-medium capitalize border ${SEV_STYLES[f.severity] ?? SEV_STYLES.info}`}>
                        {f.severity}
                      </span>
                    </td>
                    <td className="px-5 py-3 text-xs text-muted-foreground capitalize">
                      {f.category.replace(/_/g, ' ')}
                    </td>
                    <td className="px-5 py-3">
                      <span className="inline-flex items-center rounded-md bg-muted px-2 py-0.5 text-xs font-medium uppercase text-muted-foreground">
                        {f.scan_tool}
                      </span>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </div>
      )}
    </div>
  )
}

export default function ReportsOperator() {
  const [riskFilter, setRiskFilter] = useState<RiskLevel | 'all'>('all')

  const { data: reports = [], isLoading } = useQuery<ReportEntry[]>({
    queryKey: ['reports-operator'],
    queryFn: () => api.get('/reports/my').then(r => r.data),
  })

  const filtered = riskFilter === 'all'
    ? reports
    : reports.filter(r => r.risk_level === riskFilter)

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-semibold text-foreground">My Reports</h1>
        <p className="text-sm text-muted-foreground mt-0.5">Reports from my audits</p>
      </div>

      {/* Filter chips */}
      <div className="flex flex-wrap gap-2">
        <button
          onClick={() => setRiskFilter('all')}
          className={`rounded-full px-3 py-1 text-xs font-medium border transition-colors ${
            riskFilter === 'all'
              ? 'bg-foreground text-background border-foreground'
              : 'border-border text-muted-foreground hover:text-foreground'
          }`}
        >
          All <span className="ml-1">{reports.length}</span>
        </button>
        {RISK_LEVELS.map(level => {
          const count = reports.filter(r => r.risk_level === level).length
          if (count === 0) return null
          return (
            <button
              key={level}
              onClick={() => setRiskFilter(riskFilter === level ? 'all' : level)}
              className={`rounded-full px-3 py-1 text-xs font-medium capitalize border transition-colors ${
                riskFilter === level
                  ? RISK_STYLES[level]
                  : `border-border text-muted-foreground ${CHIP_FILTER[level]}`
              }`}
            >
              {level} <span className="ml-1">{count}</span>
            </button>
          )
        })}
      </div>

      {/* Cards */}
      {isLoading ? (
        <div className="flex items-center justify-center py-20 text-muted-foreground">
          <Loader2 className="h-5 w-5 animate-spin mr-2" /> Loading reports…
        </div>
      ) : filtered.length === 0 ? (
        <div className="py-20 text-center text-sm text-muted-foreground">
          {reports.length === 0
            ? 'No reports yet. Run an audit first.'
            : 'No reports match the current filter.'}
        </div>
      ) : (
        <div className="space-y-3">
          {filtered.map(r => <ReportCard key={r.id} report={r} />)}
        </div>
      )}
    </div>
  )
}
