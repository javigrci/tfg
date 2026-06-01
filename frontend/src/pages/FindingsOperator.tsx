import { useState, useMemo } from 'react'
import { useQuery } from '@tanstack/react-query'
import { useNavigate } from 'react-router-dom'
import { useTranslation } from 'react-i18next'
import { ChevronDown, ChevronRight } from 'lucide-react'
import { PageLoader } from '@/components/ui/PageLoader'
import { PageError } from '@/components/ui/PageError'
import api from '@/lib/api'
import type { SeverityLevel, FindingStatus } from '@/types'

interface FindingWithContext {
  id: number
  title: string
  description: string
  severity: SeverityLevel
  category: string
  evidence: string | null
  recommendation: string
  status: FindingStatus
  notes: string | null
  fingerprint: string | null
  audit_id: number
  audit_name: string
  scan_tool: string
}

interface AuditGroup {
  audit_id: number
  audit_name: string
  findings: FindingWithContext[]
  counts: Record<SeverityLevel, number>
}

const SEVERITIES: SeverityLevel[] = ['critical', 'high', 'medium', 'low', 'info']

const FINDING_STATUS_STYLES: Record<FindingStatus, string> = {
  open:           'bg-slate-500/10 text-slate-400 border border-slate-500/20',
  in_progress:    'bg-blue-500/10 text-blue-400 border border-blue-500/20',
  resolved:       'bg-green-500/10 text-green-400 border border-green-500/20',
  false_positive: 'bg-yellow-500/10 text-yellow-400 border border-yellow-500/20',
}

const FINDING_STATUSES: FindingStatus[] = ['open', 'in_progress', 'resolved', 'false_positive']

const SEV_STYLES: Record<SeverityLevel, string> = {
  critical: 'bg-red-500/10 text-red-400 border border-red-500/20',
  high:     'bg-orange-500/10 text-orange-400 border border-orange-500/20',
  medium:   'bg-yellow-500/10 text-yellow-400 border border-yellow-500/20',
  low:      'bg-blue-500/10 text-blue-400 border border-blue-500/20',
  info:     'bg-slate-500/10 text-slate-400 border border-slate-500/20',
}

const SEV_DOT: Record<SeverityLevel, string> = {
  critical: 'bg-red-400',
  high:     'bg-orange-400',
  medium:   'bg-yellow-400',
  low:      'bg-blue-400',
  info:     'bg-slate-400',
}

const SEV_TEXT: Record<SeverityLevel, string> = {
  critical: 'text-red-400',
  high:     'text-orange-400',
  medium:   'text-yellow-400',
  low:      'text-blue-400',
  info:     'text-slate-400',
}

function SeverityBadge({ severity }: { severity: SeverityLevel }) {
  const { t } = useTranslation()
  return (
    <span className={`inline-flex items-center gap-1.5 rounded-full px-2.5 py-0.5 text-xs font-medium ${SEV_STYLES[severity]}`}>
      <span className={`h-1.5 w-1.5 rounded-full ${SEV_DOT[severity]}`} />
      {t(`domain.severity.${severity}`)}
    </span>
  )
}

function StatusBadge({ status }: { status: FindingStatus }) {
  const { t } = useTranslation()
  return (
    <span className={`inline-flex items-center rounded-full px-2.5 py-0.5 text-xs font-medium ${FINDING_STATUS_STYLES[status]}`}>
      {t(`domain.findingStatus.${status}`)}
    </span>
  )
}

function groupByAudit(findings: FindingWithContext[]): AuditGroup[] {
  const map = new Map<number, AuditGroup>()

  for (const f of findings) {
    if (!map.has(f.audit_id)) {
      map.set(f.audit_id, {
        audit_id: f.audit_id,
        audit_name: f.audit_name,
        findings: [],
        counts: { critical: 0, high: 0, medium: 0, low: 0, info: 0 },
      })
    }
    const group = map.get(f.audit_id)!
    group.findings.push(f)
    group.counts[f.severity]++
  }

  return [...map.values()].sort((a, b) => {
    const maxSev = (g: AuditGroup) =>
      SEVERITIES.findIndex(s => g.counts[s] > 0)
    return maxSev(a) - maxSev(b)
  })
}

function AuditCard({
  group,
  sevFilter,
  statusFilter,
  onNavigate,
}: {
  group: AuditGroup
  sevFilter: SeverityLevel | 'all'
  statusFilter: FindingStatus | 'all'
  onNavigate: (id: number) => void
}) {
  const { t } = useTranslation()
  const [open, setOpen] = useState(false)

  const visibleFindings = group.findings.filter(f => {
    if (sevFilter !== 'all' && f.severity !== sevFilter) return false
    if (statusFilter !== 'all' && f.status !== statusFilter) return false
    return true
  })

  if (visibleFindings.length === 0) return null

  return (
    <div className="rounded-xl border border-border bg-card overflow-hidden">
      <button
        className="w-full flex items-center justify-between px-5 py-4 hover:bg-muted/10 transition-colors text-left"
        onClick={() => setOpen(v => !v)}
      >
        <div className="flex items-center gap-3 min-w-0">
          {open
            ? <ChevronDown className="h-4 w-4 text-muted-foreground shrink-0" />
            : <ChevronRight className="h-4 w-4 text-muted-foreground shrink-0" />}
          <div className="min-w-0">
            <p className="font-semibold text-foreground text-sm truncate">{group.audit_name}</p>
            <p className="text-xs text-muted-foreground mt-0.5">
              {t('findings.operator.findingCount', { count: group.findings.length })}
            </p>
          </div>
        </div>

        {/* Severity counts */}
        <div className="flex items-center gap-3 ml-4 shrink-0">
          {SEVERITIES.filter(s => group.counts[s] > 0).map(s => (
            <div key={s} className="flex items-center gap-1">
              <span className={`text-xs font-medium uppercase tracking-wider ${SEV_TEXT[s]}`}>
                {s.slice(0, 4)}
              </span>
              <span className={`text-xs font-bold ${SEV_TEXT[s]}`}>{group.counts[s]}</span>
            </div>
          ))}
          <button
            onClick={e => { e.stopPropagation(); onNavigate(group.audit_id) }}
            className="text-xs text-blue-400 hover:underline ml-2"
          >
            {t('findings.operator.viewAudit')}
          </button>
        </div>
      </button>

      {open && (
        <div className="border-t border-border">
          <table className="w-full text-sm">
            <thead>
              <tr className="bg-muted/20 text-xs uppercase tracking-wider text-muted-foreground">
                <th className="px-5 py-3 text-left">{t('findings.operator.colTitle')}</th>
                <th className="px-5 py-3 text-left">{t('findings.operator.colSeverity')}</th>
                <th className="px-5 py-3 text-left">{t('findings.operator.colCategory')}</th>
                <th className="px-5 py-3 text-left">{t('findings.operator.colTool')}</th>
                <th className="px-5 py-3 text-left">{t('findings.operator.colStatus')}</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-border">
              {visibleFindings.map(f => (
                <tr key={f.id} className="hover:bg-muted/10 transition-colors">
                  <td className="px-5 py-3 font-medium text-foreground">{f.title}</td>
                  <td className="px-5 py-3">
                    <SeverityBadge severity={f.severity} />
                  </td>
                  <td className="px-5 py-3 text-xs text-muted-foreground">
                    {t(`domain.findingCategory.${f.category}`)}
                  </td>
                  <td className="px-5 py-3">
                    <span className="inline-flex items-center rounded-md bg-muted px-2 py-0.5 text-xs font-medium uppercase text-muted-foreground">
                      {f.scan_tool}
                    </span>
                  </td>
                  <td className="px-5 py-3">
                    <StatusBadge status={f.status} />
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  )
}

export default function FindingsOperator() {
  const navigate = useNavigate()
  const { t }    = useTranslation()
  const [sevFilter, setSevFilter] = useState<SeverityLevel | 'all'>('all')
  const [statusFilter, setStatusFilter] = useState<FindingStatus | 'all'>('all')

  const { data: findings = [], isLoading, isError, refetch } = useQuery<FindingWithContext[]>({
    queryKey: ['findings'],
    queryFn: () => api.get('/findings').then(r => r.data),
  })

  const grouped = useMemo(() => groupByAudit(findings), [findings])

  const sevCounts = SEVERITIES.reduce((acc, sev) => {
    acc[sev] = findings.filter(f => f.severity === sev).length
    return acc
  }, {} as Record<SeverityLevel, number>)

  const statusCounts = FINDING_STATUSES.reduce((acc, s) => {
    acc[s] = findings.filter(f => f.status === s).length
    return acc
  }, {} as Record<FindingStatus, number>)

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-semibold text-foreground">{t('findings.operator.title')}</h1>
        <p className="text-sm text-muted-foreground mt-0.5">{t('findings.operator.subtitle')}</p>
      </div>

      {/* Severity chips */}
      <div className="flex flex-wrap gap-2">
        <button
          onClick={() => setSevFilter('all')}
          className={`rounded-full px-3 py-1 text-xs font-medium border transition-colors ${
            sevFilter === 'all'
              ? 'bg-foreground text-background border-foreground'
              : 'border-border text-muted-foreground hover:text-foreground'
          }`}
        >
          {t('findings.operator.allFilter')} <span className="ml-1">{findings.length}</span>
        </button>
        {SEVERITIES.map(sev => sevCounts[sev] > 0 && (
          <button
            key={sev}
            onClick={() => setSevFilter(sevFilter === sev ? 'all' : sev)}
            className={`inline-flex items-center gap-1.5 rounded-full px-3 py-1 text-xs font-medium border transition-colors ${
              sevFilter === sev
                ? SEV_STYLES[sev]
                : 'border-border text-muted-foreground hover:text-foreground'
            }`}
          >
            <span className={`h-1.5 w-1.5 rounded-full ${SEV_DOT[sev]}`} />
            {t(`domain.severity.${sev}`)} <span>{sevCounts[sev]}</span>
          </button>
        ))}
      </div>

      {/* Status chips */}
      <div className="flex flex-wrap gap-2">
        <button
          onClick={() => setStatusFilter('all')}
          className={`rounded-full px-3 py-1 text-xs font-medium border transition-colors ${
            statusFilter === 'all'
              ? 'bg-foreground text-background border-foreground'
              : 'border-border text-muted-foreground hover:text-foreground'
          }`}
        >
          {t('findings.operator.anyStatus')}
        </button>
        {FINDING_STATUSES.map(s => statusCounts[s] > 0 && (
          <button
            key={s}
            onClick={() => setStatusFilter(statusFilter === s ? 'all' : s)}
            className={`rounded-full px-3 py-1 text-xs font-medium border transition-colors ${
              statusFilter === s
                ? FINDING_STATUS_STYLES[s]
                : 'border-border text-muted-foreground hover:text-foreground'
            }`}
          >
            {t(`domain.findingStatus.${s}`)} <span className="ml-1">{statusCounts[s]}</span>
          </button>
        ))}
      </div>

      {/* Audit cards */}
      {isLoading ? (
        <PageLoader className="h-auto py-20" />
      ) : isError ? (
        <PageError onRetry={refetch} className="h-auto py-20" />
      ) : grouped.length === 0 ? (
        <div className="py-20 text-center text-sm text-muted-foreground">
          {t('findings.operator.empty')}
        </div>
      ) : (
        <div className="space-y-3">
          {grouped.map(group => (
            <AuditCard
              key={group.audit_id}
              group={group}
              sevFilter={sevFilter}
              statusFilter={statusFilter}
              onNavigate={id => navigate(`/audits/${id}`)}
            />
          ))}
        </div>
      )}
    </div>
  )
}
