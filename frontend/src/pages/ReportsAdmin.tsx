import { useQuery } from '@tanstack/react-query'
import { useNavigate } from 'react-router-dom'
import { PageLoader } from '@/components/ui/PageLoader'
import { PageError } from '@/components/ui/PageError'
import {
  BarChart, Bar, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer, Cell,
} from 'recharts'
import api from '@/lib/api'

interface ReportEntry {
  id: number
  audit_id: number
  audit_name: string
  target_address: string
  risk_level: string
  risk_score: number
  total_findings: number
  critical_count: number
  high_count: number
  medium_count: number
  low_count: number
  created_at: string | null
}

function scoreColor(score: number): string {
  if (score >= 7) return 'text-red-400'
  if (score >= 5) return 'text-orange-400'
  if (score >= 3) return 'text-yellow-400'
  return 'text-green-400'
}

const RISK_COLORS: Record<string, string> = {
  critical: '#ef4444',
  high:     '#f97316',
  medium:   '#eab308',
  low:      '#22c55e',
  info:     '#6b7280',
}

const RISK_STYLES: Record<string, string> = {
  critical: 'bg-red-500/10 text-red-400 border border-red-500/20',
  high:     'bg-orange-500/10 text-orange-400 border border-orange-500/20',
  medium:   'bg-yellow-500/10 text-yellow-400 border border-yellow-500/20',
  low:      'bg-green-500/10 text-green-400 border border-green-500/20',
  info:     'bg-slate-500/10 text-slate-400 border border-slate-500/20',
}

const TOOLTIP_STYLE = {
  contentStyle: { background: '#1e293b', border: '1px solid #334155', borderRadius: 8 },
  labelStyle: { color: '#f8fafc' },
  itemStyle: { color: '#94a3b8' },
}

const RISK_ORDER = ['critical', 'high', 'medium', 'low', 'info']

function RiskBadge({ level }: { level: string }) {
  return (
    <span className={`inline-flex items-center rounded-full px-2.5 py-0.5 text-xs font-medium uppercase border ${RISK_STYLES[level] ?? RISK_STYLES.info}`}>
      {level}
    </span>
  )
}

function Count({ value, color }: { value: number; color: string }) {
  return (
    <span className="font-semibold text-sm" style={{ color: value > 0 ? color : '#6b7280' }}>
      {value}
    </span>
  )
}

export default function ReportsAdmin() {
  const navigate = useNavigate()

  const { data: reports = [], isLoading, isError, refetch } = useQuery<ReportEntry[]>({
    queryKey: ['reports-admin'],
    queryFn: () => api.get('/reports').then(r => r.data),
  })

  if (isLoading) return <PageLoader />
  if (isError)   return <PageError onRetry={refetch} />

  const total    = reports.length
  const critical = reports.filter(r => r.risk_level === 'critical').length
  const high     = reports.filter(r => r.risk_level === 'high').length

  const riskDist = RISK_ORDER.map(level => ({
    name: level,
    value: reports.filter(r => r.risk_level === level).length,
  })).filter(d => d.value > 0)

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-semibold text-foreground">Reports</h1>
        <p className="text-sm text-muted-foreground mt-0.5">All audits across the system</p>
      </div>

      {/* KPIs */}
      <div className="grid grid-cols-1 sm:grid-cols-3 gap-4">
        <div className="rounded-xl border border-border bg-card p-5">
          <p className="text-xs font-medium uppercase tracking-wider text-muted-foreground">Total Reports</p>
          <p className="mt-2 text-3xl font-bold text-foreground">{total}</p>
        </div>
        <div className={`rounded-xl border bg-card p-5 ${critical > 0 ? 'border-red-500/30' : 'border-border'}`}>
          <p className="text-xs font-medium uppercase tracking-wider text-muted-foreground">Critical Risk</p>
          <p className={`mt-2 text-3xl font-bold ${critical > 0 ? 'text-red-400' : 'text-foreground'}`}>{critical}</p>
          {critical > 0 && <p className="mt-1 text-xs text-red-400">Action Required</p>}
        </div>
        <div className={`rounded-xl border bg-card p-5 ${high > 0 ? 'border-orange-500/30' : 'border-border'}`}>
          <p className="text-xs font-medium uppercase tracking-wider text-muted-foreground">High Risk</p>
          <p className={`mt-2 text-3xl font-bold ${high > 0 ? 'text-orange-400' : 'text-foreground'}`}>{high}</p>
        </div>
      </div>

      {/* Table */}
      <div className="rounded-xl border border-border bg-card overflow-hidden">
        <div className="px-5 py-4 border-b border-border">
          <h2 className="text-sm font-semibold text-foreground">All Reports</h2>
        </div>
        {reports.length === 0 ? (
          <div className="py-16 text-center text-sm text-muted-foreground">
            No reports yet. Run an audit first.
          </div>
        ) : (
          <table className="w-full text-sm">
            <thead>
              <tr className="bg-muted/30 text-xs uppercase tracking-wider text-muted-foreground border-b border-border">
                <th className="px-5 py-3 text-left">Audit Name</th>
                <th className="px-5 py-3 text-left">Target</th>
                <th className="px-5 py-3 text-left">Risk Level</th>
                <th className="px-5 py-3 text-center">Score</th>
                <th className="px-5 py-3 text-center">Findings</th>
                <th className="px-5 py-3 text-center">C</th>
                <th className="px-5 py-3 text-center">H</th>
                <th className="px-5 py-3 text-center">M</th>
                <th className="px-5 py-3 text-center">L</th>
                <th className="px-5 py-3 text-left">Date</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-border">
              {reports.map(r => (
                <tr
                  key={r.id}
                  className="hover:bg-muted/10 transition-colors cursor-pointer"
                  onClick={() => navigate(`/audits/${r.audit_id}`)}
                >
                  <td className="px-5 py-3.5 font-medium text-foreground">{r.audit_name}</td>
                  <td className="px-5 py-3.5 text-xs text-muted-foreground">{r.target_address}</td>
                  <td className="px-5 py-3.5"><RiskBadge level={r.risk_level} /></td>
                  <td className={`px-5 py-3.5 text-center font-mono font-semibold ${scoreColor(r.risk_score ?? 0)}`}>
                    {(r.risk_score ?? 0).toFixed(1)}
                  </td>
                  <td className="px-5 py-3.5 text-center text-foreground font-medium">{r.total_findings}</td>
                  <td className="px-5 py-3.5 text-center"><Count value={r.critical_count} color="#ef4444" /></td>
                  <td className="px-5 py-3.5 text-center"><Count value={r.high_count}     color="#f97316" /></td>
                  <td className="px-5 py-3.5 text-center"><Count value={r.medium_count}   color="#eab308" /></td>
                  <td className="px-5 py-3.5 text-center"><Count value={r.low_count}      color="#22c55e" /></td>
                  <td className="px-5 py-3.5 text-xs text-muted-foreground">
                    {r.created_at ? new Date(r.created_at).toLocaleDateString() : '—'}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>

      {/* Risk Distribution */}
      {riskDist.length > 0 && (
        <div className="rounded-xl border border-border bg-card p-5">
          <h2 className="text-sm font-semibold text-foreground mb-4">Risk Distribution</h2>
          <ResponsiveContainer width="100%" height={200}>
            <BarChart data={riskDist} margin={{ left: 0 }}>
              <CartesianGrid strokeDasharray="3 3" stroke="#334155" vertical={false} />
              <XAxis dataKey="name" tick={{ fontSize: 11, fill: '#94a3b8' }} className="capitalize" />
              <YAxis tick={{ fontSize: 11, fill: '#94a3b8' }} allowDecimals={false} />
              <Tooltip {...TOOLTIP_STYLE} />
              <Bar dataKey="value" radius={[4, 4, 0, 0]}>
                {riskDist.map(entry => (
                  <Cell key={entry.name} fill={RISK_COLORS[entry.name] ?? '#6b7280'} />
                ))}
              </Bar>
            </BarChart>
          </ResponsiveContainer>
        </div>
      )}
    </div>
  )
}
