import { useQuery } from '@tanstack/react-query'
import { ChevronRight, Loader2 } from 'lucide-react'
import { useNavigate } from 'react-router-dom'
import {
  PieChart, Pie, Cell, Tooltip, ResponsiveContainer,
} from 'recharts'
import api from '@/lib/api'

interface OperatorStats {
  active_audits: number
  critical_findings: number
  high_findings: number
  severity_distribution: Record<string, number>
  recent_audits: {
    id: number
    name: string
    target_address: string
    status: string
    started_at: string | null
    finished_at: string | null
  }[]
}

const SEV_COLORS: Record<string, string> = {
  critical: '#ef4444',
  high:     '#f97316',
  medium:   '#eab308',
  low:      '#22c55e',
  info:     '#6b7280',
}

const STATUS_STYLES: Record<string, string> = {
  running:   'bg-blue-500/10 text-blue-400 border border-blue-500/20',
  completed: 'bg-green-500/10 text-green-400 border border-green-500/20',
  failed:    'bg-red-500/10 text-red-400 border border-red-500/20',
  pending:   'bg-yellow-500/10 text-yellow-400 border border-yellow-500/20',
  draft:     'bg-slate-500/10 text-slate-400 border border-slate-500/20',
}

const TOOLTIP_STYLE = {
  contentStyle: { background: '#1e293b', border: '1px solid #334155', borderRadius: 8 },
  labelStyle: { color: '#f8fafc' },
  itemStyle: { color: '#94a3b8' },
}

function KpiCard({ label, value, sub, accent }: {
  label: string; value: number; sub?: string; accent?: boolean
}) {
  return (
    <div className={`rounded-xl border p-5 bg-card ${accent ? 'border-red-500/30' : 'border-border'}`}>
      <p className="text-xs font-medium uppercase tracking-wider text-muted-foreground">{label}</p>
      <p className={`mt-2 text-3xl font-bold ${accent ? 'text-red-400' : 'text-foreground'}`}>{value}</p>
      {sub && <p className="mt-1 text-xs text-muted-foreground">{sub}</p>}
    </div>
  )
}

export default function DashboardOperator() {
  const navigate = useNavigate()

  const { data: stats, isLoading, isError, refetch } = useQuery<OperatorStats>({
    queryKey: ['dashboard-operator'],
    queryFn: () => api.get('/dashboard/my-stats').then(r => r.data),
  })

  if (isLoading) {
    return (
      <div className="flex items-center justify-center h-64 text-muted-foreground">
        <Loader2 className="h-5 w-5 animate-spin mr-2" /> Loading…
      </div>
    )
  }

  if (isError || !stats) {
    return (
      <div className="flex flex-col items-center justify-center h-64 gap-3 text-muted-foreground">
        <p className="text-sm">Failed to load dashboard data.</p>
        <button onClick={() => refetch()} className="text-xs text-blue-400 hover:underline">Retry</button>
      </div>
    )
  }

  const sevData = Object.entries(stats.severity_distribution)
    .filter(([, v]) => v > 0)
    .map(([k, v]) => ({ name: k, value: v }))

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-semibold text-foreground">Dashboard</h1>
        <p className="text-sm text-muted-foreground mt-0.5">My Activity</p>
      </div>

      {/* KPIs */}
      <div className="grid grid-cols-1 sm:grid-cols-3 gap-4">
        <KpiCard label="My Active Audits" value={stats.active_audits} sub="Running or Pending" />
        <KpiCard
          label="Critical Findings"
          value={stats.critical_findings}
          sub={stats.critical_findings > 0 ? 'Immediate Action' : undefined}
          accent={stats.critical_findings > 0}
        />
        <KpiCard label="High Findings" value={stats.high_findings} sub="Across all my audits" />
      </div>

      {/* Severity Distribution + Recent Audits */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">

        {/* Severity donut */}
        <div className="rounded-xl border border-border bg-card p-5">
          <h2 className="text-sm font-semibold text-foreground mb-4">My Severity Distribution</h2>
          {sevData.length === 0 ? (
            <div className="flex items-center justify-center h-48 text-sm text-muted-foreground">
              No findings yet
            </div>
          ) : (
            <div className="flex flex-col items-center">
              <ResponsiveContainer width="100%" height={160}>
                <PieChart>
                  <Pie
                    data={sevData}
                    cx="50%"
                    cy="50%"
                    innerRadius={45}
                    outerRadius={65}
                    dataKey="value"
                    paddingAngle={2}
                  >
                    {sevData.map(entry => (
                      <Cell key={entry.name} fill={SEV_COLORS[entry.name] ?? '#6b7280'} />
                    ))}
                  </Pie>
                  <Tooltip {...TOOLTIP_STYLE} />
                </PieChart>
              </ResponsiveContainer>
              <div className="mt-3 space-y-1.5 w-full max-w-xs">
                {sevData.map(({ name, value }) => (
                  <div key={name} className="flex items-center justify-between text-xs">
                    <div className="flex items-center gap-1.5">
                      <span
                        className="h-2 w-2 rounded-full"
                        style={{ background: SEV_COLORS[name] ?? '#6b7280' }}
                      />
                      <span className="capitalize text-muted-foreground">{name}</span>
                    </div>
                    <span className="text-foreground font-medium">{value}</span>
                  </div>
                ))}
              </div>
            </div>
          )}
        </div>

        {/* Recent Audits */}
        <div className="rounded-xl border border-border bg-card overflow-hidden">
          <div className="flex items-center justify-between px-5 py-4 border-b border-border">
            <h2 className="text-sm font-semibold text-foreground">Recent Audits</h2>
            <button
              onClick={() => navigate('/audits')}
              className="text-xs text-blue-400 hover:underline"
            >
              View All
            </button>
          </div>
          {stats.recent_audits.length === 0 ? (
            <div className="py-12 text-center text-sm text-muted-foreground">
              No audits yet
            </div>
          ) : (
            <div className="divide-y divide-border">
              {stats.recent_audits.map(audit => (
                <button
                  key={audit.id}
                  onClick={() => navigate(`/audits/${audit.id}`)}
                  className="w-full flex items-center justify-between px-5 py-3.5 hover:bg-muted/10 transition-colors text-left"
                >
                  <div className="min-w-0 flex-1">
                    <p className="font-medium text-foreground text-sm truncate">{audit.name}</p>
                    <p className="text-xs text-muted-foreground mt-0.5 truncate">{audit.target_address}</p>
                  </div>
                  <div className="flex items-center gap-3 ml-3 shrink-0">
                    <span className={`inline-flex items-center rounded-full px-2.5 py-0.5 text-xs font-medium capitalize border ${STATUS_STYLES[audit.status] ?? STATUS_STYLES.draft}`}>
                      {audit.status}
                    </span>
                    {audit.started_at && (
                      <span className="text-xs text-muted-foreground hidden sm:block">
                        {new Date(audit.started_at).toLocaleDateString()}
                      </span>
                    )}
                    <ChevronRight className="h-4 w-4 text-muted-foreground" />
                  </div>
                </button>
              ))}
            </div>
          )}
        </div>
      </div>
    </div>
  )
}
