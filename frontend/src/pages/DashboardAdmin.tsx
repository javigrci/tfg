import { useQuery } from '@tanstack/react-query'
import { PageLoader } from '@/components/ui/PageLoader'
import { PageError } from '@/components/ui/PageError'
import {
  LineChart, Line, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer,
  PieChart, Pie, Cell,
  BarChart, Bar,
} from 'recharts'
import api from '@/lib/api'

interface AdminStats {
  total_audits: number
  active_audits: number
  critical_findings: number
  total_findings: number
  severity_distribution: Record<string, number>
  findings_by_category: Record<string, number>
  findings_evolution: { week: string; count: number }[]
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

function EmptyChart({ height = 200 }: { height?: number }) {
  return (
    <div
      className="flex items-center justify-center text-sm text-muted-foreground"
      style={{ height }}
    >
      No data yet
    </div>
  )
}

export default function DashboardAdmin() {
  const { data: stats, isLoading, isError, refetch } = useQuery<AdminStats>({
    queryKey: ['dashboard-admin'],
    queryFn: () => api.get('/dashboard/stats').then(r => r.data),
  })

  if (isLoading)       return <PageLoader />
  if (isError || !stats) return <PageError onRetry={refetch} />

  const sevData = Object.entries(stats.severity_distribution)
    .filter(([, v]) => v > 0)
    .map(([k, v]) => ({ name: k, value: v }))

  const catData = Object.entries(stats.findings_by_category)
    .map(([k, v]) => ({ name: k.replace(/_/g, ' '), value: v }))
    .sort((a, b) => b.value - a.value)

  const hasEvolution = stats.findings_evolution.length > 0
  const hasSev = sevData.length > 0
  const hasCat = catData.some(d => d.value > 0)

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-semibold text-foreground">Dashboard</h1>
        <p className="text-sm text-muted-foreground mt-0.5">System Overview</p>
      </div>

      {/* KPIs */}
      <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
        <KpiCard label="Total Audits" value={stats.total_audits} />
        <KpiCard label="Active Audits" value={stats.active_audits} sub="Running or Pending" />
        <KpiCard
          label="Critical Findings"
          value={stats.critical_findings}
          sub={stats.critical_findings > 0 ? 'Immediate Action' : undefined}
          accent={stats.critical_findings > 0}
        />
        <KpiCard label="Total Findings" value={stats.total_findings} />
      </div>

      {/* Evolution + Severity */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
        <div className="lg:col-span-2 rounded-xl border border-border bg-card p-5">
          <h2 className="text-sm font-semibold text-foreground mb-4">Findings Evolution</h2>
          {hasEvolution ? (
            <ResponsiveContainer width="100%" height={200}>
              <LineChart data={stats.findings_evolution}>
                <CartesianGrid strokeDasharray="3 3" stroke="#334155" />
                <XAxis dataKey="week" tick={{ fontSize: 11, fill: '#94a3b8' }} />
                <YAxis tick={{ fontSize: 11, fill: '#94a3b8' }} allowDecimals={false} />
                <Tooltip {...TOOLTIP_STYLE} />
                <Line
                  type="monotone"
                  dataKey="count"
                  stroke="#3b82f6"
                  strokeWidth={2}
                  dot={{ fill: '#3b82f6', r: 3 }}
                />
              </LineChart>
            </ResponsiveContainer>
          ) : (
            <EmptyChart />
          )}
        </div>

        <div className="rounded-xl border border-border bg-card p-5">
          <h2 className="text-sm font-semibold text-foreground mb-4">Severity Distribution</h2>
          {hasSev ? (
            <div className="flex flex-col items-center">
              <ResponsiveContainer width="100%" height={150}>
                <PieChart>
                  <Pie
                    data={sevData}
                    cx="50%"
                    cy="50%"
                    innerRadius={40}
                    outerRadius={60}
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
              <div className="mt-2 space-y-1.5 w-full">
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
          ) : (
            <EmptyChart height={190} />
          )}
        </div>
      </div>

      {/* Findings by Category */}
      <div className="rounded-xl border border-border bg-card p-5">
        <h2 className="text-sm font-semibold text-foreground mb-4">Findings by Category</h2>
        {hasCat ? (
          <ResponsiveContainer width="100%" height={260}>
            <BarChart data={catData} layout="vertical" margin={{ left: 10 }}>
              <CartesianGrid strokeDasharray="3 3" stroke="#334155" horizontal={false} />
              <XAxis type="number" tick={{ fontSize: 11, fill: '#94a3b8' }} allowDecimals={false} />
              <YAxis
                type="category"
                dataKey="name"
                tick={{ fontSize: 11, fill: '#94a3b8' }}
                width={140}
              />
              <Tooltip {...TOOLTIP_STYLE} />
              <Bar dataKey="value" fill="#3b82f6" radius={[0, 4, 4, 0]} />
            </BarChart>
          </ResponsiveContainer>
        ) : (
          <EmptyChart height={260} />
        )}
      </div>

      {/* Recent Audit Execution */}
      <div className="rounded-xl border border-border bg-card overflow-hidden">
        <div className="px-5 py-4 border-b border-border">
          <h2 className="text-sm font-semibold text-foreground">Recent Audit Execution</h2>
        </div>
        {stats.recent_audits.length === 0 ? (
          <div className="py-12 text-center text-sm text-muted-foreground">No audits yet</div>
        ) : (
          <table className="w-full text-sm">
            <thead>
              <tr className="bg-muted/30 text-xs uppercase tracking-wider text-muted-foreground border-b border-border">
                <th className="px-5 py-3 text-left">Scan Target</th>
                <th className="px-5 py-3 text-left">Status</th>
                <th className="px-5 py-3 text-left">Started</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-border">
              {stats.recent_audits.map(audit => (
                <tr key={audit.id} className="hover:bg-muted/10 transition-colors">
                  <td className="px-5 py-3.5">
                    <p className="font-medium text-foreground">{audit.name}</p>
                    <p className="text-xs text-muted-foreground mt-0.5">{audit.target_address}</p>
                  </td>
                  <td className="px-5 py-3.5">
                    <span className={`inline-flex items-center rounded-full px-2.5 py-0.5 text-xs font-medium capitalize border ${STATUS_STYLES[audit.status] ?? STATUS_STYLES.draft}`}>
                      {audit.status}
                    </span>
                  </td>
                  <td className="px-5 py-3.5 text-xs text-muted-foreground">
                    {audit.started_at
                      ? new Date(audit.started_at).toLocaleString()
                      : '—'}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>
    </div>
  )
}
