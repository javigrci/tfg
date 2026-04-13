import { useQuery } from '@tanstack/react-query'
import { Loader2 } from 'lucide-react'
import {
  LineChart, Line, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer,
  PieChart, Pie, Cell,
  BarChart, Bar,
} from 'recharts'
import api from '@/lib/api'
import type { SeverityLevel } from '@/types'

interface FindingWithContext {
  id: number
  severity: SeverityLevel
  category: string
  audit_id: number
  scan_tool: string
}

interface AdminFindingStats {
  total: number
  critical: number
  high: number
  sevData: { name: string; value: number }[]
  catData: { name: string; value: number }[]
  evolution: { week: string; count: number }[]
}

const SEV_COLORS: Record<string, string> = {
  critical: '#ef4444',
  high:     '#f97316',
  medium:   '#eab308',
  low:      '#22c55e',
  info:     '#6b7280',
}

const TOOLTIP_STYLE = {
  contentStyle: { background: '#1e293b', border: '1px solid #334155', borderRadius: 8 },
  labelStyle: { color: '#f8fafc' },
  itemStyle: { color: '#94a3b8' },
}

const CATEGORY_ORDER = [
  'injection', 'broken auth', 'xss', 'broken access', 'security misconfig',
  'sensitive exposure', 'outdated components', 'logging monitoring', 'other',
]

function computeStats(findings: FindingWithContext[]): AdminFindingStats {
  const sevCount: Record<string, number> = {}
  const catCount: Record<string, number> = {}

  for (const f of findings) {
    sevCount[f.severity] = (sevCount[f.severity] ?? 0) + 1
    const cat = f.category.replace(/_/g, ' ')
    catCount[cat] = (catCount[cat] ?? 0) + 1
  }

  const sevData = Object.entries(sevCount)
    .filter(([, v]) => v > 0)
    .map(([k, v]) => ({ name: k, value: v }))

  const catData = CATEGORY_ORDER
    .map(c => ({ name: c, value: catCount[c] ?? 0 }))
    .sort((a, b) => b.value - a.value)

  return {
    total: findings.length,
    critical: sevCount['critical'] ?? 0,
    high: sevCount['high'] ?? 0,
    sevData,
    catData,
    evolution: [],
  }
}

function EmptyChart({ height = 200 }: { height?: number }) {
  return (
    <div className="flex items-center justify-center text-sm text-muted-foreground" style={{ height }}>
      No data yet
    </div>
  )
}

export default function FindingsAdmin() {
  const { data: findings = [], isLoading } = useQuery<FindingWithContext[]>({
    queryKey: ['findings'],
    queryFn: () => api.get('/findings').then(r => r.data),
  })

  if (isLoading) {
    return (
      <div className="flex items-center justify-center h-64 text-muted-foreground">
        <Loader2 className="h-5 w-5 animate-spin mr-2" /> Loading…
      </div>
    )
  }

  const stats = computeStats(findings)

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-semibold text-foreground">Findings Overview</h1>
        <p className="text-sm text-muted-foreground mt-0.5">Aggregated metrics across all audits</p>
      </div>

      {/* KPIs */}
      <div className="grid grid-cols-1 sm:grid-cols-3 gap-4">
        <div className="rounded-xl border border-border bg-card p-5">
          <p className="text-xs font-medium uppercase tracking-wider text-muted-foreground">Total Findings</p>
          <p className="mt-2 text-3xl font-bold text-foreground">{stats.total}</p>
        </div>
        <div className={`rounded-xl border bg-card p-5 ${stats.critical > 0 ? 'border-red-500/30' : 'border-border'}`}>
          <p className="text-xs font-medium uppercase tracking-wider text-muted-foreground">Critical</p>
          <p className={`mt-2 text-3xl font-bold ${stats.critical > 0 ? 'text-red-400' : 'text-foreground'}`}>
            {stats.critical}
          </p>
          {stats.critical > 0 && (
            <p className="mt-1 text-xs text-red-400">Action Required</p>
          )}
        </div>
        <div className={`rounded-xl border bg-card p-5 ${stats.high > 0 ? 'border-orange-500/30' : 'border-border'}`}>
          <p className="text-xs font-medium uppercase tracking-wider text-muted-foreground">High</p>
          <p className={`mt-2 text-3xl font-bold ${stats.high > 0 ? 'text-orange-400' : 'text-foreground'}`}>
            {stats.high}
          </p>
        </div>
      </div>

      {/* Evolution + Severity */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
        <div className="lg:col-span-2 rounded-xl border border-border bg-card p-5">
          <h2 className="text-sm font-semibold text-foreground mb-4">Findings Evolution</h2>
          <EmptyChart />
          <p className="text-center text-xs text-muted-foreground mt-2">
            Run audits to populate this chart
          </p>
        </div>

        <div className="rounded-xl border border-border bg-card p-5">
          <h2 className="text-sm font-semibold text-foreground mb-4">Severity Distribution</h2>
          {stats.sevData.length === 0 ? (
            <EmptyChart height={190} />
          ) : (
            <div className="flex flex-col items-center">
              <ResponsiveContainer width="100%" height={150}>
                <PieChart>
                  <Pie
                    data={stats.sevData}
                    cx="50%"
                    cy="50%"
                    innerRadius={40}
                    outerRadius={60}
                    dataKey="value"
                    paddingAngle={2}
                  >
                    {stats.sevData.map(entry => (
                      <Cell key={entry.name} fill={SEV_COLORS[entry.name] ?? '#6b7280'} />
                    ))}
                  </Pie>
                  <Tooltip {...TOOLTIP_STYLE} />
                </PieChart>
              </ResponsiveContainer>
              <div className="mt-2 space-y-1.5 w-full">
                {stats.sevData.map(({ name, value }) => (
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
      </div>

      {/* Findings by Category */}
      <div className="rounded-xl border border-border bg-card p-5">
        <h2 className="text-sm font-semibold text-foreground mb-4">Findings by Category</h2>
        {stats.catData.every(d => d.value === 0) ? (
          <EmptyChart height={260} />
        ) : (
          <ResponsiveContainer width="100%" height={260}>
            <BarChart data={stats.catData} layout="vertical" margin={{ left: 10 }}>
              <CartesianGrid strokeDasharray="3 3" stroke="#334155" horizontal={false} />
              <XAxis type="number" tick={{ fontSize: 11, fill: '#94a3b8' }} allowDecimals={false} />
              <YAxis
                type="category"
                dataKey="name"
                tick={{ fontSize: 11, fill: '#94a3b8' }}
                width={145}
              />
              <Tooltip {...TOOLTIP_STYLE} />
              <Bar dataKey="value" fill="#3b82f6" radius={[0, 4, 4, 0]} />
            </BarChart>
          </ResponsiveContainer>
        )}
      </div>
    </div>
  )
}
