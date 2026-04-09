import { useState, useMemo } from 'react'
import { useQuery } from '@tanstack/react-query'
import { useNavigate } from 'react-router-dom'
import { Search, ChevronDown, ChevronRight, Loader2, ExternalLink } from 'lucide-react'
import api from '@/lib/api'
import type { SeverityLevel } from '@/types'

// ── Types ─────────────────────────────────────────────────────────────────────

interface FindingWithContext {
  id: number
  title: string
  description: string
  severity: SeverityLevel
  category: string
  evidence: string | null
  recommendation: string
  audit_id: number
  audit_name: string
  scan_tool: string
}

interface GroupedFinding {
  title: string
  severity: SeverityLevel
  category: string
  description: string
  recommendation: string
  count: number
  instances: FindingWithContext[]
  audits: { id: number; name: string }[]   // únicos
  tools: string[]                           // únicos
}

// ── Helpers ───────────────────────────────────────────────────────────────────

const SEV_ORDER: Record<SeverityLevel, number> = {
  critical: 0, high: 1, medium: 2, low: 3, info: 4,
}

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

const TOOL_STYLES: Record<string, string> = {
  nmap:   'bg-purple-500/10 text-purple-400 border border-purple-500/20',
  wapiti: 'bg-cyan-500/10 text-cyan-400 border border-cyan-500/20',
  nuclei: 'bg-pink-500/10 text-pink-400 border border-pink-500/20',
  bash:   'bg-slate-500/10 text-slate-400 border border-slate-500/20',
}

const SEVERITIES: SeverityLevel[] = ['critical', 'high', 'medium', 'low', 'info']

function SeverityBadge({ severity }: { severity: SeverityLevel }) {
  return (
    <span className={`inline-flex items-center gap-1.5 rounded-full px-2.5 py-0.5 text-xs font-medium capitalize ${SEV_STYLES[severity]}`}>
      <span className={`h-1.5 w-1.5 rounded-full ${SEV_DOT[severity]}`} />
      {severity}
    </span>
  )
}

function groupFindings(findings: FindingWithContext[]): GroupedFinding[] {
  const map = new Map<string, GroupedFinding>()

  for (const f of findings) {
    if (!map.has(f.title)) {
      map.set(f.title, {
        title: f.title,
        severity: f.severity,
        category: f.category,
        description: f.description,
        recommendation: f.recommendation,
        count: 0,
        instances: [],
        audits: [],
        tools: [],
      })
    }
    const group = map.get(f.title)!
    group.count++
    group.instances.push(f)
    if (!group.audits.find(a => a.id === f.audit_id)) {
      group.audits.push({ id: f.audit_id, name: f.audit_name })
    }
    if (!group.tools.includes(f.scan_tool)) {
      group.tools.push(f.scan_tool)
    }
  }

  return [...map.values()].sort(
    (a, b) => SEV_ORDER[a.severity] - SEV_ORDER[b.severity]
  )
}

// ── GroupedRow ────────────────────────────────────────────────────────────────

function GroupedRow({ group, onAuditClick }: {
  group: GroupedFinding
  onAuditClick: (id: number) => void
}) {
  const [open, setOpen] = useState(false)

  return (
    <>
      <tr
        className="cursor-pointer hover:bg-muted/20 transition-colors"
        onClick={() => setOpen(v => !v)}
      >
        <td className="px-4 py-3.5 w-8">
          {open
            ? <ChevronDown className="h-3.5 w-3.5 text-muted-foreground" />
            : <ChevronRight className="h-3.5 w-3.5 text-muted-foreground" />}
        </td>
        <td className="px-4 py-3.5 font-medium text-foreground text-sm">
          {group.title}
        </td>
        <td className="px-4 py-3.5">
          <SeverityBadge severity={group.severity} />
        </td>
        <td className="px-4 py-3.5 text-xs text-muted-foreground capitalize">
          {group.category.replace(/_/g, ' ')}
        </td>
        <td className="px-4 py-3.5">
          <span className="inline-flex items-center rounded-full bg-muted px-2.5 py-0.5 text-xs font-medium text-muted-foreground">
            ×{group.count}
          </span>
        </td>
        <td className="px-4 py-3.5">
          <div className="flex flex-wrap gap-1">
            {group.tools.map(tool => (
              <span key={tool} className={`inline-flex items-center rounded-md px-2 py-0.5 text-xs font-medium uppercase ${TOOL_STYLES[tool] ?? TOOL_STYLES.bash}`}>
                {tool}
              </span>
            ))}
          </div>
        </td>
        <td className="px-4 py-3.5 text-xs text-muted-foreground">
          {group.audits.length} audit{group.audits.length !== 1 ? 's' : ''}
        </td>
      </tr>

      {open && (
        <tr className="bg-muted/10">
          <td colSpan={7} className="px-6 py-4">
            <div className="space-y-4 text-sm">

              {/* Description & Recommendation */}
              <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                <div>
                  <p className="text-xs font-medium uppercase tracking-wider text-muted-foreground mb-1">Description</p>
                  <p className="text-foreground">{group.description}</p>
                </div>
                <div>
                  <p className="text-xs font-medium uppercase tracking-wider text-muted-foreground mb-1">Recommendation</p>
                  <p className="text-foreground">{group.recommendation}</p>
                </div>
              </div>

              {/* Instances */}
              <div>
                <p className="text-xs font-medium uppercase tracking-wider text-muted-foreground mb-2">
                  Occurrences ({group.count})
                </p>
                <div className="rounded-lg border border-border divide-y divide-border">
                  {group.instances.map(inst => (
                    <div key={inst.id} className="flex items-center justify-between px-3 py-2 gap-3">
                      <span className={`inline-flex items-center rounded-md px-2 py-0.5 text-xs font-medium uppercase shrink-0 ${TOOL_STYLES[inst.scan_tool] ?? TOOL_STYLES.bash}`}>
                        {inst.scan_tool}
                      </span>
                      {inst.evidence && (
                        <pre className="text-xs font-mono text-muted-foreground truncate flex-1">
                          {inst.evidence.split('\n')[0]}
                        </pre>
                      )}
                      <button
                        onClick={e => { e.stopPropagation(); onAuditClick(inst.audit_id) }}
                        className="flex items-center gap-1 text-xs text-blue-400 hover:underline shrink-0"
                      >
                        {inst.audit_name}
                        <ExternalLink className="h-3 w-3" />
                      </button>
                    </div>
                  ))}
                </div>
              </div>

            </div>
          </td>
        </tr>
      )}
    </>
  )
}

// ── Main component ────────────────────────────────────────────────────────────

export default function Findings() {
  const navigate = useNavigate()

  const [search, setSearh]        = useState('')
  const [sevFilter, setSevFilter] = useState<SeverityLevel | 'all'>('all')
  const [catFilter, setCatFilter] = useState('all')

  const { data: findings = [], isLoading } = useQuery<FindingWithContext[]>({
    queryKey: ['findings'],
    queryFn: () => api.get('/findings').then(r => r.data),
  })

  const grouped = useMemo(() => groupFindings(findings), [findings])

  const filtered = grouped.filter(g => {
    const matchSev    = sevFilter === 'all' || g.severity === sevFilter
    const matchCat    = catFilter === 'all' || g.category === catFilter
    const matchSearch = !search   || g.title.toLowerCase().includes(search.toLowerCase())
    return matchSev && matchCat && matchSearch
  })

  // Conteos por severidad (sobre findings individuales)
  const counts = SEVERITIES.reduce((acc, sev) => {
    acc[sev] = findings.filter(f => f.severity === sev).length
    return acc
  }, {} as Record<SeverityLevel, number>)

  const categories = [...new Set(findings.map(f => f.category))].sort()

  return (
    <div className="space-y-6">

      {/* Header */}
      <div>
        <h1 className="text-2xl font-semibold text-foreground">Findings</h1>
        <p className="text-sm text-muted-foreground mt-0.5">
          {grouped.length} unique finding type{grouped.length !== 1 ? 's' : ''} · {findings.length} total occurrence{findings.length !== 1 ? 's' : ''}
        </p>
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
          All <span className="ml-1">{findings.length}</span>
        </button>
        {SEVERITIES.map(sev => counts[sev] > 0 && (
          <button
            key={sev}
            onClick={() => setSevFilter(sevFilter === sev ? 'all' : sev)}
            className={`inline-flex items-center gap-1.5 rounded-full px-3 py-1 text-xs font-medium capitalize border transition-colors ${
              sevFilter === sev
                ? SEV_STYLES[sev]
                : 'border-border text-muted-foreground hover:text-foreground'
            }`}
          >
            <span className={`h-1.5 w-1.5 rounded-full ${SEV_DOT[sev]}`} />
            {sev} <span>{counts[sev]}</span>
          </button>
        ))}
      </div>

      {/* Filters */}
      <div className="flex flex-wrap gap-3">
        <div className="relative">
          <Search className="absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-muted-foreground" />
          <input
            type="text"
            placeholder="Search findings…"
            value={search}
            onChange={e => setSearh(e.target.value)}
            className="rounded-lg border border-input bg-background pl-9 pr-3 py-2 text-sm text-foreground placeholder:text-muted-foreground/50 focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-transparent w-64"
          />
        </div>
        <select
          value={catFilter}
          onChange={e => setCatFilter(e.target.value)}
          className="rounded-lg border border-input bg-background px-3 py-2 text-sm text-foreground focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-transparent"
        >
          <option value="all">All categories</option>
          {categories.map(cat => (
            <option key={cat} value={cat}>{cat.replace(/_/g, ' ')}</option>
          ))}
        </select>
      </div>

      {/* Table */}
      <div className="rounded-xl border border-border bg-card overflow-hidden">
        {isLoading ? (
          <div className="flex items-center justify-center py-20 text-muted-foreground">
            <Loader2 className="h-5 w-5 animate-spin mr-2" />
            Loading findings…
          </div>
        ) : filtered.length === 0 ? (
          <div className="py-20 text-center text-sm text-muted-foreground">
            {findings.length === 0
              ? 'No findings yet. Run an audit first.'
              : 'No findings match the current filters.'}
          </div>
        ) : (
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-border bg-muted/30 text-xs uppercase tracking-wider text-muted-foreground">
                <th className="px-4 py-3 w-8" />
                <th className="px-4 py-3 text-left">Finding</th>
                <th className="px-4 py-3 text-left">Severity</th>
                <th className="px-4 py-3 text-left">Category</th>
                <th className="px-4 py-3 text-left">Count</th>
                <th className="px-4 py-3 text-left">Tool</th>
                <th className="px-4 py-3 text-left">Scope</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-border">
              {filtered.map(group => (
                <GroupedRow
                  key={group.title}
                  group={group}
                  onAuditClick={id => navigate(`/audits/${id}`)}
                />
              ))}
            </tbody>
          </table>
        )}
      </div>

    </div>
  )
}
