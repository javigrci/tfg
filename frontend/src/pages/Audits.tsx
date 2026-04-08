import { useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { useQuery } from '@tanstack/react-query'
import { Search, Plus } from 'lucide-react'
import StatusBadge from '@/components/ui/StatusBadge'
import api from '@/lib/api'
import type { Audit, AuditType } from '@/types'

const auditTypeLabel: Record<AuditType, string> = {
  penetration_test:   'Pentest',
  vulnerability_scan: 'Vuln Scan',
  compliance:         'Compliance',
  static_analysis:    'Static Analysis',
}

function duration(started: string | null, finished: string | null): string {
  if (!started) return '—'
  const end = finished ? new Date(finished) : new Date()
  const mins = Math.round((end.getTime() - new Date(started).getTime()) / 60000)
  return mins < 60 ? `${mins}m` : `${Math.floor(mins / 60)}h ${mins % 60}m`
}

export default function Audits() {
  const navigate = useNavigate()
  const [search, setSearch] = useState('')

  const { data: audits = [], isLoading, isError } = useQuery<Audit[]>({
    queryKey: ['audits'],
    queryFn: () => api.get('/audits').then(r => r.data),
  })

  const filtered = audits.filter(a =>
    a.name.toLowerCase().includes(search.toLowerCase()) ||
    a.target.name.toLowerCase().includes(search.toLowerCase())
  )

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-semibold text-foreground">Audits</h1>
          <p className="text-sm text-muted-foreground mt-0.5">Manage and run security audits</p>
        </div>
        <button className="flex items-center gap-2 rounded-md bg-primary px-4 py-2 text-sm font-medium text-primary-foreground hover:opacity-90 transition-opacity">
          <Plus className="h-4 w-4" />
          New Audit
        </button>
      </div>

      {/* Search */}
      <div className="relative max-w-sm">
        <Search className="absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-muted-foreground" />
        <input
          type="text"
          placeholder="Search audits..."
          value={search}
          onChange={e => setSearch(e.target.value)}
          className="w-full rounded-md border border-input bg-background pl-9 pr-3 py-2 text-sm text-foreground placeholder:text-muted-foreground/50 focus:outline-none focus:ring-2 focus:ring-ring"
        />
      </div>

      {/* States */}
      {isLoading && (
        <p className="text-sm text-muted-foreground">Loading audits...</p>
      )}
      {isError && (
        <p className="text-sm text-destructive">Failed to load audits.</p>
      )}

      {/* Table */}
      {!isLoading && !isError && (
        <div className="rounded-xl border border-border overflow-hidden">
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-border bg-muted/30">
                <th className="px-4 py-3 text-left text-xs font-medium uppercase tracking-wider text-muted-foreground">Audit Name</th>
                <th className="px-4 py-3 text-left text-xs font-medium uppercase tracking-wider text-muted-foreground">Target</th>
                <th className="px-4 py-3 text-left text-xs font-medium uppercase tracking-wider text-muted-foreground">Type</th>
                <th className="px-4 py-3 text-left text-xs font-medium uppercase tracking-wider text-muted-foreground">Status</th>
                <th className="px-4 py-3 text-left text-xs font-medium uppercase tracking-wider text-muted-foreground">Start Date</th>
                <th className="px-4 py-3 text-left text-xs font-medium uppercase tracking-wider text-muted-foreground">Duration</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-border">
              {filtered.length === 0 && (
                <tr>
                  <td colSpan={6} className="px-4 py-8 text-center text-muted-foreground">
                    No audits found
                  </td>
                </tr>
              )}
              {filtered.map(audit => (
                <tr
                  key={audit.id}
                  onClick={() => navigate(`/audits/${audit.id}`)}
                  className="cursor-pointer bg-card hover:bg-muted/20 transition-colors"
                >
                  <td className="px-4 py-3.5 font-medium text-foreground">{audit.name}</td>
                  <td className="px-4 py-3.5 text-muted-foreground">{audit.target.name}</td>
                  <td className="px-4 py-3.5 text-muted-foreground">{auditTypeLabel[audit.audit_type]}</td>
                  <td className="px-4 py-3.5"><StatusBadge status={audit.status} /></td>
                  <td className="px-4 py-3.5 text-muted-foreground">
                    {audit.started_at
                      ? new Date(audit.started_at).toLocaleDateString('en-GB', { day: '2-digit', month: 'short', year: 'numeric' })
                      : '—'}
                  </td>
                  <td className="px-4 py-3.5 text-muted-foreground">{duration(audit.started_at, audit.finished_at)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  )
}
