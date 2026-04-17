import { useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { Search, Plus, X, Loader2 } from 'lucide-react'
import { toast } from 'sonner'
import StatusBadge from '@/components/ui/StatusBadge'
import api from '@/lib/api'
import type { Audit, AuditType, ScanTool, Target } from '@/types'

// ── Helpers ───────────────────────────────────────────────────────────────────

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

// ── Form types ────────────────────────────────────────────────────────────────

interface AuditForm {
  name:        string
  description: string
  audit_type:  AuditType
  target_id:   string   // '' = not selected
  modules:     ScanTool[]
}

const DEFAULT_FORM: AuditForm = {
  name:        '',
  description: '',
  audit_type:  'vulnerability_scan',
  target_id:   '',
  modules:     ['nmap'],
}

const AUDIT_TYPES: { value: AuditType; label: string }[] = [
  { value: 'vulnerability_scan', label: 'Vulnerability Scan' },
  { value: 'penetration_test',   label: 'Penetration Test' },
  { value: 'compliance',         label: 'Compliance' },
  { value: 'static_analysis',    label: 'Static Analysis' },
]

const TOOLS: { value: ScanTool; label: string; desc: string }[] = [
  { value: 'nmap',   label: 'Nmap',   desc: 'Port & service discovery' },
  { value: 'nikto',  label: 'Nikto',  desc: 'Web server vulnerabilities' },
  { value: 'wapiti', label: 'Wapiti', desc: 'Web app SQLi / XSS / LFI' },
  { value: 'nuclei', label: 'Nuclei', desc: 'CVE template scanning' },
]

// ── Component ─────────────────────────────────────────────────────────────────

export default function Audits() {
  const navigate = useNavigate()
  const qc = useQueryClient()

  const [search,    setSearch]    = useState('')
  const [showModal, setShowModal] = useState(false)
  const [form,      setForm]      = useState<AuditForm>(DEFAULT_FORM)
  const [formError, setFormError] = useState('')

  // ── Queries ────────────────────────────────────────────────────────────────

  const { data: audits = [], isLoading, isError } = useQuery<Audit[]>({
    queryKey: ['audits'],
    queryFn: () => api.get('/audits').then(r => r.data),
  })

  const { data: targets = [], isLoading: targetsLoading } = useQuery<Target[]>({
    queryKey: ['targets'],
    queryFn: () => api.get('/targets').then(r => r.data),
    enabled: showModal,
  })

  // ── Mutations ──────────────────────────────────────────────────────────────

  const createMutation = useMutation({
    mutationFn: (body: object) => api.post('/audits', body).then(r => r.data),
    onSuccess: (newAudit: Audit) => {
      qc.invalidateQueries({ queryKey: ['audits'] })
      closeModal()
      toast.success('Audit created')
      navigate(`/audits/${newAudit.id}`)
    },
    onError: () => toast.error('Failed to create audit'),
  })

  // ── Handlers ───────────────────────────────────────────────────────────────

  function closeModal() {
    setShowModal(false)
    setForm(DEFAULT_FORM)
    setFormError('')
  }

  function toggleModule(tool: ScanTool) {
    setForm(f => {
      const has = f.modules.includes(tool)
      if (has && f.modules.length === 1) return f   // keep at least one
      return { ...f, modules: has ? f.modules.filter(m => m !== tool) : [...f.modules, tool] }
    })
  }

  function handleSubmit(e: React.FormEvent) {
    e.preventDefault()
    setFormError('')

    if (!form.target_id) {
      setFormError('Please select a target.')
      return
    }
    if (form.modules.length === 0) {
      setFormError('Select at least one tool.')
      return
    }

    createMutation.mutate({
      name:        form.name,
      description: form.description || null,
      audit_type:  form.audit_type,
      target_id:   Number(form.target_id),
      modules:     form.modules,
    })
  }

  // ── Filtered list ──────────────────────────────────────────────────────────

  const filtered = audits.filter(a =>
    a.name.toLowerCase().includes(search.toLowerCase()) ||
    a.target.name.toLowerCase().includes(search.toLowerCase())
  )

  // ── Render ─────────────────────────────────────────────────────────────────

  return (
    <div className="space-y-6">

      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-semibold text-foreground">Audits</h1>
          <p className="text-sm text-muted-foreground mt-0.5">Manage and run security audits</p>
        </div>
        <button
          onClick={() => setShowModal(true)}
          className="flex items-center gap-2 rounded-lg bg-blue-500 px-4 py-2 text-sm font-medium text-white hover:bg-blue-600 transition-colors"
        >
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
        <div className="flex items-center gap-2 text-sm text-muted-foreground py-4">
          <Loader2 className="h-4 w-4 animate-spin" />
          Loading audits…
        </div>
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
                  <td colSpan={6} className="px-4 py-12 text-center text-muted-foreground">
                    {audits.length === 0
                      ? 'No audits yet. Create your first one.'
                      : 'No audits match your search.'}
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

      {/* ── Modal: New Audit ─────────────────────────────────────────────── */}
      {showModal && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 backdrop-blur-sm p-4">
          <div className="w-full max-w-lg rounded-xl border border-border bg-card shadow-2xl flex flex-col max-h-[90vh]">

            {/* Modal header */}
            <div className="flex items-center justify-between border-b border-border px-6 py-4 shrink-0">
              <div>
                <h2 className="font-semibold text-foreground">New Audit</h2>
                <p className="text-xs text-muted-foreground mt-0.5">Configure and launch a new security audit</p>
              </div>
              <button
                onClick={closeModal}
                className="rounded-md p-1 text-muted-foreground hover:text-foreground hover:bg-muted/40 transition-colors"
              >
                <X className="h-4 w-4" />
              </button>
            </div>

            {/* Modal body (scrollable) */}
            <form onSubmit={handleSubmit} className="px-6 py-5 space-y-5 overflow-y-auto">

              {/* Name */}
              <div className="space-y-1.5">
                <label className="text-xs font-medium uppercase tracking-wider text-muted-foreground">
                  Audit Name <span className="text-red-400">*</span>
                </label>
                <input
                  type="text"
                  required
                  placeholder="e.g. Q2 Web Server Scan"
                  value={form.name}
                  onChange={e => setForm(f => ({ ...f, name: e.target.value }))}
                  className="w-full rounded-lg border border-input bg-background px-3 py-2 text-sm text-foreground placeholder:text-muted-foreground/50 focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-transparent"
                />
              </div>

              {/* Description */}
              <div className="space-y-1.5">
                <label className="text-xs font-medium uppercase tracking-wider text-muted-foreground">
                  Description <span className="font-normal normal-case text-muted-foreground/60">(optional)</span>
                </label>
                <textarea
                  rows={2}
                  placeholder="Scope, context or objectives…"
                  value={form.description}
                  onChange={e => setForm(f => ({ ...f, description: e.target.value }))}
                  className="w-full rounded-lg border border-input bg-background px-3 py-2 text-sm text-foreground placeholder:text-muted-foreground/50 focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-transparent resize-none"
                />
              </div>

              {/* Audit type + Target — two columns */}
              <div className="grid grid-cols-2 gap-4">
                <div className="space-y-1.5">
                  <label className="text-xs font-medium uppercase tracking-wider text-muted-foreground">
                    Audit Type
                  </label>
                  <select
                    value={form.audit_type}
                    onChange={e => setForm(f => ({ ...f, audit_type: e.target.value as AuditType }))}
                    className="w-full rounded-lg border border-input bg-background px-3 py-2 text-sm text-foreground focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-transparent"
                  >
                    {AUDIT_TYPES.map(t => (
                      <option key={t.value} value={t.value}>{t.label}</option>
                    ))}
                  </select>
                </div>

                <div className="space-y-1.5">
                  <label className="text-xs font-medium uppercase tracking-wider text-muted-foreground">
                    Target <span className="text-red-400">*</span>
                  </label>
                  {targetsLoading ? (
                    <div className="flex items-center gap-2 h-9 text-xs text-muted-foreground">
                      <Loader2 className="h-3.5 w-3.5 animate-spin" />
                      Loading…
                    </div>
                  ) : targets.length === 0 ? (
                    <p className="text-xs text-muted-foreground pt-2">
                      No targets yet.{' '}
                      <button
                        type="button"
                        onClick={() => { closeModal(); navigate('/targets') }}
                        className="text-blue-400 hover:underline"
                      >
                        Add one first
                      </button>
                    </p>
                  ) : (
                    <select
                      value={form.target_id}
                      onChange={e => setForm(f => ({ ...f, target_id: e.target.value }))}
                      className="w-full rounded-lg border border-input bg-background px-3 py-2 text-sm text-foreground focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-transparent"
                    >
                      <option value="">Select target…</option>
                      {targets.map(t => (
                        <option key={t.id} value={t.id}>
                          {t.name} ({t.address})
                        </option>
                      ))}
                    </select>
                  )}
                </div>
              </div>

              {/* Tools */}
              <div className="space-y-2">
                <label className="text-xs font-medium uppercase tracking-wider text-muted-foreground">
                  Tools <span className="text-red-400">*</span>
                </label>
                <div className="grid grid-cols-2 gap-2">
                  {TOOLS.map(tool => {
                    const active = form.modules.includes(tool.value)
                    return (
                      <button
                        key={tool.value}
                        type="button"
                        onClick={() => toggleModule(tool.value)}
                        className={`flex items-start gap-2.5 rounded-lg border px-3 py-2.5 text-left transition-colors ${
                          active
                            ? 'border-blue-500/50 bg-blue-500/10'
                            : 'border-border bg-background hover:bg-muted/20'
                        }`}
                      >
                        {/* Checkbox indicator */}
                        <span className={`mt-0.5 flex h-4 w-4 shrink-0 items-center justify-center rounded border text-xs font-bold transition-colors ${
                          active
                            ? 'border-blue-500 bg-blue-500 text-white'
                            : 'border-border'
                        }`}>
                          {active && '✓'}
                        </span>
                        <span>
                          <span className={`block text-sm font-medium ${active ? 'text-blue-400' : 'text-foreground'}`}>
                            {tool.label}
                          </span>
                          <span className="block text-xs text-muted-foreground mt-0.5">{tool.desc}</span>
                        </span>
                      </button>
                    )
                  })}
                </div>
              </div>

              {/* Error */}
              {(formError || createMutation.isError) && (
                <p className="text-sm text-red-400">
                  {formError || 'Failed to create audit. Please try again.'}
                </p>
              )}

              {/* Actions */}
              <div className="flex gap-3 pt-1">
                <button
                  type="button"
                  onClick={closeModal}
                  className="flex-1 rounded-lg border border-border px-4 py-2 text-sm text-muted-foreground hover:text-foreground hover:bg-muted/40 transition-colors"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  disabled={createMutation.isPending || targets.length === 0}
                  className="flex-1 flex items-center justify-center gap-2 rounded-lg bg-blue-500 px-4 py-2 text-sm font-medium text-white hover:bg-blue-600 transition-colors disabled:opacity-50 disabled:cursor-not-allowed"
                >
                  {createMutation.isPending && <Loader2 className="h-4 w-4 animate-spin" />}
                  Create Audit
                </button>
              </div>
            </form>
          </div>
        </div>
      )}

    </div>
  )
}
