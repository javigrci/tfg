import { useState, useEffect, useRef } from 'react'
import { useParams, useNavigate } from 'react-router-dom'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import {
  ArrowLeft, Play, Loader2, Shield, Terminal,
  ChevronDown, ChevronRight, AlertTriangle, Info, FileDown, ArrowLeftRight, Plus, X, Table2,
} from 'lucide-react'
import { toast } from 'sonner'
import api from '@/lib/api'
import type { Audit, ComplianceMap, ComplianceStatus, DeltaResponse, Finding, FindingStatus, SeverityLevel, RiskLevel, Vulnerability } from '@/types'

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
  resolved:       'Resolved',       // manual claim — re-run to verify
  false_positive: 'False Positive',
}

// Shown in the status selector dropdown and as tooltip hint
const FINDING_STATUS_HINTS: Record<FindingStatus, string> = {
  open:           'Vulnerability is confirmed and pending remediation',
  in_progress:    'Remediation is actively in progress',
  resolved:       'Marked resolved by analyst — re-run the audit to confirm the scanner no longer detects it',
  false_positive: 'Analyst determined this is not a real vulnerability in this context',
}

const SEV_ORDER: Record<SeverityLevel, number> = {
  critical: 0, high: 1, medium: 2, low: 3, info: 4,
}
function sortBySev(findings: Finding[]): Finding[] {
  return [...findings].sort((a, b) => (SEV_ORDER[a.severity] ?? 5) - (SEV_ORDER[b.severity] ?? 5))
}

const TOOL_COLORS: Record<string, string> = {
  nmap:    'bg-purple-500/10 text-purple-400 border border-purple-500/20',
  wapiti:  'bg-cyan-500/10 text-cyan-400 border border-cyan-500/20',
  nuclei:  'bg-pink-500/10 text-pink-400 border border-pink-500/20',
  nikto:   'bg-orange-500/10 text-orange-400 border border-orange-500/20',
  bash:    'bg-slate-500/10 text-slate-400 border border-slate-500/20',
  manual:  'bg-violet-500/10 text-violet-400 border border-violet-500/20',
}

function cvssStyle(score: number | null): string {
  if (score === null) return 'bg-slate-500/10 text-slate-400 border border-slate-500/20'
  if (score >= 9.0)   return 'bg-red-500/10 text-red-400 border border-red-500/20'
  if (score >= 7.0)   return 'bg-orange-500/10 text-orange-400 border border-orange-500/20'
  if (score >= 4.0)   return 'bg-yellow-500/10 text-yellow-400 border border-yellow-500/20'
  return 'bg-blue-500/10 text-blue-400 border border-blue-500/20'
}

function CveChips({ vulnerabilities }: { vulnerabilities: Vulnerability[] }) {
  if (!vulnerabilities || vulnerabilities.length === 0) return null
  return (
    <div>
      <p className="text-xs font-medium uppercase tracking-wider text-muted-foreground mb-2">CVEs</p>
      <div className="flex flex-wrap gap-2">
        {vulnerabilities.map(v => (
          <a
            key={v.id}
            href={v.reference ? `https://nvd.nist.gov/vuln/detail/${v.reference}` : undefined}
            target="_blank"
            rel="noopener noreferrer"
            className={`inline-flex items-center gap-1.5 rounded-full px-2.5 py-0.5 text-xs font-medium ${cvssStyle(v.cvss_score)} ${v.reference ? 'hover:opacity-80 transition-opacity cursor-pointer' : ''}`}
          >
            <span className="font-mono">{v.reference ?? v.name}</span>
            {v.cvss_score !== null && (
              <span className="font-bold">{v.cvss_score.toFixed(1)}</span>
            )}
          </a>
        ))}
      </div>
    </div>
  )
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

// ── OWASP Compliance Map ──────────────────────────────────────────────────────

const COMPLIANCE_STYLES: Record<ComplianceStatus, string> = {
  green:        'border-green-500/30 bg-green-500/10',
  yellow:       'border-yellow-500/30 bg-yellow-500/10',
  red:          'border-red-500/30 bg-red-500/10',
  not_assessed: 'border-border bg-muted/20',
}

const COMPLIANCE_DOT: Record<ComplianceStatus, string> = {
  green:        'bg-green-400',
  yellow:       'bg-yellow-400',
  red:          'bg-red-400',
  not_assessed: 'bg-slate-500',
}

const COMPLIANCE_LABEL: Record<ComplianceStatus, string> = {
  green:        'Compliant',
  yellow:       'Low risk',
  red:          'At risk',
  not_assessed: 'Not assessed',
}

const COMPLIANCE_TEXT: Record<ComplianceStatus, string> = {
  green:        'text-green-400',
  yellow:       'text-yellow-400',
  red:          'text-red-400',
  not_assessed: 'text-muted-foreground',
}

function ComplianceMapSection({ compliance }: { compliance: ComplianceMap }) {
  return (
    <div className="rounded-xl border border-border bg-card overflow-hidden">
      <div className="px-5 py-4 border-b border-border flex items-center justify-between">
        <div>
          <h2 className="text-sm font-semibold text-foreground">OWASP Top 10 — 2021</h2>
          <p className="text-xs text-muted-foreground mt-0.5">Coverage based on current findings</p>
        </div>
        <div className="flex items-center gap-3 text-xs text-muted-foreground">
          <span className="flex items-center gap-1.5">
            <span className="h-2 w-2 rounded-full bg-green-400" />
            {compliance.green_count} compliant
          </span>
          <span className="flex items-center gap-1.5">
            <span className="h-2 w-2 rounded-full bg-yellow-400" />
            {compliance.yellow_count} low risk
          </span>
          <span className="flex items-center gap-1.5">
            <span className="h-2 w-2 rounded-full bg-red-400" />
            {compliance.red_count} at risk
          </span>
        </div>
      </div>
      <div className="p-5 grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-5 gap-3">
        {compliance.categories.map(cat => (
          <div
            key={cat.owasp_id}
            className={`rounded-lg border p-3 flex flex-col gap-1.5 ${COMPLIANCE_STYLES[cat.status]}`}
          >
            <div className="flex items-center justify-between">
              <span className="text-xs font-mono font-bold text-foreground">{cat.owasp_id}</span>
              <span className={`h-2 w-2 rounded-full ${COMPLIANCE_DOT[cat.status]}`} />
            </div>
            <p className="text-xs font-medium text-foreground leading-tight">{cat.owasp_name}</p>
            <div className="mt-auto pt-1 flex items-center justify-between">
              <span className={`text-[11px] font-medium ${COMPLIANCE_TEXT[cat.status]}`}>
                {COMPLIANCE_LABEL[cat.status]}
              </span>
              {cat.findings_count > 0 && (
                <span className="text-[11px] text-muted-foreground">
                  {cat.findings_count} finding{cat.findings_count !== 1 ? 's' : ''}
                </span>
              )}
            </div>
          </div>
        ))}
      </div>
    </div>
  )
}

// ── Add Manual Finding Modal ──────────────────────────────────────────────────

const SEVERITY_OPTIONS = ['info', 'low', 'medium', 'high', 'critical'] as const
const CATEGORY_OPTIONS = [
  { value: 'injection',          label: 'Injection' },
  { value: 'broken_auth',        label: 'Broken Authentication' },
  { value: 'xss',                label: 'XSS' },
  { value: 'broken_access',      label: 'Broken Access Control' },
  { value: 'security_misconfig', label: 'Security Misconfiguration' },
  { value: 'sensitive_exposure', label: 'Sensitive Data Exposure' },
  { value: 'outdated_components',label: 'Outdated Components' },
  { value: 'logging_monitoring', label: 'Logging & Monitoring' },
  { value: 'other',              label: 'Other' },
]

interface ManualFindingForm {
  title: string
  description: string
  severity: string
  category: string
  evidence: string
  recommendation: string
  cve_id: string
}

const EMPTY_FORM: ManualFindingForm = {
  title: '', description: '', severity: 'medium', category: 'other',
  evidence: '', recommendation: '', cve_id: '',
}

function AddFindingModal({
  auditId,
  onClose,
  onCreated,
}: {
  auditId: string
  onClose: () => void
  onCreated: () => void
}) {
  const [form, setForm] = useState<ManualFindingForm>(EMPTY_FORM)
  const [submitting, setSubmitting] = useState(false)
  const [errors, setErrors] = useState<Partial<ManualFindingForm>>({})

  function validate(): boolean {
    const e: Partial<ManualFindingForm> = {}
    if (!form.title.trim())          e.title = 'Required'
    if (!form.description.trim())    e.description = 'Required'
    if (!form.recommendation.trim()) e.recommendation = 'Required'
    if (form.cve_id && !/^CVE-\d{4}-\d{4,}$/i.test(form.cve_id)) {
      e.cve_id = 'Format: CVE-YYYY-NNNNN'
    }
    setErrors(e)
    return Object.keys(e).length === 0
  }

  async function handleSubmit(e: React.FormEvent) {
    e.preventDefault()
    if (!validate()) return
    setSubmitting(true)
    try {
      await api.post(`/audits/${auditId}/findings`, {
        title:          form.title.trim(),
        description:    form.description.trim(),
        severity:       form.severity,
        category:       form.category,
        evidence:       form.evidence.trim() || null,
        recommendation: form.recommendation.trim(),
        cve_id:         form.cve_id.trim().toUpperCase() || null,
      })
      toast.success('Manual finding added')
      onCreated()
      onClose()
    } catch {
      toast.error('Failed to add finding')
    } finally {
      setSubmitting(false)
    }
  }

  function field(key: keyof ManualFindingForm) {
    return {
      value: form[key],
      onChange: (e: React.ChangeEvent<HTMLInputElement | HTMLTextAreaElement | HTMLSelectElement>) =>
        setForm(f => ({ ...f, [key]: e.target.value })),
    }
  }

  const inputCls = 'w-full rounded-md border border-border bg-background px-3 py-2 text-sm text-foreground placeholder:text-muted-foreground focus:outline-none focus:ring-1 focus:ring-blue-500'
  const labelCls = 'block text-xs font-medium text-muted-foreground mb-1'
  const errorCls = 'mt-0.5 text-[11px] text-red-400'

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60" onClick={onClose}>
      <div
        className="w-full max-w-lg rounded-xl border border-border bg-card shadow-2xl overflow-hidden"
        onClick={e => e.stopPropagation()}
      >
        {/* Header */}
        <div className="flex items-center justify-between px-5 py-4 border-b border-border">
          <div className="flex items-center gap-2">
            <Shield className="h-4 w-4 text-violet-400" />
            <h2 className="text-sm font-semibold text-foreground">Add Manual Finding</h2>
          </div>
          <button onClick={onClose} className="rounded p-1 text-muted-foreground hover:text-foreground hover:bg-muted/40">
            <X className="h-4 w-4" />
          </button>
        </div>

        {/* Form */}
        <form onSubmit={handleSubmit} className="px-5 py-4 space-y-4 max-h-[70vh] overflow-y-auto">

          {/* Title */}
          <div>
            <label className={labelCls}>Title *</label>
            <input {...field('title')} placeholder="e.g. Reflected XSS in search parameter" className={inputCls} />
            {errors.title && <p className={errorCls}>{errors.title}</p>}
          </div>

          {/* Severity + Category */}
          <div className="grid grid-cols-2 gap-3">
            <div>
              <label className={labelCls}>Severity *</label>
              <select {...field('severity')} className={inputCls}>
                {SEVERITY_OPTIONS.map(s => (
                  <option key={s} value={s} className="capitalize">{s.charAt(0).toUpperCase() + s.slice(1)}</option>
                ))}
              </select>
            </div>
            <div>
              <label className={labelCls}>Category *</label>
              <select {...field('category')} className={inputCls}>
                {CATEGORY_OPTIONS.map(c => (
                  <option key={c.value} value={c.value}>{c.label}</option>
                ))}
              </select>
            </div>
          </div>

          {/* Description */}
          <div>
            <label className={labelCls}>Description *</label>
            <textarea
              {...field('description')}
              rows={3}
              placeholder="Describe the vulnerability and its context"
              className={`${inputCls} resize-none`}
            />
            {errors.description && <p className={errorCls}>{errors.description}</p>}
          </div>

          {/* Evidence */}
          <div>
            <label className={labelCls}>Evidence <span className="text-muted-foreground/60">(optional)</span></label>
            <textarea
              {...field('evidence')}
              rows={2}
              placeholder="HTTP request/response, screenshot reference, PoC payload..."
              className={`${inputCls} resize-none font-mono text-xs`}
            />
          </div>

          {/* Recommendation */}
          <div>
            <label className={labelCls}>Recommendation *</label>
            <textarea
              {...field('recommendation')}
              rows={2}
              placeholder="Describe the remediation steps"
              className={`${inputCls} resize-none`}
            />
            {errors.recommendation && <p className={errorCls}>{errors.recommendation}</p>}
          </div>

          {/* CVE ID */}
          <div>
            <label className={labelCls}>CVE ID <span className="text-muted-foreground/60">(optional — triggers NVD lookup)</span></label>
            <input
              {...field('cve_id')}
              placeholder="CVE-2021-41773"
              className={inputCls}
            />
            {errors.cve_id && <p className={errorCls}>{errors.cve_id}</p>}
          </div>

          {/* Actions */}
          <div className="flex justify-end gap-3 pt-2 border-t border-border">
            <button
              type="button"
              onClick={onClose}
              className="rounded-lg border border-border px-4 py-2 text-sm text-muted-foreground hover:text-foreground hover:bg-muted/40 transition-colors"
            >
              Cancel
            </button>
            <button
              type="submit"
              disabled={submitting}
              className="flex items-center gap-2 rounded-lg bg-violet-600 px-4 py-2 text-sm font-medium text-white hover:bg-violet-700 transition-colors disabled:opacity-50"
            >
              {submitting ? <Loader2 className="h-4 w-4 animate-spin" /> : <Plus className="h-4 w-4" />}
              {submitting ? 'Adding...' : 'Add Finding'}
            </button>
          </div>
        </form>
      </div>
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
              <CveChips vulnerabilities={finding.vulnerabilities} />
              {finding.notes && (
                <div>
                  <p className="text-xs font-medium uppercase tracking-wider text-muted-foreground mb-1">Analyst Notes</p>
                  <p className="text-foreground">{finding.notes}</p>
                </div>
              )}
              {/* Status control */}
              <div className="flex flex-col gap-2 pt-1 border-t border-border">
                <div className="flex items-center gap-3">
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
                <p className="text-[11px] text-muted-foreground/60 italic">
                  {FINDING_STATUS_HINTS[finding.status]}
                </p>
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
    // Poll every 2 s while the audit is running (background task)
    refetchInterval: (query) =>
      query.state.data?.status === 'running' ? 2000 : false,
  })

  const { data: delta } = useQuery<DeltaResponse | null>({
    queryKey: ['delta', id],
    queryFn: () => api.get(`/audits/${id}/delta`).then(r => r.data),
    enabled: !!audit,
  })

  const { data: compliance } = useQuery<ComplianceMap>({
    queryKey: ['compliance', id],
    queryFn: () => api.get(`/audits/${id}/compliance`).then(r => r.data),
    enabled: !!audit?.report,
  })

  // Detect running → completed transition to show toast and refresh delta
  const prevStatusRef = useRef<string | undefined>(undefined)
  useEffect(() => {
    const prev = prevStatusRef.current
    const curr = audit?.status
    if (prev === 'running' && curr === 'completed') {
      toast.success('Audit completed successfully')
      qc.invalidateQueries({ queryKey: ['audits'] })
      qc.invalidateQueries({ queryKey: ['delta', id] })
      qc.invalidateQueries({ queryKey: ['compliance', id] })
    }
    if (prev === 'running' && curr === 'failed') {
      toast.error('Audit execution failed')
    }
    prevStatusRef.current = curr
  }, [audit?.status, id, qc])

  const runMutation = useMutation({
    mutationFn: () => api.post(`/audits/${id}/run`).then(r => r.data),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['audit', id] })
      toast.info('Scan started — results will appear automatically')
    },
    onError: () => toast.error('Failed to start audit'),
  })

  const [pdfLoading, setPdfLoading] = useState<'technical' | 'executive' | null>(null)
  const [csvLoading, setCsvLoading] = useState(false)
  const [showAddFinding, setShowAddFinding] = useState(false)

  const handleDownloadPdf = async (type: 'technical' | 'executive') => {
    if (pdfLoading) return
    setPdfLoading(type)
    const endpoint = type === 'executive'
      ? `/audits/${id}/report/pdf/executive`
      : `/audits/${id}/report/pdf`
    const filename = type === 'executive'
      ? `audit_executive_${id}.pdf`
      : `audit_technical_${id}.pdf`
    try {
      const response = await api.get(endpoint, { responseType: 'blob' })
      const blob = new Blob([response.data], { type: 'application/pdf' })
      const url  = URL.createObjectURL(blob)
      const a    = document.createElement('a')
      a.href     = url
      a.download = filename
      document.body.appendChild(a)
      a.click()
      document.body.removeChild(a)
      URL.revokeObjectURL(url)
      toast.success(`${type === 'executive' ? 'Executive' : 'Technical'} report downloaded`)
    } catch {
      toast.error('Failed to generate PDF')
    } finally {
      setPdfLoading(null)
    }
  }

  const handleDownloadCsv = async () => {
    if (csvLoading) return
    setCsvLoading(true)
    try {
      const response = await api.get(`/audits/${id}/findings/export`, { responseType: 'blob' })
      const blob = new Blob([response.data], { type: 'text/csv' })
      const url  = URL.createObjectURL(blob)
      const a    = document.createElement('a')
      a.href     = url
      a.download = `findings_${id}_${new Date().toISOString().slice(0, 10)}.csv`
      document.body.appendChild(a)
      a.click()
      document.body.removeChild(a)
      URL.revokeObjectURL(url)
      toast.success('CSV exported')
    } catch {
      toast.error('Failed to export CSV')
    } finally {
      setCsvLoading(false)
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
  const isUnreachable = audit.target.status === 'unreachable'
  const isRunning = audit.status === 'running'
  const canRun = !isRunning && !isUnreachable

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
            <>
              <button
                onClick={() => handleDownloadPdf('executive')}
                disabled={!!pdfLoading || csvLoading}
                className="flex items-center gap-2 rounded-lg border border-border bg-card px-4 py-2 text-sm font-medium text-foreground hover:bg-muted/40 transition-colors disabled:opacity-50 disabled:cursor-not-allowed"
              >
                {pdfLoading === 'executive'
                  ? <Loader2 className="h-4 w-4 animate-spin" />
                  : <FileDown className="h-4 w-4" />}
                Executive
              </button>
              <button
                onClick={() => handleDownloadPdf('technical')}
                disabled={!!pdfLoading || csvLoading}
                className="flex items-center gap-2 rounded-lg border border-blue-500/30 bg-blue-500/10 px-4 py-2 text-sm font-medium text-blue-400 hover:bg-blue-500/20 transition-colors disabled:opacity-50 disabled:cursor-not-allowed"
              >
                {pdfLoading === 'technical'
                  ? <Loader2 className="h-4 w-4 animate-spin" />
                  : <FileDown className="h-4 w-4" />}
                Technical
              </button>
              <button
                onClick={handleDownloadCsv}
                disabled={!!pdfLoading || csvLoading}
                className="flex items-center gap-2 rounded-lg border border-green-500/30 bg-green-500/10 px-4 py-2 text-sm font-medium text-green-400 hover:bg-green-500/20 transition-colors disabled:opacity-50 disabled:cursor-not-allowed"
              >
                {csvLoading
                  ? <Loader2 className="h-4 w-4 animate-spin" />
                  : <Table2 className="h-4 w-4" />}
                CSV
              </button>
            </>
          )}
          <button
            onClick={() => runMutation.mutate()}
            disabled={!canRun || runMutation.isPending}
            className="flex items-center gap-2 rounded-lg bg-blue-500 px-4 py-2 text-sm font-medium text-white hover:bg-blue-600 transition-colors disabled:opacity-50 disabled:cursor-not-allowed"
          >
            {(runMutation.isPending || isRunning)
              ? <Loader2 className="h-4 w-4 animate-spin" />
              : <Play className="h-4 w-4" />}
            {isRunning ? 'Running...' : 'Run Audit'}
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
        <div className="col-span-2 sm:col-span-1">
          {report
            ? <KpiCard label="Risk Score" value={`${report.risk_score}/10`} sub="DefectDojo model" />
            : <KpiCard label="Risk Score" value="—" sub="Not run yet" />}
        </div>
        <KpiCard label="Total" value={report?.total_findings ?? 0} sub="findings" />
        <KpiCard label="Critical" value={report?.critical_count ?? 0} />
        <KpiCard label="High" value={report?.high_count ?? 0} />
        <KpiCard label="Medium" value={report?.medium_count ?? 0} />
        <KpiCard label="Low" value={report?.low_count ?? 0} />
      </div>

      {/* Unreachable warning */}
      {isUnreachable && (
        <div className="flex items-center gap-3 rounded-xl border border-red-500/30 bg-red-500/10 px-4 py-3 text-sm text-red-400">
          <AlertTriangle className="h-4 w-4 shrink-0" />
          <span>
            Target is <strong>unreachable</strong>. Verify connectivity before running the audit — the scan will return no findings.
          </span>
        </div>
      )}

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
              <div className="flex items-center gap-2">
                {/* Severity summary */}
                {report && allFindings.length > 0 && (
                  <>
                    {(['critical', 'high', 'medium', 'low'] as SeverityLevel[]).map(sev => {
                      const count = allFindings.filter(f => f.severity === sev).length
                      if (count === 0) return null
                      return <SeverityBadge key={sev} severity={sev} />
                    })}
                  </>
                )}
                {/* Add manual finding — visible once the audit has been run */}
                {audit.scans.length > 0 && !isRunning && (
                  <button
                    onClick={() => setShowAddFinding(true)}
                    className="flex items-center gap-1.5 rounded-md border border-violet-500/30 bg-violet-500/10 px-2.5 py-1 text-xs font-medium text-violet-400 hover:bg-violet-500/20 transition-colors"
                  >
                    <Plus className="h-3.5 w-3.5" />
                    Add Finding
                  </button>
                )}
              </div>
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
          {/* Changes since last run */}
          {delta && (
            <div className="rounded-xl border border-border bg-card overflow-hidden">
              <div className="px-4 py-3 border-b border-border">
                <h2 className="text-sm font-semibold text-foreground flex items-center gap-2">
                  <ArrowLeftRight className="h-4 w-4 text-muted-foreground" />
                  Changes since last run
                  <span className="ml-1 text-xs font-normal text-muted-foreground">
                    +{delta.summary.new} new &middot; {delta.summary.resolved} resolved &middot; {delta.summary.persisting} persisting
                  </span>
                </h2>
              </div>
              <div className="divide-y divide-border">

                {/* New */}
                {delta.new.length > 0 && (
                  <div className="px-4 py-3">
                    <p className="text-xs font-medium uppercase tracking-wider text-green-400 mb-2">
                      New ({delta.new.length})
                    </p>
                    <div className="space-y-1.5">
                      {sortBySev(delta.new).map(f => (
                        <div key={f.id} className="flex items-center gap-2 text-sm">
                          <span className="h-1.5 w-1.5 rounded-full bg-green-400 shrink-0" />
                          <span className="text-foreground flex-1 truncate">{f.title}</span>
                          <SeverityBadge severity={f.severity} />
                        </div>
                      ))}
                    </div>
                  </div>
                )}

                {/* Resolved */}
                {delta.resolved.length > 0 && (
                  <div className="px-4 py-3">
                    <p className="text-xs font-medium uppercase tracking-wider text-blue-400 mb-2">
                      Resolved ({delta.resolved.length})
                    </p>
                    <div className="space-y-1.5">
                      {sortBySev(delta.resolved).map(f => (
                        <div key={f.id} className="flex items-center gap-2 text-sm">
                          <span className="h-1.5 w-1.5 rounded-full bg-blue-400 shrink-0" />
                          <span className="text-foreground/50 flex-1 truncate line-through">{f.title}</span>
                          <SeverityBadge severity={f.severity} />
                        </div>
                      ))}
                    </div>
                  </div>
                )}

                {/* Persisting */}
                {delta.persisting.length > 0 && (
                  <div className="px-4 py-3">
                    <p className="text-xs font-medium uppercase tracking-wider text-yellow-400 mb-2">
                      Persisting ({delta.persisting.length})
                    </p>
                    <div className="space-y-1.5">
                      {sortBySev(delta.persisting).map(f => (
                        <div key={f.id} className="flex items-center gap-2 text-sm">
                          <span className="h-1.5 w-1.5 rounded-full bg-yellow-400 shrink-0" />
                          <span className="text-muted-foreground flex-1 truncate">{f.title}</span>
                          <SeverityBadge severity={f.severity} />
                        </div>
                      ))}
                    </div>
                  </div>
                )}

              </div>
            </div>
          )}

        </div>

        {/* Right — Target info + Report */}
        <div className="space-y-4">

          {/* Target info */}
          <div className="rounded-xl border border-border bg-card p-4 space-y-3">
            <h2 className="text-sm font-semibold text-foreground">Target</h2>
            <div className="space-y-2 text-sm">
              <div className="flex justify-between">
                <span className="text-muted-foreground">Name</span>
                <span className="font-medium text-foreground">{audit.target.name}</span>
              </div>
              <div className="flex justify-between">
                <span className="text-muted-foreground">Address</span>
                <span className="font-mono text-foreground">{audit.target.address}</span>
              </div>
              <div className="flex justify-between items-center">
                <span className="text-muted-foreground">Connectivity</span>
                <span className={`inline-flex items-center gap-1.5 rounded-full px-2.5 py-0.5 text-xs font-medium capitalize ${
                  audit.target.status === 'reachable'
                    ? 'bg-green-500/10 text-green-400 border border-green-500/20'
                    : audit.target.status === 'unreachable'
                    ? 'bg-red-500/10 text-red-400 border border-red-500/20'
                    : 'bg-slate-500/10 text-slate-400 border border-slate-500/20'
                }`}>
                  <span className={`h-1.5 w-1.5 rounded-full ${
                    audit.target.status === 'reachable' ? 'bg-green-400' :
                    audit.target.status === 'unreachable' ? 'bg-red-400' : 'bg-slate-400'
                  }`} />
                  {audit.target.status}
                </span>
              </div>
            </div>
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

      {/* OWASP Top 10 Compliance Map — only shown after first run */}
      {compliance && <ComplianceMapSection compliance={compliance} />}

      {/* Add Manual Finding modal */}
      {showAddFinding && id && (
        <AddFindingModal
          auditId={id}
          onClose={() => setShowAddFinding(false)}
          onCreated={() => {
            qc.invalidateQueries({ queryKey: ['audit', id] })
            qc.invalidateQueries({ queryKey: ['compliance', id] })
          }}
        />
      )}

    </div>
  )
}
