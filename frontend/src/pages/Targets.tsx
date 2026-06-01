import { useState } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { Plus, Wifi, Trash2, X, Loader2, AlertTriangle, FlaskConical, RefreshCw, Check, TrendingUp } from 'lucide-react'
import { toast } from 'sonner'
import {
  AreaChart, Area, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer,
} from 'recharts'
import api from '@/lib/api'
import type { Target, TargetHistory, TargetHistoryEntry, RiskLevel } from '@/types'
import { useTranslation } from 'react-i18next'

// ── Types ─────────────────────────────────────────────────────────────────────

interface TargetForm {
  name: string
  address: string
}

interface LabContainer {
  container: string
  status: 'running' | 'stopped' | 'not_found'
  suggested_name: string
  suggested_address: string | null
  environment: string
  recommended_modules: string[]
  details: Record<string, string>
  description: string
}

// ── Constants ─────────────────────────────────────────────────────────────────

const STATUS_STYLES: Record<string, string> = {
  reachable:   'bg-green-500/10 text-green-400 border border-green-500/20',
  unreachable: 'bg-red-500/10 text-red-400 border border-red-500/20',
  unknown:     'bg-slate-500/10 text-slate-400 border border-slate-500/20',
}

const STATUS_DOT: Record<string, string> = {
  reachable:   'bg-green-400',
  unreachable: 'bg-red-400',
  unknown:     'bg-slate-400',
}

const LAB_STATUS: Record<string, { dot: string; label: string; text: string }> = {
  running:   { dot: 'bg-green-400',  label: 'Running',   text: 'text-green-400'  },
  stopped:   { dot: 'bg-yellow-400', label: 'Stopped',   text: 'text-yellow-400' },
  not_found: { dot: 'bg-slate-500',  label: 'Not found', text: 'text-slate-400'  },
}

const RISK_BADGE: Record<RiskLevel, string> = {
  critical: 'bg-red-500/10 text-red-400 border border-red-500/20',
  high:     'bg-orange-500/10 text-orange-400 border border-orange-500/20',
  medium:   'bg-yellow-500/10 text-yellow-400 border border-yellow-500/20',
  low:      'bg-blue-500/10 text-blue-400 border border-blue-500/20',
  info:     'bg-slate-500/10 text-slate-400 border border-slate-500/20',
}

const SCORE_COLOR = (s: number) =>
  s >= 7 ? '#f87171' : s >= 5 ? '#fb923c' : s >= 3 ? '#facc15' : '#4ade80'

function fmtDate(iso: string) {
  return new Date(iso).toLocaleDateString('en-GB', { day: 'numeric', month: 'short', year: '2-digit' })
}

const MODULE_COLORS: Record<string, { bg: string; text: string }> = {
  nmap:   { bg: 'rgba(59,130,246,0.15)',  text: '#60a5fa'  },
  nikto:  { bg: 'rgba(245,158,11,0.15)',  text: '#fbbf24'  },
  nuclei: { bg: 'rgba(139,92,246,0.15)', text: '#a78bfa'  },
  wapiti: { bg: 'rgba(239,68,68,0.15)',  text: '#f87171'  },
}

// ── Sub-components ────────────────────────────────────────────────────────────

function HistoryTable({ entries }: { entries: TargetHistoryEntry[] }) {
  const { t } = useTranslation()
  return (
    <div>
      <p className="text-xs text-muted-foreground/60 mb-2 uppercase tracking-wider font-medium">
        {t('targets.history.completedAudits')}
      </p>
      <div className="rounded-lg border border-border overflow-hidden">
        <table className="w-full text-xs">
          <thead>
            <tr className="border-b border-border bg-muted/40 text-muted-foreground uppercase tracking-wider">
              <th className="px-3 py-2 text-left">{t('targets.history.colDate')}</th>
              <th className="px-3 py-2 text-left">{t('targets.history.colAudit')}</th>
              <th className="px-3 py-2 text-left">{t('targets.history.colRisk')}</th>
              <th className="px-3 py-2 text-right">{t('targets.history.colScore')}</th>
              <th className="px-3 py-2 text-right text-red-400/70">C</th>
              <th className="px-3 py-2 text-right text-orange-400/70">H</th>
              <th className="px-3 py-2 text-right text-yellow-400/70">M</th>
              <th className="px-3 py-2 text-right text-blue-400/70">L</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-border">
            {entries.map(e => (
              <tr key={e.audit_id} className="hover:bg-muted/20 transition-colors">
                <td className="px-3 py-2 text-muted-foreground whitespace-nowrap">{fmtDate(e.executed_at)}</td>
                <td className="px-3 py-2 text-foreground max-w-[180px] truncate" title={e.audit_name}>{e.audit_name}</td>
                <td className="px-3 py-2">
                  <span className={`inline-flex items-center rounded-full px-2 py-0.5 text-[10px] font-medium capitalize ${RISK_BADGE[e.risk_level]}`}>
                    {e.risk_level}
                  </span>
                </td>
                <td className="px-3 py-2 text-right font-mono font-semibold" style={{ color: SCORE_COLOR(e.risk_score) }}>
                  {e.risk_score.toFixed(1)}
                </td>
                <td className="px-3 py-2 text-right text-red-400">{e.critical_count || '—'}</td>
                <td className="px-3 py-2 text-right text-orange-400">{e.high_count || '—'}</td>
                <td className="px-3 py-2 text-right text-yellow-400">{e.medium_count || '—'}</td>
                <td className="px-3 py-2 text-right text-blue-400">{e.low_count || '—'}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  )
}

// ── Component ─────────────────────────────────────────────────────────────────

export default function Targets() {
  const qc      = useQueryClient()
  const { t }   = useTranslation()

  const [showModal, setShowModal]       = useState(false)
  const [toDelete, setToDelete]         = useState<Target | null>(null)
  const [deleteError, setDeleteError]   = useState('')
  const [checkingId, setCheckingId]     = useState<number | null>(null)
  const [showLabSetup, setShowLabSetup] = useState(false)
  const [addingContainer, setAddingContainer] = useState<string | null>(null)
  const [isAddingAll, setIsAddingAll]   = useState(false)
  const [historyTarget, setHistoryTarget] = useState<Target | null>(null)

  const [form, setForm] = useState<TargetForm>({ name: '', address: '' })

  // ── Queries ────────────────────────────────────────────────────────────────

  const { data: targets = [], isLoading } = useQuery<Target[]>({
    queryKey: ['targets'],
    queryFn: () => api.get('/targets').then(r => r.data),
  })

  const { data: historyData, isLoading: isLoadingHistory } = useQuery<TargetHistory>({
    queryKey: ['target-history', historyTarget?.id],
    queryFn: () => api.get(`/targets/${historyTarget!.id}/history`).then(r => r.data),
    enabled: historyTarget !== null,
  })

  const { data: labContainers = [], isLoading: isDetecting, refetch: refetchLab } = useQuery<LabContainer[]>({
    queryKey: ['lab-detect'],
    queryFn: () => api.get('/lab/detect').then(r => r.data),
    enabled: showLabSetup,
    staleTime: 0,
  })

  // ── Mutations ──────────────────────────────────────────────────────────────

  const createMutation = useMutation({
    mutationFn: (body: object) => api.post('/targets', body).then(r => r.data),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['targets'] })
      setShowModal(false)
      setForm({ name: '', address: '' })
      toast.success(t('targets.toasts.created'))
    },
    onError: () => toast.error(t('targets.toasts.createFailed')),
  })

  const addLabMutation = useMutation({
    mutationFn: (body: object) => api.post('/targets', body).then(r => r.data),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['targets'] })
      toast.success(t('targets.toasts.added'))
      setAddingContainer(null)
    },
    onError: () => {
      toast.error(t('targets.toasts.addFailed'))
      setAddingContainer(null)
    },
  })

  const deleteMutation = useMutation({
    mutationFn: (id: number) => api.delete(`/targets/${id}`),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['targets'] })
      setToDelete(null)
      setDeleteError('')
    },
    onError: (err: any) => {
      if (err.response?.status === 409) {
        setDeleteError(t('targets.delete.error409'))
      } else {
        setDeleteError(t('targets.delete.errorGeneric'))
      }
    },
  })

  const checkMutation = useMutation({
    mutationFn: (id: number) => api.post(`/targets/${id}/check`).then(r => r.data),
    onSuccess: (data) => {
      qc.invalidateQueries({ queryKey: ['targets'] })
      const status = data?.status ?? 'unknown'
      if (status === 'reachable') toast.success(t('targets.toasts.reachable'))
      else if (status === 'unreachable') toast.warning(t('targets.toasts.unreachable'))
      else toast.info(t('targets.toasts.checkComplete'))
    },
    onError: () => toast.error(t('targets.toasts.checkFailed')),
    onSettled: () => setCheckingId(null),
  })

  // ── Helpers ────────────────────────────────────────────────────────────────

  function isAlreadyAdded(c: LabContainer): boolean {
    if (!c.suggested_address) return false
    return targets.some(t => t.address === c.suggested_address)
  }

  async function handleAddAll() {
    const toAdd = labContainers.filter(
      c => c.status === 'running' && c.suggested_address && !isAlreadyAdded(c),
    )
    if (toAdd.length === 0) return
    setIsAddingAll(true)
    try {
      for (const c of toAdd) {
        await api.post('/targets', {
          name:        c.suggested_name,
          address:     c.suggested_address!,
          environment: c.environment,
          details:     c.details,
        })
      }
      qc.invalidateQueries({ queryKey: ['targets'] })
      toast.success(t('targets.lab.addedAll', { count: toAdd.length }))
    } catch {
      toast.error(t('targets.lab.addedAllFailed'))
    } finally {
      setIsAddingAll(false)
    }
  }

  // ── Handlers ───────────────────────────────────────────────────────────────

  function handleCreate(e: React.FormEvent) {
    e.preventDefault()
    createMutation.mutate({ name: form.name, address: form.address })
  }

  function handleCheck(target: Target) {
    setCheckingId(target.id)
    checkMutation.mutate(target.id)
  }

  // ── Render ─────────────────────────────────────────────────────────────────

  const runnableToAdd = labContainers.filter(
    c => c.status === 'running' && c.suggested_address && !isAlreadyAdded(c),
  )

  return (
    <div className="space-y-6">

      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-semibold text-foreground">{t('targets.title')}</h1>
          <p className="text-muted-foreground mt-1 text-sm">
            {t('targets.subtitle')}
          </p>
        </div>
        <div className="flex items-center gap-2">
          <button
            onClick={() => setShowLabSetup(true)}
            className="flex items-center gap-2 rounded-lg border border-border px-4 py-2 text-sm font-medium text-muted-foreground hover:text-foreground hover:bg-muted/40 transition-colors"
          >
            <FlaskConical className="h-4 w-4" />
            {t('targets.labSetup')}
          </button>
          <button
            onClick={() => setShowModal(true)}
            className="flex items-center gap-2 rounded-lg bg-blue-500 px-4 py-2 text-sm font-medium text-white hover:bg-blue-600 transition-colors"
          >
            <Plus className="h-4 w-4" />
            {t('targets.addTarget')}
          </button>
        </div>
      </div>

      {/* Table */}
      <div className="rounded-xl border border-border bg-card overflow-hidden">
        {isLoading ? (
          <div className="flex items-center justify-center py-20 text-muted-foreground">
            <Loader2 className="h-5 w-5 animate-spin mr-2" />
            {t('targets.loading')}
          </div>
        ) : targets.length === 0 ? (
          <div className="flex flex-col items-center justify-center py-20 text-muted-foreground gap-2">
            <p className="text-sm">{t('targets.empty')}</p>
            <button
              onClick={() => setShowModal(true)}
              className="text-sm text-blue-400 hover:underline"
            >
              {t('targets.addFirst')}
            </button>
          </div>
        ) : (
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-border bg-muted/40 text-xs uppercase tracking-wider text-muted-foreground">
                <th className="px-4 py-3 text-left">{t('targets.columns.name')}</th>
                <th className="px-4 py-3 text-left">{t('targets.columns.address')}</th>
                <th className="px-4 py-3 text-left">{t('targets.columns.status')}</th>
                <th className="px-4 py-3 text-right">{t('targets.columns.actions')}</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-border">
              {targets.map(target => (
                <tr key={target.id} className="hover:bg-muted/20 transition-colors">
                  <td className="px-4 py-3 font-medium text-foreground">{target.name}</td>
                  <td className="px-4 py-3 font-mono text-muted-foreground">{target.address}</td>
                  <td className="px-4 py-3">
                    <span className={`inline-flex items-center gap-1.5 rounded-full px-2.5 py-0.5 text-xs font-medium ${STATUS_STYLES[target.status]}`}>
                      <span className={`h-1.5 w-1.5 rounded-full ${STATUS_DOT[target.status]}`} />
                      {t(`domain.targetStatus.${target.status}`)}
                    </span>
                  </td>
                  <td className="px-4 py-3">
                    <div className="flex items-center justify-end gap-2">
                      <button
                        onClick={() => handleCheck(target)}
                        disabled={checkingId === target.id}
                        title={t('targets.titleCheck')}
                        className="flex items-center gap-1.5 rounded-md border border-border px-3 py-1.5 text-xs text-muted-foreground hover:text-foreground hover:bg-muted/40 transition-colors disabled:opacity-50"
                      >
                        {checkingId === target.id
                          ? <Loader2 className="h-3.5 w-3.5 animate-spin" />
                          : <Wifi className="h-3.5 w-3.5" />}
                        {t('targets.actionCheck')}
                      </button>
                      <button
                        onClick={() => setHistoryTarget(target)}
                        title={t('targets.titleHistory')}
                        className="flex items-center gap-1.5 rounded-md border border-border px-3 py-1.5 text-xs text-muted-foreground hover:text-foreground hover:bg-muted/40 transition-colors"
                      >
                        <TrendingUp className="h-3.5 w-3.5" />
                        {t('targets.actionHistory')}
                      </button>
                      <button
                        onClick={() => { setToDelete(target); setDeleteError('') }}
                        title={t('targets.titleDelete')}
                        className="flex items-center gap-1.5 rounded-md border border-border px-3 py-1.5 text-xs text-muted-foreground hover:text-red-400 hover:border-red-400/30 hover:bg-red-500/5 transition-colors"
                      >
                        <Trash2 className="h-3.5 w-3.5" />
                        {t('targets.actionDelete')}
                      </button>
                    </div>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>

      {/* ── Modal: Add Target ────────────────────────────────────────────── */}
      {showModal && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 backdrop-blur-sm p-4">
          <div className="w-full max-w-md rounded-xl border border-border bg-card shadow-2xl">
            <div className="flex items-center justify-between border-b border-border px-6 py-4">
              <div>
                <h2 className="font-semibold text-foreground">{t('targets.modal.addTitle')}</h2>
                <p className="text-xs text-muted-foreground mt-0.5">
                  {t('targets.modal.addSubtitle')}
                </p>
              </div>
              <button
                onClick={() => setShowModal(false)}
                className="rounded-md p-1 text-muted-foreground hover:text-foreground hover:bg-muted/40 transition-colors"
              >
                <X className="h-4 w-4" />
              </button>
            </div>

            <form onSubmit={handleCreate} className="px-6 py-5 space-y-4">
              <div className="space-y-1.5">
                <label className="text-xs font-medium uppercase tracking-wider text-muted-foreground">
                  {t('targets.modal.nameLabel')}
                </label>
                <input
                  type="text"
                  required
                  placeholder={t('targets.modal.namePlaceholder')}
                  value={form.name}
                  onChange={e => setForm(f => ({ ...f, name: e.target.value }))}
                  className="w-full rounded-lg border border-input bg-background px-3 py-2 text-sm text-foreground placeholder:text-muted-foreground/50 focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-transparent"
                />
              </div>

              <div className="space-y-1.5">
                <label className="text-xs font-medium uppercase tracking-wider text-muted-foreground">
                  {t('targets.modal.addressLabel')}
                </label>
                <input
                  type="text"
                  required
                  placeholder={t('targets.modal.addressPlaceholder')}
                  value={form.address}
                  onChange={e => setForm(f => ({ ...f, address: e.target.value }))}
                  className="w-full rounded-lg border border-input bg-background px-3 py-2 text-sm font-mono text-foreground placeholder:text-muted-foreground/50 focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-transparent"
                />
              </div>

              {createMutation.isError && (
                <p className="text-sm text-red-400">{t('targets.modal.createError')}</p>
              )}

              <div className="flex gap-3 pt-1">
                <button
                  type="button"
                  onClick={() => setShowModal(false)}
                  className="flex-1 rounded-lg border border-border px-4 py-2 text-sm text-muted-foreground hover:text-foreground hover:bg-muted/40 transition-colors"
                >
                  {t('common.cancel')}
                </button>
                <button
                  type="submit"
                  disabled={createMutation.isPending}
                  className="flex-1 flex items-center justify-center gap-2 rounded-lg bg-blue-500 px-4 py-2 text-sm font-medium text-white hover:bg-blue-600 transition-colors disabled:opacity-50"
                >
                  {createMutation.isPending && <Loader2 className="h-4 w-4 animate-spin" />}
                  {t('targets.modal.createButton')}
                </button>
              </div>
            </form>
          </div>
        </div>
      )}

      {/* ── Modal: Lab Setup ─────────────────────────────────────────────── */}
      {showLabSetup && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 backdrop-blur-sm p-4">
          <div className="w-full max-w-lg rounded-xl border border-border bg-card shadow-2xl flex flex-col max-h-[90vh]">

            {/* Header */}
            <div className="flex items-center justify-between border-b border-border px-6 py-4 shrink-0">
              <div className="flex items-center gap-3">
                <div className="flex h-8 w-8 items-center justify-center rounded-md bg-emerald-500/15">
                  <FlaskConical className="h-4 w-4 text-emerald-400" />
                </div>
                <div>
                  <h2 className="font-semibold text-foreground">{t('targets.lab.title')}</h2>
                  <p className="text-xs text-muted-foreground mt-0.5">
                    {t('targets.lab.subtitle')}
                  </p>
                </div>
              </div>
              <div className="flex items-center gap-1">
                <button
                  onClick={() => refetchLab()}
                  disabled={isDetecting}
                  title="Refresh"
                  className="rounded-md p-1.5 text-muted-foreground hover:text-foreground hover:bg-muted/40 transition-colors disabled:opacity-40"
                >
                  <RefreshCw className={`h-4 w-4 ${isDetecting ? 'animate-spin' : ''}`} />
                </button>
                <button
                  onClick={() => setShowLabSetup(false)}
                  className="rounded-md p-1.5 text-muted-foreground hover:text-foreground hover:bg-muted/40 transition-colors"
                >
                  <X className="h-4 w-4" />
                </button>
              </div>
            </div>

            {/* Body */}
            <div className="flex-1 overflow-y-auto px-6 py-4 space-y-3">
              {isDetecting ? (
                <div className="flex items-center justify-center py-10 gap-2 text-muted-foreground text-sm">
                  <Loader2 className="h-4 w-4 animate-spin" />
                  {t('targets.lab.detecting')}
                </div>
              ) : (
                labContainers.map(c => {
                  const s       = LAB_STATUS[c.status] ?? LAB_STATUS.not_found
                  const added   = isAlreadyAdded(c)
                  const canAdd  = c.status === 'running' && !!c.suggested_address && !added
                  const isAdding = addingContainer === c.container

                  return (
                    <div
                      key={c.container}
                      className="rounded-lg border border-border bg-background/50 p-4 space-y-3"
                    >
                      {/* Top row: name + status + button */}
                      <div className="flex items-start justify-between gap-3">
                        <div className="flex-1 min-w-0">
                          <div className="flex items-center gap-2 flex-wrap">
                            <span className="font-medium text-sm text-foreground">
                              {c.suggested_name}
                            </span>
                            <span className={`inline-flex items-center gap-1 text-xs font-medium ${s.text}`}>
                              <span className={`h-1.5 w-1.5 rounded-full ${s.dot}`} />
                              {t(`targets.lab.status.${c.status}`)}
                            </span>
                          </div>
                          {c.suggested_address ? (
                            <p className="mt-0.5 font-mono text-xs text-muted-foreground truncate">
                              {c.suggested_address}
                            </p>
                          ) : (
                            <p className="mt-0.5 text-xs text-muted-foreground/50">
                              {t('targets.lab.notRunning')}
                            </p>
                          )}
                        </div>

                        {added ? (
                          <span className="flex items-center gap-1 rounded-md border border-green-500/30 bg-green-500/10 px-2.5 py-1 text-xs font-medium text-green-400 shrink-0">
                            <Check className="h-3 w-3" />
                            {t('targets.lab.added')}
                          </span>
                        ) : (
                          <button
                            onClick={() => {
                              setAddingContainer(c.container)
                              addLabMutation.mutate({
                                name:        c.suggested_name,
                                address:     c.suggested_address!,
                                environment: c.environment,
                                details:     c.details,
                              })
                            }}
                            disabled={!canAdd || isAdding}
                            className="flex items-center gap-1.5 rounded-md bg-blue-500 px-3 py-1 text-xs font-medium text-white hover:bg-blue-600 transition-colors disabled:opacity-40 disabled:cursor-not-allowed shrink-0"
                          >
                            {isAdding && <Loader2 className="h-3 w-3 animate-spin" />}
                            {t('targets.lab.add')}
                          </button>
                        )}
                      </div>

                      {/* Modules */}
                      <div className="flex items-center gap-1.5 flex-wrap">
                        <span className="text-xs text-muted-foreground/60 mr-0.5">{t('targets.lab.recommended')}</span>
                        {c.recommended_modules.map(m => {
                          const col = MODULE_COLORS[m] ?? { bg: 'rgba(100,100,100,0.15)', text: '#9ca3af' }
                          return (
                            <span
                              key={m}
                              className="rounded px-2 py-0.5 text-xs font-medium"
                              style={{ backgroundColor: col.bg, color: col.text }}
                            >
                              {m}
                            </span>
                          )
                        })}
                      </div>

                      {/* Description */}
                      <p className="text-xs text-muted-foreground/60">{c.description}</p>
                    </div>
                  )
                })
              )}
            </div>

            {/* Footer */}
            {!isDetecting && (
              <div className="flex items-center justify-between border-t border-border px-6 py-4 shrink-0">
                <p className="text-xs text-muted-foreground">
                  {runnableToAdd.length > 0
                    ? t('targets.lab.readyToAdd', { count: runnableToAdd.length })
                    : t('targets.lab.allAdded')}
                </p>
                <button
                  onClick={handleAddAll}
                  disabled={runnableToAdd.length === 0 || isAddingAll}
                  className="flex items-center gap-2 rounded-lg bg-blue-500 px-4 py-2 text-sm font-medium text-white hover:bg-blue-600 transition-colors disabled:opacity-40 disabled:cursor-not-allowed"
                >
                  {isAddingAll && <Loader2 className="h-4 w-4 animate-spin" />}
                  {t('targets.lab.addAll')}
                </button>
              </div>
            )}
          </div>
        </div>
      )}

      {/* ── Modal: Risk History ─────────────────────────────────────────── */}
      {historyTarget && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 backdrop-blur-sm p-4">
          <div className="w-full max-w-2xl rounded-xl border border-border bg-card shadow-2xl flex flex-col max-h-[90vh]">

            {/* Header */}
            <div className="flex items-center justify-between border-b border-border px-6 py-4 shrink-0">
              <div className="flex items-center gap-3">
                <div className="flex h-8 w-8 items-center justify-center rounded-md bg-blue-500/15">
                  <TrendingUp className="h-4 w-4 text-blue-400" />
                </div>
                <div>
                  <h2 className="font-semibold text-foreground">{t('targets.history.title')}</h2>
                  <p className="text-xs text-muted-foreground font-mono mt-0.5">{historyTarget.name}</p>
                </div>
              </div>
              <button
                onClick={() => setHistoryTarget(null)}
                className="rounded-md p-1.5 text-muted-foreground hover:text-foreground hover:bg-muted/40 transition-colors"
              >
                <X className="h-4 w-4" />
              </button>
            </div>

            {/* Body */}
            <div className="flex-1 overflow-y-auto px-6 py-5 space-y-5">
              {isLoadingHistory ? (
                <div className="flex items-center justify-center py-16 gap-2 text-muted-foreground text-sm">
                  <Loader2 className="h-4 w-4 animate-spin" />
                  {t('targets.history.loading')}
                </div>
              ) : !historyData || historyData.entries.length === 0 ? (
                <div className="flex flex-col items-center justify-center py-16 text-center gap-2">
                  <TrendingUp className="h-8 w-8 text-muted-foreground/30" />
                  <p className="text-sm text-muted-foreground">{t('targets.history.empty')}</p>
                  <p className="text-xs text-muted-foreground/60">{t('targets.history.emptyHint')}</p>
                </div>
              ) : historyData.entries.length === 1 ? (
                <>
                  <p className="text-xs text-muted-foreground/70 text-center py-2">
                    {t('targets.history.onlyOne')}
                  </p>
                  {/* Still render the single-entry table */}
                  <HistoryTable entries={historyData.entries} />
                </>
              ) : (
                <>
                  {/* Chart */}
                  <div>
                    <p className="text-xs text-muted-foreground/60 mb-3 uppercase tracking-wider font-medium">
                      {t('targets.history.scoreOverTime')}
                    </p>
                    <ResponsiveContainer width="100%" height={220}>
                      <AreaChart
                        data={historyData.entries.map(e => ({
                          label: e.audit_name.length > 18 ? e.audit_name.slice(0, 16) + '…' : e.audit_name,
                          score: parseFloat(e.risk_score.toFixed(2)),
                          date:  fmtDate(e.executed_at),
                        }))}
                        margin={{ top: 8, right: 8, left: -20, bottom: 0 }}
                      >
                        <defs>
                          <linearGradient id="histGrad" x1="0" y1="0" x2="0" y2="1">
                            <stop offset="5%"  stopColor="#3b82f6" stopOpacity={0.25} />
                            <stop offset="95%" stopColor="#3b82f6" stopOpacity={0} />
                          </linearGradient>
                        </defs>
                        <CartesianGrid strokeDasharray="3 3" stroke="rgba(255,255,255,0.05)" />
                        <XAxis
                          dataKey="label"
                          tick={{ fontSize: 10, fill: 'rgba(255,255,255,0.4)' }}
                          axisLine={false}
                          tickLine={false}
                        />
                        <YAxis
                          domain={[0, 10]}
                          ticks={[0, 2, 4, 6, 8, 10]}
                          tick={{ fontSize: 10, fill: 'rgba(255,255,255,0.4)' }}
                          axisLine={false}
                          tickLine={false}
                        />
                        <Tooltip
                          contentStyle={{
                            background: 'hsl(var(--card))',
                            border: '1px solid hsl(var(--border))',
                            borderRadius: '8px',
                            fontSize: '12px',
                          }}
                          formatter={(value) => [Number(value).toFixed(2), t('targets.history.tooltipScore')]}
                          labelFormatter={(label, payload) => payload?.[0]?.payload?.date ?? label}
                        />
                        <Area
                          type="monotone"
                          dataKey="score"
                          stroke="#3b82f6"
                          strokeWidth={2}
                          fill="url(#histGrad)"
                          dot={(props: any) => {
                            const { cx, cy, payload } = props
                            return (
                              <circle
                                key={cx}
                                cx={cx} cy={cy} r={4}
                                fill={SCORE_COLOR(payload.score)}
                                stroke="hsl(var(--card))"
                                strokeWidth={2}
                              />
                            )
                          }}
                        />
                      </AreaChart>
                    </ResponsiveContainer>
                  </div>

                  {/* Table */}
                  <HistoryTable entries={historyData.entries} />
                </>
              )}
            </div>
          </div>
        </div>
      )}

      {/* ── Modal: Confirm Delete ────────────────────────────────────────── */}
      {toDelete && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 backdrop-blur-sm p-4">
          <div className="w-full max-w-sm rounded-xl border border-border bg-card shadow-2xl p-6 space-y-4">
            <div className="flex items-start gap-3">
              <div className="flex h-9 w-9 shrink-0 items-center justify-center rounded-full bg-red-500/10">
                <AlertTriangle className="h-4 w-4 text-red-400" />
              </div>
              <div>
                <h2 className="font-semibold text-foreground">{t('targets.delete.title')}</h2>
                <p className="text-sm text-muted-foreground mt-1">
                  {t('targets.delete.confirmBefore')} <span className="font-medium text-foreground">{toDelete.name}</span>
                  {t('targets.delete.confirmAfter')}
                </p>
              </div>
            </div>

            {deleteError && (
              <p className="text-sm text-red-400 bg-red-500/10 rounded-lg px-3 py-2">
                {deleteError}
              </p>
            )}

            <div className="flex gap-3">
              <button
                onClick={() => { setToDelete(null); setDeleteError('') }}
                className="flex-1 rounded-lg border border-border px-4 py-2 text-sm text-muted-foreground hover:text-foreground hover:bg-muted/40 transition-colors"
              >
                {t('common.cancel')}
              </button>
              <button
                onClick={() => deleteMutation.mutate(toDelete.id)}
                disabled={deleteMutation.isPending}
                className="flex-1 flex items-center justify-center gap-2 rounded-lg bg-red-500 px-4 py-2 text-sm font-medium text-white hover:bg-red-600 transition-colors disabled:opacity-50"
              >
                {deleteMutation.isPending && <Loader2 className="h-4 w-4 animate-spin" />}
                {t('common.delete')}
              </button>
            </div>
          </div>
        </div>
      )}

    </div>
  )
}
