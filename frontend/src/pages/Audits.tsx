import { useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { useTranslation } from 'react-i18next'
import { Search, Plus, Trash2, ChevronLeft, ChevronRight } from 'lucide-react'
import { PageLoader } from '@/components/ui/PageLoader'
import { PageError } from '@/components/ui/PageError'
import { toast } from 'sonner'
import StatusBadge from '@/components/ui/StatusBadge'
import { useAuth } from '@/context/AuthContext'
import api from '@/lib/api'
import type { Audit, AuditType } from '@/types'

// ── Constants ─────────────────────────────────────────────────────────────────

const PAGE_SIZE = 10

// ── Helpers ───────────────────────────────────────────────────────────────────

function duration(started: string | null, finished: string | null): string {
  if (!started) return '—'
  const end = finished ? new Date(finished) : new Date()
  const mins = Math.round((end.getTime() - new Date(started).getTime()) / 60000)
  return mins < 60 ? `${mins}m` : `${Math.floor(mins / 60)}h ${mins % 60}m`
}

// ── Component ─────────────────────────────────────────────────────────────────

export default function Audits() {
  const navigate    = useNavigate()
  const { user }   = useAuth()
  const queryClient = useQueryClient()
  const isAdmin     = user?.role.name === 'admin'
  const { t }       = useTranslation()

  const [search, setSearch]       = useState('')
  const [page,   setPage]         = useState(1)
  const [confirmId, setConfirmId] = useState<number | null>(null)

  const { data: audits = [], isLoading, isError, refetch } = useQuery<Audit[]>({
    queryKey: ['audits'],
    queryFn: () => api.get('/audits').then(r => r.data),
  })

  const deleteMutation = useMutation({
    mutationFn: (id: number) => api.delete(`/audits/${id}`),
    onSuccess: () => {
      toast.success(t('audits.deleted'))
      queryClient.invalidateQueries({ queryKey: ['audits'] })
      setConfirmId(null)
    },
    onError: () => toast.error(t('audits.deleteFailed')),
  })

  const filtered = audits.filter(a =>
    a.name.toLowerCase().includes(search.toLowerCase()) ||
    a.target.name.toLowerCase().includes(search.toLowerCase())
  )

  const totalPages  = Math.max(1, Math.ceil(filtered.length / PAGE_SIZE))
  const currentPage = Math.min(page, totalPages)
  const paginated   = filtered.slice((currentPage - 1) * PAGE_SIZE, currentPage * PAGE_SIZE)

  function handleSearch(value: string) {
    setSearch(value)
    setPage(1)
  }

  const colSpan = isAdmin ? 7 : 6

  return (
    <div className="space-y-6">

      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-semibold text-foreground">{t('audits.title')}</h1>
          <p className="text-sm text-muted-foreground mt-0.5">{t('audits.subtitle')}</p>
        </div>
        <button
          onClick={() => navigate('/audits/new')}
          className="flex items-center gap-2 rounded-lg bg-blue-500 px-4 py-2 text-sm font-medium text-white hover:bg-blue-600 transition-colors"
        >
          <Plus className="h-4 w-4" />
          {t('audits.newAudit')}
        </button>
      </div>

      {/* Search */}
      <div className="relative max-w-sm">
        <Search className="absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-muted-foreground" />
        <input
          type="text"
          placeholder={t('audits.searchPlaceholder')}
          value={search}
          onChange={e => handleSearch(e.target.value)}
          className="w-full rounded-md border border-input bg-background pl-9 pr-3 py-2 text-sm text-foreground placeholder:text-muted-foreground/50 focus:outline-none focus:ring-2 focus:ring-ring"
        />
      </div>

      {/* States */}
      {isLoading && <PageLoader className="h-auto py-4" />}
      {isError   && <PageError onRetry={refetch} className="h-auto py-4" />}

      {/* Table */}
      {!isLoading && !isError && (
        <>
          <div className="rounded-xl border border-border overflow-hidden">
            <table className="w-full text-sm">
              <thead>
                <tr className="border-b border-border bg-muted/30">
                  <th className="px-4 py-3 text-left text-xs font-medium uppercase tracking-wider text-muted-foreground">{t('audits.columns.name')}</th>
                  <th className="px-4 py-3 text-left text-xs font-medium uppercase tracking-wider text-muted-foreground">{t('audits.columns.target')}</th>
                  <th className="px-4 py-3 text-left text-xs font-medium uppercase tracking-wider text-muted-foreground">{t('audits.columns.type')}</th>
                  <th className="px-4 py-3 text-left text-xs font-medium uppercase tracking-wider text-muted-foreground">{t('audits.columns.status')}</th>
                  <th className="px-4 py-3 text-left text-xs font-medium uppercase tracking-wider text-muted-foreground">{t('audits.columns.startDate')}</th>
                  <th className="px-4 py-3 text-left text-xs font-medium uppercase tracking-wider text-muted-foreground">{t('audits.columns.duration')}</th>
                  {isAdmin && (
                    <th className="px-4 py-3 text-left text-xs font-medium uppercase tracking-wider text-muted-foreground">{t('audits.columns.actions')}</th>
                  )}
                </tr>
              </thead>
              <tbody className="divide-y divide-border">
                {paginated.length === 0 && (
                  <tr>
                    <td colSpan={colSpan} className="px-4 py-12 text-center text-muted-foreground">
                      {audits.length === 0
                        ? t('audits.empty')
                        : t('audits.noResults')}
                    </td>
                  </tr>
                )}
                {paginated.map(audit => (
                  <tr
                    key={audit.id}
                    onClick={() => navigate(`/audits/${audit.id}`)}
                    className="cursor-pointer bg-card hover:bg-muted/20 transition-colors"
                  >
                    <td className="px-4 py-3.5 font-medium text-foreground">{audit.name}</td>
                    <td className="px-4 py-3.5 text-muted-foreground">{audit.target.name}</td>
                    <td className="px-4 py-3.5 text-muted-foreground">
                      {t(`domain.auditType.${audit.audit_type as AuditType}`)}
                    </td>
                    <td className="px-4 py-3.5"><StatusBadge status={audit.status} /></td>
                    <td className="px-4 py-3.5 text-muted-foreground">
                      {audit.started_at
                        ? new Date(audit.started_at).toLocaleDateString('en-GB', { day: '2-digit', month: 'short', year: 'numeric' })
                        : '—'}
                    </td>
                    <td className="px-4 py-3.5 text-muted-foreground">{duration(audit.started_at, audit.finished_at)}</td>
                    {isAdmin && (
                      <td className="px-4 py-3.5" onClick={e => e.stopPropagation()}>
                        {confirmId === audit.id ? (
                          <div className="flex items-center gap-2">
                            <button
                              onClick={() => deleteMutation.mutate(audit.id)}
                              disabled={deleteMutation.isPending}
                              className="rounded px-2 py-1 text-xs font-medium bg-red-500/15 text-red-400 hover:bg-red-500/25 transition-colors"
                            >
                              {deleteMutation.isPending ? '…' : t('common.confirm')}
                            </button>
                            <button
                              onClick={() => setConfirmId(null)}
                              className="rounded px-2 py-1 text-xs font-medium bg-muted/40 text-muted-foreground hover:bg-muted/60 transition-colors"
                            >
                              {t('common.cancel')}
                            </button>
                          </div>
                        ) : (
                          <button
                            onClick={() => setConfirmId(audit.id)}
                            className="rounded p-1.5 text-muted-foreground hover:text-red-400 hover:bg-red-500/10 transition-colors"
                            title={t('audits.deleteTitle')}
                          >
                            <Trash2 className="h-4 w-4" />
                          </button>
                        )}
                      </td>
                    )}
                  </tr>
                ))}
              </tbody>
            </table>
          </div>

          {/* Pagination */}
          {totalPages > 1 && (
            <div className="flex items-center justify-between text-sm text-muted-foreground">
              <span>
                {t('audits.pagination', {
                  from:  ((currentPage - 1) * PAGE_SIZE) + 1,
                  to:    Math.min(currentPage * PAGE_SIZE, filtered.length),
                  total: filtered.length,
                })}
              </span>
              <div className="flex items-center gap-1">
                <button
                  onClick={() => setPage(p => Math.max(1, p - 1))}
                  disabled={currentPage === 1}
                  className="rounded p-1.5 hover:bg-muted/40 disabled:opacity-40 disabled:cursor-not-allowed transition-colors"
                >
                  <ChevronLeft className="h-4 w-4" />
                </button>
                {Array.from({ length: totalPages }, (_, i) => i + 1).map(p => (
                  <button
                    key={p}
                    onClick={() => setPage(p)}
                    className={`rounded px-2.5 py-1 text-xs font-medium transition-colors ${
                      p === currentPage
                        ? 'bg-primary text-primary-foreground'
                        : 'hover:bg-muted/40'
                    }`}
                  >
                    {p}
                  </button>
                ))}
                <button
                  onClick={() => setPage(p => Math.min(totalPages, p + 1))}
                  disabled={currentPage === totalPages}
                  className="rounded p-1.5 hover:bg-muted/40 disabled:opacity-40 disabled:cursor-not-allowed transition-colors"
                >
                  <ChevronRight className="h-4 w-4" />
                </button>
              </div>
            </div>
          )}
        </>
      )}

    </div>
  )
}
