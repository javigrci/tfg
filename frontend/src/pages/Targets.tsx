import { useState } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { Plus, Wifi, Trash2, X, Loader2, AlertTriangle } from 'lucide-react'
import { toast } from 'sonner'
import api from '@/lib/api'
import type { Target } from '@/types'

// ── Helpers ──────────────────────────────────────────────────────────────────

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

interface TargetForm {
  name: string
  address: string
}

// ── Component ─────────────────────────────────────────────────────────────────

export default function Targets() {
  const qc = useQueryClient()

  const [showModal, setShowModal]       = useState(false)
  const [toDelete, setToDelete]         = useState<Target | null>(null)
  const [deleteError, setDeleteError]   = useState('')
  const [checkingId, setCheckingId]     = useState<number | null>(null)

  const [form, setForm] = useState<TargetForm>({ name: '', address: '' })

  // ── Queries ────────────────────────────────────────────────────────────────

  const { data: targets = [], isLoading } = useQuery<Target[]>({
    queryKey: ['targets'],
    queryFn: () => api.get('/targets').then(r => r.data),
  })

  // ── Mutations ──────────────────────────────────────────────────────────────

  const createMutation = useMutation({
    mutationFn: (body: object) => api.post('/targets', body).then(r => r.data),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['targets'] })
      setShowModal(false)
      setForm({ name: '', address: '' })
      toast.success('Target created successfully')
    },
    onError: () => toast.error('Failed to create target'),
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
        setDeleteError('This target has associated audits and cannot be deleted.')
      } else {
        setDeleteError('An unexpected error occurred.')
      }
    },
  })

  const checkMutation = useMutation({
    mutationFn: (id: number) => api.post(`/targets/${id}/check`).then(r => r.data),
    onSuccess: (data) => {
      qc.invalidateQueries({ queryKey: ['targets'] })
      const status = data?.status ?? 'unknown'
      if (status === 'reachable') toast.success('Target is reachable')
      else if (status === 'unreachable') toast.warning('Target is unreachable')
      else toast.info('Connectivity check complete')
    },
    onError: () => toast.error('Connectivity check failed'),
    onSettled: () => setCheckingId(null),
  })

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

  return (
    <div className="space-y-6">

      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-semibold text-foreground">Targets</h1>
          <p className="text-muted-foreground mt-1 text-sm">
            Manage systems and infrastructure for audit
          </p>
        </div>
        <button
          onClick={() => setShowModal(true)}
          className="flex items-center gap-2 rounded-lg bg-blue-500 px-4 py-2 text-sm font-medium text-white hover:bg-blue-600 transition-colors"
        >
          <Plus className="h-4 w-4" />
          Add Target
        </button>
      </div>

      {/* Table */}
      <div className="rounded-xl border border-border bg-card overflow-hidden">
        {isLoading ? (
          <div className="flex items-center justify-center py-20 text-muted-foreground">
            <Loader2 className="h-5 w-5 animate-spin mr-2" />
            Loading targets…
          </div>
        ) : targets.length === 0 ? (
          <div className="flex flex-col items-center justify-center py-20 text-muted-foreground gap-2">
            <p className="text-sm">No targets yet.</p>
            <button
              onClick={() => setShowModal(true)}
              className="text-sm text-blue-400 hover:underline"
            >
              Add your first target
            </button>
          </div>
        ) : (
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-border bg-muted/40 text-xs uppercase tracking-wider text-muted-foreground">
                <th className="px-4 py-3 text-left">Name</th>
                <th className="px-4 py-3 text-left">Address</th>
                <th className="px-4 py-3 text-left">Status</th>
                <th className="px-4 py-3 text-right">Actions</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-border">
              {targets.map(target => (
                <tr key={target.id} className="hover:bg-muted/20 transition-colors">
                  <td className="px-4 py-3 font-medium text-foreground">{target.name}</td>
                  <td className="px-4 py-3 font-mono text-muted-foreground">{target.address}</td>
                  <td className="px-4 py-3">
                    <span className={`inline-flex items-center gap-1.5 rounded-full px-2.5 py-0.5 text-xs font-medium capitalize ${STATUS_STYLES[target.status]}`}>
                      <span className={`h-1.5 w-1.5 rounded-full ${STATUS_DOT[target.status]}`} />
                      {target.status}
                    </span>
                  </td>
                  <td className="px-4 py-3">
                    <div className="flex items-center justify-end gap-2">
                      <button
                        onClick={() => handleCheck(target)}
                        disabled={checkingId === target.id}
                        title="Check connectivity"
                        className="flex items-center gap-1.5 rounded-md border border-border px-3 py-1.5 text-xs text-muted-foreground hover:text-foreground hover:bg-muted/40 transition-colors disabled:opacity-50"
                      >
                        {checkingId === target.id
                          ? <Loader2 className="h-3.5 w-3.5 animate-spin" />
                          : <Wifi className="h-3.5 w-3.5" />}
                        Check
                      </button>
                      <button
                        onClick={() => { setToDelete(target); setDeleteError('') }}
                        title="Delete target"
                        className="flex items-center gap-1.5 rounded-md border border-border px-3 py-1.5 text-xs text-muted-foreground hover:text-red-400 hover:border-red-400/30 hover:bg-red-500/5 transition-colors"
                      >
                        <Trash2 className="h-3.5 w-3.5" />
                        Delete
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
            {/* Modal header */}
            <div className="flex items-center justify-between border-b border-border px-6 py-4">
              <div>
                <h2 className="font-semibold text-foreground">Add New Target</h2>
                <p className="text-xs text-muted-foreground mt-0.5">
                  Define a system to include in audits
                </p>
              </div>
              <button
                onClick={() => setShowModal(false)}
                className="rounded-md p-1 text-muted-foreground hover:text-foreground hover:bg-muted/40 transition-colors"
              >
                <X className="h-4 w-4" />
              </button>
            </div>

            {/* Modal body */}
            <form onSubmit={handleCreate} className="px-6 py-5 space-y-4">
              <div className="space-y-1.5">
                <label className="text-xs font-medium uppercase tracking-wider text-muted-foreground">
                  Name
                </label>
                <input
                  type="text"
                  required
                  placeholder="Production Web Server"
                  value={form.name}
                  onChange={e => setForm(f => ({ ...f, name: e.target.value }))}
                  className="w-full rounded-lg border border-input bg-background px-3 py-2 text-sm text-foreground placeholder:text-muted-foreground/50 focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-transparent"
                />
              </div>

              <div className="space-y-1.5">
                <label className="text-xs font-medium uppercase tracking-wider text-muted-foreground">
                  Address
                </label>
                <input
                  type="text"
                  required
                  placeholder="192.168.1.1 or http://app.internal"
                  value={form.address}
                  onChange={e => setForm(f => ({ ...f, address: e.target.value }))}
                  className="w-full rounded-lg border border-input bg-background px-3 py-2 text-sm font-mono text-foreground placeholder:text-muted-foreground/50 focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-transparent"
                />
              </div>

              {createMutation.isError && (
                <p className="text-sm text-red-400">Failed to create target.</p>
              )}

              <div className="flex gap-3 pt-1">
                <button
                  type="button"
                  onClick={() => setShowModal(false)}
                  className="flex-1 rounded-lg border border-border px-4 py-2 text-sm text-muted-foreground hover:text-foreground hover:bg-muted/40 transition-colors"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  disabled={createMutation.isPending}
                  className="flex-1 flex items-center justify-center gap-2 rounded-lg bg-blue-500 px-4 py-2 text-sm font-medium text-white hover:bg-blue-600 transition-colors disabled:opacity-50"
                >
                  {createMutation.isPending && <Loader2 className="h-4 w-4 animate-spin" />}
                  Create Target
                </button>
              </div>
            </form>
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
                <h2 className="font-semibold text-foreground">Delete target</h2>
                <p className="text-sm text-muted-foreground mt-1">
                  Are you sure you want to delete <span className="font-medium text-foreground">{toDelete.name}</span>?
                  This action cannot be undone.
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
                Cancel
              </button>
              <button
                onClick={() => deleteMutation.mutate(toDelete.id)}
                disabled={deleteMutation.isPending}
                className="flex-1 flex items-center justify-center gap-2 rounded-lg bg-red-500 px-4 py-2 text-sm font-medium text-white hover:bg-red-600 transition-colors disabled:opacity-50"
              >
                {deleteMutation.isPending && <Loader2 className="h-4 w-4 animate-spin" />}
                Delete
              </button>
            </div>
          </div>
        </div>
      )}

    </div>
  )
}
