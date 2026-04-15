import { useState } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { toast } from 'sonner'
import {
  UserPlus,
  Trash2,
  Pencil,
  Eye,
  EyeOff,
  Loader2,
  AlertCircle,
  RefreshCw,
  X,
  ShieldCheck,
  User,
} from 'lucide-react'
import api from '@/lib/api'
import type { AppUser, UserRole } from '@/types'
import { useAuth } from '@/context/AuthContext'

// ── API helpers ──────────────────────────────────────────────────────────────

function fetchUsers(): Promise<AppUser[]> {
  return api.get('/users').then((r) => r.data)
}

interface CreatePayload { username: string; password: string; role_name: UserRole }
interface UpdatePayload { password?: string; role_name?: UserRole }

// ── Styles ───────────────────────────────────────────────────────────────────

const inputCls =
  'w-full rounded-lg border border-input bg-background px-3 py-2 text-sm text-foreground placeholder:text-muted-foreground/50 focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-transparent'

// ── Sub-components ────────────────────────────────────────────────────────────

function RoleBadge({ role }: { role: UserRole }) {
  return role === 'admin' ? (
    <span className="inline-flex items-center gap-1.5 rounded-full border border-violet-500/30 bg-violet-500/15 px-2.5 py-0.5 text-xs font-medium text-violet-400">
      <ShieldCheck className="h-3 w-3" />
      Admin
    </span>
  ) : (
    <span className="inline-flex items-center gap-1.5 rounded-full border border-blue-500/30 bg-blue-500/15 px-2.5 py-0.5 text-xs font-medium text-blue-400">
      <User className="h-3 w-3" />
      Operator
    </span>
  )
}

function RoleSelector({
  value,
  onChange,
}: {
  value: UserRole
  onChange: (r: UserRole) => void
}) {
  return (
    <div className="flex gap-2">
      {(['admin', 'operator'] as UserRole[]).map((r) => (
        <button
          key={r}
          type="button"
          onClick={() => onChange(r)}
          className={`flex-1 rounded-lg border px-3 py-2 text-sm font-medium capitalize transition-colors ${
            value === r
              ? r === 'admin'
                ? 'border-violet-500 bg-violet-500/15 text-violet-400'
                : 'border-blue-500 bg-blue-500/15 text-blue-400'
              : 'border-border text-muted-foreground hover:border-muted-foreground hover:bg-muted/20'
          }`}
        >
          {r}
        </button>
      ))}
    </div>
  )
}

function PasswordInput({
  value,
  onChange,
  placeholder,
}: {
  value: string
  onChange: (v: string) => void
  placeholder?: string
}) {
  const [show, setShow] = useState(false)
  return (
    <div className="relative">
      <input
        type={show ? 'text' : 'password'}
        value={value}
        onChange={(e) => onChange(e.target.value)}
        placeholder={placeholder ?? 'Enter password'}
        className={`${inputCls} pr-10`}
      />
      <button
        type="button"
        onClick={() => setShow((s) => !s)}
        className="absolute right-3 top-1/2 -translate-y-1/2 text-muted-foreground hover:text-foreground transition-colors"
      >
        {show ? <EyeOff className="h-4 w-4" /> : <Eye className="h-4 w-4" />}
      </button>
    </div>
  )
}

// ── Main page ────────────────────────────────────────────────────────────────

export default function UsersAdmin() {
  const { user: currentUser } = useAuth()
  const queryClient = useQueryClient()

  const [createOpen, setCreateOpen] = useState(false)
  const [editTarget, setEditTarget] = useState<AppUser | null>(null)
  const [deleteTarget, setDeleteTarget] = useState<AppUser | null>(null)

  // create form state
  const [newUsername, setNewUsername] = useState('')
  const [newPassword, setNewPassword] = useState('')
  const [newRole, setNewRole] = useState<UserRole>('operator')

  // edit form state
  const [editPassword, setEditPassword] = useState('')
  const [editRole, setEditRole] = useState<UserRole>('operator')

  const {
    data: users,
    isLoading,
    isError,
    refetch,
  } = useQuery({ queryKey: ['users'], queryFn: fetchUsers })

  const createMutation = useMutation({
    mutationFn: (data: CreatePayload) => api.post('/users', data).then((r) => r.data),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['users'] })
      setCreateOpen(false)
      setNewUsername('')
      setNewPassword('')
      setNewRole('operator')
      toast.success('User created successfully')
    },
    onError: (err: any) => {
      toast.error(err?.response?.data?.detail ?? 'Failed to create user')
    },
  })

  const updateMutation = useMutation({
    mutationFn: ({ id, data }: { id: number; data: UpdatePayload }) =>
      api.put(`/users/${id}`, data).then((r) => r.data),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['users'] })
      setEditTarget(null)
      setEditPassword('')
      toast.success('User updated successfully')
    },
    onError: (err: any) => {
      toast.error(err?.response?.data?.detail ?? 'Failed to update user')
    },
  })

  const deleteMutation = useMutation({
    mutationFn: (id: number) => api.delete(`/users/${id}`),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['users'] })
      setDeleteTarget(null)
      toast.success('User deleted')
    },
    onError: (err: any) => {
      toast.error(err?.response?.data?.detail ?? 'Failed to delete user')
    },
  })

  function openEdit(u: AppUser) {
    setEditTarget(u)
    setEditRole(u.role.name)
    setEditPassword('')
  }

  function handleCreate(e: React.FormEvent) {
    e.preventDefault()
    if (!newUsername.trim() || !newPassword) return
    createMutation.mutate({ username: newUsername.trim(), password: newPassword, role_name: newRole })
  }

  function handleUpdate(e: React.FormEvent) {
    e.preventDefault()
    if (!editTarget) return
    const payload: UpdatePayload = {}
    if (editPassword) payload.password = editPassword
    if (editRole !== editTarget.role.name) payload.role_name = editRole
    updateMutation.mutate({ id: editTarget.id, data: payload })
  }

  // ── KPIs ─────────────────────────────────────────────────────────────────

  const totalUsers   = users?.length ?? 0
  const adminCount   = users?.filter((u) => u.role.name === 'admin').length ?? 0
  const operatorCount = users?.filter((u) => u.role.name === 'operator').length ?? 0

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-semibold text-foreground">User Management</h1>
          <p className="text-muted-foreground mt-1 text-sm">
            Create and manage platform accounts
          </p>
        </div>
        <button
          onClick={() => setCreateOpen(true)}
          className="flex items-center gap-2 rounded-lg bg-blue-500 px-4 py-2 text-sm font-medium text-white hover:bg-blue-600 transition-colors"
        >
          <UserPlus className="h-4 w-4" />
          Add New User
        </button>
      </div>

      {/* KPI cards */}
      <div className="grid grid-cols-3 gap-4">
        <div className="rounded-xl border border-border bg-card p-5 space-y-1">
          <p className="text-xs font-medium uppercase tracking-wider text-muted-foreground">
            Total Users
          </p>
          <p className="text-3xl font-bold text-foreground">{totalUsers}</p>
        </div>
        <div className="rounded-xl border border-border bg-card p-5 space-y-1">
          <p className="text-xs font-medium uppercase tracking-wider text-muted-foreground">
            Admins
          </p>
          <p className="text-3xl font-bold text-violet-400">{adminCount}</p>
        </div>
        <div className="rounded-xl border border-border bg-card p-5 space-y-1">
          <p className="text-xs font-medium uppercase tracking-wider text-muted-foreground">
            Operators
          </p>
          <p className="text-3xl font-bold text-blue-400">{operatorCount}</p>
        </div>
      </div>

      {/* Table */}
      <div className="rounded-xl border border-border bg-card overflow-hidden">
        {isLoading ? (
          <div className="flex items-center justify-center py-20 text-muted-foreground">
            <Loader2 className="h-5 w-5 animate-spin mr-2" />
            Loading users…
          </div>
        ) : isError ? (
          <div className="flex flex-col items-center justify-center py-20 gap-3 text-muted-foreground">
            <AlertCircle className="h-8 w-8" />
            <p className="text-sm">Failed to load users</p>
            <button
              onClick={() => refetch()}
              className="flex items-center gap-1.5 rounded-md border border-border px-3 py-1.5 text-xs hover:bg-muted/40 transition-colors"
            >
              <RefreshCw className="h-3.5 w-3.5" />
              Retry
            </button>
          </div>
        ) : (
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-border bg-muted/40 text-xs uppercase tracking-wider text-muted-foreground">
                <th className="px-4 py-3 text-left">Username</th>
                <th className="px-4 py-3 text-left">Role</th>
                <th className="px-4 py-3 text-left">Created</th>
                <th className="px-4 py-3 text-right">Actions</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-border">
              {users?.map((u) => (
                <tr key={u.id} className="hover:bg-muted/20 transition-colors">
                  <td className="px-4 py-3">
                    <div className="flex items-center gap-2.5">
                      <div className="flex h-7 w-7 items-center justify-center rounded-full bg-muted text-xs font-semibold text-muted-foreground uppercase shrink-0">
                        {u.username.slice(0, 1)}
                      </div>
                      <span className="font-medium text-foreground">
                        {u.username}
                        {u.id === currentUser?.id && (
                          <span className="ml-2 text-xs text-muted-foreground font-normal">(you)</span>
                        )}
                      </span>
                    </div>
                  </td>
                  <td className="px-4 py-3">
                    <RoleBadge role={u.role.name} />
                  </td>
                  <td className="px-4 py-3 text-muted-foreground">
                    {new Date(u.created_at).toLocaleDateString('en-GB', {
                      day: '2-digit',
                      month: 'short',
                      year: 'numeric',
                    })}
                  </td>
                  <td className="px-4 py-3">
                    <div className="flex items-center justify-end gap-2">
                      <button
                        onClick={() => openEdit(u)}
                        title="Edit user"
                        className="flex items-center gap-1.5 rounded-md border border-border px-3 py-1.5 text-xs text-muted-foreground hover:text-foreground hover:bg-muted/40 transition-colors"
                      >
                        <Pencil className="h-3.5 w-3.5" />
                        Edit
                      </button>
                      <button
                        onClick={() => setDeleteTarget(u)}
                        disabled={u.id === currentUser?.id}
                        title={u.id === currentUser?.id ? 'Cannot delete your own account' : 'Delete user'}
                        className="flex items-center gap-1.5 rounded-md border border-border px-3 py-1.5 text-xs text-muted-foreground hover:text-red-400 hover:border-red-400/30 hover:bg-red-500/5 transition-colors disabled:opacity-30 disabled:cursor-not-allowed"
                      >
                        <Trash2 className="h-3.5 w-3.5" />
                        Delete
                      </button>
                    </div>
                  </td>
                </tr>
              ))}
              {users?.length === 0 && (
                <tr>
                  <td colSpan={4} className="text-center text-muted-foreground py-12 text-sm">
                    No users found.
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        )}
      </div>

      {/* ── Modal: Create User ──────────────────────────────────────────────── */}
      {createOpen && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 backdrop-blur-sm p-4">
          <div className="w-full max-w-md rounded-xl border border-border bg-card shadow-2xl">
            <div className="flex items-center justify-between border-b border-border px-6 py-4">
              <div>
                <h2 className="font-semibold text-foreground">Add New User</h2>
                <p className="text-xs text-muted-foreground mt-0.5">
                  Create a platform account
                </p>
              </div>
              <button
                onClick={() => setCreateOpen(false)}
                className="rounded-md p-1 text-muted-foreground hover:text-foreground hover:bg-muted/40 transition-colors"
              >
                <X className="h-4 w-4" />
              </button>
            </div>
            <form onSubmit={handleCreate} className="px-6 py-5 space-y-4">
              <div className="space-y-1.5">
                <label className="text-xs font-medium uppercase tracking-wider text-muted-foreground">
                  Username
                </label>
                <input
                  type="text"
                  required
                  autoFocus
                  placeholder="e.g. john.doe"
                  value={newUsername}
                  onChange={(e) => setNewUsername(e.target.value)}
                  className={inputCls}
                />
              </div>
              <div className="space-y-1.5">
                <label className="text-xs font-medium uppercase tracking-wider text-muted-foreground">
                  Password
                </label>
                <PasswordInput value={newPassword} onChange={setNewPassword} />
              </div>
              <div className="space-y-1.5">
                <label className="text-xs font-medium uppercase tracking-wider text-muted-foreground">
                  Role
                </label>
                <RoleSelector value={newRole} onChange={setNewRole} />
              </div>
              <div className="flex gap-3 pt-1">
                <button
                  type="button"
                  onClick={() => setCreateOpen(false)}
                  className="flex-1 rounded-lg border border-border px-4 py-2 text-sm text-muted-foreground hover:text-foreground hover:bg-muted/40 transition-colors"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  disabled={createMutation.isPending || !newUsername.trim() || !newPassword}
                  className="flex-1 flex items-center justify-center gap-2 rounded-lg bg-blue-500 px-4 py-2 text-sm font-medium text-white hover:bg-blue-600 transition-colors disabled:opacity-50"
                >
                  {createMutation.isPending && <Loader2 className="h-4 w-4 animate-spin" />}
                  Create User
                </button>
              </div>
            </form>
          </div>
        </div>
      )}

      {/* ── Modal: Edit User ────────────────────────────────────────────────── */}
      {editTarget && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 backdrop-blur-sm p-4">
          <div className="w-full max-w-md rounded-xl border border-border bg-card shadow-2xl">
            <div className="flex items-center justify-between border-b border-border px-6 py-4">
              <div>
                <h2 className="font-semibold text-foreground">Edit User</h2>
                <p className="text-xs text-muted-foreground mt-0.5">
                  @{editTarget.username}
                </p>
              </div>
              <button
                onClick={() => setEditTarget(null)}
                className="rounded-md p-1 text-muted-foreground hover:text-foreground hover:bg-muted/40 transition-colors"
              >
                <X className="h-4 w-4" />
              </button>
            </div>
            <form onSubmit={handleUpdate} className="px-6 py-5 space-y-4">
              <div className="space-y-1.5">
                <label className="text-xs font-medium uppercase tracking-wider text-muted-foreground">
                  New Password
                </label>
                <PasswordInput
                  value={editPassword}
                  onChange={setEditPassword}
                  placeholder="Leave blank to keep current"
                />
                <p className="text-xs text-muted-foreground">
                  Leave blank to keep the current password.
                </p>
              </div>
              <div className="space-y-1.5">
                <label className="text-xs font-medium uppercase tracking-wider text-muted-foreground">
                  Role
                </label>
                <RoleSelector value={editRole} onChange={setEditRole} />
              </div>
              <div className="flex gap-3 pt-1">
                <button
                  type="button"
                  onClick={() => setEditTarget(null)}
                  className="flex-1 rounded-lg border border-border px-4 py-2 text-sm text-muted-foreground hover:text-foreground hover:bg-muted/40 transition-colors"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  disabled={
                    updateMutation.isPending ||
                    (!editPassword && editRole === editTarget.role.name)
                  }
                  className="flex-1 flex items-center justify-center gap-2 rounded-lg bg-blue-500 px-4 py-2 text-sm font-medium text-white hover:bg-blue-600 transition-colors disabled:opacity-50"
                >
                  {updateMutation.isPending && <Loader2 className="h-4 w-4 animate-spin" />}
                  Save Changes
                </button>
              </div>
            </form>
          </div>
        </div>
      )}

      {/* ── Modal: Confirm Delete ───────────────────────────────────────────── */}
      {deleteTarget && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 backdrop-blur-sm p-4">
          <div className="w-full max-w-sm rounded-xl border border-border bg-card shadow-2xl">
            <div className="px-6 py-5 space-y-3">
              <h2 className="font-semibold text-foreground">Delete user?</h2>
              <p className="text-sm text-muted-foreground">
                Are you sure you want to delete{' '}
                <span className="font-medium text-foreground">@{deleteTarget.username}</span>?
                This action cannot be undone. Their audits and findings will be preserved.
              </p>
            </div>
            <div className="flex gap-3 border-t border-border px-6 py-4">
              <button
                onClick={() => setDeleteTarget(null)}
                className="flex-1 rounded-lg border border-border px-4 py-2 text-sm text-muted-foreground hover:text-foreground hover:bg-muted/40 transition-colors"
              >
                Cancel
              </button>
              <button
                onClick={() => deleteMutation.mutate(deleteTarget.id)}
                disabled={deleteMutation.isPending}
                className="flex-1 flex items-center justify-center gap-2 rounded-lg bg-red-500 px-4 py-2 text-sm font-medium text-white hover:bg-red-600 transition-colors disabled:opacity-50"
              >
                {deleteMutation.isPending && <Loader2 className="h-4 w-4 animate-spin" />}
                Delete User
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  )
}
