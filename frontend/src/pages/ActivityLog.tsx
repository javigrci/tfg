import { useQuery } from '@tanstack/react-query'
import {
  LogIn, ClipboardList, Play, CheckCircle2, XCircle,
  RefreshCw, Plus, UserPlus, UserCog, UserMinus,
  Loader2, Activity,
} from 'lucide-react'
import api from '@/lib/api'
import type { ActionLogEntry } from '@/types'

// ── Config ────────────────────────────────────────────────────────────────────

type ActionConfig = {
  label: string
  icon: React.ElementType
  iconColor: string
  iconBg: string
}

const ACTION_CONFIG: Record<string, ActionConfig> = {
  user_login:              { label: 'Logged in',       icon: LogIn,        iconColor: 'text-green-400',  iconBg: 'bg-green-500/10'  },
  audit_created:           { label: 'Audit created',   icon: ClipboardList,iconColor: 'text-blue-400',   iconBg: 'bg-blue-500/10'   },
  audit_started:           { label: 'Audit started',   icon: Play,         iconColor: 'text-blue-400',   iconBg: 'bg-blue-500/10'   },
  audit_completed:         { label: 'Audit completed', icon: CheckCircle2, iconColor: 'text-green-400',  iconBg: 'bg-green-500/10'  },
  audit_failed:            { label: 'Audit failed',    icon: XCircle,      iconColor: 'text-red-400',    iconBg: 'bg-red-500/10'    },
  finding_status_changed:  { label: 'Status changed',  icon: RefreshCw,    iconColor: 'text-yellow-400', iconBg: 'bg-yellow-500/10' },
  manual_finding_created:  { label: 'Finding added',   icon: Plus,         iconColor: 'text-violet-400', iconBg: 'bg-violet-500/10' },
  user_created:            { label: 'User created',    icon: UserPlus,     iconColor: 'text-green-400',  iconBg: 'bg-green-500/10'  },
  user_updated:            { label: 'User updated',    icon: UserCog,      iconColor: 'text-blue-400',   iconBg: 'bg-blue-500/10'   },
  user_deleted:            { label: 'User deleted',    icon: UserMinus,    iconColor: 'text-red-400',    iconBg: 'bg-red-500/10'    },
}

const FALLBACK_CONFIG: ActionConfig = {
  label: 'Action',
  icon: Activity,
  iconColor: 'text-muted-foreground',
  iconBg: 'bg-muted/40',
}

// ── Helpers ───────────────────────────────────────────────────────────────────

function timeAgo(iso: string): string {
  const diff = Date.now() - new Date(iso).getTime()
  const mins = Math.floor(diff / 60_000)
  if (mins < 1) return 'just now'
  if (mins < 60) return `${mins}m ago`
  const hours = Math.floor(mins / 60)
  if (hours < 24) return `${hours}h ago`
  const days = Math.floor(hours / 24)
  return `${days}d ago`
}

function fullDate(iso: string): string {
  return new Date(iso).toLocaleString('en-GB', {
    day: '2-digit', month: 'short', year: 'numeric',
    hour: '2-digit', minute: '2-digit',
  })
}

function buildDetail(entry: ActionLogEntry): string | null {
  const p = entry.payload
  if (entry.action === 'finding_status_changed' && p.old && p.new) {
    return `${p.old} → ${p.new}`
  }
  if (entry.action === 'audit_created' && p.modules) {
    return Array.isArray(p.modules) ? p.modules.join(', ') : String(p.modules)
  }
  if (entry.action === 'user_created' && p.role) {
    return `role: ${p.role}`
  }
  if (entry.action === 'manual_finding_created' && p.severity) {
    return `severity: ${p.severity}`
  }
  return null
}

// ── Component ─────────────────────────────────────────────────────────────────

export default function ActivityLog() {
  const { data: entries = [], isLoading, isError, refetch } = useQuery<ActionLogEntry[]>({
    queryKey: ['activity-log'],
    queryFn: () => api.get('/admin/activity').then(r => r.data),
    refetchInterval: 30_000,
  })

  return (
    <div className="space-y-6">

      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-semibold text-foreground">Activity Log</h1>
          <p className="text-muted-foreground mt-1 text-sm">
            User actions across the platform — last 300 entries
          </p>
        </div>
        <button
          onClick={() => refetch()}
          className="flex items-center gap-2 rounded-lg border border-border px-4 py-2 text-sm text-muted-foreground hover:text-foreground hover:bg-muted/40 transition-colors"
        >
          <RefreshCw className="h-4 w-4" />
          Refresh
        </button>
      </div>

      {/* Content */}
      <div className="rounded-xl border border-border bg-card overflow-hidden">
        {isLoading ? (
          <div className="flex items-center justify-center py-20 text-muted-foreground gap-2">
            <Loader2 className="h-5 w-5 animate-spin" />
            Loading activity…
          </div>
        ) : isError ? (
          <div className="flex flex-col items-center justify-center py-20 text-muted-foreground gap-2">
            <p className="text-sm">Failed to load activity log.</p>
            <button onClick={() => refetch()} className="text-sm text-blue-400 hover:underline">
              Retry
            </button>
          </div>
        ) : entries.length === 0 ? (
          <div className="flex flex-col items-center justify-center py-20 text-muted-foreground gap-2">
            <Activity className="h-8 w-8 opacity-30" />
            <p className="text-sm">No activity recorded yet.</p>
            <p className="text-xs opacity-60">Actions like logins, audit runs and finding updates will appear here.</p>
          </div>
        ) : (
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-border bg-muted/40 text-xs uppercase tracking-wider text-muted-foreground">
                <th className="px-4 py-3 text-left">Action</th>
                <th className="px-4 py-3 text-left">User</th>
                <th className="px-4 py-3 text-left">Resource</th>
                <th className="px-4 py-3 text-left">Detail</th>
                <th className="px-4 py-3 text-right">When</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-border">
              {entries.map(entry => {
                const cfg = ACTION_CONFIG[entry.action] ?? FALLBACK_CONFIG
                const Icon = cfg.icon
                const detail = buildDetail(entry)

                return (
                  <tr key={entry.id} className="hover:bg-muted/20 transition-colors">
                    {/* Action */}
                    <td className="px-4 py-3">
                      <div className="flex items-center gap-2.5">
                        <div className={`flex h-7 w-7 shrink-0 items-center justify-center rounded-md ${cfg.iconBg}`}>
                          <Icon className={`h-3.5 w-3.5 ${cfg.iconColor}`} />
                        </div>
                        <span className="font-medium text-foreground">{cfg.label}</span>
                      </div>
                    </td>

                    {/* User */}
                    <td className="px-4 py-3">
                      {entry.user ? (
                        <div className="flex items-center gap-2">
                          <div className="flex h-6 w-6 items-center justify-center rounded-full bg-muted text-[10px] font-semibold text-muted-foreground uppercase shrink-0">
                            {entry.user.username.slice(0, 1)}
                          </div>
                          <div className="min-w-0">
                            <p className="text-xs font-medium text-foreground truncate">{entry.user.username}</p>
                            <p className="text-[10px] text-muted-foreground/60 capitalize">{entry.user.role.name}</p>
                          </div>
                        </div>
                      ) : (
                        <span className="text-xs text-muted-foreground/50 italic">System</span>
                      )}
                    </td>

                    {/* Resource */}
                    <td className="px-4 py-3">
                      {entry.resource_name ? (
                        <div className="flex items-center gap-1.5">
                          {entry.resource_type && (
                            <span className="rounded px-1.5 py-0.5 text-[10px] font-medium uppercase tracking-wider bg-muted/60 text-muted-foreground/70">
                              {entry.resource_type}
                            </span>
                          )}
                          <span className="text-xs text-foreground/80 max-w-[180px] truncate" title={entry.resource_name}>
                            {entry.resource_name}
                          </span>
                        </div>
                      ) : (
                        <span className="text-muted-foreground/40">—</span>
                      )}
                    </td>

                    {/* Detail */}
                    <td className="px-4 py-3 text-xs text-muted-foreground/70">
                      {detail ?? <span className="text-muted-foreground/30">—</span>}
                    </td>

                    {/* When */}
                    <td className="px-4 py-3 text-right">
                      <span
                        className="text-xs text-muted-foreground/60 cursor-default"
                        title={fullDate(entry.created_at)}
                      >
                        {timeAgo(entry.created_at)}
                      </span>
                    </td>
                  </tr>
                )
              })}
            </tbody>
          </table>
        )}
      </div>
    </div>
  )
}
