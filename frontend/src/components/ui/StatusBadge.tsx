import { cn } from '@/lib/utils'
import type { AuditStatus } from '@/types'

const config: Record<AuditStatus, { label: string; className: string }> = {
  draft:     { label: 'Draft',     className: 'bg-muted text-muted-foreground' },
  pending:   { label: 'Pending',   className: 'bg-yellow-500/15 text-yellow-400' },
  running:   { label: 'Running',   className: 'bg-blue-500/15 text-blue-400' },
  completed: { label: 'Completed', className: 'bg-green-500/15 text-green-400' },
  failed:    { label: 'Failed',    className: 'bg-red-500/15 text-red-400' },
}

export default function StatusBadge({ status }: { status: AuditStatus }) {
  const { label, className } = config[status]
  return (
    <span className={cn('inline-flex items-center rounded-md px-2 py-0.5 text-xs font-medium', className)}>
      {label}
    </span>
  )
}
