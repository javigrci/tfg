export type AuditStatus = 'draft' | 'pending' | 'running' | 'completed' | 'failed'
export type AuditType = 'penetration_test' | 'vulnerability_scan' | 'compliance' | 'static_analysis'
export type SeverityLevel = 'info' | 'low' | 'medium' | 'high' | 'critical'
export type TargetStatus = 'unknown' | 'reachable' | 'unreachable'

export interface Target {
  id: number
  name: string
  address: string
  environment: 'lab' | 'staging' | 'production'
  status: TargetStatus
  details: Record<string, unknown>
  created_at: string
}

export interface Audit {
  id: number
  name: string
  description: string
  audit_type: AuditType
  status: AuditStatus
  target: Target
  created_at: string
  started_at: string | null
  finished_at: string | null
}
