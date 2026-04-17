export type UserRole      = 'admin' | 'operator'

export interface AppUser {
  id: number
  username: string
  role: { id: number; name: UserRole }
  created_at: string
}

export type FindingStatus = 'open' | 'in_progress' | 'resolved' | 'false_positive'
export type AuditStatus   = 'draft' | 'pending' | 'running' | 'completed' | 'failed'
export type AuditType     = 'penetration_test' | 'vulnerability_scan' | 'compliance' | 'static_analysis'
export type ScanStatus    = 'pending' | 'running' | 'completed' | 'failed'
export type ScanTool      = 'bash' | 'nmap' | 'nikto' | 'wapiti' | 'nuclei'
export type SeverityLevel = 'info' | 'low' | 'medium' | 'high' | 'critical'
export type RiskLevel     = 'info' | 'low' | 'medium' | 'high' | 'critical'
export type TargetStatus  = 'unknown' | 'reachable' | 'unreachable'

export interface Target {
  id: number
  name: string
  address: string
  environment: 'lab' | 'staging' | 'production'
  status: TargetStatus
  details: Record<string, unknown>
  created_at: string
}

export interface Finding {
  id: number
  title: string
  description: string
  severity: SeverityLevel
  category: string
  evidence: string | null
  recommendation: string
  status: FindingStatus
  notes: string | null
  fingerprint: string | null
  resolved_at: string | null
}

export interface Scan {
  id: number
  tool: ScanTool
  command: string | null
  status: ScanStatus
  executed_at: string | null
  findings: Finding[]
}

export interface Report {
  id: number
  summary: string | null
  risk_level: RiskLevel
  total_findings: number
  critical_count: number
  high_count: number
  medium_count: number
  low_count: number
  created_at: string
}

export interface Audit {
  id: number
  name: string
  description: string | null
  audit_type: AuditType
  status: AuditStatus
  selected_modules: string[]
  target: Target
  created_by: { id: number; username: string; role: { id: number; name: string } }
  scans: Scan[]
  report: Report | null
  created_at: string
  started_at: string | null
  finished_at: string | null
  updated_at: string | null
}
