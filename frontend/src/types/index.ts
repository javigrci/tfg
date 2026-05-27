export type UserRole      = 'admin' | 'operator'

export interface AppUser {
  id: number
  username: string
  role: { id: number; name: UserRole }
  created_at: string
}

export type FindingStatus = 'open' | 'in_progress' | 'resolved' | 'false_positive'
export type AuditStatus   = 'draft' | 'running' | 'completed' | 'failed'
export type AuditType     = 'penetration_test' | 'vulnerability_scan' | 'compliance'
export type ScanStatus    = 'pending' | 'running' | 'completed' | 'failed'
export type ScanTool      = 'nmap' | 'nikto' | 'wapiti' | 'nuclei' | 'manual'
export type SeverityLevel = 'info' | 'low' | 'medium' | 'high' | 'critical'
export type RiskLevel     = 'info' | 'low' | 'medium' | 'high' | 'critical'
export type TargetStatus  = 'unknown' | 'reachable' | 'unreachable'

export interface Target {
  id: number
  name: string
  address: string
  status: TargetStatus
  created_at: string
}

export interface TargetHistoryEntry {
  audit_id: number
  audit_name: string
  risk_score: number
  risk_level: RiskLevel
  total_findings: number
  critical_count: number
  high_count: number
  medium_count: number
  low_count: number
  executed_at: string
}

export interface TargetHistory {
  target_id: number
  target_name: string
  entries: TargetHistoryEntry[]
}

export interface Vulnerability {
  id: number
  name: string
  reference: string | null   // CVE-XXXX-XXXXX
  cvss_score: number | null
  description: string
  remediation: string | null
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
  cpe: string | null
  resolved_at: string | null
  vulnerabilities: Vulnerability[]
}

export interface Scan {
  id: number
  run_number: number
  tool: ScanTool
  command: string | null
  status: ScanStatus
  executed_at: string | null
  findings: Finding[]
}

export interface DeltaSummary {
  new: number
  resolved: number
  persisting: number
}

export interface DeltaResponse {
  new: Finding[]
  resolved: Finding[]
  persisting: Finding[]
  summary: DeltaSummary
}

export interface Report {
  id: number
  summary: string | null
  risk_level: RiskLevel
  risk_score: number
  total_findings: number
  critical_count: number
  high_count: number
  medium_count: number
  low_count: number
  created_at: string
}

export type ComplianceStatus = 'green' | 'yellow' | 'red' | 'not_assessed'

export interface ComplianceCategory {
  owasp_id: string
  owasp_name: string
  finding_categories: string[]
  status: ComplianceStatus
  findings_count: number
  max_severity: SeverityLevel | null
}

export interface ComplianceMap {
  audit_id: number
  assessed_count: number
  green_count: number
  yellow_count: number
  red_count: number
  categories: ComplianceCategory[]
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
