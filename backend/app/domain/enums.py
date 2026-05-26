from enum import Enum


class UserRole(str, Enum):
    ADMIN = "admin"
    OPERATOR = "operator"


class AuditStatus(str, Enum):
    DRAFT = "draft"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"


class AuditType(str, Enum):
    PENETRATION_TEST = "penetration_test"
    VULNERABILITY_SCAN = "vulnerability_scan"
    COMPLIANCE = "compliance"


class ScanStatus(str, Enum):
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"


class SeverityLevel(str, Enum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class RiskLevel(str, Enum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class TargetStatus(str, Enum):
    UNKNOWN = "unknown"
    REACHABLE = "reachable"
    UNREACHABLE = "unreachable"


class FindingCategory(str, Enum):
    INJECTION = "injection"
    BROKEN_AUTH = "broken_auth"
    XSS = "xss"
    BROKEN_ACCESS = "broken_access"
    SECURITY_MISCONFIG = "security_misconfig"
    SENSITIVE_EXPOSURE = "sensitive_exposure"
    OUTDATED_COMPONENTS = "outdated_components"
    LOGGING_MONITORING = "logging_monitoring"
    OTHER = "other"


class FindingStatus(str, Enum): #revisar esto
    OPEN           = "open"
    IN_PROGRESS    = "in_progress"
    RESOLVED       = "resolved"
    FALSE_POSITIVE = "false_positive"
