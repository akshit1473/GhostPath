from pydantic import BaseModel
from typing import Optional, Dict, Any, List
from datetime import datetime
import uuid

class RuntimeEvent(BaseModel):
    id: str
    timestamp: str
    source: str  # e.g., "PATH_AUDITOR", "PROCESS_MONITOR", "ATTACK_SIMULATION"
    type: str    # e.g., "CRITICAL_VULNERABILITY", "PROCESS_SPAWNED", "REMEDIATION_APPLIED"
    severity: str # "INFO", "LOW", "WARN", "CRITICAL", "RESOLVED"
    message: str
    data: Optional[Dict[str, Any]] = None

    @classmethod
    def create(cls, source: str, event_type: str, severity: str, message: str, data: Optional[Dict[str, Any]] = None):
        return cls(
            id=str(uuid.uuid4()),
            timestamp=datetime.utcnow().isoformat() + "Z",
            source=source,
            type=event_type,
            severity=severity,
            message=message,
            data=data
        )

class IncidentTimeline(BaseModel):
    events: List[RuntimeEvent] = []
    current_threat_score: int = 0
    is_compromised: bool = False
    active_narrative: str = "System operating normally. Environment integrity verified."
    threat_confidence: int = 0
    compromise_likelihood: str = "LOW"
    severity_escalation: bool = False
    mitre_mappings: List[Dict[str, str]] = []
    correlated_incidents: List[Dict[str, Any]] = []
    remediation_confidence: str = "100% - System operating securely."
    multi_terminal_demo: Dict[str, Any] = {
        "attacker_shell": {"status": "idle", "last_command": "", "output": ""},
        "victim_shell": {"status": "secure", "last_command": "", "output": ""},
        "monitoring_status": "Active polling"
    }
