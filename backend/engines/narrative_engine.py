from backend.models.events import RuntimeEvent
from typing import List, Dict, Any

def generate_narrative(all_events: List[RuntimeEvent], latest_event: RuntimeEvent, context: Dict[str, Any] = None) -> str:
    """
    Generate a human-readable threat narrative based on the event timeline and runtime context.
    """
    context = context or {}
    has_persistent = context.get("has_persistent_risk", False)
    vulnerable = context.get("vulnerable", False)
    threat_confidence = context.get("threat_confidence", 0)
    is_remediated = context.get("is_remediated", False)
    
    # Check if a recent remediation occurred
    if (latest_event and latest_event.severity == "RESOLVED") or is_remediated:
        if has_persistent:
            return "Runtime PATH sanitized successfully. Persistent shell configuration still contains unsafe entries requiring manual remediation."
        else:
            return "Environment integrity restored successfully. Runtime PATH sanitized and verified against baseline security controls."

    if not all_events and not vulnerable:
        return "System operating normally. Environment integrity verified. No active search-order hijacking risks detected."

    critical_events = [e for e in all_events if e.severity == "CRITICAL"]
    warn_events = [e for e in all_events if e.severity == "WARN"]
    
    # Check for active exploit simulation
    if latest_event and latest_event.source == "ATTACK_SIMULATION":
        return f"Active Exploit Simulation detected: {latest_event.message}. GhostPath observed execution redirection to an untrusted local binary."

    # Check for high confidence runtime compromise (Phase 1 & Phase 3 example)
    if threat_confidence >= 70 or (vulnerable and any(e.source in ["PROCESS_MONITOR", "LOG_PARSER"] for e in all_events)):
        return "GhostPath detected command search-order hijacking after a writable directory gained precedence over trusted binaries. Correlated process anomalies indicate active execution interception."

    if latest_event and latest_event.source == "PATH_AUDITOR" and latest_event.severity == "CRITICAL":
        return f"Critical PATH vulnerability detected: {latest_event.message}. A relative or writable directory in the search path allows unauthorized binary planting."

    if latest_event and latest_event.source == "PROCESS_MONITOR":
        return f"Runtime Process Anomaly: {latest_event.message}. Suspicious execution paths or network utilities detected in active memory."

    if len(critical_events) > 0 or vulnerable:
        if has_persistent:
            return "Environment compromised: Writable or relative path entries take precedence in execution search order. Persistent shell profiles contain unsafe variable declarations."
        return f"System is currently vulnerable. {len(critical_events)} critical path configurations active. Immediate remediation recommended to prevent binary planting."

    if len(warn_events) > 0 or has_persistent:
        return "System environment has degraded. Sub-optimal PATH ordering or persistent shell profile warnings detected."

    return "System operating normally. Environment integrity verified. All security controls are within acceptable thresholds."
