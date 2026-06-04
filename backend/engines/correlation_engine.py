from backend.models.events import RuntimeEvent, IncidentTimeline
from typing import List, Dict, Any

class CorrelationEngine:
    def __init__(self):
        self.timeline = IncidentTimeline()
    
    def process_event(self, event: RuntimeEvent) -> IncidentTimeline:
        """
        Process a new event, correlate it with existing events,
        and update the timeline and threat score.
        """
        self.timeline.events.append(event)
        
        # Recalculate threat score
        score = 0
        has_critical = False
        
        for e in self.timeline.events:
            sev = e.severity.upper()
            if sev == "CRITICAL":
                score += 4
                has_critical = True
            elif sev == "HIGH":
                score += 3
                has_critical = True
            elif sev == "WARN" or sev == "MEDIUM":
                score += 2
            elif sev == "LOW":
                score += 1
            elif sev == "INFO" or sev == "RESOLVED":
                pass
                
        # Cap score at 10
        self.timeline.current_threat_score = min(score, 10)
        self.timeline.is_compromised = has_critical
        
        # Simple heuristics for narrative updates based on latest event
        self._update_narrative(event)
        
        return self.timeline
        
    def correlate_environment(self, path_analysis: Dict, process_anomalies: List[Dict], log_anomalies: List[Dict], persistent_findings: List[Dict], latest_event: RuntimeEvent = None) -> IncidentTimeline:
        # Enrich timeline with anomalies as events
        for proc in process_anomalies:
            msg = f"Suspicious Process: {proc.get('command')} - {proc.get('reason')}"
            if not any(e.message == msg for e in self.timeline.events):
                evt = RuntimeEvent.create(
                    source="PROCESS_MONITOR",
                    event_type="PROCESS_ANOMALY",
                    severity=proc.get("severity", "WARN"),
                    message=msg,
                    data=proc
                )
                self.timeline.events.append(evt)

        for log in log_anomalies:
            msg = f"Suspicious Command Logged: {log.get('raw_log')} - {log.get('reason')}"
            if not any(e.message == msg for e in self.timeline.events):
                evt = RuntimeEvent.create(
                    source="LOG_PARSER",
                    event_type="LOG_ANOMALY",
                    severity=log.get("severity", "CRITICAL"),
                    message=msg,
                    data=log
                )
                self.timeline.events.append(evt)

        for pf in persistent_findings:
            msg = f"Persistent Risk in {pf.get('file')} at line {pf.get('line_number')}: {pf.get('content')}"
            if not any(e.message == msg for e in self.timeline.events):
                evt = RuntimeEvent.create(
                    source="CONFIGURATION_SCANNER",
                    event_type="PERSISTENT_RISK",
                    severity="CRITICAL" if pf.get("issue_type") == "critical" else "WARN",
                    message=msg,
                    data=pf
                )
                self.timeline.events.append(evt)

        # Calculate threat confidence score based on Phase 5 heuristics
        confidence = 0
        mitre_map = {}
        correlated_incidents = []
        
        # 1. Writable / Relative PATH check
        path_issues = path_analysis.get("issues", [])
        has_writable_or_dot = any("'.' in PATH" in i or "empty PATH" in i or "writable" in i for i in path_issues)
        if has_writable_or_dot:
            confidence += 25
            mitre_map["T1574.007"] = {
                "id": "T1574.007",
                "name": "Hijack Execution Flow: PATH Environment Variable",
                "description": "Attacker places a malicious binary in an untrusted or writable directory listed early in the PATH search order."
            }
            correlated_incidents.append({
                "component": "PATH Auditor",
                "finding": "Vulnerable PATH Precedence detected",
                "impact": "Allows unauthorized binary planting and local execution hijacking.",
                "severity": "CRITICAL"
            })
            
        # 2. Fake binary / Log anomaly check
        has_fake_binary = any("export PATH=.:" in log.get("raw_log", "") or "chmod +x" in log.get("raw_log", "") for log in log_anomalies)
        if has_fake_binary or any(e.source == "ATTACK_SIMULATION" for e in self.timeline.events):
            confidence += 50
            mitre_map["T1059"] = {
                "id": "T1059",
                "name": "Command and Scripting Interpreter",
                "description": "Adversaries abuse command and scripting interpreters to execute arbitrary commands or malicious binaries."
            }
            correlated_incidents.append({
                "component": "Log Parser & Simulation",
                "finding": "Fake binary execution / Planting detected",
                "impact": "Execution flow intercepted by untrusted local script.",
                "severity": "CRITICAL"
            })
            
        # 3. Unexpected subprocess / Process anomaly check
        if process_anomalies:
            confidence += 30
            mitre_map["T1059.004"] = {
                "id": "T1059.004",
                "name": "Command and Scripting Interpreter: Unix Shell",
                "description": "Suspicious subprocess spawned from an unusual execution path or utilizing network utilities."
            }
            for proc in process_anomalies:
                correlated_incidents.append({
                    "component": "Process Monitor",
                    "finding": f"Suspicious Process: {proc.get('command')} ({proc.get('reason')})",
                    "impact": "Active in-memory indicator of compromise or unauthorized utility execution.",
                    "severity": proc.get("severity", "WARN")
                })
                
        # 4. Persistence check
        if persistent_findings:
            confidence += 40
            mitre_map["T1547"] = {
                "id": "T1547",
                "name": "Boot or Logon Autostart Execution",
                "description": "Unsafe PATH modifications declared in persistent shell configuration profiles (~/.bashrc, ~/.profile)."
            }
            for pf in persistent_findings:
                correlated_incidents.append({
                    "component": "Configuration Scanner",
                    "finding": f"Persistent Risk in {pf.get('file')}",
                    "impact": "Restores vulnerable search-order precedence across terminal reboots.",
                    "severity": "CRITICAL" if pf.get("issue_type") == "critical" else "WARN"
                })
                
        # Cap confidence at 100%
        self.timeline.threat_confidence = min(confidence, 100)
        
        # Determine compromise likelihood
        if self.timeline.threat_confidence >= 80:
            self.timeline.compromise_likelihood = "CRITICAL"
        elif self.timeline.threat_confidence >= 50:
            self.timeline.compromise_likelihood = "HIGH"
        elif self.timeline.threat_confidence >= 25:
            self.timeline.compromise_likelihood = "MEDIUM"
        else:
            self.timeline.compromise_likelihood = "LOW"
            
        self.timeline.severity_escalation = self.timeline.threat_confidence >= 50
        self.timeline.mitre_mappings = list(mitre_map.values())
        self.timeline.correlated_incidents = correlated_incidents
        
        # Determine remediation confidence
        if not has_writable_or_dot and not persistent_findings:
            self.timeline.remediation_confidence = "100% - System operating securely. All checks passed."
        elif not has_writable_or_dot and persistent_findings:
            self.timeline.remediation_confidence = "95% - Runtime PATH sanitized successfully, but persistent shell configuration risks remain."
        else:
            self.timeline.remediation_confidence = f"{max(0, 100 - self.timeline.threat_confidence)}% - Immediate remediation required to secure runtime environment."
            
        # Update narrative with full context
        from .narrative_engine import generate_narrative
        context = {
            "has_persistent_risk": len(persistent_findings) > 0,
            "vulnerable": path_analysis.get("vulnerable", False),
            "threat_confidence": self.timeline.threat_confidence,
            "is_remediated": latest_event and latest_event.severity == "RESOLVED"
        }
        self.timeline.active_narrative = generate_narrative(self.timeline.events, latest_event, context)
        
        # Also recalculate threat score with enriched events
        score = 0
        has_critical = False
        for e in self.timeline.events:
            sev = e.severity.upper()
            if sev == "CRITICAL":
                score += 4
                has_critical = True
            elif sev == "HIGH":
                score += 3
                has_critical = True
            elif sev == "WARN" or sev == "MEDIUM":
                score += 2
            elif sev == "LOW":
                score += 1
            elif sev == "INFO" or sev == "RESOLVED":
                pass
        self.timeline.current_threat_score = min(score, 10)
        self.timeline.is_compromised = has_critical

        return self.timeline

    def _update_narrative(self, latest_event: RuntimeEvent):
        from .narrative_engine import generate_narrative
        self.timeline.active_narrative = generate_narrative(self.timeline.events, latest_event)

    def get_current_state(self) -> IncidentTimeline:
        return self.timeline
        
    def reset(self):
        self.timeline = IncidentTimeline()
