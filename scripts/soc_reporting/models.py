"""Data models shared by the parser, analyzer, and report renderers."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import datetime
from typing import Any


ALERT_EXPORT_FIELDS = [
    "record_number",
    "event_id",
    "timestamp",
    "agent_id",
    "agent_name",
    "agent_ip",
    "manager_name",
    "source_ip",
    "source_scope",
    "source_confidence",
    "destination_ip",
    "username",
    "actor_user",
    "target_user",
    "command",
    "rule_id",
    "rule_level",
    "wazuh_severity",
    "alert_type",
    "event_category",
    "outcome",
    "classification_confidence",
    "classification_reason",
    "description",
    "fired_times",
    "affected_asset",
    "mitre_ids",
    "mitre_tactics",
    "mitre_techniques",
    "attack_stage",
    "risk_score",
    "risk_level",
    "response_suggestion",
    "location",
    "decoder",
    "full_log",
]


INCIDENT_EXPORT_FIELDS = [
    "incident_id",
    "title",
    "status",
    "confidence",
    "first_seen",
    "last_seen",
    "duration_seconds",
    "event_count",
    "risk_score",
    "risk_level",
    "max_rule_level",
    "event_category",
    "source_ip",
    "source_scope",
    "affected_asset",
    "agent_id",
    "alert_types",
    "rule_ids",
    "actor_users",
    "target_users",
    "commands",
    "mitre_ids",
    "summary",
    "recommendation",
    "evidence",
]


@dataclass
class ParseStats:
    """Input and filtering counters used for data-quality reporting."""

    total_lines: int = 0
    parsed_records: int = 0
    blank_lines: int = 0
    malformed_json: int = 0
    non_object_records: int = 0
    invalid_timestamps: int = 0
    duplicate_records: int = 0
    filtered_by_level: int = 0
    filtered_by_time: int = 0
    filtered_by_scope: int = 0
    included_alerts: int = 0
    malformed_line_samples: list[int] = field(default_factory=list)

    @property
    def rejected_records(self) -> int:
        return self.malformed_json + self.non_object_records

    @property
    def parse_success_rate(self) -> float:
        candidates = self.parsed_records + self.rejected_records
        if not candidates:
            return 100.0
        return round(self.parsed_records / candidates * 100, 2)

    def to_dict(self) -> dict[str, Any]:
        result = asdict(self)
        result["rejected_records"] = self.rejected_records
        result["parse_success_rate"] = self.parse_success_rate
        return result


@dataclass
class Alert:
    """Normalized Wazuh alert with fields suitable for analysis and export."""

    record_number: int
    event_id: str
    timestamp: str
    event_time: datetime | None
    agent_id: str
    agent_name: str
    agent_ip: str
    manager_name: str
    source_ip: str
    source_scope: str
    source_confidence: str
    destination_ip: str
    username: str
    actor_user: str
    target_user: str
    command: str
    rule_id: str
    rule_level: int
    wazuh_severity: str
    alert_type: str
    event_category: str
    outcome: str
    classification_confidence: str
    classification_reason: str
    description: str
    fired_times: int
    affected_asset: str
    mitre_ids: str
    mitre_tactics: str
    mitre_techniques: str
    attack_stage: str
    risk_score: int
    risk_level: str
    response_suggestion: str
    location: str
    decoder: str
    full_log: str

    def to_row(self) -> dict[str, Any]:
        return {field_name: getattr(self, field_name) for field_name in ALERT_EXPORT_FIELDS}


@dataclass
class Incident:
    """A time-window correlation of one or more related normalized alerts."""

    incident_id: str
    title: str
    status: str
    confidence: str
    first_seen: str
    last_seen: str
    duration_seconds: int
    event_count: int
    risk_score: int
    risk_level: str
    max_rule_level: int
    event_category: str
    source_ip: str
    source_scope: str
    affected_asset: str
    agent_id: str
    alert_types: str
    rule_ids: str
    actor_users: str
    target_users: str
    commands: str
    mitre_ids: str
    summary: str
    recommendation: str
    evidence: str
    event_times: list[datetime] = field(default_factory=list, repr=False)

    def to_row(self) -> dict[str, Any]:
        return {field_name: getattr(self, field_name) for field_name in INCIDENT_EXPORT_FIELDS}


@dataclass
class AnalysisResult:
    """All normalized and aggregated data needed by the output layer."""

    alerts: list[Alert]
    incidents: list[Incident]
    by_source: list[dict[str, Any]]
    by_type: list[dict[str, Any]]
    by_asset: list[dict[str, Any]]
    by_rule: list[dict[str, Any]]
    mitre: list[dict[str, Any]]
    recommendations: list[dict[str, Any]]
    timeline: list[dict[str, Any]]
    metrics: dict[str, Any]
