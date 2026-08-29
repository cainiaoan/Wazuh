from __future__ import annotations

import csv
import gzip
import json
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[1]

from soc_reporting.models import ParseStats
from soc_reporting.pipeline import (
    analyze,
    classify_alert,
    load_and_normalize,
    normalize_alert,
)
from soc_reporting.reporting import render_html_report, write_csv


def raw_alert(
    *,
    event_id: str = "1.1",
    timestamp: str = "2026-07-26T00:00:00.000+0800",
    rule_id: str = "5760",
    level: int = 5,
    description: str = "sshd: authentication failed.",
    groups: list[str] | None = None,
    agent_name: str = "centos7-agent",
    agent_ip: str | None = "192.168.38.135",
    data: dict | None = None,
    full_log: str = "Failed password for root from 192.168.38.1 port 22 ssh2",
) -> dict:
    agent = {"id": "001", "name": agent_name}
    if agent_ip is not None:
        agent["ip"] = agent_ip
    return {
        "timestamp": timestamp,
        "id": event_id,
        "rule": {
            "id": rule_id,
            "level": level,
            "description": description,
            "groups": groups or ["syslog", "sshd", "authentication_failed"],
            "firedtimes": 1,
        },
        "agent": agent,
        "manager": {"name": "kali"},
        "data": data or {},
        "decoder": {"name": "sshd"},
        "location": "journald",
        "full_log": full_log,
    }


class TestNormalization:
    def test_agent_ip_is_not_used_as_source_ip(self) -> None:
        raw = raw_alert(
            rule_id="503",
            level=3,
            description="Wazuh agent started.",
            groups=["wazuh"],
            data={},
            full_log="ossec: Agent started.",
        )
        alert = normalize_alert(1, raw, ParseStats())
        assert alert.source_ip == "-"
        assert alert.source_confidence == "Unknown"
        assert alert.destination_ip == "192.168.38.135"

    def test_exact_high_value_rules_are_classified(self) -> None:
        alert_type, category, outcome, confidence, reason = classify_alert(
            "2502",
            ["syslog", "sshd"],
            "User missed the password more than one time",
            "PAM authentication failures",
        )
        assert alert_type == "SSH Brute Force"
        assert category == "Credential Attack"
        assert outcome == "failure"
        assert confidence == "High"
        assert "2502" in reason

    def test_web_brute_force_is_not_misclassified_as_ssh(self) -> None:
        result = classify_alert(
            "999999",
            ["web", "accesslog"],
            "web directory brute force",
            'GET /admin HTTP/1.1" 404',
        )
        assert result[0] == "Web Directory Brute Force"
        assert result[1] == "Reconnaissance"

    def test_sudo_actor_target_and_command_are_separate(self) -> None:
        raw = raw_alert(
            rule_id="5402",
            level=3,
            description="Successful sudo to ROOT executed.",
            groups=["syslog", "sudo"],
            data={
                "srcuser": "kalilinux",
                "dstuser": "root",
                "command": "/usr/bin/id",
            },
            full_log=(
                "kalilinux : TTY=pts/1 ; PWD=/home/kalilinux ; "
                "USER=root ; COMMAND=/usr/bin/id"
            ),
        )
        alert = normalize_alert(1, raw, ParseStats())
        assert alert.actor_user == "kalilinux"
        assert alert.target_user == "root"
        assert alert.username == "kalilinux"
        assert alert.command == "/usr/bin/id"

    def test_decoder_artifact_by_is_not_a_username(self) -> None:
        raw = raw_alert(
            rule_id="5762",
            level=4,
            description="sshd: connection reset",
            data={"srcip": "192.168.38.1", "dstuser": "by"},
            full_log="Connection reset by 192.168.38.1 port 49866 [preauth]",
        )
        alert = normalize_alert(1, raw, ParseStats())
        assert alert.target_user == "-"


class TestCorrelation:
    def test_failure_followed_by_success_is_critical_incident(self) -> None:
        stats = ParseStats()
        failure = normalize_alert(
            1,
            raw_alert(
                event_id="1",
                timestamp="2026-07-26T00:00:00.000+0800",
                rule_id="2502",
                level=10,
                description="User missed the password more than one time",
                data={"srcip": "192.168.38.1", "dstuser": "root"},
                full_log="PAM failures rhost=192.168.38.1 user=root",
            ),
            stats,
        )
        success = normalize_alert(
            2,
            raw_alert(
                event_id="2",
                timestamp="2026-07-26T00:02:00.000+0800",
                rule_id="5715",
                level=3,
                description="sshd: authentication success.",
                groups=["syslog", "sshd", "authentication_success"],
                data={"srcip": "192.168.38.1", "dstuser": "root"},
                full_log="Accepted password for root from 192.168.38.1 port 22 ssh2",
            ),
            stats,
        )
        result = analyze([failure, success], incident_window_minutes=10)
        compromise = next(
            incident
            for incident in result.incidents
            if incident.event_category == "Suspected Compromise"
        )
        assert compromise.risk_level == "Critical"
        assert compromise.risk_score >= 95
        assert compromise.event_count == 2


class TestInputAndOutput:
    def test_malformed_and_duplicate_records_are_counted(
        self,
        tmp_path: Path,
    ) -> None:
        record = raw_alert(event_id="same")
        path = tmp_path / "alerts.json"
        path.write_text(
            "\n".join(
                [
                    json.dumps(record),
                    json.dumps(record),
                    "{not-json",
                    json.dumps(["not", "an", "object"]),
                ]
            ),
            encoding="utf-8",
        )
        stats = ParseStats()
        alerts = load_and_normalize(path, stats)

        assert len(alerts) == 1
        assert stats.parsed_records == 2
        assert stats.duplicate_records == 1
        assert stats.malformed_json == 1
        assert stats.non_object_records == 1

    def test_csv_formula_injection_is_neutralized(self, tmp_path: Path) -> None:
        path = tmp_path / "report.csv"
        write_csv(path, [{"value": "=cmd|' /C calc'!A0"}], ["value"])
        with path.open(encoding="utf-8-sig", newline="") as handle:
            row = next(csv.DictReader(handle))

        assert row["value"].startswith("'=")

    def test_gzip_input_and_soc_filter_keep_bruteforce(
        self,
        tmp_path: Path,
    ) -> None:
        record = raw_alert(
            event_id="gzip-1",
            rule_id="2502",
            level=10,
            description="User missed the password more than one time",
            data={"srcip": "192.168.38.1", "dstuser": "root"},
            full_log="PAM failures rhost=192.168.38.1 user=root",
        )
        path = tmp_path / "alerts.json.gz"
        with gzip.open(path, "wt", encoding="utf-8") as handle:
            handle.write(json.dumps(record) + "\n")
        stats = ParseStats()
        alerts = load_and_normalize(path, stats, soc_only=True)

        assert len(alerts) == 1
        assert alerts[0].alert_type == "SSH Brute Force"
        assert stats.filtered_by_scope == 0

    def test_html_escapes_untrusted_log_content(self) -> None:
        raw = raw_alert(full_log="<script>alert('x')</script> from 192.168.38.1")
        alert = normalize_alert(1, raw, ParseStats())
        result = analyze([alert])
        report = render_html_report(
            result,
            ParseStats(total_lines=1, parsed_records=1, included_alerts=1),
            {
                "title": "Test",
                "input_name": "alerts.json",
                "generated_at": "2026-07-26T00:00:00+00:00",
                "incident_window_minutes": 10,
                "model_version": "test",
                "filters": {},
            },
        )
        assert "<script>alert" not in report
        assert "&lt;script&gt;" in report


class TestSampleAcceptance:
    def test_real_sample_operational_metrics(self) -> None:
        stats = ParseStats()
        alerts = load_and_normalize(
            PROJECT_ROOT / "examples" / "alerts.json",
            stats,
        )
        result = analyze(alerts, incident_window_minutes=10)

        assert stats.total_lines == 108
        assert stats.parsed_records == 108
        assert stats.malformed_json == 0
        assert stats.duplicate_records == 0
        assert result.metrics["source_ip_count"] == 1
        assert result.metrics["unknown_source_alerts"] == 86
        assert result.metrics["mitre_mapped_alerts"] == 70
        assert result.metrics["mitre_unmapped_alerts"] == 38
        assert result.incidents[0].event_category == "Suspected Compromise"
        assert result.incidents[0].risk_level == "Critical"
        assert result.incidents[0].target_users == "root"
        agent_health = next(
            incident
            for incident in result.incidents
            if incident.event_category == "Agent Visibility"
        )
        assert "3 个恢复周期" in agent_health.summary
        assert "192.168.38.135" not in {
            row["source_ip"] for row in result.by_source
        }
        sudo = next(alert for alert in alerts if alert.rule_id == "5402")
        assert (sudo.actor_user, sudo.target_user) == ("kalilinux", "root")
