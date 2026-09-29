from __future__ import annotations

import csv
from copy import deepcopy
from datetime import timedelta, timezone
import gzip
import json
import os
from pathlib import Path
from types import SimpleNamespace
from xml.etree import ElementTree


PROJECT_ROOT = Path(__file__).resolve().parents[1]

from soc_reporting.models import ParseStats
from soc_reporting.pipeline import (
    CUSTOM_RULE_IDS,
    RULE_CLASSIFICATIONS,
    analyze,
    classify_alert,
    ip_scope,
    load_and_normalize,
    normalize_alert,
)
from soc_reporting.cli import run
from soc_reporting.reporting import (
    REPORT_FILENAMES,
    render_html_report,
    write_csv,
    write_report_bundle,
)


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

    def test_port_scan_rule_is_classified_as_reconnaissance(self) -> None:
        result = classify_alert(
            "100030",
            ["firewall", "port_scan"],
            "Possible port scan",
            "blocked connection",
        )
        assert result[:3] == ("Port Scan", "Reconnaissance", "failure")

        alert = normalize_alert(
            1,
            raw_alert(
                rule_id="100030",
                level=10,
                groups=["firewall", "port_scan"],
                data={"srcip": "203.0.113.10"},
                full_log="firewall dropped a multi-port probe",
            ),
            ParseStats(),
        )
        assert "目标端口" in alert.response_suggestion
        assert "ACL" in alert.response_suggestion

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

    def test_web_text_cannot_spoof_ssh_classification_or_source(self) -> None:
        raw = raw_alert(
            rule_id="31101",
            description="Web access denied",
            groups=["web", "accesslog"],
            data={},
            full_log='GET /ssh-brute-force/invalid-user/from/8.8.8.8?user=admin HTTP/1.1" 404',
        )
        alert = normalize_alert(1, raw, ParseStats())

        assert alert.alert_type == "Web Directory Brute Force"
        assert alert.event_category == "Reconnaissance"
        assert alert.source_ip == "-"
        assert alert.target_user == "-"

    def test_rule_level_and_display_controls_are_sanitized(self) -> None:
        raw = raw_alert(level=999, full_log="normal\n\u202eforged")
        alert = normalize_alert(1, raw, ParseStats())

        assert alert.rule_level == 16
        assert "\n" not in alert.full_log
        assert "\\n" in alert.full_log
        assert "\u202e" not in alert.full_log

    def test_unmapped_wazuh_critical_rule_is_not_downgraded(self) -> None:
        alert = normalize_alert(
            1,
            raw_alert(
                rule_id="999999",
                level=15,
                description="New high severity rule",
                groups=["custom"],
                full_log="new detector evidence",
            ),
            ParseStats(),
        )

        assert alert.alert_type == "Other Security Event"
        assert alert.risk_level == "Critical"
        assert alert.risk_score >= 85
        assert alert.mitre_tactics == "-"
        assert alert.attack_stage == "Unmapped"

    def test_ip_scope_only_marks_globally_routable_addresses_external(self) -> None:
        assert ip_scope("8.8.8.8") == "Public/External"
        assert ip_scope("10.0.0.1") == "Private/Internal"
        assert ip_scope("100.64.0.1") == "Reserved"
        assert ip_scope("192.0.2.1") == "Reserved"
        assert ip_scope("0.0.0.0") == "Reserved"
        assert ip_scope("::ffff:192.168.0.10") == "Private/Internal"

    def test_same_named_agents_on_different_managers_are_distinct_assets(self) -> None:
        first_raw = raw_alert(event_id="manager-a")
        second_raw = raw_alert(event_id="manager-b")
        second_raw["manager"]["name"] = "manager-b"
        stats = ParseStats()
        result = analyze(
            [
                normalize_alert(1, first_raw, stats),
                normalize_alert(2, second_raw, stats),
            ]
        )

        assert result.metrics["asset_count"] == 2
        assert {row["manager_name"] for row in result.by_asset} == {
            "kali",
            "manager-b",
        }


class TestCorrelation:
    def test_incident_id_is_stable_when_priority_order_changes(self) -> None:
        stats = ParseStats()
        base = normalize_alert(1, raw_alert(event_id="stable"), stats)
        higher = normalize_alert(
            2,
            raw_alert(
                event_id="higher",
                timestamp="2026-07-26T01:00:00+0800",
                rule_id="999999",
                level=16,
                groups=["custom"],
                data={},
                full_log="separate high severity event",
            ),
            stats,
        )

        original_id = analyze([base]).incidents[0].incident_id
        expanded = analyze([base, higher]).incidents
        assert next(
            incident.incident_id
            for incident in expanded
            if incident.rule_ids == base.rule_id
        ) == original_id

    def test_incident_id_is_stable_across_display_timezones(self) -> None:
        alert = normalize_alert(1, raw_alert(event_id="stable-timezone"), ParseStats())
        shifted = deepcopy(alert)
        target_timezone = timezone(timedelta(hours=-5))
        assert shifted.event_time is not None
        shifted.event_time = shifted.event_time.astimezone(target_timezone)
        shifted.timestamp = shifted.event_time.isoformat(timespec="milliseconds")

        assert analyze([alert]).incidents[0].incident_id == analyze(
            [shifted]
        ).incidents[0].incident_id

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
        assert all(
            incident.event_category != "Authentication Success"
            for incident in result.incidents
        )

    def test_single_failure_does_not_become_account_compromise(self) -> None:
        stats = ParseStats()
        failure = normalize_alert(
            1,
            raw_alert(
                event_id="failure",
                rule_id="5760",
                data={"srcip": "192.168.38.1", "dstuser": "root"},
            ),
            stats,
        )
        success = normalize_alert(
            2,
            raw_alert(
                event_id="success",
                timestamp="2026-07-26T00:01:00.000+0800",
                rule_id="5715",
                description="sshd: authentication success.",
                groups=["syslog", "sshd", "authentication_success"],
                data={"srcip": "192.168.38.1", "dstuser": "root"},
                full_log="Accepted password for root from 192.168.38.1 port 22 ssh2",
            ),
            stats,
        )

        result = analyze([failure, success], incident_window_minutes=10)
        assert all(
            incident.event_category != "Suspected Compromise"
            for incident in result.incidents
        )

    def test_bruteforce_does_not_match_a_different_account(self) -> None:
        stats = ParseStats()
        failure = normalize_alert(
            1,
            raw_alert(
                event_id="failure",
                rule_id="2502",
                level=10,
                data={"srcip": "192.168.38.1", "dstuser": "root"},
            ),
            stats,
        )
        success = normalize_alert(
            2,
            raw_alert(
                event_id="success",
                timestamp="2026-07-26T00:01:00.000+0800",
                rule_id="5715",
                description="sshd: authentication success.",
                groups=["syslog", "sshd", "authentication_success"],
                data={"srcip": "192.168.38.1", "dstuser": "operator"},
                full_log="Accepted password for operator from 192.168.38.1 port 22 ssh2",
            ),
            stats,
        )

        result = analyze([failure, success], incident_window_minutes=10)
        assert all(
            incident.event_category != "Suspected Compromise"
            for incident in result.incidents
        )

    def test_bruteforce_without_target_account_is_not_marked_compromised(
        self,
    ) -> None:
        stats = ParseStats()
        failure = normalize_alert(
            1,
            raw_alert(
                event_id="failure",
                rule_id="2502",
                level=10,
                data={"srcip": "192.168.38.1"},
                full_log="PAM failures rhost=192.168.38.1",
            ),
            stats,
        )
        success = normalize_alert(
            2,
            raw_alert(
                event_id="success",
                timestamp="2026-07-26T00:01:00.000+0800",
                rule_id="5715",
                description="sshd: authentication success.",
                groups=["syslog", "sshd", "authentication_success"],
                data={"srcip": "192.168.38.1", "dstuser": "operator"},
                full_log="Accepted password for operator from 192.168.38.1 port 22 ssh2",
            ),
            stats,
        )

        result = analyze([failure, success], incident_window_minutes=10)
        assert all(
            incident.event_category != "Suspected Compromise"
            for incident in result.incidents
        )

    def test_maximum_datetime_does_not_overflow_correlation(self) -> None:
        stats = ParseStats()
        failure = normalize_alert(
            1,
            raw_alert(
                event_id="failure",
                timestamp="9999-12-31T23:55:00+00:00",
                rule_id="2502",
                level=10,
                data={"srcip": "192.168.38.1", "dstuser": "root"},
            ),
            stats,
        )
        success = normalize_alert(
            2,
            raw_alert(
                event_id="success",
                timestamp="9999-12-31T23:56:00+00:00",
                rule_id="5715",
                description="sshd: authentication success.",
                groups=["syslog", "sshd", "authentication_success"],
                data={"srcip": "192.168.38.1", "dstuser": "root"},
                full_log="Accepted password for root from 192.168.38.1 port 22 ssh2",
            ),
            stats,
        )

        result = analyze([failure, success], incident_window_minutes=10)
        assert result.incidents[0].event_category == "Suspected Compromise"


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

    def test_csv_missing_value_sentinel_is_preserved(self, tmp_path: Path) -> None:
        path = tmp_path / "report.csv"
        write_csv(path, [{"value": "-"}], ["value"])
        with path.open(encoding="utf-8-sig", newline="") as handle:
            row = next(csv.DictReader(handle))

        assert row["value"] == "-"

    def test_csv_formula_injection_with_invisible_prefix_is_neutralized(
        self,
        tmp_path: Path,
    ) -> None:
        for index, value in enumerate((" +1", "\ufeff-1", "\u200b@SUM(A1:A2)")):
            path = tmp_path / f"report-{index}.csv"
            write_csv(path, [{"value": value}], ["value"])
            with path.open(encoding="utf-8-sig", newline="") as handle:
                row = next(csv.DictReader(handle))
            assert row["value"].startswith("'")

    def test_oversized_and_invalid_utf8_lines_are_rejected(self, tmp_path: Path) -> None:
        path = tmp_path / "alerts.json"
        path.write_bytes(
            json.dumps(raw_alert(event_id="large", full_log="x" * 500)).encode()
            + b"\n"
            + b'{"id":"bad-\xff"}\n'
        )
        stats = ParseStats()
        alerts = load_and_normalize(path, stats, max_line_bytes=200)

        assert alerts == []
        assert stats.oversized_lines == 1
        assert stats.encoding_errors == 1
        assert stats.rejected_records == 2

    def test_decompressed_input_limit_stops_gzip_expansion(self, tmp_path: Path) -> None:
        path = tmp_path / "alerts.json.gz"
        with gzip.open(path, "wt", encoding="utf-8") as handle:
            for index in range(10):
                handle.write(json.dumps(raw_alert(event_id=str(index))) + "\n")

        try:
            load_and_normalize(path, ParseStats(), max_input_bytes=512)
        except ValueError as error:
            assert "max-input-bytes" in str(error)
        else:
            raise AssertionError("decompressed input limit was not enforced")

    def test_line_limit_is_reported_as_truncation(self, tmp_path: Path) -> None:
        path = tmp_path / "alerts.json"
        path.write_text(
            json.dumps(raw_alert(event_id="one"))
            + "\n"
            + json.dumps(raw_alert(event_id="two"))
            + "\n",
            encoding="utf-8",
        )
        stats = ParseStats()
        alerts = load_and_normalize(path, stats, line_limit=1)

        assert len(alerts) == 1
        assert stats.line_limit_reached is True

    def test_filtered_duplicate_cannot_hide_higher_severity_record(
        self,
        tmp_path: Path,
    ) -> None:
        low = raw_alert(event_id="collision", level=0)
        high = raw_alert(event_id="collision", level=10, rule_id="2502")
        path = tmp_path / "alerts.json"
        path.write_text(
            json.dumps(low) + "\n" + json.dumps(high) + "\n",
            encoding="utf-8",
        )
        stats = ParseStats()
        alerts = load_and_normalize(path, stats, min_level=5)

        assert [alert.rule_level for alert in alerts] == [10]
        assert stats.filtered_by_level == 1
        assert stats.duplicate_records == 0

    def test_same_event_id_from_different_agents_is_not_deduplicated(
        self,
        tmp_path: Path,
    ) -> None:
        first = raw_alert(event_id="shared")
        second = raw_alert(event_id="shared", agent_name="other-agent")
        second["agent"]["id"] = "002"
        path = tmp_path / "alerts.json"
        path.write_text(
            json.dumps(first) + "\n" + json.dumps(second) + "\n",
            encoding="utf-8",
        )
        stats = ParseStats()
        alerts = load_and_normalize(path, stats)

        assert len(alerts) == 2
        assert stats.duplicate_records == 0

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
        assert "Content-Security-Policy" in report

    def test_report_bundle_contains_timeline_and_private_files(
        self,
        tmp_path: Path,
    ) -> None:
        stats = ParseStats(total_lines=1, parsed_records=1, included_alerts=1)
        alert = normalize_alert(1, raw_alert(), stats)
        result = analyze([alert])
        output_dir = tmp_path / "bundle"
        written = write_report_bundle(
            output_dir,
            result,
            stats,
            {
                "title": "Test",
                "input_name": "alerts.json",
                "generated_at": "2026-07-26T00:00:00+00:00",
                "incident_window_minutes": 10,
                "model_version": "test",
                "filters": {},
            },
        )

        assert {path.name for path in written} == set(REPORT_FILENAMES)
        with (output_dir / "alert_timeline.csv").open(
            encoding="utf-8-sig",
            newline="",
        ) as handle:
            rows = list(csv.DictReader(handle))
        assert rows[0]["alert_count"] == "1"
        if os.name == "posix":
            assert output_dir.stat().st_mode & 0o777 == 0o700
            assert all(path.stat().st_mode & 0o777 == 0o600 for path in written)

    def test_cli_refuses_to_overwrite_its_input(self, tmp_path: Path) -> None:
        output_dir = tmp_path / "bundle"
        output_dir.mkdir()
        input_path = output_dir / "cleaned_alerts.csv"
        original = json.dumps(raw_alert()) + "\n"
        input_path.write_text(original, encoding="utf-8")
        args = SimpleNamespace(
            input=str(input_path),
            output_dir=str(output_dir),
            title="Test",
            min_level=0,
            limit=0,
            max_line_bytes=1024 * 1024,
            max_input_bytes=256 * 1024 * 1024,
            since=None,
            until=None,
            timezone="input",
            incident_window_minutes=10,
            soc_only=False,
            strict=False,
        )

        try:
            run(args)
        except ValueError as error:
            assert "overwritten" in str(error)
        else:
            raise AssertionError("input/output collision was not rejected")
        assert input_path.read_text(encoding="utf-8") == original

    def test_bundle_preflight_prevents_partial_update(self, tmp_path: Path) -> None:
        output_dir = tmp_path / "bundle"
        output_dir.mkdir()
        existing = output_dir / "cleaned_alerts.csv"
        existing.write_text("previous-report", encoding="utf-8")
        (output_dir / "summary_by_rule.csv").mkdir()
        stats = ParseStats(total_lines=1, parsed_records=1, included_alerts=1)
        result = analyze([normalize_alert(1, raw_alert(), stats)])

        try:
            write_report_bundle(
                output_dir,
                result,
                stats,
                {
                    "title": "Test",
                    "input_name": "alerts.json",
                    "generated_at": "2026-07-26T00:00:00+00:00",
                    "incident_window_minutes": 10,
                    "model_version": "test",
                    "filters": {},
                },
            )
        except ValueError as error:
            assert "must not be directories" in str(error)
        else:
            raise AssertionError("invalid report target was not rejected")
        assert existing.read_text(encoding="utf-8") == "previous-report"


class TestConfigurationConsistency:
    def test_local_rule_ids_have_python_classifications(self) -> None:
        root = ElementTree.parse(PROJECT_ROOT / "rules" / "local_rules.xml").getroot()
        xml_rule_ids = {element.attrib["id"] for element in root.findall(".//rule")}

        assert xml_rule_ids == CUSTOM_RULE_IDS
        assert xml_rule_ids <= RULE_CLASSIFICATIONS.keys()


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
