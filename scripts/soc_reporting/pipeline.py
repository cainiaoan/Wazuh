"""Parsing, normalization, risk scoring, correlation, and aggregation."""

from __future__ import annotations

import gzip
import ipaddress
import json
import math
import re
from collections import Counter, defaultdict
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Iterable, Iterator

from .models import Alert, AnalysisResult, Incident, ParseStats


SOURCE_IP_KEYS = (
    "srcip",
    "src_ip",
    "sourceip",
    "source_ip",
    "clientip",
    "client_ip",
    "remote_addr",
    "remote_ip",
)

DESTINATION_IP_KEYS = (
    "dstip",
    "dst_ip",
    "destinationip",
    "destination_ip",
    "server_ip",
)

ACTOR_USER_KEYS = (
    "srcuser",
    "src_user",
    "actor_user",
    "subject_user",
    "initiating_user",
)

TARGET_USER_KEYS = (
    "dstuser",
    "dst_user",
    "target_user",
    "user",
    "username",
)

COMMAND_KEYS = ("command", "cmd", "process_command_line")

ATTACK_BY_ID = {
    "T1110": ("Credential Access", "Brute Force"),
    "T1110.001": ("Credential Access", "Password Guessing"),
    "T1021": ("Lateral Movement", "Remote Services"),
    "T1021.004": ("Lateral Movement", "SSH"),
    "T1595": ("Reconnaissance", "Active Scanning"),
    "T1595.002": ("Reconnaissance", "Vulnerability Scanning"),
    "T1046": ("Discovery", "Network Service Discovery"),
    "T1078": ("Defense Evasion", "Valid Accounts"),
    "T1548": ("Privilege Escalation", "Abuse Elevation Control Mechanism"),
    "T1548.003": ("Privilege Escalation", "Sudo and Sudo Caching"),
    "T1070.006": ("Defense Evasion", "Timestomp"),
    "T1562.001": ("Defense Evasion", "Impair Defenses"),
}

# rule_id -> (alert_type, event_category, outcome)
RULE_CLASSIFICATIONS = {
    "2502": ("SSH Brute Force", "Credential Attack", "failure"),
    "5503": ("PAM Authentication Failure", "Credential Attack", "failure"),
    "5710": ("SSH Invalid Username", "Credential Attack", "failure"),
    "5711": ("SSH Authentication Failure", "Credential Attack", "failure"),
    "5712": ("SSH Brute Force", "Credential Attack", "failure"),
    "5760": ("SSH Authentication Failure", "Credential Attack", "failure"),
    "5761": ("SSH Authentication Failure", "Credential Attack", "failure"),
    "5762": ("SSH Connection Reset", "Credential Attack", "failure"),
    "5763": ("SSH Authentication Failure", "Credential Attack", "failure"),
    "5715": ("SSH Authentication Success", "Authentication Success", "success"),
    "5501": ("PAM Session Opened", "Session Activity", "success"),
    "5502": ("PAM Session Closed", "Session Activity", "success"),
    "5402": ("Privilege Escalation / Sudo Activity", "Privilege Activity", "success"),
    "5403": ("Failed Sudo Activity", "Privilege Activity", "failure"),
    "503": ("Wazuh Agent Started", "Agent Visibility", "change"),
    "504": ("Wazuh Agent Disconnected", "Agent Visibility", "failure"),
    "505": ("Wazuh Agent Removed", "Agent Visibility", "failure"),
    "506": ("Wazuh Agent Stopped", "Agent Visibility", "failure"),
    "533": ("Network Service Change", "Network Exposure", "change"),
    "550": ("File Integrity Modified", "File Integrity", "change"),
    "553": ("File Integrity Deleted", "File Integrity", "change"),
    "554": ("File Integrity Added", "File Integrity", "change"),
    "40705": ("System Time Changed", "System Integrity", "change"),
    "100010": ("SSH Brute Force", "Credential Attack", "failure"),
    "100011": ("SSH Invalid Username", "Credential Attack", "failure"),
    "100012": ("SSH Username Enumeration", "Credential Attack", "failure"),
    "100020": ("Web Scanner Activity", "Reconnaissance", "failure"),
    "100021": ("Web Directory Brute Force", "Reconnaissance", "failure"),
}

CUSTOM_RULE_IDS = {"100010", "100011", "100012", "100020", "100021"}

SOC_CATEGORIES = {
    "Credential Attack",
    "Authentication Success",
    "Privilege Activity",
    "Reconnaissance",
    "File Integrity",
    "Vulnerability",
    "Malware",
    "Agent Visibility",
    "Network Exposure",
    "System Integrity",
}

SOURCE_PATTERNS = [
    re.compile(r"\bfrom\s+(?P<ip>[0-9a-f:.]+)", re.I),
    re.compile(r"\brhost=(?P<ip>[0-9a-f:.]+)", re.I),
    re.compile(r"\b(?:src|source|client(?:ip)?)\s*[=:]\s*(?P<ip>[0-9a-f:.]+)", re.I),
]
USERNAME_PATTERNS = [
    re.compile(r"\bfor\s+(?:invalid user\s+)?(?P<user>[^\s:;]+)\s+from\b", re.I),
    re.compile(r"\buser(?:name)?[=:]\s*(?P<user>[^\s:;]+)", re.I),
]
CONTROL_CHARS = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")

TYPE_RISK_BONUS = {
    "SSH Brute Force": 18,
    "SSH Username Enumeration": 18,
    "SSH Invalid Username": 12,
    "SSH Authentication Failure": 12,
    "PAM Authentication Failure": 12,
    "SSH Connection Reset": 8,
    "Web Scanner Activity": 16,
    "Web Directory Brute Force": 16,
    "Privilege Escalation / Sudo Activity": 22,
    "Failed Sudo Activity": 18,
    "Wazuh Agent Disconnected": 25,
    "Wazuh Agent Removed": 30,
    "Wazuh Agent Stopped": 25,
    "Network Service Change": 15,
    "File Integrity Modified": 18,
    "File Integrity Deleted": 18,
    "File Integrity Added": 18,
    "System Time Changed": 15,
}

INCIDENT_TITLES = {
    "Credential Attack": "凭据攻击与认证失败",
    "Authentication Success": "远程认证成功",
    "Session Activity": "登录会话活动",
    "Privilege Activity": "特权操作活动",
    "Reconnaissance": "侦察与扫描活动",
    "File Integrity": "文件完整性变更",
    "Vulnerability": "漏洞风险",
    "Malware": "恶意代码活动",
    "Agent Visibility": "监控覆盖状态变化",
    "Network Exposure": "网络暴露面变化",
    "System Integrity": "系统完整性变化",
    "Web Activity": "Web 安全活动",
    "Other Security Event": "其他安全事件",
}


def unique(values: Iterable[str]) -> list[str]:
    seen: set[str] = set()
    result: list[str] = []
    for value in values:
        value = str(value).strip()
        if value and value != "-" and value not in seen:
            seen.add(value)
            result.append(value)
    return result


def normalize_list(value: Any) -> list[str]:
    if isinstance(value, (list, tuple, set)):
        return unique(str(item) for item in value if item not in (None, ""))
    if value in (None, ""):
        return []
    return [str(value)]


def clean_text(value: Any, default: str = "-") -> str:
    if value in (None, ""):
        return default
    text = CONTROL_CHARS.sub(" ", str(value)).strip()
    return text or default


def coerce_int(value: Any, default: int = 0) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def parse_timestamp(value: Any) -> datetime | None:
    if value in (None, ""):
        return None
    text = str(value).strip()
    if text.endswith("Z"):
        text = f"{text[:-1]}+00:00"
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed


def normalize_filter_time(value: str | None) -> datetime | None:
    if not value:
        return None
    parsed = parse_timestamp(value)
    if parsed is None:
        raise ValueError(f"Invalid ISO-8601 timestamp: {value}")
    return parsed


def _open_alert_file(path: Path):
    if path.suffix.lower() == ".gz":
        return gzip.open(path, "rt", encoding="utf-8-sig", errors="replace")
    return path.open("r", encoding="utf-8-sig", errors="replace")


def iter_wazuh_records(
    path: Path,
    stats: ParseStats,
    line_limit: int = 0,
) -> Iterator[tuple[int, dict[str, Any]]]:
    """Yield JSON objects from JSONL or JSONL.GZ while collecting quality stats."""

    with _open_alert_file(path) as handle:
        for line_number, line in enumerate(handle, start=1):
            if line_limit and line_number > line_limit:
                break
            stats.total_lines += 1
            if not line.strip():
                stats.blank_lines += 1
                continue
            try:
                item = json.loads(line)
            except json.JSONDecodeError:
                stats.malformed_json += 1
                if len(stats.malformed_line_samples) < 10:
                    stats.malformed_line_samples.append(line_number)
                continue
            if not isinstance(item, dict):
                stats.non_object_records += 1
                continue
            stats.parsed_records += 1
            yield line_number, item


def find_value(mapping: Any, candidate_keys: Iterable[str]) -> str:
    """Find a named field recursively in Wazuh's flexible data object."""

    wanted = {key.lower() for key in candidate_keys}
    queue: list[Any] = [mapping]
    while queue:
        current = queue.pop(0)
        if isinstance(current, dict):
            for key, value in current.items():
                if str(key).lower() in wanted and value not in (None, ""):
                    if isinstance(value, (str, int, float)):
                        return str(value)
                if isinstance(value, (dict, list)):
                    queue.append(value)
        elif isinstance(current, list):
            queue.extend(item for item in current if isinstance(item, (dict, list)))
    return "-"


def normalize_ip(value: Any) -> str:
    if value in (None, "", "-"):
        return "-"
    candidate = str(value).strip().strip("[](),;'\"")
    if "%" in candidate:
        candidate = candidate.split("%", 1)[0]
    try:
        return str(ipaddress.ip_address(candidate))
    except ValueError:
        pass
    if candidate.count(":") == 1 and "." in candidate:
        host, _, port = candidate.rpartition(":")
        if port.isdigit():
            try:
                return str(ipaddress.ip_address(host))
            except ValueError:
                return "-"
    return "-"


def first_valid_ip(*values: Any) -> str:
    for value in values:
        normalized = normalize_ip(value)
        if normalized != "-":
            return normalized
    return "-"


def extract_source_ip(full_log: str) -> str:
    for pattern in SOURCE_PATTERNS:
        match = pattern.search(full_log or "")
        if match:
            candidate = normalize_ip(match.group("ip"))
            if candidate != "-":
                return candidate
    return "-"


def extract_username(full_log: str) -> str:
    for pattern in USERNAME_PATTERNS:
        match = pattern.search(full_log or "")
        if match:
            return clean_text(match.group("user"))
    return "-"


def normalize_username(value: Any) -> str:
    username = clean_text(value)
    if username.lower() in {
        "-",
        "by",
        "from",
        "unknown",
        "none",
        "null",
        "(null)",
        "n/a",
    }:
        return "-"
    return username


def ip_scope(value: str) -> str:
    if value == "-":
        return "Unknown"
    try:
        address = ipaddress.ip_address(value)
    except ValueError:
        return "Unknown"
    if address.is_loopback:
        return "Loopback"
    if address.is_link_local:
        return "Link-local"
    if address.is_multicast:
        return "Multicast"
    if address.is_private:
        return "Private/Internal"
    if address.is_reserved or address.is_unspecified:
        return "Reserved"
    return "Public/External"


def classify_alert(
    rule_id: str,
    groups: list[str],
    description: str,
    full_log: str,
) -> tuple[str, str, str, str, str]:
    if rule_id in RULE_CLASSIFICATIONS:
        alert_type, category, outcome = RULE_CLASSIFICATIONS[rule_id]
        return alert_type, category, outcome, "High", f"exact_rule_id:{rule_id}"

    group_set = {item.lower() for item in groups}
    text = f"{description} {full_log}".lower()
    is_web = bool(group_set.intersection({"web", "accesslog", "web_log"}))

    if "ssh_bruteforce" in group_set or (
        "brute force" in text and ("sshd" in group_set or "ssh" in text)
    ):
        return "SSH Brute Force", "Credential Attack", "failure", "Medium", "rule_group_or_context"
    if "ssh_invalid_user" in group_set or "invalid user" in text:
        return "SSH Invalid Username", "Credential Attack", "failure", "Medium", "rule_group_or_context"
    if "ssh_user_enum" in group_set or "username enumeration" in text:
        return "SSH Username Enumeration", "Credential Attack", "failure", "Medium", "rule_group_or_context"
    if "authentication_failed" in group_set or "authentication failure" in text:
        return "Authentication Failure", "Credential Attack", "failure", "Medium", "authentication_failed_group"
    if "authentication_success" in group_set:
        return "Authentication Success", "Authentication Success", "success", "Medium", "authentication_success_group"
    if "sudo" in group_set:
        outcome = "failure" if "fail" in text or "denied" in text else "success"
        return "Privilege Escalation / Sudo Activity", "Privilege Activity", outcome, "Medium", "sudo_group"
    if "syscheck" in group_set or "fim" in group_set:
        return "File Integrity Change", "File Integrity", "change", "Medium", "fim_group"
    if any("vulnerab" in item for item in group_set):
        return "Vulnerability Detection", "Vulnerability", "failure", "Medium", "vulnerability_group"
    if group_set.intersection({"rootcheck", "malware", "virus", "trojan"}):
        return "Malware / Rootkit Detection", "Malware", "failure", "Medium", "malware_group"

    scanner_terms = (
        "nikto",
        "sqlmap",
        "dirbuster",
        "gobuster",
        "acunetix",
        "nessus",
        "nmap",
        "masscan",
    )
    if "web_scan" in group_set or (is_web and any(term in text for term in scanner_terms)):
        return "Web Scanner Activity", "Reconnaissance", "failure", "Medium", "web_scanner_context"
    if "web_dir_bruteforce" in group_set or (is_web and " 404 " in f" {text} "):
        return "Web Directory Brute Force", "Reconnaissance", "failure", "Medium", "web_404_context"
    if is_web:
        return "Web Access Event", "Web Activity", "unknown", "Medium", "web_group"
    if "pam" in group_set:
        return "PAM Activity", "Session Activity", "unknown", "Medium", "pam_group"
    return "Other Security Event", "Other Security Event", "unknown", "Low", "fallback"


def wazuh_severity(level: int) -> str:
    if level >= 12:
        return "Critical"
    if level >= 8:
        return "High"
    if level >= 4:
        return "Medium"
    return "Informational"


def risk_level(score: int) -> str:
    if score >= 85:
        return "Critical"
    if score >= 65:
        return "High"
    if score >= 40:
        return "Medium"
    return "Low"


def alert_risk_score(
    rule_id: str,
    rule_level: int,
    alert_type: str,
    source_scope: str,
) -> int:
    score = min(max(rule_level, 0) * 6, 75)
    score += TYPE_RISK_BONUS.get(alert_type, 0)
    if source_scope == "Public/External":
        score += 7
    if rule_id in CUSTOM_RULE_IDS:
        score += 5
    return min(score, 100)


def response_for(
    event_category: str,
    alert_type: str,
    source_ip: str,
    username: str,
    risk: str,
) -> str:
    source = source_ip if source_ip != "-" else "未知来源"
    user = username if username != "-" else "相关账户"

    if event_category == "Credential Attack":
        actions = (
            f"核查来源 {source} 的认证失败频率与目标账户 {user}；"
            "检查失败后是否出现成功登录；按授权流程实施限速、封禁或 MFA，并保全认证日志。"
        )
    elif event_category == "Authentication Success":
        actions = (
            f"确认来源 {source} 与账户 {user} 是否符合运维基线；"
            "关联前序失败登录、登录后 sudo、进程和网络连接记录。"
        )
    elif event_category == "Privilege Activity":
        actions = (
            f"核验账户 {user} 的提权理由、执行命令与变更工单；"
            "检查 sudoers 和特权组成员，确认最小权限。"
        )
    elif event_category == "Reconnaissance":
        actions = (
            f"在防火墙、WAF 或反向代理核查并限制来源 {source}；"
            "复核扫描路径、User-Agent、响应码与同源后续利用行为。"
        )
    elif event_category == "Agent Visibility":
        actions = (
            "确认 Agent 停止或断连是否为计划维护；检查服务日志、网络连通性和篡改迹象，"
            "尽快恢复监控覆盖。"
        )
    elif event_category == "File Integrity":
        actions = (
            "核对文件变更人与变更窗口，比较哈希、权限和内容差异；"
            "未经授权的变更应隔离主机并保全证据。"
        )
    elif event_category == "Network Exposure":
        actions = (
            "确认端口或监听服务变化是否经过审批；识别关联进程、启动参数和外部可达性。"
        )
    elif event_category == "System Integrity":
        actions = (
            "核查系统时间、审计链和 NTP 状态；排除日志时间线被干扰或人为篡改。"
        )
    elif event_category == "Vulnerability":
        actions = "核实漏洞适用性、资产暴露面和可利用条件，按风险窗口修补并复测。"
    elif event_category == "Malware":
        actions = "立即隔离受影响资产，保全内存与磁盘证据，执行恶意代码排查和凭据轮换。"
    else:
        actions = "复核原始日志、资产负责人和相邻时间告警；确认是安全事件还是需要调优的预期行为。"

    if risk in {"Critical", "High"}:
        return f"按高优先级事件处置并指定负责人。{actions}"
    return actions


def _mitre_fields(
    mitre: dict[str, Any],
    event_category: str,
) -> tuple[str, str, str, str]:
    ids = normalize_list(mitre.get("id"))
    tactics = normalize_list(mitre.get("tactic"))
    techniques = normalize_list(mitre.get("technique"))

    derived_tactics: list[str] = []
    derived_techniques: list[str] = []
    for mitre_id in ids:
        tactic, technique = ATTACK_BY_ID.get(mitre_id, ("", ""))
        if tactic:
            derived_tactics.append(tactic)
        if technique:
            derived_techniques.append(technique)

    if not tactics:
        tactics = unique(derived_tactics)
    if not techniques:
        techniques = unique(derived_techniques)

    if not tactics:
        fallback = {
            "Credential Attack": "Credential Access",
            "Authentication Success": "Initial Access",
            "Privilege Activity": "Privilege Escalation",
            "Reconnaissance": "Reconnaissance",
            "Network Exposure": "Discovery",
            "System Integrity": "Defense Evasion",
        }
        tactics = [fallback.get(event_category, "Unmapped")]

    stages = unique(tactics)
    return (
        ", ".join(ids) if ids else "-",
        ", ".join(tactics) if tactics else "-",
        ", ".join(techniques) if techniques else "-",
        ", ".join(stages) if stages else "Unmapped",
    )


def normalize_alert(
    record_number: int,
    raw: dict[str, Any],
    stats: ParseStats,
) -> Alert:
    rule = raw.get("rule") if isinstance(raw.get("rule"), dict) else {}
    agent = raw.get("agent") if isinstance(raw.get("agent"), dict) else {}
    manager = raw.get("manager") if isinstance(raw.get("manager"), dict) else {}
    decoder_data = raw.get("decoder") if isinstance(raw.get("decoder"), dict) else {}
    data = raw.get("data") if isinstance(raw.get("data"), dict) else {}
    mitre = rule.get("mitre") if isinstance(rule.get("mitre"), dict) else {}

    timestamp = clean_text(raw.get("timestamp"))
    event_time = parse_timestamp(raw.get("timestamp"))
    if event_time is None:
        stats.invalid_timestamps += 1

    rule_id = clean_text(rule.get("id"))
    rule_level = coerce_int(rule.get("level"))
    groups = normalize_list(rule.get("groups"))
    description = clean_text(rule.get("description"))
    full_log = clean_text(raw.get("full_log"))
    (
        alert_type,
        event_category,
        outcome,
        classification_confidence,
        classification_reason,
    ) = classify_alert(
        rule_id,
        groups,
        description,
        full_log,
    )

    data_source_ip = first_valid_ip(find_value(data, SOURCE_IP_KEYS))
    log_source_ip = extract_source_ip(full_log)
    source_ip = first_valid_ip(data_source_ip, log_source_ip)
    if data_source_ip != "-":
        source_confidence = "High"
    elif log_source_ip != "-":
        source_confidence = "Medium"
    else:
        source_confidence = "Unknown"
    agent_ip = first_valid_ip(agent.get("ip"))
    destination_ip = first_valid_ip(find_value(data, DESTINATION_IP_KEYS), agent_ip)
    actor_user = normalize_username(find_value(data, ACTOR_USER_KEYS))
    target_user = normalize_username(find_value(data, TARGET_USER_KEYS))
    log_user = normalize_username(extract_username(full_log))
    if event_category in {"Credential Attack", "Authentication Success"}:
        if log_user != "-":
            target_user = log_user
    elif target_user == "-" and log_user != "-":
        target_user = log_user
    username = actor_user if event_category == "Privilege Activity" else target_user
    if username == "-":
        username = actor_user if actor_user != "-" else target_user
    command = clean_text(find_value(data, COMMAND_KEYS))

    agent_name = clean_text(agent.get("name"))
    manager_name = clean_text(manager.get("name"))
    affected_asset = next(
        (value for value in (agent_name, destination_ip, manager_name) if value != "-"),
        "-",
    )
    source_scope = ip_scope(source_ip)
    score = alert_risk_score(rule_id, rule_level, alert_type, source_scope)
    level = risk_level(score)
    mitre_ids, mitre_tactics, mitre_techniques, attack_stage = _mitre_fields(
        mitre,
        event_category,
    )

    return Alert(
        record_number=record_number,
        event_id=clean_text(raw.get("id")),
        timestamp=timestamp,
        event_time=event_time,
        agent_id=clean_text(agent.get("id")),
        agent_name=agent_name,
        agent_ip=agent_ip,
        manager_name=manager_name,
        source_ip=source_ip,
        source_scope=source_scope,
        source_confidence=source_confidence,
        destination_ip=destination_ip,
        username=username,
        actor_user=actor_user,
        target_user=target_user,
        command=command,
        rule_id=rule_id,
        rule_level=rule_level,
        wazuh_severity=wazuh_severity(rule_level),
        alert_type=alert_type,
        event_category=event_category,
        outcome=outcome,
        classification_confidence=classification_confidence,
        classification_reason=classification_reason,
        description=description,
        fired_times=max(coerce_int(rule.get("firedtimes"), 1), 1),
        affected_asset=affected_asset,
        mitre_ids=mitre_ids,
        mitre_tactics=mitre_tactics,
        mitre_techniques=mitre_techniques,
        attack_stage=attack_stage,
        risk_score=score,
        risk_level=level,
        response_suggestion=response_for(
            event_category,
            alert_type,
            source_ip,
            actor_user if event_category == "Privilege Activity" else target_user,
            level,
        ),
        location=clean_text(raw.get("location")),
        decoder=clean_text(decoder_data.get("name")),
        full_log=full_log,
    )


def load_and_normalize(
    path: Path,
    stats: ParseStats,
    *,
    min_level: int = 0,
    line_limit: int = 0,
    since: datetime | None = None,
    until: datetime | None = None,
    soc_only: bool = False,
) -> list[Alert]:
    alerts: list[Alert] = []
    seen_event_ids: set[str] = set()
    for record_number, raw in iter_wazuh_records(path, stats, line_limit):
        alert = normalize_alert(record_number, raw, stats)
        if alert.event_id != "-" and alert.event_id in seen_event_ids:
            stats.duplicate_records += 1
            continue
        if alert.event_id != "-":
            seen_event_ids.add(alert.event_id)
        if alert.rule_level < min_level:
            stats.filtered_by_level += 1
            continue
        if since or until:
            if alert.event_time is None:
                stats.filtered_by_time += 1
                continue
            if since and alert.event_time < since:
                stats.filtered_by_time += 1
                continue
            if until and alert.event_time > until:
                stats.filtered_by_time += 1
                continue
        if soc_only and alert.event_category not in SOC_CATEGORIES:
            stats.filtered_by_scope += 1
            continue
        alerts.append(alert)
    stats.included_alerts = len(alerts)
    return alerts


def _format_time(value: datetime | None, fallback: str) -> str:
    return value.isoformat(timespec="seconds") if value else fallback


def _incident_status(level: str) -> str:
    return {
        "Critical": "立即处置",
        "High": "优先调查",
        "Medium": "待调查",
        "Low": "记录观察",
    }[level]


def _incident_confidence(items: list[Alert]) -> str:
    rule_ids = {item.rule_id for item in items}
    known_source = any(item.source_ip != "-" for item in items)
    if rule_ids.intersection(CUSTOM_RULE_IDS) or max(item.rule_level for item in items) >= 10:
        return "High"
    if len(items) >= 3 and known_source:
        return "High"
    if len(items) >= 2 or known_source:
        return "Medium"
    return "Low"


def _incident_score(items: list[Alert]) -> int:
    base = max(item.risk_score for item in items)
    category = items[0].event_category
    if category in {"Session Activity", "Authentication Success"}:
        volume_bonus = min(3, max(len(items) - 1, 0))
    else:
        volume_bonus = min(15, round(math.log2(len(items) + 1) * 4))
    rule_bonus = 5 if len({item.rule_id for item in items}) >= 2 else 0
    credential_bonus = 5 if category == "Credential Attack" and len(items) >= 3 else 0
    return min(base + volume_bonus + rule_bonus + credential_bonus, 100)


def _agent_health_summary(items: list[Alert]) -> str:
    pending_stops: list[datetime] = []
    recovered_durations: list[int] = []
    stop_count = 0
    start_count = 0
    for item in items:
        if item.rule_id in {"504", "505", "506"}:
            stop_count += 1
            if item.event_time is not None:
                pending_stops.append(item.event_time)
        elif item.rule_id == "503":
            start_count += 1
            if item.event_time is not None and pending_stops:
                stopped_at = pending_stops.pop(0)
                recovered_durations.append(
                    max(int((item.event_time - stopped_at).total_seconds()), 0)
                )
    recovery_text = (
        f"已匹配 {len(recovered_durations)} 个恢复周期，累计中断约 "
        f"{sum(recovered_durations)} 秒。"
        if recovered_durations
        else "未匹配到完整的停止—恢复周期。"
    )
    outstanding = f"仍有 {len(pending_stops)} 次停止未见恢复。 " if pending_stops else ""
    return (
        f"检测到 {stop_count} 次停止/断连与 {start_count} 次启动/恢复；"
        f"{recovery_text}{outstanding}"
    )


def _build_incident(items: list[Alert]) -> Incident:
    ordered = sorted(
        items,
        key=lambda item: (
            item.event_time or datetime.min.replace(tzinfo=timezone.utc),
            item.record_number,
        ),
    )
    first = ordered[0]
    last = ordered[-1]
    event_times = [item.event_time for item in ordered if item.event_time is not None]
    duration = int((event_times[-1] - event_times[0]).total_seconds()) if event_times else 0
    score = _incident_score(ordered)
    level = risk_level(score)
    alert_types = unique(item.alert_type for item in ordered)
    rule_ids = unique(item.rule_id for item in ordered)
    actor_users = unique(item.actor_user for item in ordered)
    target_users = unique(item.target_user for item in ordered)
    commands = unique(item.command for item in ordered)
    mitre_ids = unique(
        value.strip()
        for item in ordered
        for value in item.mitre_ids.split(",")
        if value.strip() != "-"
    )
    highest = max(ordered, key=lambda item: (item.risk_score, item.rule_level))
    title_base = INCIDENT_TITLES.get(first.event_category, first.event_category)
    source_text = first.source_ip if first.source_ip != "-" else "来源未知"
    summary = (
        f"资产 {first.affected_asset} 在 {duration} 秒内出现 {len(ordered)} 条相关告警，"
        f"来源 {source_text}，涉及规则 {', '.join(rule_ids)}；最高 Wazuh 等级 "
        f"{max(item.rule_level for item in ordered)}。"
    )
    if first.event_category == "Agent Visibility":
        summary = f"资产 {first.affected_asset} 的监控覆盖发生变化：{_agent_health_summary(ordered)}"
    evidence = highest.full_log
    if len(evidence) > 320:
        evidence = f"{evidence[:317]}..."

    return Incident(
        incident_id="",
        title=f"{title_base} · {first.affected_asset}",
        status=_incident_status(level),
        confidence=_incident_confidence(ordered),
        first_seen=_format_time(first.event_time, first.timestamp),
        last_seen=_format_time(last.event_time, last.timestamp),
        duration_seconds=max(duration, 0),
        event_count=len(ordered),
        risk_score=score,
        risk_level=level,
        max_rule_level=max(item.rule_level for item in ordered),
        event_category=first.event_category,
        source_ip=first.source_ip,
        source_scope=first.source_scope,
        affected_asset=first.affected_asset,
        agent_id=first.agent_id,
        alert_types=", ".join(alert_types),
        rule_ids=", ".join(rule_ids),
        actor_users=", ".join(actor_users) if actor_users else "-",
        target_users=", ".join(target_users) if target_users else "-",
        commands="; ".join(commands) if commands else "-",
        mitre_ids=", ".join(mitre_ids) if mitre_ids else "-",
        summary=summary,
        recommendation=response_for(
            first.event_category,
            highest.alert_type,
            first.source_ip,
            (
                actor_users[0]
                if first.event_category == "Privilege Activity" and actor_users
                else target_users[0] if target_users else "-"
            ),
            level,
        ),
        evidence=evidence,
        event_times=event_times,
    )


def correlate_incidents(alerts: list[Alert], window_minutes: int = 10) -> list[Incident]:
    """Group related alerts by asset, source, category, and time window."""

    window = timedelta(minutes=max(window_minutes, 1))
    grouped: dict[tuple[str, str, str], list[list[Alert]]] = defaultdict(list)
    ordered = sorted(
        alerts,
        key=lambda item: (
            item.event_time or datetime.max.replace(tzinfo=timezone.utc),
            item.record_number,
        ),
    )

    for alert in ordered:
        key = (alert.affected_asset, alert.source_ip, alert.event_category)
        sequences = grouped[key]
        if (
            not sequences
            or alert.event_time is None
            or sequences[-1][-1].event_time is None
            or alert.event_time - sequences[-1][-1].event_time > window
        ):
            sequences.append([alert])
        else:
            sequences[-1].append(alert)

    sequences = [
        sequence
        for grouped_sequences in grouped.values()
        for sequence in grouped_sequences
        if sequence
    ]

    # Escalate an authentication-failure chain if the same source subsequently
    # authenticates successfully to the same asset/account inside the window.
    success_alerts = [
        alert
        for alert in ordered
        if alert.event_category == "Authentication Success"
        and alert.event_time is not None
        and alert.source_ip != "-"
    ]
    compromise_sequence_ids: set[int] = set()
    for sequence in sequences:
        if sequence[0].event_category != "Credential Attack":
            continue
        failure_times = [item.event_time for item in sequence if item.event_time is not None]
        if not failure_times:
            continue
        failure_end = max(failure_times)
        target_users = {item.target_user for item in sequence if item.target_user != "-"}
        candidates = [
            success
            for success in success_alerts
            if success.affected_asset == sequence[0].affected_asset
            and success.source_ip == sequence[0].source_ip
            and failure_end < success.event_time <= failure_end + window
            and (
                not target_users
                or success.target_user == "-"
                or success.target_user in target_users
            )
        ]
        if candidates:
            sequence.append(min(candidates, key=lambda item: item.event_time))
            compromise_sequence_ids.add(id(sequence))

    incidents = []
    for sequence in sequences:
        incident = _build_incident(sequence)
        if id(sequence) in compromise_sequence_ids:
            incident.title = f"疑似凭据攻陷：失败后成功登录 · {incident.affected_asset}"
            incident.event_category = "Suspected Compromise"
            incident.risk_score = max(incident.risk_score, 95)
            incident.risk_level = "Critical"
            incident.status = "立即处置"
            incident.confidence = "High"
            incident.summary += " 同一来源在失败链之后成功完成认证，需优先排查账户是否失陷。"
            incident.recommendation = (
                "立即验证成功登录是否获得授权；隔离可疑会话，轮换相关凭据，"
                "检查登录后的 sudo、进程、文件和网络活动，并保全完整时间线。"
            )
        incidents.append(incident)
    incidents.sort(
        key=lambda item: (
            item.risk_score,
            item.max_rule_level,
            item.event_count,
            item.last_seen,
        ),
        reverse=True,
    )
    for index, incident in enumerate(incidents, start=1):
        date_part = "UNKNOWN"
        if incident.event_times:
            date_part = incident.event_times[0].strftime("%Y%m%d")
        incident.incident_id = f"INC-{date_part}-{index:04d}"
    return incidents


def _risk_counts(items: Iterable[Alert]) -> Counter[str]:
    return Counter(item.risk_level for item in items)


def _time_range(items: list[Alert]) -> tuple[str, str]:
    valid = sorted(item.event_time for item in items if item.event_time is not None)
    if valid:
        return (
            valid[0].isoformat(timespec="seconds"),
            valid[-1].isoformat(timespec="seconds"),
        )
    values = [item.timestamp for item in items if item.timestamp != "-"]
    if values:
        return min(values), max(values)
    return "-", "-"


def _common_summary(items: list[Alert]) -> dict[str, Any]:
    risk_counts = _risk_counts(items)
    first_seen, last_seen = _time_range(items)
    max_score = max(item.risk_score for item in items)
    return {
        "alert_count": len(items),
        "max_risk_score": max_score,
        "max_risk_level": risk_level(max_score),
        "critical_count": risk_counts.get("Critical", 0),
        "high_count": risk_counts.get("High", 0),
        "medium_count": risk_counts.get("Medium", 0),
        "low_count": risk_counts.get("Low", 0),
        "first_seen": first_seen,
        "last_seen": last_seen,
    }


def summarize_sources(alerts: list[Alert], incidents: list[Incident]) -> list[dict[str, Any]]:
    buckets: dict[str, list[Alert]] = defaultdict(list)
    for alert in alerts:
        if alert.source_ip != "-":
            buckets[alert.source_ip].append(alert)
    incident_counts = Counter(
        incident.source_ip for incident in incidents if incident.source_ip != "-"
    )
    rows: list[dict[str, Any]] = []
    for source_ip, items in buckets.items():
        row = {
            "source_ip": source_ip,
            "source_scope": items[0].source_scope,
            "incident_count": incident_counts.get(source_ip, 0),
            **_common_summary(items),
            "top_alert_types": "; ".join(
                f"{name}({count})"
                for name, count in Counter(item.alert_type for item in items).most_common(5)
            ),
            "affected_assets": "; ".join(
                f"{name}({count})"
                for name, count in Counter(item.affected_asset for item in items).most_common(5)
            ),
            "usernames": ", ".join(unique(item.username for item in items)) or "-",
        }
        rows.append(row)
    return sorted(
        rows,
        key=lambda row: (row["max_risk_score"], row["alert_count"]),
        reverse=True,
    )


def summarize_types(alerts: list[Alert]) -> list[dict[str, Any]]:
    buckets: dict[str, list[Alert]] = defaultdict(list)
    for alert in alerts:
        buckets[alert.alert_type].append(alert)
    rows = []
    for alert_type, items in buckets.items():
        rows.append(
            {
                "alert_type": alert_type,
                "event_category": items[0].event_category,
                **_common_summary(items),
                "source_ips": "; ".join(
                    f"{name}({count})"
                    for name, count in Counter(
                        item.source_ip for item in items if item.source_ip != "-"
                    ).most_common(5)
                )
                or "-",
                "affected_assets": "; ".join(
                    f"{name}({count})"
                    for name, count in Counter(item.affected_asset for item in items).most_common(5)
                ),
            }
        )
    return sorted(
        rows,
        key=lambda row: (row["max_risk_score"], row["alert_count"]),
        reverse=True,
    )


def summarize_assets(alerts: list[Alert], incidents: list[Incident]) -> list[dict[str, Any]]:
    buckets: dict[str, list[Alert]] = defaultdict(list)
    for alert in alerts:
        buckets[alert.affected_asset].append(alert)
    incident_counts = Counter(incident.affected_asset for incident in incidents)
    rows = []
    for asset, items in buckets.items():
        rows.append(
            {
                "affected_asset": asset,
                "agent_id": items[0].agent_id,
                "agent_ip": items[0].agent_ip,
                "incident_count": incident_counts.get(asset, 0),
                **_common_summary(items),
                "top_alert_types": "; ".join(
                    f"{name}({count})"
                    for name, count in Counter(item.alert_type for item in items).most_common(5)
                ),
                "source_ips": "; ".join(
                    f"{name}({count})"
                    for name, count in Counter(
                        item.source_ip for item in items if item.source_ip != "-"
                    ).most_common(5)
                )
                or "-",
            }
        )
    return sorted(
        rows,
        key=lambda row: (row["max_risk_score"], row["alert_count"]),
        reverse=True,
    )


def summarize_rules(alerts: list[Alert]) -> list[dict[str, Any]]:
    buckets: dict[tuple[str, str], list[Alert]] = defaultdict(list)
    for alert in alerts:
        buckets[(alert.rule_id, alert.description)].append(alert)
    rows = []
    for (rule_id, description), items in buckets.items():
        max_level = max(item.rule_level for item in items)
        rows.append(
            {
                "rule_id": rule_id,
                "description": description,
                "alert_count": len(items),
                "rule_level": max_level,
                "wazuh_severity": wazuh_severity(max_level),
                "max_risk_score": max(item.risk_score for item in items),
                "max_risk_level": risk_level(max(item.risk_score for item in items)),
                "affected_assets": ", ".join(unique(item.affected_asset for item in items)),
            }
        )
    return sorted(
        rows,
        key=lambda row: (row["max_risk_score"], row["alert_count"]),
        reverse=True,
    )


def summarize_mitre(alerts: list[Alert]) -> list[dict[str, Any]]:
    buckets: dict[tuple[str, str, str, str], list[Alert]] = defaultdict(list)
    for alert in alerts:
        ids = [value.strip() for value in alert.mitre_ids.split(",") if value.strip() != "-"]
        tactics = [
            value.strip() for value in alert.mitre_tactics.split(",") if value.strip() != "-"
        ]
        techniques = [
            value.strip()
            for value in alert.mitre_techniques.split(",")
            if value.strip() != "-"
        ]
        if not ids and not tactics:
            buckets[("Unmapped", "Unmapped", "-", "-")].append(alert)
            continue
        for tactic in tactics:
            buckets[("Tactic", tactic, "-", "-")].append(alert)
        for index, mitre_id in enumerate(ids):
            mapped_tactic, mapped_technique = ATTACK_BY_ID.get(mitre_id, ("", ""))
            technique = mapped_technique or (
                techniques[index] if index < len(techniques) else "-"
            )
            buckets[("Technique", mapped_tactic or "-", mitre_id, technique)].append(alert)

    rows = []
    for (mapping_type, tactic, mitre_id, technique), items in buckets.items():
        rows.append(
            {
                "mapping_type": mapping_type,
                "attack_stage": tactic,
                "mitre_id": mitre_id,
                "technique": technique,
                "alert_count": len(items),
                "max_risk_level": risk_level(max(item.risk_score for item in items)),
                "top_source_ips": "; ".join(
                    f"{name}({count})"
                    for name, count in Counter(
                        item.source_ip for item in items if item.source_ip != "-"
                    ).most_common(5)
                )
                or "-",
                "affected_assets": "; ".join(
                    f"{name}({count})"
                    for name, count in Counter(item.affected_asset for item in items).most_common(5)
                ),
            }
        )
    return sorted(
        rows,
        key=lambda row: (
            row["mapping_type"] == "Technique",
            row["max_risk_level"] == "Critical",
            row["alert_count"],
        ),
        reverse=True,
    )


def summarize_recommendations(incidents: list[Incident]) -> list[dict[str, Any]]:
    return [
        {
            "incident_id": incident.incident_id,
            "risk_level": incident.risk_level,
            "risk_score": incident.risk_score,
            "source_ip": incident.source_ip,
            "affected_asset": incident.affected_asset,
            "event_category": incident.event_category,
            "event_count": incident.event_count,
            "recommendation": incident.recommendation,
        }
        for incident in incidents
    ]


def build_timeline(alerts: list[Alert]) -> list[dict[str, Any]]:
    valid = [alert for alert in alerts if alert.event_time is not None]
    if not valid:
        return []
    valid.sort(key=lambda alert: alert.event_time)
    duration = valid[-1].event_time - valid[0].event_time
    if duration <= timedelta(hours=2):
        bucket_seconds = 10 * 60
    elif duration <= timedelta(days=1):
        bucket_seconds = 60 * 60
    elif duration <= timedelta(days=7):
        bucket_seconds = 6 * 60 * 60
    else:
        bucket_seconds = 24 * 60 * 60

    buckets: dict[datetime, list[Alert]] = defaultdict(list)
    for alert in valid:
        assert alert.event_time is not None
        epoch = int(alert.event_time.timestamp())
        bucket_epoch = epoch - epoch % bucket_seconds
        bucket = datetime.fromtimestamp(bucket_epoch, tz=alert.event_time.tzinfo)
        buckets[bucket].append(alert)

    rows = []
    for bucket, items in sorted(buckets.items()):
        rows.append(
            {
                "period_start": bucket.isoformat(timespec="minutes"),
                "alert_count": len(items),
                "high_or_critical_count": sum(
                    item.risk_level in {"High", "Critical"} for item in items
                ),
                "credential_attack_count": sum(
                    item.event_category == "Credential Attack" for item in items
                ),
            }
        )
    return rows


def build_metrics(alerts: list[Alert], incidents: list[Incident]) -> dict[str, Any]:
    alert_risks = _risk_counts(alerts)
    incident_risks = Counter(item.risk_level for item in incidents)
    first_seen, last_seen = _time_range(alerts)
    valid_times = sorted(item.event_time for item in alerts if item.event_time is not None)
    duration_seconds = (
        int((valid_times[-1] - valid_times[0]).total_seconds())
        if len(valid_times) >= 2
        else 0
    )
    mapped_alerts = sum(item.mitre_ids != "-" for item in alerts)
    highest_incident_score = max((item.risk_score for item in incidents), default=0)
    return {
        "total_alerts": len(alerts),
        "total_incidents": len(incidents),
        "critical_alerts": alert_risks.get("Critical", 0),
        "high_alerts": alert_risks.get("High", 0),
        "medium_alerts": alert_risks.get("Medium", 0),
        "low_alerts": alert_risks.get("Low", 0),
        "critical_incidents": incident_risks.get("Critical", 0),
        "high_incidents": incident_risks.get("High", 0),
        "medium_incidents": incident_risks.get("Medium", 0),
        "low_incidents": incident_risks.get("Low", 0),
        "source_ip_count": len({item.source_ip for item in alerts if item.source_ip != "-"}),
        "external_source_count": len(
            {
                item.source_ip
                for item in alerts
                if item.source_ip != "-" and item.source_scope == "Public/External"
            }
        ),
        "unknown_source_alerts": sum(item.source_ip == "-" for item in alerts),
        "asset_count": len({item.affected_asset for item in alerts}),
        "rule_count": len({item.rule_id for item in alerts}),
        "credential_attack_alerts": sum(
            item.event_category == "Credential Attack" for item in alerts
        ),
        "privilege_alerts": sum(
            item.event_category == "Privilege Activity" for item in alerts
        ),
        "agent_visibility_alerts": sum(
            item.event_category == "Agent Visibility" for item in alerts
        ),
        "mitre_mapped_alerts": mapped_alerts,
        "mitre_unmapped_alerts": len(alerts) - mapped_alerts,
        "mitre_coverage_percent": round(mapped_alerts / len(alerts) * 100, 1)
        if alerts
        else 0.0,
        "low_confidence_classifications": sum(
            item.classification_confidence == "Low" for item in alerts
        ),
        "first_seen": first_seen,
        "last_seen": last_seen,
        "duration_seconds": duration_seconds,
        "highest_risk_score": highest_incident_score,
        "highest_risk_level": risk_level(highest_incident_score)
        if incidents
        else "None",
    }


def analyze(alerts: list[Alert], incident_window_minutes: int = 10) -> AnalysisResult:
    incidents = correlate_incidents(alerts, incident_window_minutes)
    return AnalysisResult(
        alerts=alerts,
        incidents=incidents,
        by_source=summarize_sources(alerts, incidents),
        by_type=summarize_types(alerts),
        by_asset=summarize_assets(alerts, incidents),
        by_rule=summarize_rules(alerts),
        mitre=summarize_mitre(alerts),
        recommendations=summarize_recommendations(incidents),
        timeline=build_timeline(alerts),
        metrics=build_metrics(alerts, incidents),
    )
