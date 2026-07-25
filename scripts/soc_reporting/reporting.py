"""Secure CSV/JSON writers and the Chinese SOC HTML report renderer."""

from __future__ import annotations

import csv
import html
import json
import os
import tempfile
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Iterable

from .models import (
    ALERT_EXPORT_FIELDS,
    INCIDENT_EXPORT_FIELDS,
    AnalysisResult,
    ParseStats,
)


RISK_ZH = {
    "Critical": "严重",
    "High": "高危",
    "Medium": "中危",
    "Low": "低危",
    "None": "无",
}

SCOPE_ZH = {
    "Public/External": "公网/外部",
    "Private/Internal": "私网/内部",
    "Loopback": "本机回环",
    "Link-local": "链路本地",
    "Multicast": "组播",
    "Reserved": "保留地址",
    "Unknown": "未知",
}

CATEGORY_ZH = {
    "Suspected Compromise": "疑似账户失陷",
    "Credential Attack": "凭据攻击",
    "Authentication Success": "认证成功",
    "Session Activity": "会话活动",
    "Privilege Activity": "特权操作",
    "Reconnaissance": "侦察扫描",
    "File Integrity": "文件完整性",
    "Vulnerability": "漏洞风险",
    "Malware": "恶意代码",
    "Agent Visibility": "监控覆盖",
    "Network Exposure": "网络暴露",
    "System Integrity": "系统完整性",
    "Web Activity": "Web 活动",
    "Other Security Event": "其他事件",
}

COLUMN_LABELS = {
    "incident_id": "事件编号",
    "title": "事件",
    "status": "处置状态",
    "confidence": "置信度",
    "first_seen": "首次发现",
    "last_seen": "最近发现",
    "duration_seconds": "持续(秒)",
    "event_count": "证据数",
    "risk_score": "风险分",
    "risk_level": "风险",
    "max_rule_level": "最高规则等级",
    "event_category": "事件类别",
    "source_ip": "来源 IP",
    "source_scope": "地址属性",
    "source_confidence": "来源置信度",
    "affected_asset": "受影响资产",
    "agent_id": "Agent ID",
    "agent_ip": "资产 IP",
    "alert_count": "告警数",
    "incident_count": "事件数",
    "max_risk_level": "最高风险",
    "max_risk_score": "最高风险分",
    "top_alert_types": "主要告警类型",
    "affected_assets": "受影响资产",
    "source_ips": "来源 IP",
    "usernames": "相关账户",
    "actor_user": "操作账户",
    "target_user": "目标账户",
    "command": "命令",
    "timestamp": "时间",
    "alert_type": "告警类型",
    "rule_id": "规则 ID",
    "rule_level": "规则等级",
    "description": "规则描述",
    "wazuh_severity": "Wazuh 严重度",
    "attack_stage": "ATT&CK 战术",
    "mitre_id": "技术 ID",
    "technique": "技术",
    "mapping_type": "映射类型",
    "top_source_ips": "主要来源",
    "recommendation": "处置建议",
    "period_start": "时间桶",
    "high_or_critical_count": "高危及以上",
    "credential_attack_count": "凭据攻击",
}


def _excel_safe(value: Any) -> Any:
    """Neutralize cells that spreadsheet applications may interpret as formulas."""

    if not isinstance(value, str):
        return value
    stripped = value.lstrip()
    if len(stripped) > 1 and stripped.startswith(("=", "+", "-", "@", "\t", "\r")):
        return f"'{value}"
    return value


def _atomic_text(path: Path, text: str, encoding: str = "utf-8") -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary_name = tempfile.mkstemp(
        dir=path.parent,
        prefix=f".{path.name}.",
        suffix=".tmp",
        text=True,
    )
    temporary = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "w", encoding=encoding, newline="") as handle:
            handle.write(text)
            handle.flush()
            os.fsync(handle.fileno())
        try:
            temporary.chmod(0o600)
        except OSError:
            pass
        os.replace(temporary, path)
    except Exception:
        temporary.unlink(missing_ok=True)
        raise


def write_csv(
    path: Path,
    rows: Iterable[dict[str, Any]],
    fieldnames: list[str],
) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary_name = tempfile.mkstemp(
        dir=path.parent,
        prefix=f".{path.name}.",
        suffix=".tmp",
        text=True,
    )
    temporary = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8-sig", newline="") as handle:
            writer = csv.DictWriter(handle, fieldnames=fieldnames, extrasaction="ignore")
            writer.writeheader()
            for row in rows:
                writer.writerow(
                    {field: _excel_safe(row.get(field, "")) for field in fieldnames}
                )
            handle.flush()
            os.fsync(handle.fileno())
        try:
            temporary.chmod(0o600)
        except OSError:
            pass
        os.replace(temporary, path)
    except Exception:
        temporary.unlink(missing_ok=True)
        raise


def write_json(path: Path, payload: dict[str, Any]) -> None:
    _atomic_text(
        path,
        json.dumps(payload, ensure_ascii=False, indent=2, default=str),
    )


def _escape(value: Any) -> str:
    return html.escape(str(value), quote=True)


def _risk_badge(value: Any) -> str:
    risk = str(value)
    label = RISK_ZH.get(risk, risk)
    css = risk.lower() if risk in RISK_ZH else "neutral"
    return f'<span class="badge badge-{_escape(css)}">{_escape(label)}</span>'


def _category(value: Any) -> str:
    return CATEGORY_ZH.get(str(value), str(value))


def _scope(value: Any) -> str:
    return SCOPE_ZH.get(str(value), str(value))


def _confidence(value: Any) -> str:
    return {"High": "高", "Medium": "中", "Low": "低", "Unknown": "未知"}.get(
        str(value),
        str(value),
    )


def _duration(seconds: int) -> str:
    seconds = max(int(seconds), 0)
    if seconds < 60:
        return f"{seconds} 秒"
    minutes, remainder = divmod(seconds, 60)
    if minutes < 60:
        return f"{minutes} 分 {remainder} 秒"
    hours, minutes = divmod(minutes, 60)
    return f"{hours} 小时 {minutes} 分"


def _table_value(column: str, value: Any) -> str:
    if column in {"risk_level", "max_risk_level"}:
        return _risk_badge(value)
    if column == "event_category":
        return _escape(_category(value))
    if column == "source_scope":
        return _escape(_scope(value))
    if column in {"confidence", "source_confidence"}:
        return _escape(_confidence(value))
    return _escape(value)


def render_table(
    rows: list[dict[str, Any]],
    columns: list[str],
    *,
    limit: int = 20,
    empty_message: str = "没有符合条件的记录。",
) -> str:
    if not rows:
        return f'<div class="empty">{_escape(empty_message)}</div>'
    visible = rows[:limit] if limit else rows
    head = "".join(
        f"<th>{_escape(COLUMN_LABELS.get(column, column))}</th>" for column in columns
    )
    body = []
    for row in visible:
        cells = "".join(
            f"<td>{_table_value(column, row.get(column, '-'))}</td>" for column in columns
        )
        body.append(f"<tr>{cells}</tr>")
    truncation = ""
    if limit and len(rows) > limit:
        truncation = (
            f'<p class="table-note">当前展示前 {limit} 条，共 {len(rows)} 条；'
            "完整数据见对应 CSV 文件。</p>"
        )
    return (
        f'<div class="table-scroll"><table><thead><tr>{head}</tr></thead>'
        f"<tbody>{''.join(body)}</tbody></table></div>{truncation}"
    )


def _incident_cards(result: AnalysisResult, limit: int = 12) -> str:
    if not result.incidents:
        return '<div class="empty">本报告周期内没有可关联的安全事件。</div>'
    cards = []
    for incident in result.incidents[:limit]:
        source = (
            f"{incident.source_ip}（{_scope(incident.source_scope)}）"
            if incident.source_ip != "-"
            else "未知"
        )
        identity_parts = []
        if incident.actor_users != "-":
            identity_parts.append(f"操作账户：{incident.actor_users}")
        if incident.target_users != "-":
            identity_parts.append(f"目标账户：{incident.target_users}")
        identities = " · ".join(identity_parts) or "未提取到账户"
        commands = ""
        if incident.commands != "-":
            commands = (
                '<div class="detail-row"><span>命令</span>'
                f"<code>{_escape(incident.commands)}</code></div>"
            )
        cards.append(
            f"""
            <article class="incident-card risk-{_escape(incident.risk_level.lower())}">
              <div class="incident-head">
                <div>
                  <div class="incident-id">{_escape(incident.incident_id)}</div>
                  <h3>{_escape(incident.title)}</h3>
                </div>
                <div class="incident-score">
                  {_risk_badge(incident.risk_level)}
                  <strong>{incident.risk_score}</strong><span>/100</span>
                </div>
              </div>
              <div class="incident-meta">
                <span>状态：{_escape(incident.status)}</span>
                <span>置信度：{_escape(_confidence(incident.confidence))}</span>
                <span>证据：{incident.event_count} 条</span>
                <span>持续：{_escape(_duration(incident.duration_seconds))}</span>
              </div>
              <p class="summary">{_escape(incident.summary)}</p>
              <div class="detail-grid">
                <div class="detail-row"><span>来源</span><strong>{_escape(source)}</strong></div>
                <div class="detail-row"><span>资产</span><strong>{_escape(incident.affected_asset)}</strong></div>
                <div class="detail-row"><span>账户</span><strong>{_escape(identities)}</strong></div>
                <div class="detail-row"><span>规则</span><code>{_escape(incident.rule_ids)}</code></div>
                <div class="detail-row"><span>时间</span><strong>{_escape(incident.first_seen)} → {_escape(incident.last_seen)}</strong></div>
                <div class="detail-row"><span>ATT&CK</span><code>{_escape(incident.mitre_ids)}</code></div>
                {commands}
              </div>
              <div class="recommendation"><strong>建议：</strong>{_escape(incident.recommendation)}</div>
              <details>
                <summary>查看代表性原始证据</summary>
                <pre>{_escape(incident.evidence)}</pre>
              </details>
            </article>
            """
        )
    note = ""
    if len(result.incidents) > limit:
        note = (
            f'<p class="table-note">页面展示优先级最高的 {limit} 个事件，'
            f"完整 {len(result.incidents)} 个事件见 incidents.csv。</p>"
        )
    return "".join(cards) + note


def _risk_distribution(result: AnalysisResult) -> str:
    metrics = result.metrics
    total = max(metrics["total_incidents"], 1)
    rows = []
    for risk in ("Critical", "High", "Medium", "Low"):
        count = metrics[f"{risk.lower()}_incidents"]
        width = count / total * 100
        rows.append(
            f"""
            <div class="bar-row">
              <span>{_risk_badge(risk)}</span>
              <div class="bar-track"><div class="bar bar-{risk.lower()}" style="width:{width:.2f}%"></div></div>
              <strong>{count}</strong>
            </div>
            """
        )
    return "".join(rows)


def _timeline(result: AnalysisResult) -> str:
    if not result.timeline:
        return '<div class="empty">没有带有效时间戳的告警。</div>'
    maximum = max(row["alert_count"] for row in result.timeline) or 1
    bars = []
    for row in result.timeline:
        height = max(row["alert_count"] / maximum * 120, 4)
        bars.append(
            f"""
            <div class="timeline-item" title="{_escape(row['period_start'])}：{row['alert_count']} 条">
              <div class="timeline-count">{row['alert_count']}</div>
              <div class="timeline-bar" style="height:{height:.1f}px">
                <span style="height:{row['high_or_critical_count'] / maximum * 120:.1f}px"></span>
              </div>
              <div class="timeline-label">{_escape(row['period_start'][11:16])}</div>
            </div>
            """
        )
    return f'<div class="timeline-chart">{"".join(bars)}</div>'


def _executive_summary(result: AnalysisResult) -> str:
    metrics = result.metrics
    high_priority = metrics["critical_incidents"] + metrics["high_incidents"]
    if metrics["critical_incidents"]:
        posture = "报告周期内存在严重事件，需要立即确认处置。"
    elif metrics["high_incidents"]:
        posture = "报告周期内存在高危事件，需要优先调查。"
    elif metrics["medium_incidents"]:
        posture = "未发现严重事件，但存在需要核查的中危活动。"
    else:
        posture = "未发现中高危关联事件，建议继续监控并维护检测基线。"
    top_text = ""
    if result.incidents:
        top = result.incidents[0]
        top_text = (
            f"最高优先事件为“{top.title}”（{top.risk_score}/100，"
            f"{top.event_count} 条证据）。"
        )
    return (
        f"{posture} 本次共纳入 {metrics['total_alerts']} 条告警，"
        f"关联形成 {metrics['total_incidents']} 个事件，覆盖 "
        f"{metrics['asset_count']} 台资产和 {metrics['source_ip_count']} 个已知来源地址；"
        f"其中高危及以上事件 {high_priority} 个。{top_text}"
    )


def _metric_card(value: Any, label: str, hint: str = "", css: str = "") -> str:
    hint_html = f"<small>{_escape(hint)}</small>" if hint else ""
    return (
        f'<div class="metric {css}"><strong>{_escape(value)}</strong>'
        f"<span>{_escape(label)}</span>{hint_html}</div>"
    )


def _data_quality(stats: ParseStats, result: AnalysisResult) -> str:
    rows = [
        {"metric": "读取物理行", "value": stats.total_lines, "note": "输入文件实际读取行数"},
        {"metric": "有效 JSON 对象", "value": stats.parsed_records, "note": f"解析成功率 {stats.parse_success_rate:.2f}%"},
        {"metric": "损坏 JSON", "value": stats.malformed_json, "note": f"样例行号：{stats.malformed_line_samples or '-'}"},
        {"metric": "非对象 JSON", "value": stats.non_object_records, "note": "数组或标量不会作为告警处理"},
        {"metric": "重复事件 ID", "value": stats.duplicate_records, "note": "重复记录已排除"},
        {"metric": "无效时间戳", "value": stats.invalid_timestamps, "note": "使用时间筛选时会被排除"},
        {"metric": "等级过滤", "value": stats.filtered_by_level, "note": "低于 --min-level"},
        {"metric": "时间过滤", "value": stats.filtered_by_time, "note": "不在 --since/--until 范围"},
        {"metric": "场景过滤", "value": stats.filtered_by_scope, "note": "--soc-only 排除"},
        {"metric": "最终纳入", "value": stats.included_alerts, "note": "用于本报告"},
        {
            "metric": "来源未知",
            "value": result.metrics["unknown_source_alerts"],
            "note": "不会回退为 Agent/资产 IP",
        },
        {
            "metric": "低置信度分类",
            "value": result.metrics["low_confidence_classifications"],
            "note": "建议补充精确规则映射",
        },
    ]
    return render_table(rows, ["metric", "value", "note"], limit=0)


def render_html_report(
    result: AnalysisResult,
    stats: ParseStats,
    context: dict[str, Any],
) -> str:
    metrics = result.metrics
    generated_at = context["generated_at"]
    filters = context.get("filters", {})
    filter_text = (
        f"最低规则等级 {filters.get('min_level', 0)}；"
        f"起始 {filters.get('since') or '不限'}；"
        f"结束 {filters.get('until') or '不限'}；"
        f"SOC 聚焦 {'是' if filters.get('soc_only') else '否'}"
    )

    privilege_rows = [
        alert.to_row()
        for alert in sorted(
            (
                item
                for item in result.alerts
                if item.event_category == "Privilege Activity"
            ),
            key=lambda item: item.event_time or datetime.min.replace(tzinfo=timezone.utc),
            reverse=True,
        )
    ]
    authentication_rows = [
        alert.to_row()
        for alert in sorted(
            (
                item
                for item in result.alerts
                if item.event_category in {"Credential Attack", "Authentication Success"}
            ),
            key=lambda item: item.event_time or datetime.min.replace(tzinfo=timezone.utc),
            reverse=True,
        )
    ]
    health_rows = [
        alert.to_row()
        for alert in sorted(
            (item for item in result.alerts if item.event_category == "Agent Visibility"),
            key=lambda item: item.event_time or datetime.min.replace(tzinfo=timezone.utc),
            reverse=True,
        )
    ]

    mapped = metrics["mitre_mapped_alerts"]
    unmapped = metrics["mitre_unmapped_alerts"]
    html_doc = f"""<!doctype html>
<html lang="zh-CN">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>{_escape(context['title'])}</title>
  <style>
    :root {{
      --bg: #f3f6fa; --panel: #fff; --ink: #152536; --muted: #607286;
      --line: #dce4ed; --navy: #0b2239; --blue: #146c94; --cyan: #1d93b8;
      --critical: #a11a2f; --high: #d45520; --medium: #b77905; --low: #26735f;
      --shadow: 0 10px 28px rgba(16, 42, 67, .08);
    }}
    * {{ box-sizing: border-box; }}
    html {{ scroll-behavior: smooth; }}
    body {{
      margin: 0; background: var(--bg); color: var(--ink);
      font-family: "Microsoft YaHei", "PingFang SC", "Noto Sans CJK SC", Arial, sans-serif;
      line-height: 1.55;
    }}
    header {{
      color: #fff; background:
        radial-gradient(circle at 85% -20%, rgba(29,147,184,.65), transparent 38%),
        linear-gradient(135deg, #071827, #123f5b);
      padding: 42px max(24px, calc((100vw - 1320px)/2));
    }}
    .eyebrow {{ color: #78d4eb; font-size: 12px; letter-spacing: .16em; font-weight: 700; }}
    header h1 {{ margin: 8px 0 10px; font-size: clamp(28px, 4vw, 42px); line-height: 1.2; }}
    header p {{ margin: 0; color: #d7e8f2; }}
    .scope {{ display:flex; flex-wrap:wrap; gap:10px 24px; margin-top:22px; font-size:13px; }}
    .scope span {{ color:#a9c8d9; }} .scope strong {{ color:#fff; }}
    nav {{
      position: sticky; top: 0; z-index: 10; background: rgba(255,255,255,.94);
      backdrop-filter: blur(12px); border-bottom: 1px solid var(--line);
      padding: 10px max(24px, calc((100vw - 1320px)/2)); overflow-x: auto; white-space: nowrap;
    }}
    nav a {{ color:#35546d; text-decoration:none; margin-right:20px; font-size:13px; font-weight:700; }}
    nav a:hover {{ color:var(--blue); }}
    main {{ max-width:1320px; margin:0 auto; padding:30px 24px 60px; }}
    section {{ margin-bottom:34px; scroll-margin-top:60px; }}
    h2 {{ font-size:22px; margin:0 0 14px; display:flex; align-items:center; gap:10px; }}
    h2::before {{ content:""; width:5px; height:24px; border-radius:3px; background:var(--cyan); }}
    h3 {{ margin:0; font-size:17px; }}
    .panel {{ background:var(--panel); border:1px solid var(--line); border-radius:14px; box-shadow:var(--shadow); padding:20px; }}
    .executive {{ font-size:16px; margin:0; }}
    .metrics {{ display:grid; grid-template-columns:repeat(auto-fit,minmax(155px,1fr)); gap:12px; margin-top:16px; }}
    .metric {{ background:var(--panel); border:1px solid var(--line); border-radius:12px; padding:17px; min-height:106px; box-shadow:var(--shadow); }}
    .metric strong {{ display:block; font-size:28px; line-height:1.1; }}
    .metric span {{ display:block; margin-top:7px; color:var(--muted); font-size:13px; font-weight:700; }}
    .metric small {{ display:block; margin-top:5px; color:#8291a1; font-size:11px; }}
    .metric.attention {{ border-top:4px solid var(--critical); }}
    .grid-2 {{ display:grid; grid-template-columns:repeat(2,minmax(0,1fr)); gap:18px; }}
    .badge {{ display:inline-flex; align-items:center; border-radius:999px; padding:3px 9px; font-size:11px; font-weight:800; white-space:nowrap; }}
    .badge-critical {{ color:#fff; background:var(--critical); }}
    .badge-high {{ color:#fff; background:var(--high); }}
    .badge-medium {{ color:#5d3a00; background:#f9d98a; }}
    .badge-low {{ color:#0f5746; background:#cceee3; }}
    .badge-none,.badge-neutral {{ color:#46576a; background:#e7edf3; }}
    .incident-card {{ background:var(--panel); border:1px solid var(--line); border-left:5px solid var(--low); border-radius:14px; padding:20px; box-shadow:var(--shadow); margin-bottom:14px; }}
    .incident-card.risk-critical {{ border-left-color:var(--critical); }}
    .incident-card.risk-high {{ border-left-color:var(--high); }}
    .incident-card.risk-medium {{ border-left-color:var(--medium); }}
    .incident-head {{ display:flex; align-items:flex-start; justify-content:space-between; gap:16px; }}
    .incident-id {{ color:var(--blue); font-size:11px; font-weight:800; letter-spacing:.08em; margin-bottom:4px; }}
    .incident-score {{ display:flex; align-items:baseline; gap:6px; }}
    .incident-score strong {{ font-size:26px; }} .incident-score span {{ color:var(--muted); font-size:11px; }}
    .incident-meta {{ display:flex; flex-wrap:wrap; gap:8px 18px; color:var(--muted); font-size:12px; margin:13px 0; }}
    .summary {{ margin:10px 0 15px; }}
    .detail-grid {{ display:grid; grid-template-columns:repeat(2,minmax(0,1fr)); gap:7px 20px; }}
    .detail-row {{ display:grid; grid-template-columns:64px minmax(0,1fr); gap:8px; font-size:12px; }}
    .detail-row span {{ color:var(--muted); }} .detail-row strong,.detail-row code {{ overflow-wrap:anywhere; }}
    code {{ color:#174b66; background:#edf6f9; border-radius:4px; padding:1px 4px; }}
    .recommendation {{ background:#edf7fa; border-left:3px solid var(--cyan); padding:11px 13px; margin-top:15px; font-size:13px; }}
    details {{ margin-top:12px; font-size:12px; }} summary {{ cursor:pointer; color:var(--blue); font-weight:700; }}
    pre {{ white-space:pre-wrap; overflow-wrap:anywhere; background:#0d2031; color:#d6e7f1; padding:12px; border-radius:8px; }}
    .table-scroll {{ overflow-x:auto; border:1px solid var(--line); border-radius:12px; background:var(--panel); }}
    table {{ width:100%; border-collapse:collapse; min-width:720px; }}
    th,td {{ padding:10px 12px; border-bottom:1px solid var(--line); text-align:left; vertical-align:top; font-size:12px; }}
    th {{ color:#314b61; background:#edf3f8; font-weight:800; position:sticky; top:0; }}
    tr:last-child td {{ border-bottom:0; }} tbody tr:hover {{ background:#f8fbfd; }}
    .table-note,.method-note {{ color:var(--muted); font-size:12px; }}
    .empty {{ padding:24px; border:1px dashed #b8c6d3; color:var(--muted); border-radius:12px; text-align:center; }}
    .bar-row {{ display:grid; grid-template-columns:65px 1fr 36px; align-items:center; gap:10px; margin:12px 0; }}
    .bar-track {{ height:10px; background:#e8eef4; border-radius:99px; overflow:hidden; }}
    .bar {{ height:100%; min-width:0; border-radius:99px; }} .bar-critical{{background:var(--critical)}} .bar-high{{background:var(--high)}} .bar-medium{{background:var(--medium)}} .bar-low{{background:var(--low)}}
    .timeline-chart {{ display:flex; align-items:flex-end; gap:10px; min-height:175px; overflow-x:auto; padding:12px 4px 0; }}
    .timeline-item {{ min-width:52px; text-align:center; }}
    .timeline-count {{ font-size:11px; font-weight:800; margin-bottom:4px; }}
    .timeline-bar {{ width:28px; margin:0 auto; background:#87c5d8; border-radius:5px 5px 0 0; position:relative; overflow:hidden; }}
    .timeline-bar span {{ position:absolute; bottom:0; left:0; right:0; background:var(--high); }}
    .timeline-label {{ color:var(--muted); font-size:10px; margin-top:5px; }}
    .legend {{ display:flex; gap:16px; color:var(--muted); font-size:11px; margin-top:10px; }}
    .dot {{ width:9px; height:9px; display:inline-block; border-radius:2px; margin-right:4px; }}
    footer {{ color:var(--muted); border-top:1px solid var(--line); padding-top:20px; font-size:12px; }}
    @media (max-width:850px) {{ .grid-2,.detail-grid{{grid-template-columns:1fr}} .incident-head{{flex-direction:column}} }}
    @media print {{ nav{{display:none}} body{{background:#fff}} .panel,.metric,.incident-card{{box-shadow:none;break-inside:avoid}} main{{max-width:none;padding:16px}} details{{display:none}} }}
  </style>
</head>
<body>
  <header>
    <div class="eyebrow">WAZUH · SECURITY OPERATIONS</div>
    <h1>{_escape(context['title'])}</h1>
    <p>面向安全运营的告警归一化、风险评估、事件关联与响应建议</p>
    <div class="scope">
      <div><span>数据源</span> <strong>{_escape(context['input_name'])}</strong></div>
      <div><span>报告周期</span> <strong>{_escape(metrics['first_seen'])} → {_escape(metrics['last_seen'])}</strong></div>
      <div><span>生成时间</span> <strong>{_escape(generated_at)}</strong></div>
      <div><span>关联窗口</span> <strong>{context['incident_window_minutes']} 分钟</strong></div>
    </div>
  </header>
  <nav>
    <a href="#summary">执行摘要</a><a href="#incidents">优先事件</a>
    <a href="#identity">身份与特权</a><a href="#assets">来源与资产</a>
    <a href="#mitre">MITRE</a><a href="#quality">数据质量</a>
  </nav>
  <main>
    <section id="summary">
      <h2>执行摘要</h2>
      <div class="panel"><p class="executive">{_escape(_executive_summary(result))}</p></div>
      <div class="metrics">
        {_metric_card(metrics['total_alerts'], '纳入告警', f"原始有效记录 {stats.parsed_records}")}
        {_metric_card(metrics['total_incidents'], '关联事件', f"窗口 {context['incident_window_minutes']} 分钟")}
        {_metric_card(metrics['critical_incidents'], '严重事件', '需要立即确认', 'attention' if metrics['critical_incidents'] else '')}
        {_metric_card(metrics['high_incidents'], '高危事件', '优先进入调查队列')}
        {_metric_card(metrics['asset_count'], '覆盖资产', f"规则 {metrics['rule_count']} 个")}
        {_metric_card(metrics['source_ip_count'], '已知来源 IP', f"来源未知 {metrics['unknown_source_alerts']} 条")}
      </div>
      <div class="grid-2" style="margin-top:18px">
        <div class="panel"><h3>事件风险分布</h3>{_risk_distribution(result)}</div>
        <div class="panel"><h3>告警时间趋势</h3>{_timeline(result)}
          <div class="legend"><span><i class="dot" style="background:#87c5d8"></i>全部告警</span><span><i class="dot" style="background:var(--high)"></i>高危及以上</span></div>
        </div>
      </div>
    </section>

    <section id="incidents">
      <h2>优先处置事件队列</h2>
      {_incident_cards(result)}
    </section>

    <section id="identity">
      <h2>身份认证与特权活动</h2>
      <div class="panel" style="margin-bottom:18px">
        <h3>认证攻击与成功登录时间线</h3>
        <p class="method-note">同一来源在认证失败后成功登录会升级为“疑似凭据攻陷”，但仍需人工确认授权背景。</p>
        {render_table(authentication_rows, ['timestamp','affected_asset','source_ip','target_user','alert_type','rule_id','rule_level','risk_level'], limit=30)}
      </div>
      <div class="panel">
        <h3>特权操作审计</h3>
        <p class="method-note">操作账户与目标账户分别呈现，避免将 sudo 的目标 root 误认为实际操作者。</p>
        {render_table(privilege_rows, ['timestamp','affected_asset','actor_user','target_user','command','rule_id','risk_level'], limit=30)}
      </div>
    </section>

    <section id="assets">
      <h2>来源与资产画像</h2>
      <div class="grid-2">
        <div>
          <h3 style="margin-bottom:10px">已知来源 IP</h3>
          {render_table(result.by_source, ['source_ip','source_scope','alert_count','incident_count','max_risk_level','top_alert_types','affected_assets'], limit=15)}
        </div>
        <div>
          <h3 style="margin-bottom:10px">受影响资产</h3>
          {render_table(result.by_asset, ['affected_asset','agent_id','agent_ip','alert_count','incident_count','max_risk_level','top_alert_types'], limit=15)}
        </div>
      </div>
      <div class="panel" style="margin-top:18px">
        <h3>Agent 监控覆盖变化</h3>
        {render_table(health_rows, ['timestamp','affected_asset','alert_type','rule_id','rule_level','risk_level'], limit=30, empty_message='没有 Agent 启停或断连告警。')}
      </div>
    </section>

    <section>
      <h2>规则与告警类型</h2>
      <div class="grid-2">
        <div>{render_table(result.by_type, ['alert_type','event_category','alert_count','max_risk_level','source_ips','affected_assets'], limit=20)}</div>
        <div>{render_table(result.by_rule, ['rule_id','rule_level','alert_count','max_risk_level','description','affected_assets'], limit=20)}</div>
      </div>
    </section>

    <section id="mitre">
      <h2>MITRE ATT&amp;CK 覆盖</h2>
      <div class="panel" style="margin-bottom:14px">
        <strong>映射覆盖：{mapped}/{metrics['total_alerts']}（{metrics['mitre_coverage_percent']}%）</strong>
        <p class="method-note">未映射告警 {unmapped} 条。战术与技术采用多对多统计，因此下表映射出现次数可能大于原始告警数。</p>
      </div>
      {render_table(result.mitre, ['mapping_type','attack_stage','mitre_id','technique','alert_count','max_risk_level','top_source_ips','affected_assets'], limit=30)}
    </section>

    <section id="quality">
      <h2>数据质量与分析口径</h2>
      <div class="panel">
        {_data_quality(stats, result)}
        <p class="method-note"><strong>筛选条件：</strong>{_escape(filter_text)}</p>
        <p class="method-note"><strong>来源归因：</strong>仅使用 Wazuh data 字段或原始日志中可验证的来源地址；缺失时保持“未知”，不会使用 Agent IP 代替攻击源。</p>
        <p class="method-note"><strong>频次口径：</strong>rule.firedtimes 仅作为 Wazuh 累计信息保留，不直接作为单事件频率；事件频次由来源、资产、类别和时间窗口重新计算。</p>
        <p class="method-note"><strong>评分限制：</strong>风险分是运营排序辅助，不等同于事件定性。自动建议不得未经授权直接执行封禁、隔离或账户操作。</p>
      </div>
    </section>

    <footer>
      报告模型版本 {_escape(context['model_version'])} · 输入 {_escape(context['input_name'])} ·
      生成于 {_escape(generated_at)}。完整明细、事件、规则、时间线和建议均已输出为 CSV/JSON。
    </footer>
  </main>
</body>
</html>
"""
    return html_doc


def write_report_bundle(
    output_dir: Path,
    result: AnalysisResult,
    stats: ParseStats,
    context: dict[str, Any],
) -> list[Path]:
    if output_dir.exists() and output_dir.is_symlink():
        raise ValueError(f"Refusing to write to a symbolic-link directory: {output_dir}")
    output_dir.mkdir(parents=True, exist_ok=True)

    written: list[Path] = []

    def emit_csv(name: str, rows: Iterable[dict[str, Any]], fields: list[str]) -> None:
        path = output_dir / name
        write_csv(path, rows, fields)
        written.append(path)

    emit_csv(
        "cleaned_alerts.csv",
        (alert.to_row() for alert in result.alerts),
        ALERT_EXPORT_FIELDS,
    )
    emit_csv(
        "incidents.csv",
        (incident.to_row() for incident in result.incidents),
        INCIDENT_EXPORT_FIELDS,
    )
    emit_csv(
        "summary_by_source_ip.csv",
        result.by_source,
        [
            "source_ip",
            "source_scope",
            "alert_count",
            "incident_count",
            "max_risk_score",
            "max_risk_level",
            "critical_count",
            "high_count",
            "medium_count",
            "low_count",
            "first_seen",
            "last_seen",
            "top_alert_types",
            "affected_assets",
            "usernames",
        ],
    )
    emit_csv(
        "summary_by_alert_type.csv",
        result.by_type,
        [
            "alert_type",
            "event_category",
            "alert_count",
            "max_risk_score",
            "max_risk_level",
            "critical_count",
            "high_count",
            "medium_count",
            "low_count",
            "first_seen",
            "last_seen",
            "source_ips",
            "affected_assets",
        ],
    )
    emit_csv(
        "summary_by_asset.csv",
        result.by_asset,
        [
            "affected_asset",
            "agent_id",
            "agent_ip",
            "alert_count",
            "incident_count",
            "max_risk_score",
            "max_risk_level",
            "critical_count",
            "high_count",
            "medium_count",
            "low_count",
            "first_seen",
            "last_seen",
            "top_alert_types",
            "source_ips",
        ],
    )
    emit_csv(
        "summary_by_rule.csv",
        result.by_rule,
        [
            "rule_id",
            "description",
            "alert_count",
            "rule_level",
            "wazuh_severity",
            "max_risk_score",
            "max_risk_level",
            "affected_assets",
        ],
    )
    emit_csv(
        "mitre_attack_summary.csv",
        result.mitre,
        [
            "mapping_type",
            "attack_stage",
            "mitre_id",
            "technique",
            "alert_count",
            "max_risk_level",
            "top_source_ips",
            "affected_assets",
        ],
    )
    emit_csv(
        "response_recommendations.csv",
        result.recommendations,
        [
            "incident_id",
            "risk_level",
            "risk_score",
            "source_ip",
            "affected_asset",
            "event_category",
            "event_count",
            "recommendation",
        ],
    )
    emit_csv(
        "alert_timeline.csv",
        result.timeline,
        [
            "period_start",
            "alert_count",
            "high_or_critical_count",
            "credential_attack_count",
        ],
    )

    summary_path = output_dir / "report_summary.json"
    write_json(
        summary_path,
        {
            "report": context,
            "metrics": result.metrics,
            "data_quality": stats.to_dict(),
            "priority_incidents": [
                incident.to_row() for incident in result.incidents[:10]
            ],
        },
    )
    written.append(summary_path)

    html_path = output_dir / "security_operations_report.html"
    _atomic_text(html_path, render_html_report(result, stats, context))
    written.append(html_path)
    return written
