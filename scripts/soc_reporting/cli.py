"""Command-line interface for Wazuh SOC report generation."""

from __future__ import annotations

import argparse
import os
import re
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

from . import __version__
from .models import ParseStats
from .pipeline import (
    DEFAULT_LINE_LIMIT,
    DEFAULT_MAX_INPUT_BYTES,
    DEFAULT_MAX_LINE_BYTES,
    analyze,
    load_and_normalize,
    normalize_filter_time,
)
from .reporting import REPORT_FILENAMES, write_report_bundle


def bounded_int(minimum: int, maximum: int):
    def parse(value: str) -> int:
        try:
            parsed = int(value)
        except ValueError as error:
            raise argparse.ArgumentTypeError("must be an integer") from error
        if not minimum <= parsed <= maximum:
            raise argparse.ArgumentTypeError(
                f"must be between {minimum} and {maximum}"
            )
        return parsed

    return parse


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "读取 Wazuh alerts.json，完成归一化、风险评估、时间窗关联，"
            "并生成中文安全运营 HTML/CSV/JSON 报告。"
        ),
    )
    parser.add_argument(
        "--input",
        required=True,
        help="alerts.json 或轮转后的 .json.gz 文件路径。",
    )
    parser.add_argument(
        "--output-dir",
        default="reports/latest",
        help="报告输出目录。默认：reports/latest。",
    )
    parser.add_argument(
        "--title",
        default="企业内网安全运营监控报告",
        help="HTML 报告标题。",
    )
    parser.add_argument(
        "--min-level",
        type=bounded_int(0, 16),
        default=0,
        help="只纳入 rule.level 不低于该值的告警，范围 0-16。",
    )
    parser.add_argument(
        "--limit",
        type=bounded_int(0, 100_000_000),
        default=DEFAULT_LINE_LIMIT,
        help=f"最多读取 N 个物理行；默认 {DEFAULT_LINE_LIMIT}，0 表示不限制。",
    )
    parser.add_argument(
        "--max-line-bytes",
        type=bounded_int(0, 100_000_000),
        default=DEFAULT_MAX_LINE_BYTES,
        help=(
            "单条 JSONL 物理行的最大字节数；超限行将被拒绝，"
            f"默认 {DEFAULT_MAX_LINE_BYTES}，0 表示不限制。"
        ),
    )
    parser.add_argument(
        "--max-input-bytes",
        type=bounded_int(0, 1_000_000_000_000),
        default=DEFAULT_MAX_INPUT_BYTES,
        help=(
            "解压后输入的最大总字节数；超限时停止且不生成报告，"
            f"默认 {DEFAULT_MAX_INPUT_BYTES}，0 表示不限制。"
        ),
    )
    parser.add_argument(
        "--since",
        help="只纳入该 ISO-8601 时间之后的告警，建议携带时区偏移。",
    )
    parser.add_argument(
        "--until",
        help="只纳入该 ISO-8601 时间之前的告警，建议携带时区偏移。",
    )
    parser.add_argument(
        "--timezone",
        default="input",
        help=(
            "报告时间显示时区，如 Asia/Shanghai、Europe/London 或 UTC；"
            "默认 input，保留告警原始偏移。"
        ),
    )
    parser.add_argument(
        "--incident-window-minutes",
        type=bounded_int(1, 1_440),
        default=10,
        help="同源、同资产、同类别告警的关联窗口，默认 10 分钟。",
    )
    parser.add_argument(
        "--soc-only",
        action="store_true",
        help="排除普通会话和未分类噪声，保留认证、提权、FIM、漏洞、Agent 健康等 SOC 场景。",
    )
    parser.add_argument(
        "--strict",
        action="store_true",
        help="发现损坏/非对象 JSON、超长行或非法 UTF-8 时终止，不生成报告。",
    )
    parser.add_argument(
        "--version",
        action="version",
        version=f"%(prog)s {__version__}",
    )
    return parser


def _convert_timezone(alerts, timezone_name: str) -> None:
    if timezone_name.lower() == "input":
        return
    normalized = timezone_name.strip()
    if normalized.upper() in {"UTC", "Z"}:
        target = timezone.utc
    else:
        offset_match = re.fullmatch(r"([+-])(\d{2}):?(\d{2})", normalized)
        if offset_match:
            sign = 1 if offset_match.group(1) == "+" else -1
            hours = int(offset_match.group(2))
            minutes = int(offset_match.group(3))
            if hours > 23 or minutes > 59:
                raise ValueError(f"Invalid UTC offset: {timezone_name}")
            target = timezone(sign * timedelta(hours=hours, minutes=minutes))
        else:
            try:
                target = ZoneInfo(normalized)
            except ZoneInfoNotFoundError as error:
                # Windows Python may not ship an IANA timezone database. The
                # common lab timezone has no DST and is safe to represent as +08.
                if normalized in {"Asia/Shanghai", "Asia/Chongqing"}:
                    target = timezone(timedelta(hours=8), name=normalized)
                else:
                    raise ValueError(
                        f"Unknown timezone: {timezone_name}. Use input, UTC, "
                        "a fixed offset such as +08:00, or install tzdata."
                    ) from error
    for alert in alerts:
        if alert.event_time is None:
            continue
        alert.event_time = alert.event_time.astimezone(target)
        alert.timestamp = alert.event_time.isoformat(timespec="milliseconds")


def run(args: argparse.Namespace) -> tuple[list[Path], ParseStats, dict]:
    input_path = Path(args.input).expanduser()
    if not input_path.exists():
        raise FileNotFoundError(f"Input file does not exist: {input_path}")
    if not input_path.is_file():
        raise ValueError(f"Input path is not a file: {input_path}")

    output_dir = Path(args.output_dir).expanduser()
    try:
        input_resolved = input_path.resolve()
        if output_dir.exists():
            output_is_input = os.path.samefile(output_dir, input_path)
        else:
            output_is_input = output_dir.resolve() == input_resolved
        if output_is_input:
            raise ValueError("Output directory cannot be the input file")
        colliding_targets = [
            name
            for name in REPORT_FILENAMES
            if (
                os.path.samefile(output_dir / name, input_path)
                if (output_dir / name).exists()
                else (output_dir / name).resolve() == input_resolved
            )
        ]
        if colliding_targets:
            raise ValueError(
                "Input file would be overwritten by report output: "
                + ", ".join(colliding_targets)
            )
    except OSError as error:
        raise ValueError(
            "Unable to validate input/output path separation"
        ) from error

    since = normalize_filter_time(args.since)
    until = normalize_filter_time(args.until)
    if since and until and since > until:
        raise ValueError("--since must be earlier than or equal to --until")

    stats = ParseStats()
    alerts = load_and_normalize(
        input_path,
        stats,
        min_level=args.min_level,
        line_limit=args.limit,
        since=since,
        until=until,
        soc_only=args.soc_only,
        max_line_bytes=args.max_line_bytes,
        max_input_bytes=args.max_input_bytes,
    )
    if args.strict and (
        stats.malformed_json
        or stats.non_object_records
        or stats.oversized_lines
        or stats.encoding_errors
    ):
        raise ValueError(
            "Strict mode rejected the input: "
            f"{stats.malformed_json} malformed JSON and "
            f"{stats.non_object_records} non-object records and "
            f"{stats.oversized_lines} oversized lines and "
            f"{stats.encoding_errors} encoding errors"
        )

    _convert_timezone(alerts, args.timezone)
    result = analyze(alerts, args.incident_window_minutes)
    generated_at = datetime.now(timezone.utc).isoformat(timespec="seconds")
    context = {
        "title": args.title,
        "input_name": input_path.name,
        "input_path": str(input_path.resolve()),
        "output_path": str(output_dir.resolve()),
        "generated_at": generated_at,
        "model_version": __version__,
        "incident_window_minutes": args.incident_window_minutes,
        "timezone": args.timezone,
        "filters": {
            "min_level": args.min_level,
            "line_limit": args.limit,
            "max_line_bytes": args.max_line_bytes,
            "max_input_bytes": args.max_input_bytes,
            "since": args.since,
            "until": args.until,
            "soc_only": args.soc_only,
            "strict": args.strict,
        },
    }
    written = write_report_bundle(output_dir, result, stats, context)
    return written, stats, result.metrics


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        written, stats, metrics = run(args)
    except (OSError, ValueError) as error:
        print(f"Error: {error}", file=sys.stderr)
        return 2

    print(
        "Input summary: "
        f"lines={stats.total_lines}, valid={stats.parsed_records}, "
        f"bytes={stats.input_bytes}, truncated={stats.line_limit_reached}, "
        f"malformed={stats.malformed_json}, oversized={stats.oversized_lines}, "
        f"encoding_errors={stats.encoding_errors}, "
        f"duplicates={stats.duplicate_records}, "
        f"filtered={stats.filtered_by_level + stats.filtered_by_time + stats.filtered_by_scope}, "
        f"included={stats.included_alerts}"
    )
    print(
        "Analysis summary: "
        f"incidents={metrics['total_incidents']}, "
        f"critical={metrics['critical_incidents']}, high={metrics['high_incidents']}, "
        f"assets={metrics['asset_count']}, known_sources={metrics['source_ip_count']}"
    )
    if stats.line_limit_reached:
        print(
            "Warning: input contains additional lines beyond --limit; "
            "the report covers only the processed prefix.",
            file=sys.stderr,
        )
    print(f"Reports written to: {written[0].parent.resolve()}")
    for path in written:
        print(f"  - {path.name}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
