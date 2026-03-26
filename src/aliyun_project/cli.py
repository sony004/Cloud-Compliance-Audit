from __future__ import annotations

import argparse
import csv
import os
import subprocess
import sys
from collections import Counter
from pathlib import Path

from aliyun_project.nist_mapping import generate_nist_control_report

PROJECT_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_OUTPUT_DIR = PROJECT_ROOT / "output"
DEFAULT_COMPLIANCE = "cis_2.0_alibabacloud"
DEFAULT_CHECKS_FILE = PROJECT_ROOT / "rules" / "checks" / "alibabacloud_all_checks.json"
DEFAULT_NIST_MAPPING_FILE = (
    PROJECT_ROOT / "rules" / "mappings" / "nist_800_53_rev5_alibabacloud.json"
)


def _load_env_file(env_path: Path) -> None:
    if not env_path.exists():
        return

    for raw_line in env_path.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue

        key, value = line.split("=", 1)
        key = key.strip()
        value = value.strip().strip("\"").strip("'")
        if key and key not in os.environ:
            os.environ[key] = value


def _build_prowler_cmd(args: argparse.Namespace, passthrough: list[str]) -> list[str]:
    cmd = [sys.executable, "-m", "prowler", "alibabacloud"]

    if args.list_compliance:
        cmd.append("--list-compliance")
        return cmd + passthrough

    if args.checks_file:
        cmd.extend(["--checks-file", str(args.checks_file.resolve())])
    else:
        cmd.extend(["--compliance", args.compliance])

    if args.region:
        cmd.extend(["--region", *args.region])

    cmd.extend(["--output-directory", str(args.output_dir.resolve())])

    if args.output_formats:
        cmd.extend(["--output-formats", *args.output_formats])

    if args.ignore_exit_code_3:
        cmd.append("--ignore-exit-code-3")

    if args.verbose:
        cmd.append("--verbose")

    if args.log_level:
        cmd.extend(["--log-level", args.log_level])

    if args.no_banner:
        cmd.append("--no-banner")

    return cmd + passthrough


def _run_scan(args: argparse.Namespace, passthrough: list[str]) -> int:
    _load_env_file(args.env_file)

    cmd = _build_prowler_cmd(args, passthrough)

    if not args.list_compliance:
        if not os.getenv("ALIBABA_CLOUD_ACCESS_KEY_ID"):
            print(
                "Missing ALIBABA_CLOUD_ACCESS_KEY_ID (set env var or aliyun/.env).",
                file=sys.stderr,
            )
            return 2

        if not os.getenv("ALIBABA_CLOUD_ACCESS_KEY_SECRET"):
            print(
                "Missing ALIBABA_CLOUD_ACCESS_KEY_SECRET (set env var or aliyun/.env).",
                file=sys.stderr,
            )
            return 2

        args.output_dir.mkdir(parents=True, exist_ok=True)

    print("Running:")
    print(" ".join(cmd))
    completed = subprocess.run(cmd, cwd=PROJECT_ROOT)
    return completed.returncode


def _latest_compliance_csv(output_dir: Path) -> Path | None:
    compliance_dir = output_dir / "compliance"
    if not compliance_dir.exists():
        return None

    candidates = sorted(
        compliance_dir.glob("*_alibabacloud.csv"),
        key=lambda p: p.stat().st_mtime,
        reverse=True,
    )
    return candidates[0] if candidates else None


def _latest_scan_csv(output_dir: Path) -> Path | None:
    if not output_dir.exists():
        return None

    candidates = sorted(
        [p for p in output_dir.glob("prowler-output-*.csv") if "_alibabacloud" not in p.stem],
        key=lambda p: p.stat().st_mtime,
        reverse=True,
    )
    return candidates[0] if candidates else None


def _summarize(args: argparse.Namespace) -> int:
    csv_path = Path(args.file) if args.file else _latest_compliance_csv(args.output_dir)
    if not csv_path or not csv_path.exists():
        print("No compliance CSV found. Run a scan first or pass --file.", file=sys.stderr)
        return 1

    with csv_path.open("r", encoding="utf-8", newline="") as fp:
        reader = csv.DictReader(fp, delimiter=";")
        rows = list(reader)

    if not rows:
        print(f"Empty report: {csv_path}")
        return 1

    status_counts = Counter(row.get("STATUS", "UNKNOWN") for row in rows)
    fail_rows = [row for row in rows if row.get("STATUS") == "FAIL"]

    print(f"Report: {csv_path}")
    print(f"Total: {len(rows)}")
    print("Status counts:")
    for status in sorted(status_counts):
        print(f"  {status}: {status_counts[status]}")

    if fail_rows:
        print("\nTop FAIL items:")
        for row in fail_rows[: args.top]:
            req_id = row.get("REQUIREMENTS_ID", "-")
            check_id = row.get("CHECKID", "-")
            desc = row.get("REQUIREMENTS_DESCRIPTION", "")
            print(f"  [{req_id}] {check_id} - {desc}")

    return 0


def _map_nist(args: argparse.Namespace) -> int:
    csv_path = Path(args.file) if args.file else _latest_scan_csv(args.output_dir)
    if not csv_path:
        csv_path = _latest_compliance_csv(args.output_dir)

    if not csv_path or not csv_path.exists():
        print("No report CSV found. Run a scan first or pass --file.", file=sys.stderr)
        return 1

    mapping_file = args.mapping_file.resolve()
    if not mapping_file.exists():
        print(f"Mapping file not found: {mapping_file}", file=sys.stderr)
        return 1

    try:
        result = generate_nist_control_report(
            source_csv=csv_path,
            mapping_file=mapping_file,
            report_dir=args.report_dir.resolve(),
            top=args.top,
        )
    except ValueError as exc:
        print(str(exc), file=sys.stderr)
        return 1

    print(f"Source report: {result.source_csv}")
    print(f"NIST summary CSV: {result.summary_csv}")
    print(f"NIST details CSV: {result.details_csv}")
    print(f"NIST summary JSON: {result.summary_json}")
    print(f"Rows: {result.total_rows}")
    print(f"Mapped rows: {result.mapped_rows}")
    print(f"Unmapped rows: {result.unmapped_rows}")
    print(f"Mapped controls: {result.control_count}")
    print("Status counts:")
    for status in sorted(result.status_counts):
        print(f"  {status}: {result.status_counts[status]}")

    if result.top_failed_controls:
        print("\nTop controls by FAIL count:")
        for control_id, fail_count in result.top_failed_controls:
            print(f"  {control_id}: {fail_count}")

    return 0


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="aliyun-audit",
        description="Standalone Alibaba Cloud audit flow powered by Prowler",
    )

    subparsers = parser.add_subparsers(dest="command", required=True)

    scan = subparsers.add_parser("scan", help="Run Alibaba Cloud compliance scan")
    scan.add_argument("--compliance", default=DEFAULT_COMPLIANCE)
    scan.add_argument("--checks-file", type=Path, help="Run checks from a local JSON file")
    scan.add_argument(
        "--use-local-checks",
        action="store_true",
        help="Use rules/checks/alibabacloud_all_checks.json",
    )
    scan.add_argument("--region", nargs="+", help="Alibaba Cloud regions (e.g., cn-beijing)")
    scan.add_argument("--output-dir", type=Path, default=DEFAULT_OUTPUT_DIR)
    scan.add_argument(
        "--output-formats",
        nargs="+",
        default=["csv", "html", "json-ocsf"],
        help="Prowler output formats",
    )
    scan.add_argument("--env-file", type=Path, default=PROJECT_ROOT / ".env")
    scan.add_argument(
        "--ignore-exit-code-3",
        action="store_true",
        help="Do not fail the command when findings exist (Prowler exit code 3).",
    )
    scan.add_argument("--verbose", action="store_true")
    scan.add_argument("--log-level", choices=["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"])
    scan.add_argument("--no-banner", action="store_true")
    scan.add_argument("--list-compliance", action="store_true", help="List all compliances")

    summary = subparsers.add_parser("summary", help="Summarize latest Alibaba Cloud compliance CSV")
    summary.add_argument("--output-dir", type=Path, default=DEFAULT_OUTPUT_DIR)
    summary.add_argument("--file", help="Path to a specific compliance CSV")
    summary.add_argument("--top", type=int, default=10)

    nist = subparsers.add_parser("nist-map", help="Map scan findings to NIST SP 800-53 controls")
    nist.add_argument("--output-dir", type=Path, default=DEFAULT_OUTPUT_DIR)
    nist.add_argument("--file", help="Path to a specific scan/compliance CSV")
    nist.add_argument("--mapping-file", type=Path, default=DEFAULT_NIST_MAPPING_FILE)
    nist.add_argument("--report-dir", type=Path, default=DEFAULT_OUTPUT_DIR / "nist")
    nist.add_argument("--top", type=int, default=10)

    return parser


def main() -> int:
    parser = _parser()
    args, passthrough = parser.parse_known_args()

    if args.command == "scan":
        if args.use_local_checks and not args.checks_file:
            args.checks_file = DEFAULT_CHECKS_FILE
        return _run_scan(args, passthrough)

    if args.command == "summary":
        return _summarize(args)

    if args.command == "nist-map":
        return _map_nist(args)

    parser.print_help()
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
