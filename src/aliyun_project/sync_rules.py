from __future__ import annotations

import argparse
import json
import shutil
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[2]
RULES_ROOT = PROJECT_ROOT / "rules"


def _resolve_prowler_root(source_root: str | None) -> Path:
    if source_root:
        src = Path(source_root).resolve()
        candidate = src / "prowler"
        return candidate if candidate.exists() else src

    import prowler  # pylint: disable=import-outside-toplevel

    return Path(prowler.__file__).resolve().parent


def _copy_compliance_files(prowler_root: Path, target_root: Path) -> int:
    src_dir = prowler_root / "compliance" / "alibabacloud"
    dst_dir = target_root / "compliance" / "alibabacloud"
    dst_dir.mkdir(parents=True, exist_ok=True)

    copied = 0
    for src_file in sorted(src_dir.glob("*.json")):
        shutil.copy2(src_file, dst_dir / src_file.name)
        copied += 1
    return copied


def _collect_all_checks(prowler_root: Path) -> list[str]:
    services_dir = prowler_root / "providers" / "alibabacloud" / "services"
    checks: set[str] = set()

    for metadata_file in services_dir.rglob("*.metadata.json"):
        checks.add(metadata_file.stem.replace(".metadata", ""))

    return sorted(checks)


def _collect_cis_checks(prowler_root: Path) -> list[str]:
    cis_file = prowler_root / "compliance" / "alibabacloud" / "cis_2.0_alibabacloud.json"
    payload = json.loads(cis_file.read_text(encoding="utf-8"))

    checks: set[str] = set()
    for requirement in payload.get("Requirements", []):
        for check in requirement.get("Checks", []):
            if check:
                checks.add(check)

    return sorted(checks)


def _write_checks_file(path: Path, checks: list[str]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = {"alibabacloud": checks}
    path.write_text(json.dumps(payload, indent=2), encoding="utf-8")


def run(source_root: str | None, rules_root: Path) -> int:
    prowler_root = _resolve_prowler_root(source_root)

    copied = _copy_compliance_files(prowler_root, rules_root)
    all_checks = _collect_all_checks(prowler_root)
    cis_checks = _collect_cis_checks(prowler_root)

    _write_checks_file(rules_root / "checks" / "alibabacloud_all_checks.json", all_checks)
    _write_checks_file(
        rules_root / "checks" / "cis_2.0_alibabacloud_checks.json",
        cis_checks,
    )

    print(f"Prowler source: {prowler_root}")
    print(f"Compliance files copied: {copied}")
    print(f"All checks generated: {len(all_checks)}")
    print(f"CIS checks generated: {len(cis_checks)}")
    print(f"Rules directory: {rules_root}")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(
        prog="aliyun-sync-rules",
        description="Refresh local Alibaba Cloud compliance/checks files from Prowler",
    )
    parser.add_argument(
        "--source-root",
        help="Optional Prowler source root. If omitted, use installed 'prowler' package.",
    )
    parser.add_argument(
        "--rules-root",
        type=Path,
        default=RULES_ROOT,
        help="Destination rules directory (default: ./rules)",
    )
    args = parser.parse_args()

    return run(args.source_root, args.rules_root.resolve())


if __name__ == "__main__":
    raise SystemExit(main())
