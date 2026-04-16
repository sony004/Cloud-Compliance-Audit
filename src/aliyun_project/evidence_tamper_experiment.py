from __future__ import annotations

import argparse
import json
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

from aliyun_project.verify_evidence_chain import verify_manifest

PROJECT_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_NIST_DIR = PROJECT_ROOT / "output" / "nist"
DEFAULT_OUTPUT_DIR = PROJECT_ROOT / "output" / "analysis" / "evidence_tamper"


@dataclass
class TamperResult:
    manifest_path: Path
    tamper_type: str
    tampered_index: int | None
    evidence_id: str
    before_status: str | None
    after_status: str | None
    before_root_match: bool
    after_root_match: bool
    after_payload_mismatch: int
    after_chain_mismatch: int
    rollback_done: bool
    report_path: Path


def _latest_manifest(nist_dir: Path) -> Path | None:
    if not nist_dir.exists():
        return None
    candidates = sorted(
        nist_dir.glob("*_nist80053_evidence_manifest.json"),
        key=lambda p: p.stat().st_mtime,
        reverse=True,
    )
    return candidates[0] if candidates else None


def _pick_fail_record_index(records: list[dict]) -> int | None:
    for idx, record in enumerate(records):
        if str(record.get("status", "")).upper() == "FAIL":
            return idx
    return None


def _tamper_status_fail_to_pass(records: list[dict], to_status: str) -> tuple[int, str, str, str]:
    target_idx = _pick_fail_record_index(records)
    if target_idx is None:
        raise ValueError("No FAIL record found in manifest; cannot perform FAIL->PASS tamper experiment.")

    target = records[target_idx]
    evidence_id = str(target.get("evidence_id", "-"))
    before_status = str(target.get("status", ""))
    target["status"] = to_status
    return target_idx, evidence_id, before_status, to_status


def _tamper_add_record(records: list[dict]) -> tuple[int, str]:
    if not records:
        raise ValueError("Manifest has no records; cannot perform add-record tamper experiment.")

    source = dict(records[0])
    source["evidence_id"] = f"{source.get('evidence_id', 'evidence')}_forged"
    records.append(source)
    return len(records) - 1, str(source.get("evidence_id", "-"))


def _tamper_delete_record(records: list[dict]) -> tuple[int, str]:
    if not records:
        raise ValueError("Manifest has no records; cannot perform delete-record tamper experiment.")

    removed = records.pop(0)
    return 0, str(removed.get("evidence_id", "-"))


def _tamper_reorder_records(records: list[dict]) -> tuple[int, str]:
    if len(records) < 2:
        raise ValueError("Manifest has fewer than 2 records; cannot perform reorder-records tamper experiment.")

    first = records.pop(0)
    records.append(first)
    moved_idx = len(records) - 1
    return moved_idx, str(first.get("evidence_id", "-"))


def run_tamper_experiment(
    manifest_path: Path,
    report_dir: Path,
    tamper_mode: str = "status_fail_to_pass",
    from_status: str = "FAIL",
    to_status: str = "PASS",
) -> TamperResult:
    report_dir.mkdir(parents=True, exist_ok=True)
    original_text = manifest_path.read_text(encoding="utf-8-sig")

    before = verify_manifest(manifest_path)
    payload = json.loads(original_text)
    records = payload.get("records", [])
    if not records:
        raise ValueError("Manifest has no records.")

    tamper_mode = tamper_mode.strip().lower()
    target_idx: int | None = None
    evidence_id = "-"
    before_status: str | None = None
    after_status: str | None = None
    tamper_type = tamper_mode

    if tamper_mode == "status_fail_to_pass":
        from_status = from_status.upper().strip()
        to_status = to_status.upper().strip()
        if from_status != "FAIL":
            raise ValueError("status_fail_to_pass mode currently supports from-status=FAIL only.")
        target_idx, evidence_id, before_status, after_status = _tamper_status_fail_to_pass(
            records, to_status
        )
        tamper_type = f"status:{from_status}->{to_status}"
    elif tamper_mode == "add_record":
        target_idx, evidence_id = _tamper_add_record(records)
    elif tamper_mode == "delete_record":
        target_idx, evidence_id = _tamper_delete_record(records)
    elif tamper_mode == "reorder_records":
        target_idx, evidence_id = _tamper_reorder_records(records)
    else:
        raise ValueError(
            "Unsupported tamper mode. Use one of: "
            "status_fail_to_pass, add_record, delete_record, reorder_records."
        )

    # Write tampered content and verify.
    manifest_path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    after = verify_manifest(manifest_path)

    # Roll back to preserve dataset.
    manifest_path.write_text(original_text, encoding="utf-8")

    report_payload = {
        "timestamp_utc": datetime.now(timezone.utc).replace(microsecond=0).isoformat(),
        "manifest_path": str(manifest_path),
        "tamper_type": tamper_type,
        "tampered_index": target_idx,
        "evidence_id": evidence_id,
        "before_status": before_status,
        "after_status": after_status,
        "before_verify": {
            "payload_mismatch": before.payload_mismatch,
            "chain_mismatch": before.chain_mismatch,
            "root_match": before.root_match,
        },
        "after_verify": {
            "payload_mismatch": after.payload_mismatch,
            "chain_mismatch": after.chain_mismatch,
            "root_match": after.root_match,
        },
        "rollback_done": True,
        "expected": "after_verify should show mismatch and root_match=False",
    }

    report_path = report_dir / f"{manifest_path.stem}_tamper_{tamper_mode}_report.json"
    report_path.write_text(json.dumps(report_payload, indent=2), encoding="utf-8")

    return TamperResult(
        manifest_path=manifest_path,
        tamper_type=tamper_type,
        tampered_index=target_idx,
        evidence_id=evidence_id,
        before_status=before_status,
        after_status=after_status,
        before_root_match=before.root_match,
        after_root_match=after.root_match,
        after_payload_mismatch=after.payload_mismatch,
        after_chain_mismatch=after.chain_mismatch,
        rollback_done=True,
        report_path=report_path,
    )


def main() -> int:
    parser = argparse.ArgumentParser(
        prog="evidence-tamper-experiment",
        description="Inject tamper into evidence manifest, verify, and auto-rollback.",
    )
    parser.add_argument("--file", type=Path, help="Specific evidence manifest JSON file path.")
    parser.add_argument("--nist-dir", type=Path, default=DEFAULT_NIST_DIR)
    parser.add_argument("--report-dir", type=Path, default=DEFAULT_OUTPUT_DIR)
    parser.add_argument(
        "--mode",
        choices=["status_fail_to_pass", "add_record", "delete_record", "reorder_records"],
        default="status_fail_to_pass",
        help="Tamper mode.",
    )
    args = parser.parse_args()

    manifest_path = args.file.resolve() if args.file else _latest_manifest(args.nist_dir.resolve())
    if not manifest_path or not manifest_path.exists():
        print("No evidence manifest found. Pass --file or run nist-map first.")
        return 1

    result = run_tamper_experiment(
        manifest_path=manifest_path,
        report_dir=args.report_dir.resolve(),
        tamper_mode=args.mode,
        from_status="FAIL",
        to_status="PASS",
    )

    print(f"Manifest: {result.manifest_path}")
    print(f"Tamper type: {result.tamper_type}")
    print(f"Tampered record index: {result.tampered_index}")
    print(f"Evidence ID: {result.evidence_id}")
    if result.before_status is not None or result.after_status is not None:
        print(f"Status change: {result.before_status} -> {result.after_status}")
    print(f"Before root match: {result.before_root_match}")
    print(f"After root match: {result.after_root_match}")
    print(f"After payload mismatch: {result.after_payload_mismatch}")
    print(f"After chain mismatch: {result.after_chain_mismatch}")
    print(f"Rollback done: {result.rollback_done}")
    print(f"Report: {result.report_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
