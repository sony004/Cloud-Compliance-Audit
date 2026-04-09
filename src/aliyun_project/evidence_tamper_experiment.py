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
    tampered_index: int
    evidence_id: str
    before_status: str
    after_status: str
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


def run_tamper_experiment(
    manifest_path: Path,
    report_dir: Path,
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

    from_status = from_status.upper().strip()
    to_status = to_status.upper().strip()
    if from_status != "FAIL":
        raise ValueError("This experiment currently supports from-status=FAIL only.")

    target_idx = _pick_fail_record_index(records)
    if target_idx is None:
        raise ValueError("No FAIL record found in manifest; cannot perform FAIL->PASS tamper experiment.")

    target = records[target_idx]
    evidence_id = str(target.get("evidence_id", "-"))
    before_status = str(target.get("status", ""))
    target["status"] = to_status

    # Write tampered content and verify.
    manifest_path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    after = verify_manifest(manifest_path)

    # Roll back to preserve dataset.
    manifest_path.write_text(original_text, encoding="utf-8")

    report_payload = {
        "timestamp_utc": datetime.now(timezone.utc).replace(microsecond=0).isoformat(),
        "manifest_path": str(manifest_path),
        "tamper_type": f"status:{from_status}->{to_status}",
        "tampered_index": target_idx,
        "evidence_id": evidence_id,
        "before_status": before_status,
        "after_status": to_status,
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

    report_path = report_dir / f"{manifest_path.stem}_tamper_fail_to_pass_report.json"
    report_path.write_text(json.dumps(report_payload, indent=2), encoding="utf-8")

    return TamperResult(
        manifest_path=manifest_path,
        tampered_index=target_idx,
        evidence_id=evidence_id,
        before_status=before_status,
        after_status=to_status,
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
        description="Inject FAIL->PASS tamper into evidence manifest, verify, and auto-rollback.",
    )
    parser.add_argument("--file", type=Path, help="Specific evidence manifest JSON file path.")
    parser.add_argument("--nist-dir", type=Path, default=DEFAULT_NIST_DIR)
    parser.add_argument("--report-dir", type=Path, default=DEFAULT_OUTPUT_DIR)
    args = parser.parse_args()

    manifest_path = args.file.resolve() if args.file else _latest_manifest(args.nist_dir.resolve())
    if not manifest_path or not manifest_path.exists():
        print("No evidence manifest found. Pass --file or run nist-map first.")
        return 1

    result = run_tamper_experiment(
        manifest_path=manifest_path,
        report_dir=args.report_dir.resolve(),
        from_status="FAIL",
        to_status="PASS",
    )

    print(f"Manifest: {result.manifest_path}")
    print(f"Tampered record index: {result.tampered_index}")
    print(f"Evidence ID: {result.evidence_id}")
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
