from __future__ import annotations

import argparse
import hashlib
import json
from dataclasses import dataclass
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_NIST_DIR = PROJECT_ROOT / "output" / "nist"


@dataclass
class VerifyResult:
    manifest_path: Path
    records: int
    payload_mismatch: int
    chain_mismatch: int
    root_match: bool
    computed_root: str
    stored_root: str


def _sha256_text(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _latest_manifest(nist_dir: Path) -> Path | None:
    if not nist_dir.exists():
        return None
    candidates = sorted(
        nist_dir.glob("*_nist80053_evidence_manifest.json"),
        key=lambda p: p.stat().st_mtime,
        reverse=True,
    )
    return candidates[0] if candidates else None


def _canonical_payload(record: dict) -> str:
    payload = {
        "check_id": record.get("check_id", ""),
        "status": record.get("status", ""),
        "resource_uid": record.get("resource_uid", ""),
        "resource_name": record.get("resource_name", ""),
        "region": record.get("region", ""),
        "timestamp": record.get("timestamp", ""),
        "finding_uid": record.get("finding_uid", ""),
        "evidence": record.get("evidence", ""),
        "source_csv": record.get("source_csv", ""),
    }
    return json.dumps(payload, sort_keys=True, separators=(",", ":"))


def verify_manifest(manifest_path: Path) -> VerifyResult:
    payload = json.loads(manifest_path.read_text(encoding="utf-8-sig"))
    records = payload.get("records", [])
    stored_root = str(payload.get("chain_root_hash", ""))

    payload_mismatch = 0
    chain_mismatch = 0
    previous = "GENESIS"

    for idx, record in enumerate(records):
        canonical_json = _canonical_payload(record)
        calc_payload_sha = _sha256_text(canonical_json)
        if calc_payload_sha != record.get("payload_sha256", ""):
            payload_mismatch += 1
            print(f"[PAYLOAD_MISMATCH] index={idx} evidence_id={record.get('evidence_id', '-')}")

        # Use recomputed payload hash to ensure tampered records trigger chain drift downstream.
        calc_chain = _sha256_text(f"{previous}|{calc_payload_sha}")
        if calc_chain != record.get("chain_hash", ""):
            chain_mismatch += 1
            print(f"[CHAIN_MISMATCH] index={idx} evidence_id={record.get('evidence_id', '-')}")
        previous = calc_chain

    computed_root = previous
    root_match = computed_root == stored_root
    return VerifyResult(
        manifest_path=manifest_path,
        records=len(records),
        payload_mismatch=payload_mismatch,
        chain_mismatch=chain_mismatch,
        root_match=root_match,
        computed_root=computed_root,
        stored_root=stored_root,
    )


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="verify-evidence-chain",
        description="Verify payload and hash-chain integrity for NIST evidence manifest.",
    )
    parser.add_argument("--file", type=Path, help="Specific evidence manifest JSON file path.")
    parser.add_argument(
        "--nist-dir",
        type=Path,
        default=DEFAULT_NIST_DIR,
        help="Directory to auto-detect latest evidence manifest if --file is omitted.",
    )
    return parser


def main() -> int:
    parser = _parser()
    args = parser.parse_args()

    manifest_path = args.file.resolve() if args.file else _latest_manifest(args.nist_dir.resolve())
    if not manifest_path or not manifest_path.exists():
        print("No evidence manifest found. Pass --file or run nist-map first.")
        return 1

    result = verify_manifest(manifest_path)
    print(f"Manifest: {result.manifest_path}")
    print(f"Records: {result.records}")
    print(f"Payload mismatches: {result.payload_mismatch}")
    print(f"Chain mismatches: {result.chain_mismatch}")
    print(f"Computed root: {result.computed_root}")
    print(f"Stored root: {result.stored_root}")
    print(f"Root match: {result.root_match}")

    return 0 if result.payload_mismatch == 0 and result.chain_mismatch == 0 and result.root_match else 2


if __name__ == "__main__":
    raise SystemExit(main())
