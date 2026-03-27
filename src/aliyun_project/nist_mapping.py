from __future__ import annotations

import csv
import hashlib
import json
from collections import Counter, defaultdict
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path


@dataclass
class NistMapResult:
    source_csv: Path
    summary_csv: Path
    details_csv: Path
    summary_json: Path
    evidence_manifest_json: Path
    control_evidence_index_csv: Path
    total_rows: int
    mapped_rows: int
    unmapped_rows: int
    control_count: int
    evidence_count: int
    status_counts: dict[str, int]
    top_failed_controls: list[tuple[str, int]]


def _read_csv_rows(csv_path: Path) -> list[dict[str, str]]:
    with csv_path.open("r", encoding="utf-8", newline="") as fp:
        reader = csv.DictReader(fp, delimiter=";")
        return list(reader)


def _normalize_status(raw: str | None) -> str:
    if not raw:
        return "UNKNOWN"
    status = raw.strip().upper()
    return status if status in {"PASS", "FAIL", "MANUAL"} else "UNKNOWN"


def _resolve_check_id(row: dict[str, str]) -> str:
    return (row.get("CHECK_ID") or row.get("CHECKID") or "").strip()


def _load_mapping(mapping_file: Path) -> dict:
    return json.loads(mapping_file.read_text(encoding="utf-8"))


def _lookup_mapping(check_id: str, mapping_doc: dict) -> dict | None:
    explicit = mapping_doc.get("check_mappings", {})
    if check_id in explicit:
        return explicit[check_id]

    for rule in mapping_doc.get("prefix_mappings", []):
        prefix = rule.get("prefix", "")
        if prefix and check_id.startswith(prefix):
            return rule
    return None


def _build_evidence(row: dict[str, str], evidence_keys: list[str]) -> str:
    chunks: list[str] = []
    for key in evidence_keys:
        value = (row.get(key) or "").strip()
        if value:
            chunks.append(f"{key}={value}")
    return " | ".join(chunks)


def _sha256_text(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _build_evidence_record(
    row: dict[str, str],
    check_id: str,
    status: str,
    evidence: str,
    source_csv: Path,
    mapping_file: Path,
    collected_at: str,
) -> dict[str, str]:
    resource_uid = (row.get("RESOURCE_UID") or row.get("RESOURCEID") or "").strip()
    resource_name = (row.get("RESOURCE_NAME") or row.get("RESOURCENAME") or "").strip()
    region = (row.get("REGION") or "").strip()
    timestamp = (row.get("TIMESTAMP") or row.get("ASSESSMENTDATE") or "").strip()
    finding_uid = (row.get("FINDING_UID") or "").strip()

    canonical_payload = {
        "check_id": check_id,
        "status": status,
        "resource_uid": resource_uid,
        "resource_name": resource_name,
        "region": region,
        "timestamp": timestamp,
        "finding_uid": finding_uid,
        "evidence": evidence,
        "source_csv": str(source_csv),
    }
    payload_json = json.dumps(canonical_payload, sort_keys=True, separators=(",", ":"))
    evidence_id = _sha256_text(payload_json)

    return {
        "evidence_id": evidence_id,
        "source_csv": str(source_csv),
        "mapping_file": str(mapping_file),
        "collector_version": "nist-map-v1",
        "collected_at_utc": collected_at,
        "check_id": check_id,
        "status": status,
        "resource_uid": resource_uid,
        "resource_name": resource_name,
        "region": region,
        "timestamp": timestamp,
        "finding_uid": finding_uid,
        "evidence": evidence,
        "evidence_sha256": _sha256_text(evidence),
        "payload_sha256": _sha256_text(payload_json),
    }


def generate_nist_control_report(
    source_csv: Path,
    mapping_file: Path,
    report_dir: Path,
    top: int = 10,
) -> NistMapResult:
    rows = _read_csv_rows(source_csv)
    if not rows:
        raise ValueError(f"Input report is empty: {source_csv}")

    mapping_doc = _load_mapping(mapping_file)
    control_catalog = mapping_doc.get("control_catalog", {})
    default_evidence_keys = mapping_doc.get("default_evidence_keys", [])

    details: list[dict[str, str]] = []
    control_status_counts: dict[str, Counter] = defaultdict(Counter)
    control_check_ids: dict[str, set[str]] = defaultdict(set)
    control_strengths: dict[str, set[str]] = defaultdict(set)
    control_evidence_ids: dict[str, set[str]] = defaultdict(set)
    evidence_records: dict[str, dict[str, str]] = {}
    mapped_rows = 0
    unmapped_rows = 0
    status_counts: Counter = Counter()
    collected_at = datetime.now(timezone.utc).replace(microsecond=0).isoformat()

    for row in rows:
        check_id = _resolve_check_id(row)
        status = _normalize_status(row.get("STATUS"))
        status_counts[status] += 1
        mapping = _lookup_mapping(check_id, mapping_doc) if check_id else None

        if not mapping:
            unmapped_rows += 1
            continue

        mapped_rows += 1
        primary = mapping.get("primary_control")
        secondary = mapping.get("secondary_controls", [])
        controls = [control for control in [primary, *secondary] if control]
        if not controls:
            unmapped_rows += 1
            mapped_rows -= 1
            continue

        evidence_keys = mapping.get("evidence_keys", default_evidence_keys)
        evidence = _build_evidence(row, evidence_keys)
        mapping_strength = mapping.get("mapping_strength", "partial")
        rationale = mapping.get("rationale", "")
        evidence_record = _build_evidence_record(
            row=row,
            check_id=check_id,
            status=status,
            evidence=evidence,
            source_csv=source_csv,
            mapping_file=mapping_file,
            collected_at=collected_at,
        )
        evidence_id = evidence_record["evidence_id"]
        evidence_records[evidence_id] = evidence_record

        for idx, control_id in enumerate(controls):
            control_name = control_catalog.get(control_id, "Unknown control")
            control_status_counts[control_id][status] += 1
            control_check_ids[control_id].add(check_id)
            control_strengths[control_id].add(mapping_strength)
            control_evidence_ids[control_id].add(evidence_id)

            details.append(
                {
                    "CONTROL_ID": control_id,
                    "CONTROL_NAME": control_name,
                    "MAPPING_LEVEL": "primary" if idx == 0 else "secondary",
                    "MAPPING_STRENGTH": mapping_strength,
                    "CHECK_ID": check_id,
                    "STATUS": status,
                    "RESOURCE_UID": (row.get("RESOURCE_UID") or row.get("RESOURCEID") or "").strip(),
                    "RESOURCE_NAME": (row.get("RESOURCE_NAME") or row.get("RESOURCENAME") or "").strip(),
                    "REGION": (row.get("REGION") or "").strip(),
                    "TIMESTAMP": (row.get("TIMESTAMP") or row.get("ASSESSMENTDATE") or "").strip(),
                    "RATIONALE": rationale,
                    "EVIDENCE_ID": evidence_id,
                    "EVIDENCE": evidence,
                }
            )

    summary_rows: list[dict[str, str]] = []
    for control_id in sorted(control_status_counts):
        counts = control_status_counts[control_id]
        total = sum(counts.values())
        summary_rows.append(
            {
                "CONTROL_ID": control_id,
                "CONTROL_NAME": control_catalog.get(control_id, "Unknown control"),
                "TOTAL": str(total),
                "PASS": str(counts.get("PASS", 0)),
                "FAIL": str(counts.get("FAIL", 0)),
                "MANUAL": str(counts.get("MANUAL", 0)),
                "UNKNOWN": str(counts.get("UNKNOWN", 0)),
                "MAPPING_STRENGTHS": ", ".join(sorted(control_strengths[control_id])),
                "CHECK_IDS": ", ".join(sorted(control_check_ids[control_id])),
            }
        )

    report_dir.mkdir(parents=True, exist_ok=True)
    stem = source_csv.stem
    summary_csv = report_dir / f"{stem}_nist80053_control_summary.csv"
    details_csv = report_dir / f"{stem}_nist80053_control_details.csv"
    summary_json = report_dir / f"{stem}_nist80053_control_summary.json"
    evidence_manifest_json = report_dir / f"{stem}_nist80053_evidence_manifest.json"
    control_evidence_index_csv = report_dir / f"{stem}_nist80053_control_evidence_index.csv"

    with summary_csv.open("w", encoding="utf-8", newline="") as fp:
        writer = csv.DictWriter(
            fp,
            fieldnames=[
                "CONTROL_ID",
                "CONTROL_NAME",
                "TOTAL",
                "PASS",
                "FAIL",
                "MANUAL",
                "UNKNOWN",
                "MAPPING_STRENGTHS",
                "CHECK_IDS",
            ],
            delimiter=";",
        )
        writer.writeheader()
        writer.writerows(summary_rows)

    with details_csv.open("w", encoding="utf-8", newline="") as fp:
        writer = csv.DictWriter(
            fp,
            fieldnames=[
                "CONTROL_ID",
                "CONTROL_NAME",
                "MAPPING_LEVEL",
                "MAPPING_STRENGTH",
                "CHECK_ID",
                "STATUS",
                "RESOURCE_UID",
                "RESOURCE_NAME",
                "REGION",
                "TIMESTAMP",
                "RATIONALE",
                "EVIDENCE_ID",
                "EVIDENCE",
            ],
            delimiter=";",
        )
        writer.writeheader()
        writer.writerows(details)

    control_evidence_rows: list[dict[str, str]] = []
    for control_id in sorted(control_evidence_ids):
        evidence_ids = sorted(control_evidence_ids[control_id])
        control_evidence_rows.append(
            {
                "CONTROL_ID": control_id,
                "CONTROL_NAME": control_catalog.get(control_id, "Unknown control"),
                "EVIDENCE_COUNT": str(len(evidence_ids)),
                "EVIDENCE_IDS": ", ".join(evidence_ids),
            }
        )

    with control_evidence_index_csv.open("w", encoding="utf-8", newline="") as fp:
        writer = csv.DictWriter(
            fp,
            fieldnames=["CONTROL_ID", "CONTROL_NAME", "EVIDENCE_COUNT", "EVIDENCE_IDS"],
            delimiter=";",
        )
        writer.writeheader()
        writer.writerows(control_evidence_rows)

    ordered_evidence = []
    previous_chain_hash = "GENESIS"
    for evidence_id in sorted(evidence_records):
        record = dict(evidence_records[evidence_id])
        chain_input = f"{previous_chain_hash}|{record['payload_sha256']}"
        chain_hash = _sha256_text(chain_input)
        record["chain_prev_hash"] = previous_chain_hash
        record["chain_hash"] = chain_hash
        ordered_evidence.append(record)
        previous_chain_hash = chain_hash

    failed_controls = sorted(
        (
            (control_id, counts.get("FAIL", 0))
            for control_id, counts in control_status_counts.items()
            if counts.get("FAIL", 0) > 0
        ),
        key=lambda item: item[1],
        reverse=True,
    )

    payload = {
        "framework": mapping_doc.get("framework"),
        "framework_version": mapping_doc.get("framework_version"),
        "provider": mapping_doc.get("provider"),
        "source_csv": str(source_csv),
        "mapping_file": str(mapping_file),
        "total_rows": len(rows),
        "mapped_rows": mapped_rows,
        "unmapped_rows": unmapped_rows,
        "control_count": len(summary_rows),
        "evidence_count": len(ordered_evidence),
        "status_counts": dict(status_counts),
        "top_failed_controls": [
            {
                "control_id": control_id,
                "control_name": control_catalog.get(control_id, "Unknown control"),
                "fail_count": fail_count,
            }
            for control_id, fail_count in failed_controls[:top]
        ],
    }
    summary_json.write_text(json.dumps(payload, indent=2), encoding="utf-8")

    evidence_manifest_payload = {
        "framework": mapping_doc.get("framework"),
        "framework_version": mapping_doc.get("framework_version"),
        "provider": mapping_doc.get("provider"),
        "source_csv": str(source_csv),
        "mapping_file": str(mapping_file),
        "collected_at_utc": collected_at,
        "collector_version": "nist-map-v1",
        "evidence_count": len(ordered_evidence),
        "chain_root_hash": previous_chain_hash,
        "records": ordered_evidence,
    }
    evidence_manifest_json.write_text(json.dumps(evidence_manifest_payload, indent=2), encoding="utf-8")

    return NistMapResult(
        source_csv=source_csv,
        summary_csv=summary_csv,
        details_csv=details_csv,
        summary_json=summary_json,
        evidence_manifest_json=evidence_manifest_json,
        control_evidence_index_csv=control_evidence_index_csv,
        total_rows=len(rows),
        mapped_rows=mapped_rows,
        unmapped_rows=unmapped_rows,
        control_count=len(summary_rows),
        evidence_count=len(ordered_evidence),
        status_counts=dict(status_counts),
        top_failed_controls=failed_controls[:top],
    )
