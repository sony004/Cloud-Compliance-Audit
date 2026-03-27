from __future__ import annotations

import csv
import json
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path


@dataclass
class ContinuousComplianceResult:
    snapshot_json: Path
    diff_csv: Path
    diff_json: Path
    trend_csv: Path
    compared_with_snapshot: str | None
    control_count: int
    new_fail_count: int
    fixed_count: int
    status_changed_count: int


def _read_summary_csv(summary_csv: Path) -> list[dict[str, str]]:
    with summary_csv.open("r", encoding="utf-8", newline="") as fp:
        reader = csv.DictReader(fp, delimiter=";")
        return list(reader)


def _to_int(value: str | None) -> int:
    try:
        return int(value or "0")
    except ValueError:
        return 0


def _control_status(pass_count: int, fail_count: int, manual_count: int, unknown_count: int) -> str:
    if fail_count > 0:
        return "FAIL"
    if manual_count > 0:
        return "MANUAL"
    if unknown_count > 0:
        return "UNKNOWN"
    if pass_count > 0:
        return "PASS"
    return "UNKNOWN"


def _status_change_type(previous: str | None, current: str) -> str:
    if previous is None:
        return "new_control"
    if previous == current:
        return "unchanged"
    if previous != "FAIL" and current == "FAIL":
        return "new_fail"
    if previous == "FAIL" and current != "FAIL":
        return "fixed"
    return "status_changed"


def _load_previous_snapshot(snapshots_dir: Path) -> tuple[str | None, dict[str, dict[str, int | str]]]:
    candidates = sorted(snapshots_dir.glob("*_control_snapshot.json"))
    if not candidates:
        return None, {}
    latest = candidates[-1]
    payload = json.loads(latest.read_text(encoding="utf-8"))
    controls = payload.get("controls", {})
    return payload.get("snapshot_id"), controls


def _append_trend(
    trend_csv: Path,
    snapshot_id: str,
    collected_at: str,
    controls: dict[str, dict[str, int | str]],
) -> None:
    trend_csv.parent.mkdir(parents=True, exist_ok=True)
    exists = trend_csv.exists()
    with trend_csv.open("a", encoding="utf-8", newline="") as fp:
        writer = csv.DictWriter(
            fp,
            fieldnames=[
                "SNAPSHOT_ID",
                "COLLECTED_AT_UTC",
                "CONTROL_ID",
                "CONTROL_NAME",
                "STATUS",
                "PASS",
                "FAIL",
                "MANUAL",
                "UNKNOWN",
                "TOTAL",
            ],
            delimiter=";",
        )
        if not exists:
            writer.writeheader()
        for control_id in sorted(controls):
            c = controls[control_id]
            writer.writerow(
                {
                    "SNAPSHOT_ID": snapshot_id,
                    "COLLECTED_AT_UTC": collected_at,
                    "CONTROL_ID": control_id,
                    "CONTROL_NAME": c["control_name"],
                    "STATUS": c["status"],
                    "PASS": c["pass"],
                    "FAIL": c["fail"],
                    "MANUAL": c["manual"],
                    "UNKNOWN": c["unknown"],
                    "TOTAL": c["total"],
                }
            )


def update_continuous_compliance(
    summary_csv: Path,
    continuous_dir: Path,
) -> ContinuousComplianceResult:
    rows = _read_summary_csv(summary_csv)
    if not rows:
        raise ValueError(f"Empty NIST summary CSV: {summary_csv}")

    collected_at = datetime.now(timezone.utc).replace(microsecond=0).isoformat()
    snapshot_id = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")

    controls: dict[str, dict[str, int | str]] = {}
    for row in rows:
        control_id = (row.get("CONTROL_ID") or "").strip()
        if not control_id:
            continue
        pass_count = _to_int(row.get("PASS"))
        fail_count = _to_int(row.get("FAIL"))
        manual_count = _to_int(row.get("MANUAL"))
        unknown_count = _to_int(row.get("UNKNOWN"))
        total_count = _to_int(row.get("TOTAL"))
        controls[control_id] = {
            "control_name": (row.get("CONTROL_NAME") or "").strip(),
            "status": _control_status(pass_count, fail_count, manual_count, unknown_count),
            "pass": pass_count,
            "fail": fail_count,
            "manual": manual_count,
            "unknown": unknown_count,
            "total": total_count,
        }

    snapshots_dir = continuous_dir / "snapshots"
    snapshots_dir.mkdir(parents=True, exist_ok=True)
    compared_snapshot_id, previous_controls = _load_previous_snapshot(snapshots_dir)

    diff_rows: list[dict[str, str | int]] = []
    new_fail_count = 0
    fixed_count = 0
    status_changed_count = 0

    for control_id in sorted(controls):
        current = controls[control_id]
        previous = previous_controls.get(control_id) if previous_controls else None
        previous_status = previous.get("status") if previous else None
        previous_fail = int(previous.get("fail", 0)) if previous else 0
        change_type = _status_change_type(previous_status, str(current["status"]))
        if change_type == "new_fail":
            new_fail_count += 1
        if change_type == "fixed":
            fixed_count += 1
        if change_type == "status_changed":
            status_changed_count += 1
        diff_rows.append(
            {
                "CONTROL_ID": control_id,
                "CONTROL_NAME": current["control_name"],
                "PREV_STATUS": previous_status or "N/A",
                "CURR_STATUS": current["status"],
                "PREV_FAIL": previous_fail,
                "CURR_FAIL": current["fail"],
                "CHANGE_TYPE": change_type,
            }
        )

    snapshot_payload = {
        "snapshot_id": snapshot_id,
        "collected_at_utc": collected_at,
        "summary_csv": str(summary_csv),
        "control_count": len(controls),
        "controls": controls,
    }
    snapshot_json = snapshots_dir / f"{snapshot_id}_control_snapshot.json"
    snapshot_json.write_text(json.dumps(snapshot_payload, indent=2), encoding="utf-8")

    diff_csv = continuous_dir / f"{snapshot_id}_control_diff.csv"
    with diff_csv.open("w", encoding="utf-8", newline="") as fp:
        writer = csv.DictWriter(
            fp,
            fieldnames=[
                "CONTROL_ID",
                "CONTROL_NAME",
                "PREV_STATUS",
                "CURR_STATUS",
                "PREV_FAIL",
                "CURR_FAIL",
                "CHANGE_TYPE",
            ],
            delimiter=";",
        )
        writer.writeheader()
        writer.writerows(diff_rows)

    diff_json = continuous_dir / f"{snapshot_id}_control_diff.json"
    diff_payload = {
        "snapshot_id": snapshot_id,
        "collected_at_utc": collected_at,
        "compared_with_snapshot": compared_snapshot_id,
        "control_count": len(controls),
        "new_fail_count": new_fail_count,
        "fixed_count": fixed_count,
        "status_changed_count": status_changed_count,
        "rows": diff_rows,
    }
    diff_json.write_text(json.dumps(diff_payload, indent=2), encoding="utf-8")

    trend_csv = continuous_dir / "control_trend.csv"
    _append_trend(
        trend_csv=trend_csv,
        snapshot_id=snapshot_id,
        collected_at=collected_at,
        controls=controls,
    )

    return ContinuousComplianceResult(
        snapshot_json=snapshot_json,
        diff_csv=diff_csv,
        diff_json=diff_json,
        trend_csv=trend_csv,
        compared_with_snapshot=compared_snapshot_id,
        control_count=len(controls),
        new_fail_count=new_fail_count,
        fixed_count=fixed_count,
        status_changed_count=status_changed_count,
    )
