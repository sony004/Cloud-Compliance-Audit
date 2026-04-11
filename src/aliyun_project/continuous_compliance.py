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
    trend_chart_png: Path | None
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


def _generate_trend_chart(trend_csv: Path, output_png: Path) -> Path | None:
    """
    Generate a control trajectory line chart from control_trend.csv.

    Returns the chart path on success; returns None when dependencies are
    unavailable or chart generation fails.
    """
    def _fallback_svg_chart(csv_path: Path, svg_path: Path) -> Path | None:
        try:
            with csv_path.open("r", encoding="utf-8", newline="") as fp:
                reader = csv.DictReader(fp, delimiter=";")
                rows = list(reader)
            if not rows:
                return None

            snapshots = sorted(
                {str(r.get("SNAPSHOT_ID", "")).strip() for r in rows if str(r.get("SNAPSHOT_ID", "")).strip()}
            )
            if not snapshots:
                return None

            control_name: dict[str, str] = {}
            status_map: dict[str, dict[str, str]] = {}
            for r in rows:
                cid = str(r.get("CONTROL_ID", "")).strip()
                if not cid:
                    continue
                cname = str(r.get("CONTROL_NAME", "")).strip()
                snap = str(r.get("SNAPSHOT_ID", "")).strip()
                status = str(r.get("STATUS", "UNKNOWN")).strip().upper() or "UNKNOWN"
                control_name[cid] = cname
                status_map.setdefault(cid, {})[snap] = status

            controls = sorted(status_map.keys())
            if not controls:
                return None

            status_order = {"PASS": 0, "UNKNOWN": 1, "MANUAL": 2, "FAIL": 3}
            status_labels = ["PASS", "UNKNOWN", "MANUAL", "FAIL"]
            point_fill = {"PASS": "#2e7d32", "UNKNOWN": "#6b7280", "MANUAL": "#f9a825", "FAIL": "#c62828"}
            line_palette = [
                "#1e88e5",
                "#8e24aa",
                "#00897b",
                "#ef6c00",
                "#6d4c41",
                "#3949ab",
                "#43a047",
                "#d81b60",
                "#5e35b1",
                "#039be5",
                "#7cb342",
                "#f4511e",
            ]

            width, height = 1800, 860
            left, right, top, bottom = 120, 80, 140, 90
            plot_w = width - left - right
            plot_h = height - top - bottom

            def _fmt(v: float) -> str:
                return f"{v:.1f}"

            x_points: list[float] = []
            if len(snapshots) == 1:
                x_points = [left + plot_w / 2]
            else:
                x_points = [left + plot_w * i / (len(snapshots) - 1) for i in range(len(snapshots))]

            y_points = {
                label: top + plot_h * idx / (len(status_labels) - 1)
                for idx, label in enumerate(status_labels)
            }

            svg: list[str] = []
            svg.append(f"<svg xmlns='http://www.w3.org/2000/svg' width='{width}' height='{height}'>")
            svg.append("<rect width='100%' height='100%' fill='white'/>")
            svg.append(
                "<text x='120' y='36' font-size='28' font-family='Arial' fill='#111'>Control Status Trajectory</text>"
            )
            svg.append(
                f"<text x='120' y='60' font-size='13' font-family='Arial' fill='#555'>Controls: {', '.join(controls)}</text>"
            )

            for label in status_labels:
                y = y_points[label]
                svg.append(f"<line x1='{left}' y1='{_fmt(y)}' x2='{left + plot_w}' y2='{_fmt(y)}' stroke='#e0e0e0'/>")
                svg.append(
                    f"<text x='{left - 12}' y='{_fmt(y + 4)}' text-anchor='end' font-size='12' fill='#333'>{label}</text>"
                )

            for i, snap in enumerate(snapshots):
                x = x_points[i]
                svg.append(f"<line x1='{_fmt(x)}' y1='{top}' x2='{_fmt(x)}' y2='{top + plot_h}' stroke='#f0f0f0'/>")
                svg.append(
                    f"<text x='{_fmt(x)}' y='{top + plot_h + 28}' text-anchor='middle' font-size='11' fill='#333'>{snap}</text>"
                )

            legend_cols = 6
            legend_dx = 260
            legend_dy = 22
            for idx, cid in enumerate(controls):
                line_color = line_palette[idx % len(line_palette)]
                pts: list[str] = []
                for j, snap in enumerate(snapshots):
                    status = status_map.get(cid, {}).get(snap, "UNKNOWN")
                    y = y_points.get(status, y_points["UNKNOWN"])
                    x = x_points[j]
                    pts.append(f"{_fmt(x)},{_fmt(y)}")
                svg.append(
                    f"<polyline points='{' '.join(pts)}' fill='none' stroke='{line_color}' stroke-width='2'/>"
                )
                for j, snap in enumerate(snapshots):
                    status = status_map.get(cid, {}).get(snap, "UNKNOWN")
                    y = y_points.get(status, y_points["UNKNOWN"])
                    x = x_points[j]
                    fill = point_fill.get(status, point_fill["UNKNOWN"])
                    svg.append(
                        f"<circle cx='{_fmt(x)}' cy='{_fmt(y)}' r='4.5' fill='{fill}' stroke='{line_color}' stroke-width='1.2'/>"
                    )

                col = idx % legend_cols
                row = idx // legend_cols
                lx = left + col * legend_dx
                ly = 90 + row * legend_dy
                svg.append(f"<rect x='{lx}' y='{ly - 10}' width='11' height='11' fill='{line_color}'/>")
                svg.append(
                    f"<text x='{lx + 16}' y='{ly}' font-size='12' font-family='Arial' fill='#222'>{cid}</text>"
                )

            svg.append("</svg>")
            svg_path.parent.mkdir(parents=True, exist_ok=True)
            svg_path.write_text("\n".join(svg), encoding="utf-8")
            return svg_path
        except Exception:
            return None

    try:
        import matplotlib.pyplot as plt  # type: ignore
        import pandas as pd  # type: ignore
    except Exception:
        return _fallback_svg_chart(trend_csv, output_png.with_suffix(".svg"))

    try:
        df = pd.read_csv(trend_csv, delimiter=";")
        if df.empty:
            return None

        pivot = (
            df.pivot_table(
                index=["CONTROL_ID", "CONTROL_NAME"],
                columns="SNAPSHOT_ID",
                values="STATUS",
                aggfunc="last",
            )
            .sort_index(axis=1)
            .reset_index()
        )

        if pivot.empty:
            return None

        status_order = {
            "PASS": 0,
            "UNKNOWN": 1,
            "MANUAL": 2,
            "FAIL": 3,
        }

        time_cols = [c for c in pivot.columns if c not in ("CONTROL_ID", "CONTROL_NAME")]
        if not time_cols:
            return None

        plt.rcParams.update({"font.size": 12})
        fig, ax = plt.subplots(figsize=(16, 7))
        ax.set_facecolor("white")
        fig.patch.set_facecolor("white")

        for _, row in pivot.iterrows():
            control_id = str(row["CONTROL_ID"])
            y_values = [status_order.get(str(row[col]).upper(), 1) for col in time_cols]
            ax.plot(
                time_cols,
                y_values,
                marker="o",
                linewidth=1.5,
                markersize=5,
                label=control_id,
            )

        all_controls = ", ".join(pivot["CONTROL_ID"].astype(str).tolist())
        ax.text(
            0.0,
            1.01,
            f"Controls: {all_controls}",
            transform=ax.transAxes,
            fontsize=14,
            color="#444444",
            va="bottom",
        )

        ax.set_yticks([0, 1, 2, 3])
        ax.set_yticklabels(["PASS", "UNKNOWN", "MANUAL", "FAIL"], fontsize=13)
        ax.tick_params(axis="x", labelsize=12)
        ax.tick_params(axis="y", length=0)

        ax.grid(axis="y", linestyle="-", alpha=0.25)
        ax.grid(axis="x", linestyle="-", alpha=0.15)
        ax.spines["top"].set_visible(False)
        ax.spines["right"].set_visible(False)
        ax.spines["left"].set_alpha(0.2)
        ax.spines["bottom"].set_alpha(0.2)

        ax.legend(
            loc="center left",
            bbox_to_anchor=(1.02, 0.5),
            ncol=1,
            frameon=False,
            fontsize=11,
        )

        plt.subplots_adjust(right=0.8)
        plt.tight_layout()
        output_png.parent.mkdir(parents=True, exist_ok=True)
        fig.savefig(output_png, dpi=200)
        plt.close(fig)
        return output_png
    except Exception:
        return _fallback_svg_chart(trend_csv, output_png.with_suffix(".svg"))


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
    trend_chart_png = _generate_trend_chart(
        trend_csv=trend_csv,
        output_png=continuous_dir / "control_trend_trajectory.png",
    )

    return ContinuousComplianceResult(
        snapshot_json=snapshot_json,
        diff_csv=diff_csv,
        diff_json=diff_json,
        trend_csv=trend_csv,
        trend_chart_png=trend_chart_png,
        compared_with_snapshot=compared_snapshot_id,
        control_count=len(controls),
        new_fail_count=new_fail_count,
        fixed_count=fixed_count,
        status_changed_count=status_changed_count,
    )
