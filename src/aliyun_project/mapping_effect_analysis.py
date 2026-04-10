from __future__ import annotations

import argparse
import csv
import json
from collections import defaultdict
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_CHECKS_FILE = PROJECT_ROOT / "rules" / "checks" / "cis_2.0_alibabacloud_checks.json"
DEFAULT_MAPPING_FILE = PROJECT_ROOT / "rules" / "mappings" / "nist_800_53_rev5_alibabacloud.json"
DEFAULT_OUTPUT_DIR = PROJECT_ROOT / "output" / "analysis" / "mapping_effect"
DEFAULT_NIST_DIR = PROJECT_ROOT / "output" / "nist"


def _load_json(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8-sig"))


def _load_checks(path: Path) -> list[str]:
    payload = _load_json(path)
    checks = payload.get("alibabacloud", [])
    return [str(check).strip() for check in checks if str(check).strip()]


def _lookup_mapping(check_id: str, mapping_doc: dict) -> dict | None:
    explicit = mapping_doc.get("check_mappings", {})
    if check_id in explicit:
        return explicit[check_id]
    for rule in mapping_doc.get("prefix_mappings", []):
        prefix = rule.get("prefix", "")
        if prefix and check_id.startswith(prefix):
            return rule
    return None


def _resolve_latest_nist_summary(nist_dir: Path) -> Path | None:
    if not nist_dir.exists():
        return None
    candidates = sorted(
        nist_dir.glob("*_nist80053_control_summary.csv"),
        key=lambda p: p.stat().st_mtime,
        reverse=True,
    )
    return candidates[0] if candidates else None


def _load_observed_check_ids(summary_csv: Path | None) -> set[str]:
    if not summary_csv or not summary_csv.exists():
        return set()
    observed: set[str] = set()
    with summary_csv.open("r", encoding="utf-8", newline="") as fp:
        reader = csv.DictReader(fp, delimiter=";")
        for row in reader:
            for check_id in (row.get("CHECK_IDS") or "").split(","):
                check_id = check_id.strip()
                if check_id:
                    observed.add(check_id)
    return observed


def _load_observed_control_family_distribution(summary_csv: Path | None) -> dict[str, int]:
    if not summary_csv or not summary_csv.exists():
        return {}
    family_distribution: dict[str, int] = defaultdict(int)
    with summary_csv.open("r", encoding="utf-8", newline="") as fp:
        reader = csv.DictReader(fp, delimiter=";")
        for row in reader:
            control_id = (row.get("CONTROL_ID") or "").strip()
            if not control_id:
                continue
            family = control_id.split("-", 1)[0]
            family_distribution[family] += 1
    return dict(family_distribution)


def _write_csv(path: Path, fieldnames: list[str], rows: list[dict[str, str]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="") as fp:
        writer = csv.DictWriter(fp, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)


def _build_visualizations(
    output_dir: Path,
    mapped_count: int,
    unmapped_count: int,
    family_distribution: dict[str, int],
) -> list[Path]:
    def _fallback_svg() -> list[Path]:
        generated_svg: list[Path] = []

        total = max(mapped_count + unmapped_count, 1)
        mapped_ratio = mapped_count / total
        circumference = 2 * 3.1415926 * 60
        mapped_len = circumference * mapped_ratio
        unmapped_len = circumference - mapped_len

        pie_svg = output_dir / "mapping_coverage_pie.svg"
        pie_content = f"""<svg xmlns=\"http://www.w3.org/2000/svg\" width=\"500\" height=\"280\">
  <rect width=\"100%\" height=\"100%\" fill=\"white\"/>
  <text x=\"20\" y=\"30\" font-size=\"18\" font-family=\"Arial\">Control Mapping Coverage</text>
  <g transform=\"translate(140,150) rotate(-90)\">
    <circle cx=\"0\" cy=\"0\" r=\"60\" fill=\"none\" stroke=\"#e5e7eb\" stroke-width=\"28\"/>
    <circle cx=\"0\" cy=\"0\" r=\"60\" fill=\"none\" stroke=\"#2563eb\" stroke-width=\"28\"
      stroke-dasharray=\"{mapped_len:.2f} {unmapped_len:.2f}\" stroke-linecap=\"butt\"/>
  </g>
  <rect x=\"270\" y=\"95\" width=\"14\" height=\"14\" fill=\"#2563eb\"/>
  <text x=\"292\" y=\"107\" font-size=\"14\" font-family=\"Arial\">Mapped: {mapped_count}</text>
  <rect x=\"270\" y=\"125\" width=\"14\" height=\"14\" fill=\"#e5e7eb\" stroke=\"#9ca3af\"/>
  <text x=\"292\" y=\"137\" font-size=\"14\" font-family=\"Arial\">Unmapped: {unmapped_count}</text>
</svg>"""
        pie_svg.write_text(pie_content, encoding="utf-8")
        generated_svg.append(pie_svg)

        bar_svg = output_dir / "control_family_distribution_bar.svg"
        width = 720
        height = 420
        margin_left = 70
        margin_right = 20
        margin_top = 50
        margin_bottom = 70
        plot_width = width - margin_left - margin_right
        plot_height = height - margin_top - margin_bottom
        items = sorted(family_distribution.items())
        max_count = max([count for _, count in items], default=1)
        bar_w = plot_width / max(len(items), 1)

        bars = []
        labels = []
        for idx, (family, count) in enumerate(items):
            h = 0 if max_count == 0 else (count / max_count) * (plot_height - 10)
            x = margin_left + idx * bar_w + 8
            y = margin_top + (plot_height - h)
            bars.append(
                f'<rect x="{x:.1f}" y="{y:.1f}" width="{max(bar_w - 16, 8):.1f}" '
                f'height="{h:.1f}" fill="#2563eb" />'
            )
            labels.append(
                f'<text x="{x + (max(bar_w - 16, 8))/2:.1f}" y="{height - 40}" text-anchor="middle" '
                f'font-size="12" font-family="Arial">{family}</text>'
            )
            labels.append(
                f'<text x="{x + (max(bar_w - 16, 8))/2:.1f}" y="{max(y - 6, margin_top)}" text-anchor="middle" '
                f'font-size="11" font-family="Arial">{count}</text>'
            )

        bar_content = (
            f'<svg xmlns="http://www.w3.org/2000/svg" width="{width}" height="{height}">'
            '<rect width="100%" height="100%" fill="white"/>'
            f'<line x1="{margin_left}" y1="{margin_top}" x2="{margin_left}" y2="{margin_top + plot_height}" stroke="#111827"/>'
            f'<line x1="{margin_left}" y1="{margin_top + plot_height}" x2="{margin_left + plot_width}" y2="{margin_top + plot_height}" stroke="#111827"/>'
            + "".join(bars)
            + "".join(labels)
            + f'<text x="{margin_left - 45}" y="{margin_top - 10}" font-size="12" font-family="Arial">控制项数量</text>'
            + f'<text x="{margin_left + plot_width / 2:.1f}" y="{height - 12}" text-anchor="middle" font-size="12" font-family="Arial">控制域</text>'
            + "</svg>"
        )
        bar_svg.write_text(bar_content, encoding="utf-8")
        generated_svg.append(bar_svg)
        return generated_svg

    try:
        import matplotlib.pyplot as plt  # type: ignore
    except Exception:
        return _fallback_svg()

    generated: list[Path] = []

    pie_path = output_dir / "mapping_coverage_pie.png"
    fig1, ax1 = plt.subplots(figsize=(6, 6))
    ax1.pie(
        [mapped_count, unmapped_count],
        labels=["Mapped checks", "Unmapped checks"],
        autopct="%1.1f%%",
        startangle=90,
    )
    ax1.axis("equal")
    ax1.set_title("Control Mapping Coverage")
    fig1.tight_layout()
    fig1.savefig(pie_path, dpi=150)
    plt.close(fig1)
    generated.append(pie_path)

    bar_path = output_dir / "control_family_distribution_bar.png"
    families = sorted(family_distribution.keys())
    counts = [family_distribution[f] for f in families]
    fig2, ax2 = plt.subplots(figsize=(8, 4.5))
    ax2.bar(families, counts)
    ax2.set_xlabel("控制域")
    ax2.set_ylabel("控制项数量")
    fig2.tight_layout()
    fig2.savefig(bar_path, dpi=150)
    plt.close(fig2)
    generated.append(bar_path)

    return generated


def run(
    checks_file: Path,
    mapping_file: Path,
    output_dir: Path,
    top_examples: int,
    nist_summary_csv: Path | None,
) -> int:
    checks = _load_checks(checks_file)
    mapping_doc = _load_json(mapping_file)
    observed_check_ids = _load_observed_check_ids(nist_summary_csv)

    mapped_checks: list[str] = []
    unmapped_checks: list[str] = []
    control_to_checks: dict[str, set[str]] = defaultdict(set)
    sample_rows: list[dict[str, str]] = []

    for check_id in checks:
        mapping = _lookup_mapping(check_id, mapping_doc)
        if not mapping:
            unmapped_checks.append(check_id)
            continue

        mapped_checks.append(check_id)
        primary = mapping.get("primary_control")
        secondary = mapping.get("secondary_controls", [])
        controls = [c for c in [primary, *secondary] if c]
        for control_id in controls:
            control_to_checks[control_id].add(check_id)

        if len(sample_rows) < top_examples:
            sample_rows.append(
                {
                    "check_id": check_id,
                    "mapped_controls": ", ".join(controls),
                    "mapping_strength": str(mapping.get("mapping_strength", "")),
                    "mapping_rationale": str(mapping.get("rationale", "")),
                }
            )

    total_checks = len(checks)
    mapped_count = len(mapped_checks)
    unmapped_count = len(unmapped_checks)
    coverage = (mapped_count / total_checks * 100) if total_checks else 0.0
    control_count = len(control_to_checks)
    relation_count = sum(len(v) for v in control_to_checks.values())
    avg_checks_per_control = (relation_count / control_count) if control_count else 0.0

    family_distribution: dict[str, int] = defaultdict(int)
    for control_id in control_to_checks:
        family = control_id.split("-", 1)[0]
        family_distribution[family] += 1
    observed_family_distribution = _load_observed_control_family_distribution(nist_summary_csv)
    chart_family_distribution = observed_family_distribution or dict(family_distribution)

    summary_rows = [
        {"metric": "total_checks", "value": str(total_checks)},
        {"metric": "mapped_checks", "value": str(mapped_count)},
        {"metric": "unmapped_checks", "value": str(unmapped_count)},
        {"metric": "mapping_coverage_percent", "value": f"{coverage:.2f}"},
        {"metric": "mapped_controls", "value": str(control_count)},
        {"metric": "avg_checks_per_control", "value": f"{avg_checks_per_control:.2f}"},
        {"metric": "observed_checks_in_latest_run", "value": str(len(observed_check_ids))},
    ]

    output_dir.mkdir(parents=True, exist_ok=True)
    table43_path = output_dir / "table_4_3_mapping_statistics.csv"
    table44_path = output_dir / "table_4_4_mapping_examples.csv"
    unmapped_path = output_dir / "unmapped_checks.csv"
    family_path = output_dir / "control_family_distribution.csv"

    _write_csv(table43_path, ["metric", "value"], summary_rows)
    _write_csv(
        table44_path,
        ["check_id", "mapped_controls", "mapping_strength", "mapping_rationale"],
        sample_rows,
    )
    _write_csv(unmapped_path, ["check_id"], [{"check_id": c} for c in sorted(unmapped_checks)])
    _write_csv(
        family_path,
        ["control_family", "control_count"],
        [
            {"control_family": family, "control_count": str(count)}
            for family, count in sorted(chart_family_distribution.items())
        ],
    )

    charts = _build_visualizations(output_dir, mapped_count, unmapped_count, chart_family_distribution)
    md_path = output_dir / "mapping_effect_summary.md"
    md = [
        "# Mapping Effect Summary",
        "",
        f"- Checks file: `{checks_file}`",
        f"- Mapping file: `{mapping_file}`",
        f"- Latest NIST summary: `{nist_summary_csv}`" if nist_summary_csv else "- Latest NIST summary: `N/A`",
        "",
        "## Table 4-3 Metrics",
        "",
    ]
    for row in summary_rows:
        md.append(f"- {row['metric']}: {row['value']}")

    md.extend(["", "## Output Artifacts", ""])
    for p in [table43_path, table44_path, unmapped_path, family_path, *charts]:
        md.append(f"- `{p}`")
    md_path.write_text("\n".join(md), encoding="utf-8")

    print(f"Table 4-3: {table43_path}")
    print(f"Table 4-4: {table44_path}")
    print(f"Unmapped checks: {unmapped_path}")
    print(f"Control family distribution: {family_path}")
    if charts:
        for chart in charts:
            print(f"Chart: {chart}")
    else:
        print("Charts not generated (matplotlib is unavailable).")
    print(f"Summary markdown: {md_path}")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(
        prog="mapping-effect-analysis",
        description="Generate mapping effectiveness statistics and visualizations for Section 4.3",
    )
    parser.add_argument("--checks-file", type=Path, default=DEFAULT_CHECKS_FILE)
    parser.add_argument("--mapping-file", type=Path, default=DEFAULT_MAPPING_FILE)
    parser.add_argument("--output-dir", type=Path, default=DEFAULT_OUTPUT_DIR)
    parser.add_argument("--top-examples", type=int, default=10)
    parser.add_argument(
        "--nist-summary-csv",
        type=Path,
        help="Optional nist control summary csv. If omitted, auto-detect latest under output/nist.",
    )
    args = parser.parse_args()

    summary_csv = args.nist_summary_csv
    if not summary_csv:
        summary_csv = _resolve_latest_nist_summary(DEFAULT_NIST_DIR)

    return run(
        checks_file=args.checks_file.resolve(),
        mapping_file=args.mapping_file.resolve(),
        output_dir=args.output_dir.resolve(),
        top_examples=args.top_examples,
        nist_summary_csv=summary_csv.resolve() if summary_csv else None,
    )


if __name__ == "__main__":
    raise SystemExit(main())
