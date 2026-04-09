#!/usr/bin/env python3
"""Analyze and compare evaluation results across runs.

Usage:
    python experiments/analyze_results.py

Reads all runs from experiments/results/ and produces:
    - experiments/results/comparison_table.md
    - experiments/results/summary.json
"""

import json
from pathlib import Path

RESULTS_DIR = Path(__file__).parent / "results"


def load_run(run_dir: Path) -> list[dict]:
    all_results_file = run_dir / "all_results.json"
    if all_results_file.exists():
        with open(all_results_file, encoding="utf-8") as f:
            return json.load(f)
    return []


def compute_metrics(results: list[dict]) -> dict:
    n = len(results)
    if n == 0:
        return {}

    schema_valid = sum(1 for r in results if r.get("schema_valid"))
    sev_match = sum(1 for r in results if r["scores"]["severity_match"])
    resp_match = sum(1 for r in results if r["scores"]["response_match"])
    avg_coverage = sum(r["scores"]["indicator_coverage"] for r in results) / n
    avg_latency = sum(r.get("latency_ms", 0) for r in results) / n
    avg_prompt_tokens = sum(r.get("prompt_tokens", 0) or 0 for r in results) / n
    avg_completion_tokens = sum(r.get("completion_tokens", 0) or 0 for r in results) / n

    benign = [r for r in results if r["scores"]["false_positive_correct"] is not None]
    fp_correct = sum(1 for r in benign if r["scores"]["false_positive_correct"])

    by_category: dict[str, dict] = {}
    for r in results:
        cat = r.get("category", "unknown")
        if cat not in by_category:
            by_category[cat] = {"total": 0, "sev_match": 0, "resp_match": 0}
        by_category[cat]["total"] += 1
        if r["scores"]["severity_match"]:
            by_category[cat]["sev_match"] += 1
        if r["scores"]["response_match"]:
            by_category[cat]["resp_match"] += 1

    return {
        "total_alerts": n,
        "schema_conformance": round(schema_valid / n, 3),
        "severity_accuracy": round(sev_match / n, 3),
        "response_accuracy": round(resp_match / n, 3),
        "indicator_coverage": round(avg_coverage, 3),
        "fp_detection_rate": round(fp_correct / len(benign), 3) if benign else None,
        "fp_total": len(benign),
        "fp_correct": fp_correct,
        "avg_latency_ms": round(avg_latency, 1),
        "avg_prompt_tokens": round(avg_prompt_tokens, 1),
        "avg_completion_tokens": round(avg_completion_tokens, 1),
        "by_category": by_category,
    }


def format_markdown_table(runs: dict[str, dict]) -> str:
    lines = [
        "# Evaluation Comparison",
        "",
        "| Metric | " + " | ".join(runs.keys()) + " |",
        "|--------|" + "|".join(["--------"] * len(runs)) + "|",
    ]

    metrics = [
        ("Total alerts", "total_alerts", lambda v: str(v)),
        ("Schema conformance", "schema_conformance", lambda v: f"{100*v:.1f}%"),
        ("Severity accuracy", "severity_accuracy", lambda v: f"{100*v:.1f}%"),
        ("Response accuracy", "response_accuracy", lambda v: f"{100*v:.1f}%"),
        ("Indicator coverage", "indicator_coverage", lambda v: f"{100*v:.1f}%"),
        ("FP detection rate", "fp_detection_rate",
         lambda v: f"{100*v:.1f}%" if v is not None else "N/A"),
        ("Avg latency (ms)", "avg_latency_ms", lambda v: f"{v:.0f}"),
        ("Avg prompt tokens", "avg_prompt_tokens", lambda v: f"{v:.0f}"),
        ("Avg completion tokens", "avg_completion_tokens", lambda v: f"{v:.0f}"),
    ]

    for label, key, fmt in metrics:
        values = []
        for run_metrics in runs.values():
            val = run_metrics.get(key)
            values.append(fmt(val) if val is not None else "—")
        lines.append(f"| {label} | " + " | ".join(values) + " |")

    lines.extend(["", "## Per-category breakdown", ""])

    all_categories = set()
    for m in runs.values():
        all_categories.update(m.get("by_category", {}).keys())

    if all_categories:
        lines.append("| Category | " + " | ".join(f"{r} sev/resp" for r in runs) + " |")
        lines.append("|----------|" + "|".join(["--------"] * len(runs)) + "|")

        for cat in sorted(all_categories):
            values = []
            for run_metrics in runs.values():
                cat_data = run_metrics.get("by_category", {}).get(cat, {})
                total = cat_data.get("total", 0)
                if total > 0:
                    sev = cat_data.get("sev_match", 0)
                    resp = cat_data.get("resp_match", 0)
                    values.append(f"{sev}/{total}, {resp}/{total}")
                else:
                    values.append("—")
            lines.append(f"| {cat} | " + " | ".join(values) + " |")

    return "\n".join(lines) + "\n"


def main():
    run_dirs = sorted([d for d in RESULTS_DIR.iterdir() if d.is_dir()])
    if not run_dirs:
        print("No result directories found in experiments/results/")
        return

    all_runs: dict[str, dict] = {}
    for run_dir in run_dirs:
        results = load_run(run_dir)
        if results:
            metrics = compute_metrics(results)
            all_runs[run_dir.name] = metrics
            print(f"Loaded {run_dir.name}: {len(results)} results")

    if not all_runs:
        print("No results found to analyze")
        return

    summary_path = RESULTS_DIR / "summary.json"
    with open(summary_path, "w", encoding="utf-8") as f:
        json.dump(all_runs, f, indent=2, ensure_ascii=False)
    print(f"Summary saved to {summary_path}")

    md = format_markdown_table(all_runs)
    md_path = RESULTS_DIR / "comparison_table.md"
    with open(md_path, "w", encoding="utf-8") as f:
        f.write(md)
    print(f"Comparison table saved to {md_path}")
    print(f"\n{md}")


if __name__ == "__main__":
    main()
