#!/usr/bin/env python3
"""Evaluation runner — analyses every alert in the corpus in a specified mode.

Usage:
    python experiments/run_evaluation.py --mode baseline
    python experiments/run_evaluation.py --mode llm --model qwen2.5-7b
    python experiments/run_evaluation.py --mode llm_enriched --model qwen2.5-7b

Results are written to experiments/results/<mode>_<model>/
"""

import argparse
import json
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from backend.app.integrations.wazuh.normalizer import (
    alert_data_for_prompt,
    extract_alert_fields,
    normalize_wazuh_alert,
)
from backend.app.schemas.analysis import AnalysisResult
from backend.app.services.baseline_service import baseline_assessment
from backend.app.services.llm_service import (
    build_analysis_prompt,
    get_system_prompt,
    parse_llm_response,
)

CORPUS_PATH = Path(__file__).parent / "corpus.json"


class FakeAlert:
    """Minimal alert object compatible with baseline_assessment()."""
    def __init__(self, raw: dict, normalized: dict, fields: dict):
        self.raw_data = raw
        self.normalized_data = normalized
        self.severity = fields["severity"]
        self.rule_id = fields["rule_id"]
        self.rule_description = fields["rule_description"]
        self.agent_name = fields["agent_name"]


def load_corpus() -> list[dict]:
    with open(CORPUS_PATH, encoding="utf-8") as f:
        return json.load(f)


def run_baseline(alert_entry: dict) -> dict:
    raw = alert_entry["wazuh_alert"]
    normalized = normalize_wazuh_alert(raw)
    fields = extract_alert_fields(raw)
    fake = FakeAlert(raw, normalized, fields)

    start = time.monotonic()
    result = baseline_assessment(fake)
    elapsed_ms = int((time.monotonic() - start) * 1000)

    return {
        "mode": "baseline",
        "model": "baseline_rules",
        "result": result.model_dump(),
        "raw_response": "[baseline]",
        "latency_ms": elapsed_ms,
        "prompt_tokens": 0,
        "completion_tokens": 0,
        "schema_valid": True,
    }


def run_llm(alert_entry: dict, *, model: str, use_enrichment: bool) -> dict:
    from backend.app.integrations.lm_studio.client import LMStudioClient

    raw = alert_entry["wazuh_alert"]
    normalized = normalize_wazuh_alert(raw)
    fields = extract_alert_fields(raw)

    enrichment_data = None
    if use_enrichment:
        enrichment_data = alert_entry.get("simulated_enrichment", {})

    user_prompt = build_analysis_prompt(
        rule_id=fields["rule_id"],
        rule_description=fields["rule_description"],
        severity=fields["severity"],
        agent_name=fields["agent_name"],
        timestamp=normalized.get("timestamp", ""),
        alert_data=alert_data_for_prompt(normalized),
        enrichment_data=enrichment_data,
    )

    client = LMStudioClient()
    start = time.monotonic()
    try:
        llm_result = client.analyze(user_prompt, get_system_prompt())
        elapsed_ms = int((time.monotonic() - start) * 1000)
        parsed = parse_llm_response(llm_result["content"])
        schema_valid = True
    except Exception as e:
        elapsed_ms = int((time.monotonic() - start) * 1000)
        parsed = AnalysisResult(summary=f"ERROR: {e}", confidence_note="Analysis failed")
        schema_valid = False
        llm_result = {"content": str(e), "model": model, "prompt_tokens": 0, "completion_tokens": 0}

    return {
        "mode": "llm_enriched" if use_enrichment else "llm",
        "model": llm_result.get("model", model),
        "result": parsed.model_dump(),
        "raw_response": llm_result.get("content", ""),
        "latency_ms": elapsed_ms,
        "prompt_tokens": llm_result.get("prompt_tokens", 0),
        "completion_tokens": llm_result.get("completion_tokens", 0),
        "schema_valid": schema_valid,
    }


def score_result(result: dict, ground_truth: dict) -> dict:
    """Compare analysis result against ground truth."""
    r = result["result"]
    gt = ground_truth

    crit_level = (r.get("criticality", {}) or {}).get("level", "medium")
    resp_action = (r.get("response", {}) or {}).get("action", "investigate")

    severity_match = crit_level == gt["expected_severity"]
    response_match = resp_action == gt["expected_response"]

    analysis_text = json.dumps(r, ensure_ascii=False).lower()
    indicators_found = 0
    for indicator in gt.get("expected_key_indicators", []):
        if indicator.lower() in analysis_text:
            indicators_found += 1
    total_indicators = len(gt.get("expected_key_indicators", []))
    indicator_coverage = indicators_found / total_indicators if total_indicators > 0 else 1.0

    is_benign = not gt["is_true_positive"]
    if is_benign:
        fp_correct = crit_level in ("info", "low") and resp_action in ("ignore", "monitor")
    else:
        fp_correct = None

    return {
        "severity_match": severity_match,
        "response_match": response_match,
        "indicator_coverage": round(indicator_coverage, 3),
        "false_positive_correct": fp_correct,
        "predicted_severity": crit_level,
        "expected_severity": gt["expected_severity"],
        "predicted_action": resp_action,
        "expected_action": gt["expected_response"],
    }


def main():
    parser = argparse.ArgumentParser(description="Run evaluation on alert corpus")
    parser.add_argument("--mode", required=True, choices=["baseline", "llm", "llm_enriched"])
    parser.add_argument("--model", default="default", help="Model name for LLM modes")
    args = parser.parse_args()

    corpus = load_corpus()
    print(f"Loaded {len(corpus)} alerts from corpus")

    run_name = f"{args.mode}_{args.model}"
    output_dir = Path(__file__).parent / "results" / run_name
    output_dir.mkdir(parents=True, exist_ok=True)

    all_results = []

    for i, entry in enumerate(corpus):
        alert_id = entry["id"]
        print(f"[{i+1}/{len(corpus)}] Processing {alert_id} ({entry.get('category', '?')})...")

        if args.mode == "baseline":
            result = run_baseline(entry)
        elif args.mode == "llm":
            result = run_llm(entry, model=args.model, use_enrichment=False)
        else:
            result = run_llm(entry, model=args.model, use_enrichment=True)

        scores = score_result(result, entry["ground_truth"])

        output = {
            "alert_id": alert_id,
            "category": entry.get("category", ""),
            "ground_truth": entry["ground_truth"],
            **result,
            "scores": scores,
        }
        all_results.append(output)

        with open(output_dir / f"{alert_id}.json", "w", encoding="utf-8") as f:
            json.dump(output, f, indent=2, ensure_ascii=False, default=str)

    with open(output_dir / "all_results.json", "w", encoding="utf-8") as f:
        json.dump(all_results, f, indent=2, ensure_ascii=False, default=str)

    n = len(all_results)
    schema_valid = sum(1 for r in all_results if r["schema_valid"])
    sev_match = sum(1 for r in all_results if r["scores"]["severity_match"])
    resp_match = sum(1 for r in all_results if r["scores"]["response_match"])
    avg_coverage = sum(r["scores"]["indicator_coverage"] for r in all_results) / n if n else 0
    avg_latency = sum(r["latency_ms"] for r in all_results) / n if n else 0

    benign = [r for r in all_results if r["scores"]["false_positive_correct"] is not None]
    fp_correct = sum(1 for r in benign if r["scores"]["false_positive_correct"])

    print(f"\n{'='*60}")
    print(f"Run: {run_name}")
    print(f"Alerts: {n}")
    print(f"Schema conformance: {schema_valid}/{n} ({100*schema_valid/n:.1f}%)")
    print(f"Severity accuracy:  {sev_match}/{n} ({100*sev_match/n:.1f}%)")
    print(f"Response accuracy:  {resp_match}/{n} ({100*resp_match/n:.1f}%)")
    print(f"Indicator coverage: {100*avg_coverage:.1f}%")
    if benign:
        print(f"FP detection:       {fp_correct}/{len(benign)} ({100*fp_correct/len(benign):.1f}%)")
    else:
        print("FP detection:       N/A")
    print(f"Avg latency:        {avg_latency:.0f}ms")
    print(f"{'='*60}")
    print(f"Results saved to {output_dir}")


if __name__ == "__main__":
    main()
