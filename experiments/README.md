# Evaluation Framework

## Overview

This framework evaluates LLM-AlertBridge's alert analysis in three modes:

| Mode | Description |
|---|---|
| `baseline` | Deterministic rule-based assessment (no LLM) |
| `llm` | LLM analysis using only alert data |
| `llm_enriched` | LLM analysis with osquery host context + correlation |

## Corpus

`corpus.json` contains 20 labeled Wazuh alerts covering:
- SSH brute force (3 alerts)
- File integrity (3 alerts)
- Privilege escalation (3 alerts)
- Web attacks (3 alerts)
- Rootkit detection (1 alert)
- Audit/command execution (2 alerts)
- Malware/C2 (1 alert)
- Benign/false positive (4 alerts)

Each alert includes ground truth labels and simulated osquery enrichment data.

## Running evaluations

### Prerequisites

- Python 3.12+ with project dependencies installed (`uv sync`)
- For `llm` and `llm_enriched` modes: LM Studio running with a loaded model

### Commands

```bash
# Run baseline (no LLM required)
python experiments/run_evaluation.py --mode baseline

# Run LLM-only mode
python experiments/run_evaluation.py --mode llm --model "qwen2.5-7b-instruct"

# Run LLM with enrichment
python experiments/run_evaluation.py --mode llm_enriched --model "qwen2.5-7b-instruct"

# Compare results across all runs
python experiments/analyze_results.py
```

### Output

Results are saved to `experiments/results/<mode>_<model>/`:
- Individual alert results: `eval-NNN.json`
- Combined results: `all_results.json`

After running `analyze_results.py`:
- `experiments/results/summary.json` — raw metrics
- `experiments/results/comparison_table.md` — formatted table for thesis

## Metrics

| Metric | What it measures |
|---|---|
| Schema conformance | % of LLM responses that parsed into valid JSON |
| Severity accuracy | % where predicted criticality matches ground truth |
| Response accuracy | % where predicted action matches ground truth |
| Indicator coverage | Average % of expected key indicators mentioned |
| FP detection rate | % of benign alerts correctly scored as low-risk |
| Latency | Average processing time per alert |
| Token usage | Average prompt + completion tokens |

## Reproducing thesis results

1. Run all three modes with the same model
2. Run `analyze_results.py` to generate comparison table
3. Copy `comparison_table.md` content into thesis chapter 5
