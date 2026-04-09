# Step 3: Run Experiments for the Thesis

This is the most important step for producing thesis content. The evaluation framework compares three analysis modes across 20 labeled alerts.

## Prerequisites

- Python 3.12+ with project dependencies (`uv sync`)
- For LLM modes: LM Studio running on your laptop with a model loaded
- Make sure `LM_STUDIO_BASE_URL` in `.env` points to your LM Studio instance

## Step-by-step

### 1. Run baseline evaluation (no LLM required)

```bash
python experiments/run_evaluation.py --mode baseline
```

This runs instantly and produces results in `experiments/results/baseline_baseline/`.

### 2. Run LLM-only evaluation

Start LM Studio, load your model, then:

```bash
# Replace with your actual model name from LM Studio
python experiments/run_evaluation.py --mode llm --model "qwen2.5-7b-instruct"
```

This takes ~2-5 minutes depending on your hardware.

### 3. Run LLM + enrichment evaluation

```bash
python experiments/run_evaluation.py --mode llm_enriched --model "qwen2.5-7b-instruct"
```

### 4. (Optional) Run with a second model for comparison

```bash
# Load a different model in LM Studio, then:
python experiments/run_evaluation.py --mode llm --model "llama-3.1-8b-instruct"
python experiments/run_evaluation.py --mode llm_enriched --model "llama-3.1-8b-instruct"
```

### 5. Generate comparison table

```bash
python experiments/analyze_results.py
```

This produces:
- `experiments/results/summary.json` — raw metrics for all runs
- `experiments/results/comparison_table.md` — formatted table you can paste into your thesis

## What to put in the thesis

### Chapter 5 (Experimental Evaluation) should contain:

1. **Methodology description:**
   - Corpus: 20 labeled Wazuh alerts across 8 categories
   - Ground truth: manually labeled severity, response action, key indicators
   - Three modes compared: baseline (rule-based), LLM-only, LLM + enrichment

2. **Metrics table** (from `comparison_table.md`):
   - Schema conformance rate
   - Severity accuracy (predicted vs ground truth)
   - Response accuracy
   - Indicator coverage
   - False positive detection rate
   - Latency and token usage

3. **Per-category breakdown:**
   - How does each mode perform on SSH attacks vs benign events vs rootkits?

4. **Multi-model comparison** (if you ran with 2+ models):
   - Which model is more accurate?
   - Trade-offs: accuracy vs speed vs token usage

5. **Key findings to highlight:**
   - Does LLM improve over baseline?
   - Does enrichment improve over LLM-only?
   - Which alert types benefit most from enrichment?
   - False positive handling: does the LLM correctly identify benign events?

6. **Limitations:**
   - Corpus size (20 alerts — acknowledge this is small)
   - Ground truth is author-labeled (not independent analysts)
   - Local LLM quality varies by model and quantization
   - Mock enrichment vs real osquery data

## Useful raw data

Individual alert results are in `experiments/results/<run_name>/eval-NNN.json`. Each file contains the full LLM response, scores, and comparison against ground truth — useful for cherry-picking examples in the thesis text.
