# Step 4: LM Studio Model Selection

You mentioned doing LLM benchmarking separately. This document lists what you need to do within LM Studio to support the evaluation framework.

## Minimum requirement

Load at least **one** model in LM Studio and run experiments with it. The evaluation framework records the model name automatically.

## Recommended: compare 2-3 models

For a stronger thesis, compare models of different sizes/families. Suggested pairs:

| Model | Size | Why |
|---|---|---|
| `qwen2.5-7b-instruct` | 7B | Good balance of quality and speed |
| `llama-3.1-8b-instruct` | 8B | Popular baseline, different architecture |
| `mistral-7b-instruct-v0.3` | 7B | Strong reasoning, different training mix |
| `phi-3-mini-4k-instruct` | 3.8B | Smallest viable option, tests small model limits |

## How to run comparison

1. Load Model A in LM Studio
2. Run evaluation:
   ```bash
   python experiments/run_evaluation.py --mode llm --model "model-a-name"
   python experiments/run_evaluation.py --mode llm_enriched --model "model-a-name"
   ```
3. Load Model B in LM Studio
4. Run evaluation:
   ```bash
   python experiments/run_evaluation.py --mode llm --model "model-b-name"
   python experiments/run_evaluation.py --mode llm_enriched --model "model-b-name"
   ```
5. Compare:
   ```bash
   python experiments/analyze_results.py
   ```

## What to record for the thesis

For each model, document:
- Full model name and version
- Quantization level (Q4_K_M, Q5_K_M, etc.)
- Parameter count
- Context window size
- Hardware used (your laptop specs: CPU, RAM, GPU if applicable)

## LM Studio settings

Keep these consistent across models for fair comparison:
- **Temperature:** 0.3 (hardcoded in `lm_studio/client.py`)
- **Max tokens:** default (let the model finish its response)
- **System prompt:** unchanged between runs (loaded from `prompts/system.txt`)
