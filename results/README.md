# Final paper results

| Directory | Experiment |
|---|---|
| `accuracy` | 477 cases × 3 harnesses × 2 evidence conditions = 2,862 views |
| `components` | Rules, LLM and Hybrid routing comparisons |
| `backends` | DeepSeek, GPT and GLM comparisons |
| `evidence-ablation` | Full plus E1 Contract, E1 Field, E2 Association, E3 State, E3 Delivery and E4 Closure; 3,231 applicable views |
| `performance` | Local processing, process scaling and real Hybrid latency measurements |
| `prompt-stability` | 12 candidate tasks × 5 independent validation trials |
| `live-cases` | 3 tasks, 10 conditions × 5 runs; 50 executions and 350 evidence views |

Run `python3 tools/validate_reports.py` from the repository root. It independently checks outcome counts, the evidence-ablation confidence intervals and measured performance summaries. Failures and Uncertain outcomes remain in the corresponding denominators.

Control batches must remain separate: evidence-ablation Full accuracy is 89.31%, while cross-harness OpenCode Full is 89.52%. Performance-run responses also do not replace the accuracy experiment's responses.
