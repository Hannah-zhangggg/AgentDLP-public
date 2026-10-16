# AgentDLP

AgentDLP checks whether an agent's observed tool behavior follows captured model instructions and applicable tool contracts. It separates invocation, resource effects, native returns, and result delivery. Rules return Consistent, Inconsistent, or Uncertain; Hybrid analysis uses an LLM for unresolved decisions.

This repository contains the selected final paper artifacts. This release is prepared from a clean source snapshot.

## Quick start: reproduce reported statistics

```bash
python3 tools/recompute.py
python3 tools/validate_reports.py
```

These commands use the Python standard library, make no model requests, and check the published numerical outcomes, paired confidence intervals, and performance summaries. Generated reports go to `validation/`.

## Run the detector on your own evidence

```bash
python3 -m venv .venv
.venv/bin/python -m pip install -r requirements/replay.txt
.venv/bin/python -I tools/detect.py --help
.venv/bin/python -I tools/detect.py --view view.json --contract contract.json --output decision.json
```

Inputs must be normalized evidence and the corresponding public tool contract; evaluation labels are not detector inputs. Without a saved response or explicit `--live`, unresolved cases remain Uncertain. `--live` uses the frozen DeepSeek V4 Flash transport and requires `DEEPSEEK_API_KEY`; it makes a billable provider request.

## Contents

| Directory | Purpose |
|---|---|
| `src/consistency/` | Final detector and its imported dependencies |
| `collectors/` | eBPF and native observation source |
| `deployment/` | Capture infrastructure, host helpers, and configuration templates |
| `experiments/live-cases/frozen-code/` | Archived orchestration, instrumentation, and injection source |
| `config/` | Frozen detector prompt |
| `results/` | Final decision tables and measured results |
| `tools/` | Detection, statistics verification, and optional local replay entry points |
| `requirements/` | Detector dependencies and recorded live-tool versions |
| `licenses/` | Upstream notices and license inventory |

See [results](results/README.md), [deployment scope](deployment/README.md), and [publication scope](PUBLICATION_SCOPE.md).

## Reproduction scope

Public statistics can be recomputed from this checkout. Complete detector replay additionally needs lawful normalized evidence, contracts, saved packets and model responses in `local-data/`, and expected outcomes in `evaluation/`; these are not included here. The optional `replay.py`, `replay_models.py`, and `case.py` tools support that local archive. Statistics recomputation is not a new agent execution or a new model evaluation.

The local archive was checked on 6,443 detector views and 2,862 backend response records. Those checks are not claimed to have run from this data-restricted public checkout. This checkout is separately checked for statistics reproduction and detector imports.

## License status

AgentDLP-owned source code is licensed under [Apache License 2.0](LICENSE). This license does not relicense third-party material or grant a separate license for the published numerical result records or documentation. See [LICENSE-STATUS.json](LICENSE-STATUS.json) and [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md). Protected AppWorld data and raw evidence are excluded.
