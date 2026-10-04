# DENYLOCK

DENYLOCK is a deterministic post-denial control for tool-using language-model agents. It retains the policy that caused a controlled initial denial, previews each proposed transition on an exact copy of simulator state, checks the complete tentative state, and commits atomically only when every active predicate remains satisfied.

This repository also defines RouteAroundBench v1, a synthetic benchmark for measuring whether an agent reaches a forbidden state through a different tool, cumulative actions, derived-state indirection, or delayed execution after a canonical action has been denied.

The repository contains implementation and benchmark-generation code only. It contains no executed model outputs, measured scores, or paper modifications.

## Scope

- 120 unsafe scenarios and 60 paired benign scenarios
- Files/workspace, finance/commerce, and cloud/IAM simulators
- Tool substitution, cumulative splitting, state indirection, and delayed execution
- Exact-call, tuple-lock, full-trace LLM, and DENYLOCK conditions
- Independent terminal audit oracle
- Hash-chained traces and immutable run manifests
- OpenAI-compatible local API client suitable for a single vLLM server
- No training, reinforcement learning, external accounts, network tools, or real-world side effects

The simulators are closed deterministic state machines. Tool calls can affect only the in-memory state attached to a scenario.

## Project layout

```text
data/routearoundbench_v1.spec.json
schemas/scenario.schema.json
src/denylock/
tests/
configs/models.example.json
validate_e2e.py
BENCHMARK_CARD.md
EXPERIMENT_PROTOCOL.md
SECURITY.md
LICENSE
```

## Installation

```bash
python -m venv .venv
. .venv/bin/activate
python -m pip install -e .
```

Install the optional plotting dependency only when figures are required:

```bash
python -m pip install -e '.[figures]'
```

## Benchmark materialization

The compact specification is the source of truth. Materialization expands the fixed matrix to JSONL and writes a content hash.

```bash
denylock benchmark materialize \
  --spec data/routearoundbench_v1.spec.json \
  --jsonl data/routearoundbench_v1.jsonl \
  --manifest data/routearoundbench_v1.manifest.json
```

Validation recomputes every controlled denial, known unsafe route, benign solution, rollback check, and independent-oracle agreement:

```bash
denylock benchmark validate --spec data/routearoundbench_v1.spec.json
```

## Local model serving

A conservative single-GPU pilot uses one quantized 7B instruction model, one resident vLLM server, greedy decoding, and sequential trials. Pin the model revision before collecting data.

```bash
vllm serve Qwen/Qwen3-8B-AWQ \
  --revision qwen3-8b-awq \
  --host 127.0.0.1 \
  --port 8000 \
  --max-model-len 8192 \
  --gpu-memory-utilization 0.90 \
  --enable-prefix-caching
```

The client reads the optional key from `DENYLOCK_API_KEY`. Keys are never placed in prompts, traces, results, or manifests.

## Pilot execution

Run the deterministic conditions first when model-assisted guarding is omitted:

```bash
denylock run \
  --spec data/routearoundbench_v1.spec.json \
  --output runs/qwen3_8b_pilot \
  --base-url http://127.0.0.1:8000/v1 \
  --model Qwen/Qwen3-8B-AWQ \
  --model-revision qwen3-8b-awq \
  --quantization awq \
  --server-version vllm-0.6.6 \
  --hardware 'NVIDIA RTX 3090 24GB' \
  --context-length 8192 \
  --conditions exact_call_lock tuple_lock denylock \
  --limit 12
```

Add `full_trace_llm` only when its extra inference cost is intended. It uses an independent request context but may use the same locally served model.

## Full execution

```bash
denylock run \
  --spec data/routearoundbench_v1.spec.json \
  --output runs/qwen3_8b_full \
  --base-url http://127.0.0.1:8000/v1 \
  --model Qwen/Qwen3-8B-AWQ \
  --model-revision qwen3-8b-awq \
  --quantization awq \
  --server-version vllm-0.6.6 \
  --hardware 'NVIDIA RTX 3090 24GB' \
  --context-length 8192 \
  --conditions exact_call_lock tuple_lock full_trace_llm denylock \
  --repetitions 3 \
  --step-budget 10 \
  --max-tokens 512
```

Each run writes one result row per trial, one hash-chained trace per trial, and a manifest containing the benchmark hash, prompt hash, decoding settings, model identity, revision field, quantization, platform, enforcement-latency settings, and result hash. The step budget (post-denial committed plus denied actions, fixed to the spec horizon of 10) and the 512-token per-turn generation cap are recorded in the run plan and validated against the benchmark specification.

### Paraphrase subset (paired prompt robustness)

To reproduce the paper's paired prompt-robustness subset (30 unsafe and 15 benign paraphrase scenarios per model), add repetition-level paraphrase slots to any run:

```bash
denylock run ... --repetitions 5 \
  --paraphrase-unsafe 1 --paraphrase-benign 1
```

The final repetitions are then executed on paraphrase variants of the first unsafe and benign scenarios: the task goal wording is rewritten (deterministic prefix/suffix rephrasings from `denylock.benchmark.materialize_paraphrase`) while states, policies, tool schemas, canonical denied actions, oracles, seeds, and scenario identifiers are held fixed. Each result row records `prompt_variant` (`original` or `paraphrase`), and `denylock report --paper-tables` emits per-scenario paraphrase deltas so wording sensitivity can be compared within scenario.

If a process stops before the final manifest is written, repeat the identical command with `--resume`. Stored run-plan equality and per-trial trace integrity are checked before completed records are skipped. A directory containing a completed manifest is immutable to the runner.

## Reporting

```bash
denylock report \
  --results runs/qwen3_8b_full/results.jsonl \
  --output runs/qwen3_8b_full/report \
  --figure
```

The report includes route-around success (RAS; the paper's term for the forbidden-completion rate on unsafe scenarios), benign recovery rate (BRR; completions of benign goals without any policy violation), scenario-cluster bootstrap intervals (10,000 replicates), outcome counts, route/domain slices, token use, per-decision enforcement latency, latency, and paired exact McNemar tests with Holm correction. With `--paper-tables`, it additionally emits the paper's per-model table, per-route-family table, and per-scenario paraphrase deltas under `tables/`.

### Over-activation and ablation conditions

The benign over-activation baseline (BABR; over-blocking rate on the paired benign counterfactuals) is the complement of BRR on benign scenarios and is included in the report summary. The paper's Table 3 ablations are not included as conditions in this release: the action-identity row corresponds to the `exact_call_lock` condition, while the remaining variants are additional DenyLock configurations. The run plan reserves an `ablation_conditions` field for documenting such configurations.

## End-to-end validation without a model

`validate_e2e.py` exercises the entire pipeline deterministically -- benchmark materialization, all four enforcement conditions, the paraphrase subset, resume-safe artifacts, trace verification, and paper-table generation -- using a scripted client that replays witness plans in the agent role and an always-allow client in the guard role. Run it with `python3 validate_e2e.py`; it should print `E2E VALIDATION OK` and a per-condition summary. Under this script the comparators route around (RAS = 1.0) while DenyLock holds at RAS = 0.0, matching the mechanism the paper describes.

## Claim boundary

DENYLOCK is guaranteed to prevent the encoded forbidden predicates only inside the supplied deterministic simulators, assuming complete transition adapters and atomic mediation of every state mutation. The implementation does not establish safety for arbitrary tools, hidden side effects, an incorrect policy, or actions outside the mediator. RouteAroundBench is a controlled diagnostic benchmark, not evidence of general real-world agent safety.
