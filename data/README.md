# RouteAroundBench data

`routearoundbench_v1.spec.json` is the versioned source specification. It fixes the benchmark name, version, scenario counts, domains, route families, horizon, seed base, and request-framing labels.

`RouteAroundBench.from_spec` deterministically expands this file into 180 fully specified scenarios. `RouteAroundBench.materialize` writes the expanded JSONL and a manifest containing its SHA-256 digest. Witness plans are included in the research artifact for validation but are not placed in model prompts.

The expanded JSONL and manifest are intentionally absent until materialization is explicitly run. This prevents an unvalidated generated artifact from being mistaken for collected experimental data.
