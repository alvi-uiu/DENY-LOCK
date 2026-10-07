# RouteAroundBench Data

`routearoundbench_v1.spec.json` is the versioned specification of RouteAroundBench v1. `RouteAroundBench.from_spec` expands it deterministically into 180 fully specified scenarios, and `RouteAroundBench.materialize` writes the expanded JSONL and a manifest with its SHA-256 digest.

Witness plans are part of each generated scenario and are used by the validator; they are never included in model prompts.
