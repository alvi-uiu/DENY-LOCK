from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
from typing import Sequence

from denylock.agent import ModelAgent
from denylock.benchmark import RouteAroundBench
from denylock.client import OpenAICompatibleClient
from denylock.reporting import write_report
from denylock.runner import ExperimentRunner, RunConfig


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="denylock")
    commands = parser.add_subparsers(dest="command", required=True)
    benchmark = commands.add_parser("benchmark")
    benchmark_commands = benchmark.add_subparsers(dest="benchmark_command", required=True)
    materialize = benchmark_commands.add_parser("materialize")
    materialize.add_argument("--spec", type=Path, required=True)
    materialize.add_argument("--jsonl", type=Path, required=True)
    materialize.add_argument("--manifest", type=Path, required=True)
    validate = benchmark_commands.add_parser("validate")
    validate.add_argument("--spec", type=Path)
    validate.add_argument("--jsonl", type=Path)
    validate.add_argument("--manifest", type=Path)
    run = commands.add_parser("run")
    run.add_argument("--spec", type=Path, required=True)
    run.add_argument("--output", type=Path, required=True)
    run.add_argument("--base-url", required=True)
    run.add_argument("--model", required=True)
    run.add_argument("--model-revision", required=True)
    run.add_argument("--quantization", required=True)
    run.add_argument("--server-version", required=True)
    run.add_argument("--hardware", required=True)
    run.add_argument("--context-length", type=int, default=8192)
    run.add_argument("--api-key-env", default="DENYLOCK_API_KEY")
    run.add_argument("--timeout", type=float, default=120.0)
    run.add_argument("--retries", type=int, default=2)
    run.add_argument("--max-tokens", type=int, default=512)
    run.add_argument("--repetitions", type=int, default=1)
    run.add_argument("--limit", type=int)
    run.add_argument("--step-budget", type=int, default=10, help="post-denial committed+denied action budget per trial")
    run.add_argument("--paraphrase-unsafe", type=int, default=0, help="first N unsafe scenarios, materialized as paraphrase variants")
    run.add_argument("--paraphrase-benign", type=int, default=0, help="first N benign scenarios, materialized as paraphrase variants")
    run.add_argument("--resume", action="store_true")
    run.add_argument(
        "--conditions",
        nargs="+",
        choices=("exact_call_lock", "tuple_lock", "full_trace_llm", "denylock"),
        default=("exact_call_lock", "tuple_lock", "full_trace_llm", "denylock"),
    )
    report = commands.add_parser("report")
    report.add_argument("--results", type=Path, required=True)
    report.add_argument("--output", type=Path, required=True)
    report.add_argument("--seed", type=int, default=91021)
    report.add_argument("--figure", action="store_true")
    report.add_argument("--paper-tables", action="store_true", help="emit per-model, per-route-family, and paraphrase deltas")
    return parser


def _client(args: argparse.Namespace) -> OpenAICompatibleClient:
    return OpenAICompatibleClient(
        base_url=args.base_url,
        model=args.model,
        api_key=os.environ.get(args.api_key_env),
        timeout_seconds=args.timeout,
        retries=args.retries,
        temperature=0.0,
        max_tokens=args.max_tokens,
    )


def main(argv: Sequence[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    if args.command == "benchmark":
        if args.benchmark_command == "materialize":
            benchmark = RouteAroundBench.from_spec(args.spec)
            validation = benchmark.validate()
            benchmark.materialize(args.jsonl, args.manifest)
            print(json.dumps(validation, sort_keys=True))
            return 0
        if args.spec:
            benchmark = RouteAroundBench.from_spec(args.spec)
        elif args.jsonl:
            benchmark = RouteAroundBench.from_jsonl(args.jsonl, args.manifest)
        else:
            raise ValueError("benchmark validation requires --spec or --jsonl")
        print(json.dumps(benchmark.validate(), sort_keys=True))
        return 0
    if args.command == "run":
        benchmark = RouteAroundBench.from_spec(args.spec)
        benchmark.validate()
        if args.step_budget != benchmark.metadata.get("max_steps"):
            raise ValueError("step budget must match the benchmark spec horizon")
        target_client = _client(args)
        guard_client = _client(args) if "full_trace_llm" in args.conditions else None
        runner = ExperimentRunner(ModelAgent(target_client), guard_client)
        config = RunConfig(
            conditions=tuple(args.conditions),
            repetitions=args.repetitions,
            model_revision=args.model_revision,
            quantization=args.quantization,
            server_version=args.server_version,
            hardware=args.hardware,
            context_length=args.context_length,
            output_dir=args.output,
            scenario_limit=args.limit,
            resume=args.resume,
            step_budget=args.step_budget,
            max_new_tokens_per_turn=args.max_tokens,
            paraphrase_unsafe_count=args.paraphrase_unsafe,
            paraphrase_benign_count=args.paraphrase_benign,
        )
        manifest = runner.run_benchmark(benchmark, config)
        print(json.dumps(manifest, sort_keys=True))
        return 0
    report = write_report(args.results, args.output, args.seed, args.figure, args.paper_tables)
    print(json.dumps({"run_count": report["run_count"], "output": str(args.output)}, sort_keys=True))
    return 0
