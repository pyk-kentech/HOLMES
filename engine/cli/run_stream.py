from __future__ import annotations

import argparse
import time

from engine.cli.run_pipeline import _parse_paper_weights, _resolve_effective_config
from engine.hsg.builder import load_graph_path_allowlist
from engine.noise.model import load_noise_model
from engine.rules.schema import load_rules_yaml
from engine.stream.runner import StreamingEngine
from engine.stream.source import FileJsonlSource


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="HOLMES streaming MVP runner")
    parser.add_argument("--events", required=True, help="Path to input events JSONL")
    parser.add_argument("--rules", required=True, help="Path to YAML rules file")
    parser.add_argument("--out", "--output", dest="out", required=True, help="Path to output snapshot directory")
    parser.add_argument("--follow", action="store_true", help="Follow the JSONL file as it grows (tail -f style).")
    parser.add_argument("--alpha", dest="alpha", type=float, default=None, help="Legacy weighted-scenario alpha override.")
    parser.add_argument(
        "--scoring",
        dest="scoring_mode",
        choices=["legacy", "paper"],
        default="legacy",
        help="Scenario scoring mode (legacy additive or paper weighted-product).",
    )
    parser.add_argument(
        "--paper-weights",
        dest="paper_weights",
        default="1,1,1,1,1,1,1",
        help="Comma-separated 7 floats for paper weighted-product scoring.",
    )
    parser.add_argument(
        "--paper-mode",
        dest="paper_mode",
        choices=["hybrid", "strict"],
        default="hybrid",
        help="graph_path edge-weight mode: hybrid=dependency_strength*path_factor, strict=path_factor.",
    )
    parser.add_argument(
        "--min-path-factor",
        dest="min_path_factor",
        type=float,
        default=None,
        help=(
            "Path-factor threshold. In paper mode this is interpreted as path_thres. "
            "Resolver default is 3 only when scoring=paper and value is omitted."
        ),
    )
    parser.add_argument(
        "--path-factor-op",
        dest="path_factor_op",
        choices=["ge", "le"],
        default=None,
        help=(
            "Path-factor threshold direction. Resolver default is le for scoring=paper "
            "and ge for scoring=legacy when omitted."
        ),
    )
    parser.add_argument(
        "--prereq-policy",
        dest="prereq_policy",
        choices=["dst_only", "union"],
        default="union",
        help="Prerequisite relation policy: union keeps legacy behavior; dst_only uses only destination rule prerequisites.",
    )
    parser.add_argument(
        "--graph-path-allowlist",
        dest="graph_path_allowlist",
        default="none",
        help="Optional allowlist file for graph_path rule pairs; use 'none' to disable (default).",
    )
    parser.add_argument(
        "--max-graph-path-edges",
        dest="max_graph_path_edges",
        type=int,
        default=10000,
        help="Maximum number of graph_path edges to create (default: 10000).",
    )
    parser.add_argument(
        "--max-graph-path-candidates-per-match",
        dest="max_graph_path_candidates_per_match",
        type=int,
        default=200,
        help="Maximum graph_path destination candidates evaluated per source match (default: 200).",
    )
    parser.add_argument("--noise-model", dest="noise_model", default=None, help="Path to trained benign noise model JSON.")
    parser.add_argument(
        "--noise-bytes-threshold",
        dest="noise_bytes_threshold",
        choices=["p50", "p95", "p99", "max"],
        default="p95",
        help="Byte-volume threshold key used with --noise-model.",
    )
    parser.add_argument(
        "--noise-signature-min-ratio",
        dest="noise_signature_min_ratio",
        type=float,
        default=0.1,
        help="Minimum benign signature frequency ratio within the same rule_id needed to drop (default: 0.1).",
    )
    parser.add_argument("--snapshot-every", dest="snapshot_every", type=int, default=10, help="Write snapshot every N events.")
    parser.add_argument(
        "--snapshot-interval-sec",
        dest="snapshot_interval_sec",
        type=float,
        default=5.0,
        help="When --follow, force periodic snapshots after this interval.",
    )
    return parser


def main() -> int:
    args = _build_parser().parse_args()
    resolved_effective_config = _resolve_effective_config(
        scoring_mode=args.scoring_mode,
        paper_mode=args.paper_mode,
        paper_weights=args.paper_weights,
        min_path_factor=args.min_path_factor,
        path_factor_op=args.path_factor_op,
    )
    ruleset = load_rules_yaml(args.rules)
    noise_model = load_noise_model(args.noise_model) if args.noise_model else None
    allowlist = load_graph_path_allowlist(args.graph_path_allowlist)
    engine = StreamingEngine(
        ruleset=ruleset,
        scoring_mode=str(resolved_effective_config["scoring"]),
        paper_weights=list(resolved_effective_config["paper_weights"]),
        paper_mode=str(resolved_effective_config["paper_mode"]),
        resolved_effective_config=resolved_effective_config,
        prereq_policy=args.prereq_policy,
        alpha=args.alpha,
        noise_model=noise_model,
        noise_bytes_threshold=args.noise_bytes_threshold,
        noise_signature_min_ratio=max(0.0, min(1.0, float(args.noise_signature_min_ratio))),
        graph_path_allowlist=allowlist,
        max_graph_path_edges=args.max_graph_path_edges,
        max_graph_path_candidates_per_match=args.max_graph_path_candidates_per_match,
    )
    source = FileJsonlSource(args.events, follow=args.follow)

    event_count = 0
    last_snapshot = time.monotonic()
    for event in source:
        engine.process_event(event)
        event_count += 1
        should_snapshot = args.snapshot_every > 0 and (event_count % args.snapshot_every == 0)
        if not should_snapshot and args.follow:
            should_snapshot = (time.monotonic() - last_snapshot) >= float(args.snapshot_interval_sec)
        if should_snapshot:
            engine.write_snapshot(args.out)
            last_snapshot = time.monotonic()

    engine.write_snapshot(args.out)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
