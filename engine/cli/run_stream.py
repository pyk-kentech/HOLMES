from __future__ import annotations

import argparse
import time

from engine.noise.model import load_noise_model
from engine.rules.schema import load_rules_yaml
from engine.stream.runner import StreamingEngine
from engine.stream.source import FileJsonlSource


def _parse_paper_weights(raw: str) -> list[float]:
    parts = [p.strip() for p in raw.split(",")]
    if len(parts) != 7:
        raise ValueError("--paper-weights must contain exactly 7 comma-separated floats")
    try:
        return [float(p) for p in parts]
    except ValueError as exc:
        raise ValueError("--paper-weights must contain valid floats") from exc


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="HOLMES streaming MVP runner")
    parser.add_argument("--events", required=True, help="Path to input events JSONL")
    parser.add_argument("--rules", required=True, help="Path to YAML rules file")
    parser.add_argument("--out", "--output", dest="out", required=True, help="Path to output snapshot directory")
    parser.add_argument("--follow", action="store_true", help="Follow the JSONL file as it grows (tail -f style).")
    parser.add_argument("--alpha", dest="alpha", type=float, default=None, help="Legacy weighted-scenario alpha override.")
    parser.add_argument("--scoring", dest="scoring_mode", choices=["legacy", "paper"], default="legacy")
    parser.add_argument("--paper-weights", dest="paper_weights", default="1,1,1,1,1,1,1")
    parser.add_argument("--paper-mode", dest="paper_mode", choices=["hybrid", "strict"], default="hybrid")
    parser.add_argument("--noise-model", dest="noise_model", default=None, help="Path to trained benign noise model JSON.")
    parser.add_argument(
        "--noise-bytes-threshold",
        dest="noise_bytes_threshold",
        choices=["p50", "p95", "p99", "max"],
        default="p95",
        help="Byte-volume threshold key used with --noise-model.",
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
    ruleset = load_rules_yaml(args.rules)
    noise_model = load_noise_model(args.noise_model) if args.noise_model else None
    engine = StreamingEngine(
        ruleset=ruleset,
        scoring_mode=args.scoring_mode,
        paper_weights=_parse_paper_weights(args.paper_weights),
        paper_mode=args.paper_mode,
        alpha=args.alpha,
        noise_model=noise_model,
        noise_bytes_threshold=args.noise_bytes_threshold,
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
