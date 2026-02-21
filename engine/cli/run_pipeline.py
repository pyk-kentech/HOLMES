from __future__ import annotations

import argparse
import json
from pathlib import Path

from engine.core.graph import ProvenanceGraph
from engine.core.matcher import Matcher
from engine.hsg.builder import build_hsg, hsg_to_dict
from engine.hsg.scorer import rank_hsg_scenarios
from engine.io.events import load_events_jsonl
from engine.noise.filter import apply_noise_filter, build_noise_counts, load_noise_config
from engine.rules.schema import load_rules_yaml


def run_pipeline(
    events_path: str,
    rules_path: str,
    output_path: str,
    noise_path: str | None = None,
    alpha: float | None = None,
) -> dict:
    events = load_events_jsonl(events_path)

    graph = ProvenanceGraph()
    graph.add_events(events)

    ruleset = load_rules_yaml(rules_path)
    matcher = Matcher()
    matches_before = matcher.match(graph=graph, ruleset=ruleset, events=events)
    hsg_before = build_hsg(matches_before, graph, ruleset)

    if noise_path:
        noise_config = load_noise_config(noise_path)
        matches_after, hsg_after = apply_noise_filter(matches_before, hsg_before, noise_config)
    else:
        matches_after, hsg_after = matches_before, hsg_before

    noise_counts = build_noise_counts(
        before_matches=len(matches_before),
        before_nodes=len(hsg_before.nodes),
        before_edges=len(hsg_before.edges),
        after_matches=len(matches_after),
        after_nodes=len(hsg_after.nodes),
        after_edges=len(hsg_after.edges),
    )
    rule_severity = {r.rule_id: r.severity for r in ruleset.rules}
    # Priority: rules.yaml scoring.alpha > CLI --alpha > default 1.0
    if ruleset.has_scoring_alpha:
        scoring_alpha = ruleset.scoring_alpha
    elif alpha is not None:
        scoring_alpha = alpha
    else:
        scoring_alpha = 1.0
    top_scenarios = rank_hsg_scenarios(
        hsg_after,
        scoring="weighted",
        rule_severity=rule_severity,
        alpha=scoring_alpha,
        top_k=3,
    )

    result = {
        "summary": {
            "events": len(events),
            "rules": len(ruleset.rules),
            "matches": len(matches_after),
            "hsg_nodes": len(hsg_after.nodes),
            "hsg_edges": len(hsg_after.edges),
            "noise_filter": noise_counts,
            "top_scenarios": top_scenarios,
        },
        "matches": [
            {
                "match_id": m.match_id,
                "rule_id": m.rule_id,
                "event_ids": m.event_ids,
                "entities": m.entities,
                "bindings": m.bindings,
                "metadata": m.metadata,
            }
            for m in matches_after
        ],
        "hsg": hsg_to_dict(hsg_after),
    }

    output_dir = Path(output_path)
    output_dir.mkdir(parents=True, exist_ok=True)

    (output_dir / "result.json").write_text(json.dumps(result, indent=2), encoding="utf-8")
    (output_dir / "summary.json").write_text(json.dumps(result["summary"], indent=2), encoding="utf-8")
    (output_dir / "matches.json").write_text(json.dumps(result["matches"], indent=2), encoding="utf-8")
    (output_dir / "hsg.json").write_text(json.dumps(result["hsg"], indent=2), encoding="utf-8")

    return result


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="HOLMES-style APT detection MVP pipeline")
    parser.add_argument("--events", required=True, help="Path to input events JSONL")
    parser.add_argument("--rules", required=True, help="Path to YAML rules file")
    parser.add_argument(
        "--out",
        "--output",
        dest="out",
        required=True,
        help="Path to output directory (result.json/summary.json/matches.json/hsg.json)",
    )
    parser.add_argument(
        "--noise",
        dest="noise",
        default=None,
        help="Path to static noise config YAML (optional; when omitted no noise filter is applied)",
    )
    parser.add_argument(
        "--alpha",
        dest="alpha",
        type=float,
        default=None,
        help="Weighted-scenario alpha (severity + alpha*weight). Overridden by rules scoring.alpha if set.",
    )
    return parser


def main() -> int:
    args = _build_parser().parse_args()
    run_pipeline(
        events_path=args.events,
        rules_path=args.rules,
        output_path=args.out,
        noise_path=args.noise,
        alpha=args.alpha,
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
