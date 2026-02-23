import json
from pathlib import Path

from engine.cli.run_pipeline import run_pipeline
from engine.rules.schema import load_rules_yaml
from engine.stream.runner import StreamingEngine
from engine.stream.source import FileJsonlSource


def test_streaming_engine_file_source_builds_hsg_and_matches_batch_summary(tmp_path):
    repo_root = Path(__file__).resolve().parents[1]
    events_path = repo_root / "experiments" / "sample.jsonl"
    rules_path = repo_root / "rules" / "test_rules.yaml"
    out_stream = tmp_path / "out_stream"
    out_batch = tmp_path / "out_batch"

    ruleset = load_rules_yaml(rules_path)
    engine = StreamingEngine(
        ruleset=ruleset,
        scoring_mode="paper",
        paper_weights=[1.0] * 7,
        paper_mode="strict",
    )
    for ev in FileJsonlSource(events_path, follow=False):
        engine.process_event(ev)
    stream_result = engine.write_snapshot(out_stream)

    batch_result = run_pipeline(
        events_path=str(events_path),
        rules_path=str(rules_path),
        output_path=str(out_batch),
        scoring_mode="paper",
        paper_mode="strict",
    )

    hsg = json.loads((out_stream / "hsg.json").read_text(encoding="utf-8"))
    assert any(e.get("relation") == "graph_path" for e in hsg.get("edges", []))
    assert stream_result["summary"]["events"] == batch_result["summary"]["events"]
    assert stream_result["summary"]["matches"] == batch_result["summary"]["matches"]
    assert stream_result["summary"]["hsg_edges"] == batch_result["summary"]["hsg_edges"]
