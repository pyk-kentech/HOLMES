import json
from pathlib import Path

from engine.cli import run_stream
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


def test_run_stream_writes_resolved_effective_config(monkeypatch, tmp_path):
    repo_root = Path(__file__).resolve().parents[1]
    events_path = repo_root / "experiments" / "sample.jsonl"
    rules_path = repo_root / "rules" / "test_rules.yaml"
    out_dir = tmp_path / "out_stream_cli"

    monkeypatch.setattr(
        "sys.argv",
        [
            "run_stream.py",
            "--events",
            str(events_path),
            "--rules",
            str(rules_path),
            "--out",
            str(out_dir),
            "--scoring",
            "paper",
            "--paper-mode",
            "strict",
            "--paper-weights",
            "1.1,1.2,1.3,1.4,1.5,1.6,1.7",
            "--snapshot-every",
            "1000",
        ],
    )
    rc = run_stream.main()
    assert rc == 0

    summary = json.loads((out_dir / "summary.json").read_text(encoding="utf-8"))
    resolved = summary["resolved_effective_config"]
    assert resolved == {
        "path_thres": 3.0,
        "path_factor_op": "le",
        "scoring": "paper",
        "paper_mode": "strict",
        "paper_weights": [1.1, 1.2, 1.3, 1.4, 1.5, 1.6, 1.7],
    }
    ps = summary["paper_scoring"]
    assert "threat_tuple" in ps
    assert "stage_severity" in ps
    assert "paper_weights" in ps
    assert "score_paper" in ps
