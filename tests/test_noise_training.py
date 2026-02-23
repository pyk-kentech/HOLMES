import json
from pathlib import Path

from engine.cli.run_pipeline import run_pipeline, train_noise_model_pipeline


def _write_minimal_rules(path: Path) -> None:
    path.write_text(
        "\n".join(
            [
                "rules:",
                "  - rule_id: R_PROC_FILE",
                "    name: proc file",
                "    source_types: [process]",
                "    target_types: [file]",
                "    prerequisites: []",
                "    event_predicate:",
                "      event_type: proc_to_file",
                "    severity: 1",
            ]
        )
        + "\n",
        encoding="utf-8",
    )


def _write_minimal_events(path: Path) -> None:
    path.write_text(
        '{"event_id":"e1","event_type":"proc_to_file","subject":"proc:a","object":"file:x","bytes":42}\n',
        encoding="utf-8",
    )


def test_noise_training_then_detection_suppresses_matching_signature(tmp_path):
    events_path = tmp_path / "events.jsonl"
    rules_path = tmp_path / "rules.yaml"
    out_train = tmp_path / "out_train"
    out_detect = tmp_path / "out_detect"
    model_path = tmp_path / "noise_model.json"
    _write_minimal_events(events_path)
    _write_minimal_rules(rules_path)

    train_noise_model_pipeline(
        train_events_path=str(events_path),
        rules_path=str(rules_path),
        output_path=str(out_train),
        save_noise_model_path=str(model_path),
        min_count=1,
    )
    assert model_path.exists()
    saved = json.loads(model_path.read_text(encoding="utf-8"))
    assert saved["version"] == 1
    assert saved["benign_signatures"]

    result = run_pipeline(
        events_path=str(events_path),
        rules_path=str(rules_path),
        output_path=str(out_detect),
        noise_model_path=str(model_path),
    )
    noise = result["summary"]["noise_filter"]
    assert noise["dropped"]["matches"] == 1
    assert noise["after"]["matches"] == 0
    assert noise["after"]["hsg_nodes"] < noise["before"]["hsg_nodes"]


def test_noise_model_not_used_keeps_legacy_behavior(tmp_path):
    events_path = tmp_path / "events.jsonl"
    rules_path = tmp_path / "rules.yaml"
    out_train = tmp_path / "out_train"
    out_no_model = tmp_path / "out_no_model"
    model_path = tmp_path / "noise_model.json"
    _write_minimal_events(events_path)
    _write_minimal_rules(rules_path)

    train_noise_model_pipeline(
        train_events_path=str(events_path),
        rules_path=str(rules_path),
        output_path=str(out_train),
        save_noise_model_path=str(model_path),
        min_count=1,
    )

    result = run_pipeline(
        events_path=str(events_path),
        rules_path=str(rules_path),
        output_path=str(out_no_model),
    )
    noise = result["summary"]["noise_filter"]
    assert noise["dropped"]["matches"] == 0
    assert noise["after"]["matches"] == noise["before"]["matches"] == 1
