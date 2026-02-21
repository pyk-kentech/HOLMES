import json
from pathlib import Path

from engine.cli.run_pipeline import run_pipeline


def test_noise_filter_records_before_after_counts(tmp_path):
    events_path = tmp_path / "events.jsonl"
    rules_path = tmp_path / "rules.yaml"
    noise_path = tmp_path / "noise.yaml"
    out_dir = tmp_path / "out"

    events_path.write_text(
        '{"event_id":"e1","op":"exec","event_type":"exec","subject":"proc:p","object":"file:/bin/x"}\n',
        encoding="utf-8",
    )
    rules_path.write_text(
        "\n".join(
            [
                "rules:",
                "  - rule_id: r_keep_1",
                "    name: test",
                "    event_predicate:",
                "      op: exec",
                "  - rule_id: r_keep_2",
                "    name: test",
                "    event_predicate:",
                "      op: exec",
                "  - rule_id: r_drop",
                "    name: test",
                "    event_predicate:",
                "      op: exec",
            ]
        )
        + "\n",
        encoding="utf-8",
    )
    noise_path.write_text(
        "\n".join(
            [
                "drop:",
                "  rule_id: [r_drop]",
                "  prerequisite_type: [shared_entity]",
            ]
        )
        + "\n",
        encoding="utf-8",
    )

    result = run_pipeline(str(events_path), str(rules_path), str(out_dir), noise_path=str(noise_path))
    summary = result["summary"]
    noise = summary["noise_filter"]

    assert noise["before"]["matches"] == 3
    assert noise["before"]["hsg_nodes"] == 3
    assert noise["before"]["hsg_edges"] == 0
    assert noise["after"]["matches"] == 2
    assert noise["after"]["hsg_nodes"] == 2
    assert noise["after"]["hsg_edges"] == 0
    assert noise["dropped"]["matches"] == 1
    assert noise["dropped"]["hsg_edges"] == 0

    on_disk_summary = json.loads((out_dir / "summary.json").read_text(encoding="utf-8"))
    assert on_disk_summary["noise_filter"]["after"]["matches"] == 2


def test_noise_filter_drop_rule_ids_affects_final_outputs_with_sample_data(tmp_path):
    repo_root = Path(__file__).resolve().parents[1]
    events_path = repo_root / "experiments" / "sample.jsonl"
    rules_path = repo_root / "rules" / "test_rules.yaml"
    noise_path = tmp_path / "noise.yaml"
    out_dir = tmp_path / "out"

    noise_path.write_text("drop_rule_ids: [TEST_PROC_TO_FILE]\n", encoding="utf-8")

    run_pipeline(str(events_path), str(rules_path), str(out_dir), noise_path=str(noise_path))

    matches = json.loads((out_dir / "matches.json").read_text(encoding="utf-8"))
    summary = json.loads((out_dir / "summary.json").read_text(encoding="utf-8"))
    result = json.loads((out_dir / "result.json").read_text(encoding="utf-8"))

    assert summary["matches"] == 2
    assert result["summary"]["matches"] == 2
    assert summary["noise_filter"]["before"]["matches"] == 4
    assert summary["noise_filter"]["after"]["matches"] == 2
    assert summary["noise_filter"]["dropped"]["matches"] == 2
    assert len(matches) == 2
    assert [m["rule_id"] for m in matches] == ["TEST_FILE_TO_IP", "TEST_PROC_TO_PROC"]
