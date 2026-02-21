from engine.rules.schema import RuleValidationError, load_rules_yaml


def test_empty_ruleset_is_valid(tmp_path):
    p = tmp_path / "empty.yaml"
    p.write_text("rules: []\n", encoding="utf-8")

    ruleset = load_rules_yaml(p)

    assert ruleset.rules == []


def test_duplicate_rule_id_rejected(tmp_path):
    p = tmp_path / "bad.yaml"
    p.write_text(
        """
rules:
  - rule_id: r1
    name: one
  - rule_id: r1
    name: two
""".strip(),
        encoding="utf-8",
    )

    try:
        load_rules_yaml(p)
        assert False, "expected RuleValidationError"
    except RuleValidationError:
        pass


def test_event_predicate_op_and_event_type_together_rejected(tmp_path):
    p = tmp_path / "bad_predicate.yaml"
    p.write_text(
        """
rules:
  - rule_id: r1
    name: bad
    event_predicate:
      op: exec
      event_type: proc_to_file
""".strip(),
        encoding="utf-8",
    )

    try:
        load_rules_yaml(p)
        assert False, "expected RuleValidationError"
    except RuleValidationError as exc:
        assert str(exc) == "event_predicate supports exactly one key: op or event_type"


def test_event_predicate_invalid_key_rejected(tmp_path):
    p = tmp_path / "bad_predicate_key.yaml"
    p.write_text(
        """
rules:
  - rule_id: r1
    name: bad
    event_predicate:
      foo: bar
""".strip(),
        encoding="utf-8",
    )

    try:
        load_rules_yaml(p)
        assert False, "expected RuleValidationError"
    except RuleValidationError as exc:
        assert str(exc) == "event_predicate supports exactly one key: op or event_type"
