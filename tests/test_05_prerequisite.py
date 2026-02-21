from engine.core.graph import ProvenanceGraph
from engine.core.matcher import TTPMatch
from engine.hsg.prerequisite import is_prerequisite_satisfied
from engine.io.events import Event


def test_prerequisite_shared_entity_satisfied_when_binding_key_value_matches():
    g = ProvenanceGraph()
    m1 = TTPMatch(match_id="m1", rule_id="r1", event_ids=["e1"], entities=["p1"], bindings={"process": "p1"})
    m2 = TTPMatch(match_id="m2", rule_id="r2", event_ids=["e2"], entities=["p2"], bindings={"process": "p1"})

    assert is_prerequisite_satisfied(g, m1, m2, "shared_entity")


def test_prerequisite_shared_entity_not_satisfied_when_binding_differs():
    g = ProvenanceGraph()
    m1 = TTPMatch(match_id="m1", rule_id="r1", event_ids=["e1"], entities=["p1"], bindings={"process": "p1"})
    m2 = TTPMatch(match_id="m2", rule_id="r2", event_ids=["e2"], entities=["p2"], bindings={"process": "p2"})

    assert not is_prerequisite_satisfied(g, m1, m2, "shared_entity")


def test_prerequisite_graph_path_satisfied_when_path_exists():
    g = ProvenanceGraph()
    g.add_events(
        [
            Event(event_id="e1", ts=None, event_type="flow", subject="proc:a", object="file:x", raw={}),
            Event(event_id="e2", ts=None, event_type="flow", subject="file:x", object="ip:1.2.3.4", raw={}),
        ]
    )
    m1 = TTPMatch(
        match_id="m1",
        rule_id="r1",
        event_ids=["e1"],
        entities=["proc:a"],
        bindings={"src_proc": "proc:a"},
    )
    m2 = TTPMatch(
        match_id="m2",
        rule_id="r2",
        event_ids=["e2"],
        entities=["ip:1.2.3.4"],
        bindings={"dst_ip": "ip:1.2.3.4"},
    )

    assert is_prerequisite_satisfied(
        g,
        m1,
        m2,
        "graph_path",
        {"from_binding": "src_proc", "to_binding": "dst_ip"},
    )


def test_prerequisite_graph_path_not_satisfied_when_no_path():
    g = ProvenanceGraph()
    g.add_event(Event(event_id="e1", ts=None, event_type="flow", subject="proc:a", object="file:x", raw={}))
    m1 = TTPMatch(
        match_id="m1",
        rule_id="r1",
        event_ids=["e1"],
        entities=["proc:a"],
        bindings={"src_proc": "proc:a"},
    )
    m2 = TTPMatch(
        match_id="m2",
        rule_id="r2",
        event_ids=["e2"],
        entities=["ip:9.9.9.9"],
        bindings={"dst_ip": "ip:9.9.9.9"},
    )

    assert not is_prerequisite_satisfied(
        g,
        m1,
        m2,
        "graph_path",
        {"from_binding": "src_proc", "to_binding": "dst_ip"},
    )


def test_prerequisite_graph_path_min_strength_passes_threshold():
    g = ProvenanceGraph()
    g.add_event(Event(event_id="e1", ts=None, event_type="flow", subject="a", object="b", raw={}))
    m1 = TTPMatch(match_id="m1", rule_id="r1", event_ids=["e1"], entities=["a"], bindings={"from": "a"})
    m2 = TTPMatch(match_id="m2", rule_id="r2", event_ids=["e2"], entities=["b"], bindings={"to": "b"})

    # a -> b direct edge: strength = 1 / (1 + 1) = 0.5
    assert is_prerequisite_satisfied(
        g,
        m1,
        m2,
        "graph_path",
        {"from_binding": "from", "to_binding": "to", "min_strength": 0.5},
    )


def test_prerequisite_graph_path_min_strength_fails_threshold():
    g = ProvenanceGraph()
    g.add_event(Event(event_id="e1", ts=None, event_type="flow", subject="a", object="b", raw={}))
    m1 = TTPMatch(match_id="m1", rule_id="r1", event_ids=["e1"], entities=["a"], bindings={"from": "a"})
    m2 = TTPMatch(match_id="m2", rule_id="r2", event_ids=["e2"], entities=["b"], bindings={"to": "b"})

    # a -> b direct edge: strength = 0.5, so 0.51 should fail.
    assert not is_prerequisite_satisfied(
        g,
        m1,
        m2,
        "graph_path",
        {"from_binding": "from", "to_binding": "to", "min_strength": 0.51},
    )
