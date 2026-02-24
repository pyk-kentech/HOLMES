from engine.core.graph import ProvenanceGraph
from engine.core.matcher import TTPMatch
from engine.hsg.builder import build_hsg
from engine.io.events import Event
from engine.rules.schema import Rule, RuleSet


def test_prerequisite_empty_rule_is_immediately_active_in_hsg():
    g = ProvenanceGraph()
    g.add_event(Event(event_id="e1", ts=None, event_type="proc_to_file", subject="proc:a", object="file:x", raw={}))
    matches = [
        TTPMatch(
            match_id="m1",
            rule_id="R_A",
            event_ids=["e1"],
            entities=["proc:a", "file:x"],
            bindings={"subject": "proc:a", "object": "file:x"},
        )
    ]
    ruleset = RuleSet(rules=[Rule(rule_id="R_A", name="a", prerequisites=[])])

    hsg = build_hsg(matches, g, ruleset)

    assert [n.match_id for n in hsg.nodes] == ["m1"]


def test_graph_path_prerequisite_stays_pending_without_connectivity():
    g = ProvenanceGraph()
    g.add_events(
        [
            Event(event_id="e1", ts=None, event_type="proc_to_file", subject="proc:a", object="file:a", raw={}),
            Event(event_id="e2", ts=None, event_type="file_to_ip", subject="file:b", object="ip:1.2.3.4", raw={}),
        ]
    )
    matches = [
        TTPMatch(
            match_id="m1",
            rule_id="R_A",
            event_ids=["e1"],
            entities=["proc:a", "file:a"],
            bindings={"subject": "proc:a", "object": "file:a"},
        ),
        TTPMatch(
            match_id="m2",
            rule_id="R_B",
            event_ids=["e2"],
            entities=["file:b", "ip:1.2.3.4"],
            bindings={"subject": "file:b", "object": "ip:1.2.3.4"},
        ),
    ]
    ruleset = RuleSet(
        rules=[
            Rule(rule_id="R_A", name="a", prerequisites=[]),
            Rule(rule_id="R_B", name="b", prerequisites=["graph_path"]),
        ]
    )

    hsg = build_hsg(matches, g, ruleset)
    node_ids = {n.match_id for n in hsg.nodes}

    assert "m1" in node_ids
    assert "m2" not in node_ids
    assert all(e.relation != "graph_path" for e in hsg.edges)


def test_graph_path_prerequisite_promotes_pending_match_when_satisfied():
    g = ProvenanceGraph()
    g.add_events(
        [
            Event(event_id="e1", ts=None, event_type="proc_to_file", subject="proc:a", object="file:x", raw={}),
            Event(event_id="e2", ts=None, event_type="file_to_ip", subject="file:x", object="ip:z", raw={}),
        ]
    )
    matches = [
        TTPMatch(
            match_id="m1",
            rule_id="R_A",
            event_ids=["e1"],
            entities=["proc:a", "file:x"],
            bindings={"subject": "proc:a", "object": "file:x"},
        ),
        TTPMatch(
            match_id="m2",
            rule_id="R_B",
            event_ids=["e2"],
            entities=["file:x", "ip:z"],
            bindings={"subject": "file:x", "object": "ip:z"},
        ),
    ]
    ruleset = RuleSet(
        rules=[
            Rule(rule_id="R_A", name="a", prerequisites=[]),
            Rule(rule_id="R_B", name="b", prerequisites=["graph_path"]),
        ]
    )

    hsg = build_hsg(matches, g, ruleset)
    node_ids = {n.match_id for n in hsg.nodes}

    assert "m1" in node_ids
    assert "m2" in node_ids
    assert any(e.relation == "graph_path" and e.src == "m1" and e.dst == "m2" for e in hsg.edges)
