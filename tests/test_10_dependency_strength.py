import pytest

from engine.core.graph import ProvenanceGraph
from engine.io.events import Event


def test_dependency_strength_one_hop_is_half():
    g = ProvenanceGraph()
    g.add_event(Event(event_id="e1", ts=None, event_type="flow", subject="A", object="B", raw={}))

    assert g.shortest_path_len("A", "B") == 1
    assert g.dependency_strength("A", "B") == 0.5


def test_dependency_strength_two_hop_is_one_third():
    g = ProvenanceGraph()
    g.add_events(
        [
            Event(event_id="e1", ts=None, event_type="flow", subject="A", object="X", raw={}),
            Event(event_id="e2", ts=None, event_type="flow", subject="X", object="B", raw={}),
        ]
    )

    assert g.shortest_path_len("A", "B") == 2
    assert g.dependency_strength("A", "B") == pytest.approx(1.0 / 3.0)


def test_dependency_strength_no_path_is_zero():
    g = ProvenanceGraph()
    g.add_event(Event(event_id="e1", ts=None, event_type="flow", subject="A", object="B", raw={}))
    g.add_event(Event(event_id="e2", ts=None, event_type="flow", subject="C", object="D", raw={}))

    assert g.shortest_path_len("C", "B") is None
    assert g.dependency_strength("C", "B") == 0.0


def test_path_factor_final_weight_decreases_with_longer_path():
    g = ProvenanceGraph()
    g.add_events(
        [
            Event(event_id="e1", ts=None, event_type="flow", subject="A", object="B", raw={}),
            Event(event_id="e2", ts=None, event_type="flow", subject="A", object="X", raw={}),
            Event(event_id="e3", ts=None, event_type="flow", subject="X", object="C", raw={}),
        ]
    )

    w_one_hop = g.dependency_strength("A", "B") * g.path_factor("A", "B")
    w_two_hop = g.dependency_strength("A", "C") * g.path_factor("A", "C")

    assert w_one_hop > w_two_hop
    assert w_one_hop == pytest.approx(0.5)
    assert w_two_hop == pytest.approx(1.0 / 6.0)


def test_path_factor_no_path_is_zero():
    g = ProvenanceGraph()
    g.add_event(Event(event_id="e1", ts=None, event_type="flow", subject="A", object="B", raw={}))

    assert g.path_factor("C", "B") == 0.0
    assert g.dependency_strength("C", "B") * g.path_factor("C", "B") == 0.0
