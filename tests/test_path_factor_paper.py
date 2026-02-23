import pytest

from engine.core.graph import ProvenanceGraph
from engine.io.events import Event


def test_path_factor_paper_self_is_one():
    g = ProvenanceGraph()
    g.add_event(Event(event_id="e1", ts=None, event_type="flow", subject="proc:A", object="file:X", raw={}))

    assert g.path_factor("proc:A", "proc:A") == 1.0


def test_path_factor_paper_non_process_propagates_one():
    g = ProvenanceGraph()
    g.add_event(Event(event_id="e1", ts=None, event_type="flow", subject="proc:A", object="file:X", raw={}))

    assert g.path_factor("proc:A", "file:X") == 1.0


def test_path_factor_paper_process_without_common_ancestor_increments():
    g = ProvenanceGraph()
    # 'flow' keeps process lineage independent, so proc:C has no common ancestor with proc:A.
    g.add_event(Event(event_id="e1", ts=None, event_type="flow", subject="proc:A", object="proc:C", raw={}))

    assert g.path_factor("proc:A", "proc:C") > 1.0
    assert g.path_factor("proc:A", "proc:C") == 2.0


def test_path_factor_paper_multi_path_uses_minimum():
    g = ProvenanceGraph()
    g.add_events(
        [
            Event(event_id="e1", ts=None, event_type="flow", subject="proc:A", object="proc:P1", raw={}),
            Event(event_id="e2", ts=None, event_type="flow", subject="proc:P1", object="file:D", raw={}),
            Event(event_id="e3", ts=None, event_type="flow", subject="proc:A", object="file:F", raw={}),
            Event(event_id="e4", ts=None, event_type="flow", subject="file:F", object="file:D", raw={}),
        ]
    )

    # Path via proc:P1 yields 2, path via file:F yields 1. Minimum should be chosen.
    assert g.path_factor("proc:A", "file:D") == pytest.approx(1.0)
