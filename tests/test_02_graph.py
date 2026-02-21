from engine.core.graph import ProvenanceGraph
from engine.io.events import Event


def test_provenance_graph_path_and_has_path():
    events = [
        Event(event_id="e1", ts=None, event_type="flow", subject="a", object="b", raw={}),
        Event(event_id="e2", ts=None, event_type="flow", subject="b", object="c", raw={}),
    ]

    g = ProvenanceGraph()
    g.add_events(events)

    assert g.has_path("a", "c") is True
    assert g.path("a", "c") == ["a", "b", "c"]
    assert g.has_path("c", "a") is False


def test_op_write_flow_process_to_file():
    g = ProvenanceGraph()
    g.add_event(Event(event_id="e1", ts=None, event_type="write", subject="proc:p", object="file:f", raw={}))
    assert g.has_path("proc:p", "file:f") is True
    assert g.has_path("file:f", "proc:p") is False
    assert g.edges[0].src == "proc:p" and g.edges[0].dst == "file:f"


def test_op_read_flow_file_to_process():
    g = ProvenanceGraph()
    g.add_event(Event(event_id="e1", ts=None, event_type="read", subject="proc:p", object="file:f", raw={}))
    assert g.has_path("file:f", "proc:p") is True
    assert g.has_path("proc:p", "file:f") is False
    assert g.edges[0].src == "file:f" and g.edges[0].dst == "proc:p"


def test_op_exec_flow_file_to_process_new():
    g = ProvenanceGraph()
    g.add_event(Event(event_id="e1", ts=None, event_type="exec", subject="proc:new", object="file:bin", raw={}))
    assert g.has_path("file:bin", "proc:new") is True
    assert g.has_path("proc:new", "file:bin") is False
    assert g.edges[0].src == "file:bin" and g.edges[0].dst == "proc:new"


def test_op_fork_flow_parent_to_child():
    g = ProvenanceGraph()
    g.add_event(Event(event_id="e1", ts=None, event_type="fork", subject="proc:parent", object="proc:child", raw={}))
    assert g.has_path("proc:parent", "proc:child") is True
    assert g.has_path("proc:child", "proc:parent") is False
    assert g.edges[0].src == "proc:parent" and g.edges[0].dst == "proc:child"


def test_op_connect_flow_process_to_socket():
    g = ProvenanceGraph()
    g.add_event(Event(event_id="e1", ts=None, event_type="connect", subject="proc:p", object="sock:s", raw={}))
    assert g.has_path("proc:p", "sock:s") is True
    assert g.has_path("sock:s", "proc:p") is False
    assert g.edges[0].src == "proc:p" and g.edges[0].dst == "sock:s"


def test_op_send_flow_process_to_socket():
    g = ProvenanceGraph()
    g.add_event(Event(event_id="e1", ts=None, event_type="send", subject="proc:p", object="sock:s", raw={}))
    assert g.has_path("proc:p", "sock:s") is True
    assert g.has_path("sock:s", "proc:p") is False
    assert g.edges[0].src == "proc:p" and g.edges[0].dst == "sock:s"


def test_op_recv_flow_socket_to_process():
    g = ProvenanceGraph()
    g.add_event(Event(event_id="e1", ts=None, event_type="recv", subject="proc:p", object="sock:s", raw={}))
    assert g.has_path("sock:s", "proc:p") is True
    assert g.has_path("proc:p", "sock:s") is False
    assert g.edges[0].src == "sock:s" and g.edges[0].dst == "proc:p"
