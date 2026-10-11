from etherlens.investigation_workspace import (
    EvidenceItem,
    InvestigationWorkspace,
    evidence_summary,
)


def test_evidence_locker_deduplicates_reference_and_updates_context():
    workspace = InvestigationWorkspace("Case 001")
    first = workspace.add_evidence(EvidenceItem("packet", "pkt-1", title="Initial"))
    second = workspace.add_evidence(EvidenceItem("packet", "pkt-1", title="Important", note="Review SYN flags"))
    assert first.id == second.id
    assert len(workspace.evidence) == 1
    assert workspace.evidence[0].title == "Important"
    assert workspace.evidence[0].note == "Review SYN flags"


def test_notes_and_finding_lifecycle_round_trip():
    workspace = InvestigationWorkspace("Suspicious host", description="Analyst case")
    workspace.add_note("Check DNS fan-out")
    workspace.set_finding_state("finding-1", "investigating", "Correlating DNS")
    workspace.add_evidence(EvidenceItem("finding", "finding-1", snapshot={"severity": "high"}))

    restored = InvestigationWorkspace.from_dict(workspace.to_dict())
    assert restored.name == "Suspicious host"
    assert restored.notes[0]["text"] == "Check DNS fan-out"
    assert restored.finding_states["finding-1"]["state"] == "investigating"
    assert restored.evidence[0].snapshot["severity"] == "high"


def test_evidence_summary_and_removal():
    workspace = InvestigationWorkspace("Case")
    packet = workspace.add_evidence(EvidenceItem("packet", "p1"))
    workspace.add_evidence(EvidenceItem("host", "192.168.1.10"))
    assert evidence_summary(workspace.evidence)["total"] == 2
    assert evidence_summary(workspace.evidence)["packet"] == 1
    assert workspace.remove_evidence(packet.id) is True
    assert workspace.remove_evidence(packet.id) is False


def test_invalid_evidence_and_finding_state_are_rejected():
    try:
        EvidenceItem("unknown", "x")
        assert False, "expected invalid evidence type to fail"
    except ValueError:
        pass

    workspace = InvestigationWorkspace("Case")
    try:
        workspace.set_finding_state("finding-1", "maybe")
        assert False, "expected invalid finding state to fail"
    except ValueError:
        pass
