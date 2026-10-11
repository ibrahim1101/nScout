import asyncio
import json

import pytest
from fastapi import HTTPException

from etherlens.investigation_store import InvestigationNotFound, InvestigationStore
from etherlens.investigation_workspace import EvidenceItem


def test_store_persists_lists_mutates_and_deletes(tmp_path):
    store = InvestigationStore(tmp_path / "investigations")
    workspace = store.create("DNS review", "Investigate fan-out")
    store.mutate(workspace.id, lambda item: item.add_note("Check resolver history"))
    store.mutate(workspace.id, lambda item: item.add_evidence(
        EvidenceItem("host", "192.0.2.10", title="Observed resolver")
    ))

    restored = store.get(workspace.id)
    assert restored.name == "DNS review"
    assert restored.notes[0]["text"] == "Check resolver history"
    assert restored.evidence[0].ref_id == "192.0.2.10"
    assert store.list()[0]["evidence"]["host"] == 1
    assert store.list()[0]["note_count"] == 1
    assert store.delete(workspace.id) is True
    assert store.delete(workspace.id) is False
    with pytest.raises(InvestigationNotFound):
        store.get(workspace.id)


def test_store_rejects_invalid_ids_and_skips_corrupt_files(tmp_path):
    store = InvestigationStore(tmp_path)
    (tmp_path / "corrupt.json").write_text("not json", encoding="utf-8")
    assert store.list() == []
    with pytest.raises(InvestigationNotFound):
        store.get("../outside")


def test_store_atomic_write_leaves_no_temporary_file(tmp_path):
    store = InvestigationStore(tmp_path)
    workspace = store.create("Atomic case")
    data = json.loads((tmp_path / f"{workspace.id}.json").read_text(encoding="utf-8"))
    assert data["id"] == workspace.id
    assert list(tmp_path.glob("*.tmp")) == []


def test_investigation_api_lifecycle(tmp_path, monkeypatch):
    import server

    store = InvestigationStore(tmp_path)
    monkeypatch.setattr(server, "_investigation_store", store)

    async def scenario():
        created = await server.investigations_create(
            server.CreateInvestigationRequest(name="Incident 42", description="Triage")
        )
        workspace_id = created["investigation"]["id"]
        await server.investigations_add_evidence(
            workspace_id,
            server.EvidenceRequest(type="packet", ref_id="pkt-42", snapshot={"protocol": "DNS"}),
        )
        await server.investigations_add_note(
            workspace_id,
            server.InvestigationNoteRequest(text="Compare with baseline"),
        )
        await server.investigations_set_finding_state(
            workspace_id,
            "finding-42",
            server.FindingStateRequest(state="investigating", note="Needs review"),
        )
        updated = await server.investigations_update(
            workspace_id,
            server.UpdateInvestigationRequest(name="Incident 42A"),
        )
        listed = await server.investigations_list()
        loaded = await server.investigations_get(workspace_id)
        return workspace_id, updated, listed, loaded

    workspace_id, updated, listed, loaded = asyncio.run(scenario())
    assert updated["investigation"]["name"] == "Incident 42A"
    assert listed["investigations"][0]["evidence"]["packet"] == 1
    assert loaded["investigation"]["notes"][0]["text"] == "Compare with baseline"
    assert loaded["investigation"]["finding_states"]["finding-42"]["state"] == "investigating"
    asyncio.run(server.investigations_delete(workspace_id))


def test_investigation_api_maps_validation_and_missing_errors(tmp_path, monkeypatch):
    import server

    monkeypatch.setattr(server, "_investigation_store", InvestigationStore(tmp_path))

    with pytest.raises(HTTPException) as missing:
        asyncio.run(server.investigations_get("00000000-0000-0000-0000-000000000000"))
    assert missing.value.status_code == 404

    created = asyncio.run(server.investigations_create(server.CreateInvestigationRequest(name="Case")))
    workspace_id = created["investigation"]["id"]
    with pytest.raises(HTTPException) as invalid:
        asyncio.run(server.investigations_add_evidence(
            workspace_id,
            server.EvidenceRequest(type="unsupported", ref_id="x"),
        ))
    assert invalid.value.status_code == 400


def test_investigation_api_rejects_large_snapshots(tmp_path, monkeypatch):
    import server

    monkeypatch.setattr(server, "_investigation_store", InvestigationStore(tmp_path))
    created = asyncio.run(server.investigations_create(server.CreateInvestigationRequest(name="Case")))
    workspace_id = created["investigation"]["id"]
    with pytest.raises(HTTPException) as error:
        asyncio.run(server.investigations_add_evidence(
            workspace_id,
            server.EvidenceRequest(type="packet", ref_id="p1", snapshot={"raw": "x" * (129 * 1024)}),
        ))
    assert error.value.status_code == 413
