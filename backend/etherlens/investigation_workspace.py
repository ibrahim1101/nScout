"""Local investigation workspace primitives for nScout v0.4.

The model is deliberately storage-agnostic so the API can persist it in MongoDB,
a local file, or an in-memory fallback without coupling evidence semantics to a
particular backend.
"""
from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, Iterable, List, Optional
import uuid

EVIDENCE_TYPES = {"packet", "host", "connection", "dns", "finding", "timeline"}
FINDING_STATES = {"new", "investigating", "benign", "suspicious", "confirmed", "resolved"}


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


@dataclass
class EvidenceItem:
    type: str
    ref_id: str
    title: str = ""
    note: str = ""
    snapshot: Dict[str, Any] = field(default_factory=dict)
    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    created_at: str = field(default_factory=_utc_now)

    def __post_init__(self) -> None:
        if self.type not in EVIDENCE_TYPES:
            raise ValueError(f"Unsupported evidence type: {self.type}")
        if not self.ref_id.strip():
            raise ValueError("Evidence ref_id is required")


@dataclass
class InvestigationWorkspace:
    name: str
    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    description: str = ""
    created_at: str = field(default_factory=_utc_now)
    updated_at: str = field(default_factory=_utc_now)
    evidence: List[EvidenceItem] = field(default_factory=list)
    notes: List[Dict[str, str]] = field(default_factory=list)
    finding_states: Dict[str, Dict[str, str]] = field(default_factory=dict)

    def _touch(self) -> None:
        self.updated_at = _utc_now()

    def add_evidence(self, item: EvidenceItem) -> EvidenceItem:
        # One referenced object should appear once in the locker. Updating its
        # analyst context is safer than silently producing duplicate evidence.
        for existing in self.evidence:
            if existing.type == item.type and existing.ref_id == item.ref_id:
                if item.title:
                    existing.title = item.title
                if item.note:
                    existing.note = item.note
                if item.snapshot:
                    existing.snapshot = dict(item.snapshot)
                self._touch()
                return existing
        self.evidence.append(item)
        self._touch()
        return item

    def remove_evidence(self, evidence_id: str) -> bool:
        before = len(self.evidence)
        self.evidence = [item for item in self.evidence if item.id != evidence_id]
        changed = len(self.evidence) != before
        if changed:
            self._touch()
        return changed

    def add_note(self, text: str, author: str = "analyst") -> Dict[str, str]:
        text = text.strip()
        if not text:
            raise ValueError("Note text is required")
        note = {"id": str(uuid.uuid4()), "text": text, "author": author, "created_at": _utc_now()}
        self.notes.append(note)
        self._touch()
        return note

    def set_finding_state(self, finding_id: str, state: str, note: str = "") -> Dict[str, str]:
        if state not in FINDING_STATES:
            raise ValueError(f"Unsupported finding state: {state}")
        if not finding_id.strip():
            raise ValueError("finding_id is required")
        record = {"state": state, "note": note.strip(), "updated_at": _utc_now()}
        self.finding_states[finding_id] = record
        self._touch()
        return record

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "name": self.name,
            "description": self.description,
            "created_at": self.created_at,
            "updated_at": self.updated_at,
            "evidence": [asdict(item) for item in self.evidence],
            "notes": list(self.notes),
            "finding_states": dict(self.finding_states),
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "InvestigationWorkspace":
        workspace = cls(
            id=data.get("id") or str(uuid.uuid4()),
            name=data.get("name") or "Untitled Investigation",
            description=data.get("description", ""),
            created_at=data.get("created_at") or _utc_now(),
            updated_at=data.get("updated_at") or _utc_now(),
        )
        workspace.evidence = [EvidenceItem(**item) for item in data.get("evidence", [])]
        workspace.notes = list(data.get("notes", []))
        workspace.finding_states = dict(data.get("finding_states", {}))
        return workspace


def evidence_summary(items: Iterable[EvidenceItem]) -> Dict[str, int]:
    counts = {kind: 0 for kind in sorted(EVIDENCE_TYPES)}
    total = 0
    for item in items:
        counts[item.type] += 1
        total += 1
    return {"total": total, **counts}
