"""Atomic local persistence for v0.4 investigation workspaces."""
from __future__ import annotations

import json
import os
import threading
import uuid
from pathlib import Path
from typing import Any, Callable, Dict, List

from .investigation_workspace import InvestigationWorkspace, evidence_summary


class InvestigationNotFound(KeyError):
    pass


class InvestigationStore:
    """Persist one investigation per JSON file without requiring MongoDB."""

    def __init__(self, root: Path):
        self.root = Path(root)
        self._lock = threading.RLock()

    @staticmethod
    def _validated_id(workspace_id: str) -> str:
        try:
            return str(uuid.UUID(str(workspace_id)))
        except (ValueError, TypeError, AttributeError) as exc:
            raise InvestigationNotFound(workspace_id) from exc

    def _path(self, workspace_id: str) -> Path:
        return self.root / f"{self._validated_id(workspace_id)}.json"

    def _write(self, workspace: InvestigationWorkspace) -> None:
        self.root.mkdir(parents=True, exist_ok=True)
        path = self._path(workspace.id)
        temporary = path.with_suffix(".tmp")
        temporary.write_text(
            json.dumps(workspace.to_dict(), ensure_ascii=False, separators=(",", ":")),
            encoding="utf-8",
        )
        os.replace(temporary, path)

    def create(self, name: str, description: str = "") -> InvestigationWorkspace:
        name = name.strip()
        if not name:
            raise ValueError("Investigation name is required")
        workspace = InvestigationWorkspace(name=name, description=description.strip())
        with self._lock:
            self._write(workspace)
        return workspace

    def save(self, workspace: InvestigationWorkspace) -> InvestigationWorkspace:
        with self._lock:
            self._write(workspace)
        return workspace

    def mutate(
        self,
        workspace_id: str,
        operation: Callable[[InvestigationWorkspace], None],
    ) -> InvestigationWorkspace:
        """Apply and persist one mutation while holding the store lock."""
        with self._lock:
            workspace = self.get(workspace_id)
            operation(workspace)
            self._write(workspace)
        return workspace

    def get(self, workspace_id: str) -> InvestigationWorkspace:
        path = self._path(workspace_id)
        with self._lock:
            try:
                data = json.loads(path.read_text(encoding="utf-8"))
            except FileNotFoundError as exc:
                raise InvestigationNotFound(workspace_id) from exc
            except (OSError, ValueError, TypeError) as exc:
                raise ValueError("Investigation data is unreadable") from exc
        return InvestigationWorkspace.from_dict(data)

    def delete(self, workspace_id: str) -> bool:
        path = self._path(workspace_id)
        with self._lock:
            try:
                path.unlink()
            except FileNotFoundError:
                return False
        return True

    def list(self) -> List[Dict[str, Any]]:
        with self._lock:
            if not self.root.exists():
                return []
            records: List[Dict[str, Any]] = []
            for path in self.root.glob("*.json"):
                try:
                    workspace = InvestigationWorkspace.from_dict(
                        json.loads(path.read_text(encoding="utf-8"))
                    )
                except (OSError, ValueError, TypeError):
                    continue
                records.append({
                    "id": workspace.id,
                    "name": workspace.name,
                    "description": workspace.description,
                    "created_at": workspace.created_at,
                    "updated_at": workspace.updated_at,
                    "evidence": evidence_summary(workspace.evidence),
                    "note_count": len(workspace.notes),
                    "finding_count": len(workspace.finding_states),
                })
        return sorted(records, key=lambda item: item["updated_at"], reverse=True)
