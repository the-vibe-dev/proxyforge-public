from __future__ import annotations

from typing import Any

from secops.services.skills import SkillPack, SkillRegistry


class SkillCatalog:
    """Thin adapter around the existing registry, keeping old imports stable."""

    def __init__(self, registry: SkillRegistry | None = None) -> None:
        self.registry = registry or SkillRegistry()

    def all(self) -> list[SkillPack]:
        return self.registry.all()

    def get(self, skill_id: str) -> SkillPack | None:
        return self.registry.get(skill_id)

    def public(self) -> list[dict[str, Any]]:
        return [pack.public() for pack in self.all()]
