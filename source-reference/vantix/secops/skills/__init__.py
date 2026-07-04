from secops.skills.contracts import ReconFeatureSet, SkillRouteDecision
from secops.skills.features import ReconFeatureExtractor

__all__ = ["ReconFeatureExtractor", "ReconFeatureSet", "ReconSkillRouter", "SkillRouteDecision"]


def __getattr__(name: str):
    if name == "ReconSkillRouter":
        from secops.skills.router import ReconSkillRouter

        return ReconSkillRouter
    raise AttributeError(name)
