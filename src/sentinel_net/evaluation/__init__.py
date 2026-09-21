"""
Evaluation framework for SENTINEL-NET.
"""

from sentinel_net.evaluation.novelty import (  # noqa: F401
    Phase8Protocol,
    ProtocolViolation,
    LeaveOneAttackOut,
    AttackFamilyFold,
    NoveltyRanking,
    NoveltyRankingResult,
    SupervisedAnomalyFusion,
    MultiOperatingPointAnalysis,
    CategorizedFPAnalysis,
    validate_result_category,
    RESULT_CATEGORIES,
)
