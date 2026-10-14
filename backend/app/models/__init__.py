"""ORM models. Importing this package registers every table on ``Base.metadata``."""

from app.models.base import Base
from app.models.ml import (
    AnomalyResult,
    ClassificationResult,
    MlModel,
    MlScoringRun,
    MlTrainingRun,
)
from app.models.ops import AppUser, AuditLog, AuthSession, DimDate, Job
from app.models.warehouse import (
    DataQualityResult,
    DimAsset,
    DimAttackCategory,
    DimSource,
    EventGroundTruth,
    FactSecurityEvent,
    IngestionBatch,
    RawRecord,
    RejectedRecord,
)

__all__ = [
    "AnomalyResult",
    "AppUser",
    "AuditLog",
    "AuthSession",
    "Base",
    "ClassificationResult",
    "DataQualityResult",
    "DimAsset",
    "DimAttackCategory",
    "DimDate",
    "DimSource",
    "EventGroundTruth",
    "FactSecurityEvent",
    "IngestionBatch",
    "Job",
    "MlModel",
    "MlScoringRun",
    "MlTrainingRun",
    "RawRecord",
    "RejectedRecord",
]
