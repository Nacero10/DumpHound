"""Composition root.

Instantiates every singleton once and exposes FastAPI dependency callables.
This is the only place where concrete implementations are wired together, so
swapping a repository or service is a one-line change here.
"""
from __future__ import annotations

from functools import lru_cache

from core.config import Settings, get_settings
from core.logging import AuditLogger
from repositories.artifact_repository import ArtifactRepository
from repositories.job_repository import JobRepository
from services.artifact_service import ArtifactService
from services.detection_service import DetectionService
from services.dump_service import DumpService
from services.job_service import JobService
from services.activity import ActivityLog
from services.volatility_service import VolatilityService


class Container:
    def __init__(self, settings: Settings) -> None:
        self.settings = settings
        self.audit = AuditLogger(settings.audit_log)
        self.activity = ActivityLog()
        self.artifact_repo = ArtifactRepository()
        self.job_repo = JobRepository()
        self.volatility = VolatilityService(settings, self.audit, self.activity)
        self.artifacts = ArtifactService(self.artifact_repo)
        self.dumps = DumpService(self.volatility, self.artifacts)
        self.jobs = JobService(settings, self.job_repo)
        self.detection = DetectionService(settings.rules_dir)


@lru_cache
def get_container() -> Container:
    return Container(get_settings())


# --- FastAPI dependency callables ------------------------------------------
def settings_dep() -> Settings:
    return get_container().settings


def volatility_dep() -> VolatilityService:
    return get_container().volatility


def artifact_dep() -> ArtifactService:
    return get_container().artifacts


def dump_dep() -> DumpService:
    return get_container().dumps


def job_dep() -> JobService:
    return get_container().jobs


def detection_dep() -> DetectionService:
    return get_container().detection


def audit_dep() -> AuditLogger:
    return get_container().audit


def activity_dep() -> ActivityLog:
    return get_container().activity
