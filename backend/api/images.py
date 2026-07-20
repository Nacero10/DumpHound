"""Image catalogue endpoints."""
from __future__ import annotations

from datetime import datetime, timezone

from fastapi import APIRouter, Depends

from core.config import Settings
from core.container import settings_dep
from models.responses import ImageInfo, ImageListResponse

router = APIRouter(prefix="/images", tags=["images"])

# Common memory-image extensions; directories without these are ignored.
_IMAGE_SUFFIXES = {".mem", ".raw", ".lime", ".vmem", ".dmp", ".img", ".bin", ".vol", ".core"}


@router.get("", response_model=ImageListResponse)
def list_images(settings: Settings = Depends(settings_dep)) -> ImageListResponse:
    images: list[ImageInfo] = []
    if settings.image_dir.is_dir():
        for path in sorted(settings.image_dir.iterdir()):
            if path.is_file() and (path.suffix.lower() in _IMAGE_SUFFIXES or not path.suffix):
                stat = path.stat()
                images.append(
                    ImageInfo(
                        name=path.name,
                        size_bytes=stat.st_size,
                        modified=datetime.fromtimestamp(stat.st_mtime, tz=timezone.utc),
                    )
                )
    return ImageListResponse(images=images)
