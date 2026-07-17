from .assets import router as assets_router
from .meta import router as meta_router
from .projects import router as projects_router
from .registry import router as registry_router
from .scans import router as scans_router

__all__ = [
    "assets_router",
    "meta_router",
    "projects_router",
    "registry_router",
    "scans_router",
]
