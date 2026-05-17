import os
from pathlib import Path

from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles


FRONTEND_DIST_CANDIDATES = [
    Path(os.getenv("FRONTEND_DIST_PATH", "")) if os.getenv("FRONTEND_DIST_PATH") else None,
    Path(__file__).resolve().parent.parent.parent / "frontend-dist",
    Path(__file__).resolve().parent.parent.parent.parent / "frontend" / "dist",
]
FRONTEND_DIST_PATH = next(
    (path for path in FRONTEND_DIST_CANDIDATES if path and (path / "index.html").exists()),
    Path(__file__).resolve().parent.parent.parent / "frontend-dist",
)


def mount_frontend_assets(app: FastAPI) -> None:
    assets_path = FRONTEND_DIST_PATH / "assets"
    if assets_path.exists():
        app.mount("/assets", StaticFiles(directory=assets_path), name="frontend-assets")
