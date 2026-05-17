from fastapi import APIRouter, HTTPException
from fastapi.responses import FileResponse, HTMLResponse

from app.core.frontend import FRONTEND_DIST_PATH


router = APIRouter(tags=["frontend"])


@router.get("/api/health")
def health():
    return {"status": "ok"}


@router.get("/", response_class=HTMLResponse)
def home():
    frontend_index = FRONTEND_DIST_PATH / "index.html"
    if frontend_index.exists():
        return FileResponse(frontend_index)
    raise HTTPException(status_code=503, detail="Frontend build is missing. Run npm run build or rebuild the backend image.")
