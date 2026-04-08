from fastapi import APIRouter

router = APIRouter(tags=["health"])


@router.get("/")
def root() -> dict[str, str]:
    return {
        "service": "AuditFlow",
        "status": "ok",
        "docs": "/docs",
    }
