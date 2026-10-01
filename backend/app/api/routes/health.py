from fastapi import APIRouter

router = APIRouter(tags=["health"])


@router.get("/")
def root() -> dict[str, str]:
    return {
        "service": "sonda",
        "status": "ok",
        "docs": "/docs",
    }
