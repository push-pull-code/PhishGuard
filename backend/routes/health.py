# FILE: health.py
# PURPOSE: Health-check endpoint for uptime monitoring
# CONNECTS TO: backend/main.py

from fastapi import APIRouter

router = APIRouter(prefix="/health", tags=["Health"])


@router.get("/")
async def health_check():
    """Return service health status."""
    return {"status": "healthy"}
