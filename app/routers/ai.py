"""Status of the optional AI layer."""

from __future__ import annotations

from fastapi import APIRouter, Depends

from ..ai.status import cached_status
from ..deps import get_current_user
from ..models import User

router = APIRouter(prefix="/api/ai", tags=["ai"])


@router.get("/status")
def status(user: User = Depends(get_current_user)) -> dict:
    """Report whether a local model is available and which one would be used."""
    return cached_status()
