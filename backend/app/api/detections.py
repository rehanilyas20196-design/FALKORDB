
import logging
from typing import Any

from fastapi import APIRouter, HTTPException, status
from pydantic import BaseModel, Field

from backend.app.services.detection_service import DetectionService

logger = logging.getLogger("graphguard.detections")

router = APIRouter(
    prefix="/detections",
    tags=["Detections"],
)


# --------------------------------------------------
# RESPONSE SCHEMAS
# --------------------------------------------------

class DetectionRunResponse(BaseModel):
    status: str
    message: str
    results: Any = None


class DetectionHealthResponse(BaseModel):
    status: str
    service: str


class DetectionRequest(BaseModel):
    event_ids: list[str] = Field(default_factory=list)


# --------------------------------------------------
# HEALTH CHECK
# --------------------------------------------------

@router.get(
    "/health",
    response_model=DetectionHealthResponse,
)
async def detection_health():
    return DetectionHealthResponse(
        status="healthy",
        service="GraphGuard Detection API",
    )


# --------------------------------------------------
# RUN DETECTION RULES
# --------------------------------------------------

@router.post(
    "/run",
    response_model=DetectionRunResponse,
    status_code=status.HTTP_200_OK,
)
async def run_detections():
    try:
        results = DetectionService.run_detection_rules()

        return DetectionRunResponse(
            status="success",
            message="Detection rules executed successfully.",
            results=results,
        )

    except Exception as exc:
        logger.exception("Failed to run detection rules.")

        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Detection failed: {str(exc)}",
        ) from exc


# --------------------------------------------------
# DETECTION API INFORMATION
# --------------------------------------------------

@router.get("/")
async def detection_info():
    return {
        "service": "GraphGuard AI Detection Engine",
        "description": (
            "Runs detection rules to identify suspicious "
            "activity and potential security threats."
        ),
        "endpoints": [
            "GET /api/detections/health",
            "POST /api/detections/run",
        ],
    }
