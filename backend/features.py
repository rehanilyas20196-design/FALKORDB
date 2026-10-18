"""
GraphGuard AI - Feature Router Registration

This module registers the feature routers that exist in the source tree
but are not wired up in `backend/main.py`. It reuses the exact `app`
object created by `backend.main`, so there is no second application and
no change to the existing entry point.

Run (from the repository root):

    python -m uvicorn backend.features:app --reload

Routers registered here:
    - cases      (backend/app/api/cases.py)       -> /api/v1/cases
    - detections (backend/app/api/detections.py)  -> /api/v1/detections
    - graph      (backend/app/api/graph.py)       -> /api/v1/graph
    - audit      (backend/app/api/audit.py)       -> /api/v1/audit

The assistant and event routers are already registered in backend.main
and are intentionally not re-registered here.
"""

import logging

from backend.main import API_PREFIX, app

from backend.app.api.cases import router as cases_router
from backend.app.api.detections import router as detections_router
from backend.app.api.graph import router as graph_router
from backend.app.api.audit import router as audit_router

logger = logging.getLogger("folderdb-agent.features")


# --------------------------------------------------
# Register feature routers on the existing app
# --------------------------------------------------

FEATURE_ROUTERS = (
    ("cases", cases_router),
    ("detections", detections_router),
    ("graph", graph_router),
    ("audit", audit_router),
)

for name, router in FEATURE_ROUTERS:
    app.include_router(router, prefix=API_PREFIX)
    logger.info("Feature router registered: %s at %s", name, API_PREFIX)

logger.info("Feature router registration complete.")
