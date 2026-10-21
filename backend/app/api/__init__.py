from backend.app.api.health import router as health_router
from backend.app.api.pcaps import router as pcaps_router
from backend.app.api.flows import router as flows_router
from backend.app.api.alerts import router as alerts_router
from backend.app.api.stats import router as stats_router

__all__ = [
    "health_router",
    "pcaps_router",
    "flows_router",
    "alerts_router",
    "stats_router",
]
