import uuid
import logging
from fastapi import FastAPI, Request, Response, Depends, HTTPException, status
from fastapi.responses import JSONResponse
from fastapi.middleware.cors import CORSMiddleware
from starlette.middleware.base import BaseHTTPMiddleware
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession
from manager.config import settings
from manager.database.session import get_db
from manager.auth.exceptions import AuthException
from manager.agents.exceptions import AgentException
from manager.api.routers.auth import router as auth_router
from manager.api.routers.users import router as users_router
from manager.api.routers.agents import router as agents_router, agent_router
from manager.api.routers.telemetry import telemetry_router, agent_telemetry_router
from manager.api.routers.rules import router as rules_router
from manager.api.routers.mitre import router as mitre_router
from manager.api.routers.risk import router as risk_router
from manager.api.routers.alerts import router as alerts_router
from manager.api.routers.timeline import router as timeline_router
from manager.api.routers.audit import router as audit_router
from manager.api.routers.websocket import router as websocket_router
from manager.api.routers.threat_intel import router as threat_intel_router
from manager.api.routers.commands import router as commands_router
from manager.api.routers.policies import router as policies_router

# Setup basic logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("manager_api")


class CorrelationIDMiddleware(BaseHTTPMiddleware):
    """Middleware to assign or pass through a unique Correlation ID (X-Request-ID) 
    to track requests across service boundaries and log events.
    """
    async def dispatch(self, request: Request, call_next) -> Response:
        correlation_id = request.headers.get("X-Request-ID")
        if not correlation_id:
            correlation_id = str(uuid.uuid4())
            
        request.state.correlation_id = correlation_id
        response: Response = await call_next(request)
        response.headers["X-Request-ID"] = correlation_id
        return response


def create_app() -> FastAPI:
    """FastAPI Application Factory."""
    app = FastAPI(
        title="Zero Trust EDR Manager API",
        version="1.0.0",
        description="Core control console APIs for Zero Trust EDRContinuous Insider Threat Detection",
        docs_url="/docs",
        redoc_url="/redoc"
    )

    # 1. CORS Middleware
    app.add_middleware(
        CORSMiddleware,
        allow_origins=[
            "http://localhost:3000", "http://127.0.0.1:3000",
            "http://localhost:5173", "http://127.0.0.1:5173",  # Vite dev server
        ],
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    # 2. Correlation ID Middleware
    app.add_middleware(CorrelationIDMiddleware)

    # 3. Global Exception Handlers
    @app.exception_handler(AuthException)
    async def auth_exception_handler(request: Request, exc: AuthException) -> JSONResponse:
        correlation_id = getattr(request.state, "correlation_id", str(uuid.uuid4()))
        logger.warning(f"AuthException [{exc.__class__.__name__}]: {exc.message} | Correlation: {correlation_id}")
        return JSONResponse(
            status_code=exc.status_code,
            content={
                "error": {
                    "code": exc.__class__.__name__,
                    "message": exc.message,
                    "correlation_id": correlation_id
                }
            }
        )

    @app.exception_handler(AgentException)
    async def agent_exception_handler(request: Request, exc: AgentException) -> JSONResponse:
        correlation_id = getattr(request.state, "correlation_id", str(uuid.uuid4()))
        logger.warning(f"AgentException [{exc.__class__.__name__}]: {exc.message} | Correlation: {correlation_id}")
        status_map = {
            "TokenExpiredError": 401,
            "TokenExhaustedError": 401,
            "TokenRevokedError": 401,
            "TokenNotFoundError": 401,
            "DuplicateAgentError": 409,
            "InvalidCSRError": 422,
            "AgentNotFoundError": 404,
        }
        http_status = status_map.get(exc.__class__.__name__, 400)
        return JSONResponse(
            status_code=http_status,
            content={
                "error": {
                    "code": exc.__class__.__name__,
                    "message": exc.message,
                    "correlation_id": correlation_id
                }
            }
        )

    @app.exception_handler(HTTPException)
    async def http_exception_handler(request: Request, exc: HTTPException) -> JSONResponse:
        correlation_id = getattr(request.state, "correlation_id", str(uuid.uuid4()))
        logger.warning(f"HTTPException [{exc.status_code}]: {exc.detail} | Correlation: {correlation_id}")
        return JSONResponse(
            status_code=exc.status_code,
            content={
                "error": {
                    "code": "HTTPException",
                    "message": exc.detail,
                    "correlation_id": correlation_id
                }
            }
        )

    @app.exception_handler(Exception)
    async def generic_exception_handler(request: Request, exc: Exception) -> JSONResponse:
        correlation_id = getattr(request.state, "correlation_id", str(uuid.uuid4()))
        logger.error(f"Unhandled Exception: {str(exc)} | Correlation: {correlation_id}", exc_info=True)
        return JSONResponse(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            content={
                "error": {
                    "code": "InternalServerError",
                    "message": "An unexpected error occurred on the server.",
                    "correlation_id": correlation_id
                }
            }
        )

    # 4. Include Routers
    app.include_router(auth_router, prefix="/api/v1")
    app.include_router(users_router, prefix="/api/v1")
    app.include_router(agents_router, prefix="/api/v1")
    app.include_router(telemetry_router, prefix="/api/v1")
    app.include_router(rules_router)
    app.include_router(mitre_router)
    app.include_router(alerts_router, prefix="/api/v1")
    app.include_router(timeline_router, prefix="/api/v1")
    app.include_router(audit_router, prefix="/api/v1")
    app.include_router(websocket_router)
    app.include_router(threat_intel_router)
    app.include_router(commands_router)
    app.include_router(policies_router)
    app.include_router(agent_router, prefix="/agent")
    app.include_router(agent_telemetry_router, prefix="/agent")

    # 5. Health Check Endpoints
    @app.get("/healthz", tags=["Health"], summary="Liveness Probe check.")
    async def healthz() -> dict:
        return {"status": "ok"}

    @app.get("/readyz", tags=["Health"], summary="Readiness Probe (DB Connection) check.")
    async def readyz(db: AsyncSession = Depends(get_db)) -> dict:
        try:
            await db.execute(text("SELECT 1"))
            return {"status": "ready"}
        except Exception as e:
            logger.critical(f"Readiness check failed: {str(e)}")
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="Database connectivity failed"
            )

    return app


app = create_app()
