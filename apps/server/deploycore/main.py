from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.openapi.docs import get_swagger_ui_html
from fastapi.responses import HTMLResponse, JSONResponse

from .body_limit import AgentBodyLimit
from .agent_package_api import router as agent_package_router
from .device_api import router as device_router
from .database import create_database_engine
from .health import router as health_router
from .execution_api import router as execution_router
from .detection_api import router as detection_router
from .job_api import router as job_router
from .license_api import router as license_router
from .package_api import router as package_router
from .system_api import router as system_router


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncIterator[None]:
    database = create_database_engine()
    app.state.database = database
    try:
        yield
    finally:
        database.dispose()


app = FastAPI(
    title="DeployCore",
    version="0.3.1",
    openapi_url="/api/openapi.json",
    docs_url=None,
    redoc_url=None,
    lifespan=lifespan,
)
app.include_router(health_router)
app.include_router(system_router)
app.include_router(device_router)
app.include_router(agent_package_router)
app.include_router(package_router)
app.include_router(job_router)
app.include_router(license_router)
app.include_router(execution_router)
app.include_router(detection_router)
app.add_middleware(AgentBodyLimit)


@app.middleware("http")
async def prevent_caching(request: Request, call_next):
    response = await call_next(request)
    if request.url.path.startswith("/api/v1/"):
        response.headers["Cache-Control"] = "no-store"
        expiry = getattr(request.state, "session_expiry", None)
        if expiry is not None and response.status_code < 300:
            response.headers["X-DeployCore-Session-Expires"] = expiry.isoformat()
    return response


@app.exception_handler(RequestValidationError)
async def redact_validation_errors(request: Request, exc: RequestValidationError) -> JSONResponse:
    errors = [{"loc": error["loc"], "type": error["type"]} for error in exc.errors()]
    return JSONResponse(status_code=422, content={"detail": errors})


@app.get("/api/docs", include_in_schema=False, response_class=HTMLResponse)
def swagger() -> HTMLResponse:
    return get_swagger_ui_html(
        openapi_url="/api/openapi.json",
        title="DeployCore API",
        swagger_js_url="/assets/swagger/swagger-ui-bundle.js",
        swagger_css_url="/assets/swagger/swagger-ui.css",
        swagger_favicon_url="/assets/swagger/favicon-32x32.png",
        swagger_ui_parameters={"validatorUrl": None},
    )
