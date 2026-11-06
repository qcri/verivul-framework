from fastapi import FastAPI, Request, Response
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from starlette.exceptions import HTTPException as StarletteHTTPException
import os
import sys

# Add the project root to the path
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "../..")))

from src.web.api.routes import router
from src.utils.logger import logger

log = logger.get_logger("web_server")

app = FastAPI(
    title="VeriVul Dashboard",
    description="Dashboard for monitoring code generation and verification",
    version="1.0.0"
)

# Configure CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # For development; restrict in production
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Prevent browsers from caching API responses so the dashboard always shows live data
@app.middleware("http")
async def no_cache_api(request: Request, call_next):
    response = await call_next(request)
    if request.url.path.startswith("/api"):
        response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate"
        response.headers["Pragma"] = "no-cache"
    return response

# Include API routes
app.include_router(router, prefix="/api")

# Serve the React frontend with SPA fallback (any *navigation* path not matched by
# the API returns index.html so that React Router can handle client-side routing).
#
# Two rules matter here, and getting either wrong makes the dashboard unusable
# after a rebuild:
#
#  1. A missing **asset** must 404, not fall back to index.html.  Falling back
#     answers a request for a stale bundle (`/static/js/main.<oldhash>.js`) with
#     HTML and a 200, so the browser tries to execute HTML as JavaScript, the app
#     never mounts, and the page just spins.
#  2. index.html must be revalidated on every load.  Without an explicit
#     Cache-Control, browsers apply heuristic freshness and keep serving the
#     pre-rebuild HTML — which points at exactly that stale bundle.  The hashed
#     files under /static/ are immutable and can be cached hard.
_SPA_FALLBACK_EXTENSIONS = {"", ".html"}


def _is_asset_request(path: str) -> bool:
    """True for requests that name a concrete file rather than an SPA route."""
    if path.startswith("static/"):
        return True
    return os.path.splitext(path)[1].lower() not in _SPA_FALLBACK_EXTENSIONS


class SPAStaticFiles(StaticFiles):
    async def get_response(self, path: str, scope):
        try:
            response = await super().get_response(path, scope)
        except StarletteHTTPException as exc:
            if exc.status_code != 404 or _is_asset_request(path):
                raise  # a genuinely missing file must stay a 404
            # Unknown navigation path → serve index.html so React Router takes over
            response = await super().get_response("index.html", scope)
            path = "index.html"

        if path.startswith("static/"):
            # Content-hashed filenames: safe to cache indefinitely.
            response.headers["Cache-Control"] = "public, max-age=31536000, immutable"
        else:
            # index.html and friends: always revalidate so a rebuild is picked up.
            response.headers["Cache-Control"] = "no-cache, must-revalidate"
        return response

try:
    frontend_path = os.path.join(os.path.dirname(__file__), "frontend/build")
    if os.path.isdir(frontend_path):
        app.mount("/", SPAStaticFiles(directory=frontend_path, html=True), name="static")
        log.info(f"Mounted frontend static files from {frontend_path}")
    else:
        log.warning(f"Frontend build directory not found at {frontend_path}")
except Exception as e:
    log.error(f"Failed to mount static files: {str(e)}", exc_info=True)

if __name__ == "__main__":
    import uvicorn
    # Pass the app object, not "src.web.main:app": an import string makes uvicorn
    # import this module a second time in the same process, so everything at module
    # scope — including the API's DatabaseManager and its connection pool — is
    # built twice and the migrations run twice.
    uvicorn.run(app, host="0.0.0.0", port=int(os.environ.get("VERIVUL_WEB_PORT", "54333")), reload=False)
