from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from config import ALLOWED_ORIGINS, APP_NAME, APP_VERSION

app = FastAPI(title=APP_NAME, version=APP_VERSION)

# CORS: without this, a browser loading your HTML from one origin
# (e.g. file:// or localhost:5500) will be blocked from calling
# this API on localhost:8000, even though both are "local".
app.add_middleware(
    CORSMiddleware,
    allow_origins=ALLOWED_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.get("/")
def root():
    """Basic status check — confirms the server is up at all."""
    return {
        "status": "ok",
        "service": APP_NAME,
        "version": APP_VERSION,
    }


@app.get("/api/health")
def health():
    """
    Health endpoint under /api, matching the prefix every future
    real endpoint (/api/scan, /api/medicines, ...) will use.
    """
    return {"status": "healthy"}