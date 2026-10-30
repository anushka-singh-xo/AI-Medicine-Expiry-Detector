"""
Central place for backend settings.
Keeping these here (instead of scattered across files) means Phase 2+
features like OCR thresholds or DB paths just get added to this one file.
"""

# Browser origins allowed to call this API. Add deployed frontend origins to
# MEDGUARD_ALLOWED_ORIGINS as a comma-separated list.
import os

ALLOWED_ORIGINS = [
    "http://localhost",
    "http://localhost:3000",
    "http://localhost:5500",
    "http://127.0.0.1",
    "http://127.0.0.1:3000",
    "http://127.0.0.1:5500",
    "null",  # browsers send this Origin when a page is opened via file://
]
ALLOWED_ORIGINS.extend(
    origin.strip()
    for origin in os.getenv("MEDGUARD_ALLOWED_ORIGINS", "").split(",")
    if origin.strip()
)

# Local dev servers commonly choose a free port (Vite, Live Server, etc.).
LOCAL_ORIGIN_REGEX = r"^https?://(localhost|127\.0\.0\.1|\[::1\])(:[0-9]+)?$"

# App metadata
APP_NAME = "MedGuard API"
APP_VERSION = "0.1.0"
