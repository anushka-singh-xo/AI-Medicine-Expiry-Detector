"""
Central place for backend settings.
Keeping these here (instead of scattered across files) means Phase 2+
features like OCR thresholds or DB paths just get added to this one file.
"""

# Origins allowed to call this API from a browser.
# This covers opening index.html directly (file://) and common local dev ports.
ALLOWED_ORIGINS = [
    "http://localhost",
    "http://localhost:3000",
    "http://localhost:5500",
    "http://127.0.0.1",
    "http://127.0.0.1:3000",
    "http://127.0.0.1:5500",
    "null",  # browsers send this Origin when a page is opened via file://
]

# App metadata
APP_NAME = "MedGuard API"
APP_VERSION = "0.1.0"