# MedGuard

## Backend setup (Windows)

The backend uses RapidOCR 3.10 with ONNX Runtime's CPU inference engine. Use
standard Windows CPython 3.10–3.14. From `medguard\backend`, run:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\setup.ps1
powershell -NoProfile -ExecutionPolicy Bypass -File .\start_backend.ps1
```

The setup script creates `backend\.venv`, installs `requirements.txt`, and
initializes RapidOCR once so missing packages or runtime problems are reported
during setup. The existing MinGW Python environment is not compatible with
ONNX Runtime wheels; the script therefore uses the installed standard Windows
CPython. To install manually into an existing compatible environment, run
`python -m pip install -r requirements.txt` from this folder.

No separate OCR executable, system package, or GPU is required. RapidOCR
supplies its OCR models with the Python package, and this project uses ONNX
Runtime on the CPU.

The start script launches the backend in the background and verifies OCR
health. The API is available at `http://127.0.0.1:8000`; the frontend is
served at `http://127.0.0.1:8000/app/`. `run.ps1` is available when you want
to keep the server attached to the terminal. `GET /api/health` reports whether
OCR initialized.

If OCR dependencies are unavailable, the backend still serves inventory and
manual-entry features, logs the missing dependency, and returns a descriptive
error from scanning. Manual medicine entry remains available from the Scan a
package page.
