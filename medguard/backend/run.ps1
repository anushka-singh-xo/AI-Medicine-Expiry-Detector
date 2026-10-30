$ErrorActionPreference = "Stop"
$backendDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$python = Join-Path $backendDir ".venv\Scripts\python.exe"
if (-not (Test-Path -LiteralPath $python)) { throw "Backend environment not found. Run .\setup.ps1 first." }

& $python -c "import rapidocr, onnxruntime"
if ($LASTEXITCODE -ne 0) { throw "OCR dependencies are missing from $python. Run .\setup.ps1 first." }
Set-Location $backendDir
& $python -m uvicorn main:app --host 127.0.0.1 --port 8000
