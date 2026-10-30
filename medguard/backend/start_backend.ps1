$ErrorActionPreference = "Stop"
$backendDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$python = Join-Path $backendDir ".venv\Scripts\python.exe"
if (-not (Test-Path -LiteralPath $python)) {
    throw "Backend environment not found. Run .\setup.ps1 first."
}

& $python -c "import rapidocr, onnxruntime"
if ($LASTEXITCODE -ne 0) {
    throw "OCR dependencies are missing. Run .\setup.ps1 first."
}

$listener = Get-NetTCPConnection -LocalPort 8000 -State Listen -ErrorAction SilentlyContinue
if ($listener) {
    try {
        $health = Invoke-RestMethod -Uri "http://127.0.0.1:8000/api/health" -TimeoutSec 3
        if ($health.status -eq "healthy" -and $health.ocr -eq "available") {
            Write-Host "MedGuard backend with OCR is already running at http://127.0.0.1:8000/app/"
            exit 0
        }
    } catch {}
    throw "Port 8000 is already in use by another process. Close that process, then rerun .\start_backend.ps1."
}

$stdout = Join-Path $backendDir "backend.log"
$stderr = Join-Path $backendDir "backend-error.log"
$process = Start-Process -FilePath $python `
    -ArgumentList @("-m", "uvicorn", "main:app", "--host", "127.0.0.1", "--port", "8000") `
    -WorkingDirectory $backendDir -WindowStyle Hidden -PassThru `
    -RedirectStandardOutput $stdout -RedirectStandardError $stderr

for ($attempt = 0; $attempt -lt 40; $attempt++) {
    Start-Sleep -Milliseconds 750
    try {
        $health = Invoke-RestMethod -Uri "http://127.0.0.1:8000/api/health" -TimeoutSec 2
        if ($health.status -eq "healthy" -and $health.ocr -eq "available") {
            Write-Host "MedGuard backend with OCR is running at http://127.0.0.1:8000/app/"
            Write-Host "Backend logs: $stdout and $stderr"
            exit 0
        }
    } catch {}
    if ($process.HasExited) { break }
}

if (-not $process.HasExited) { Stop-Process -Id $process.Id -Force }
$errorTail = if (Test-Path -LiteralPath $stderr) { (Get-Content -LiteralPath $stderr -Tail 20) -join "`n" } else { "No backend log was created." }
throw "Backend did not become healthy with OCR enabled. Startup output:`n$errorTail"
