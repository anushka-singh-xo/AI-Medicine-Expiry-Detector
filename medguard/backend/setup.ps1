$ErrorActionPreference = "Stop"
$backendDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$venvDir = Join-Path $backendDir ".venv"
if (-not (Test-Path -LiteralPath (Join-Path $venvDir "Scripts\python.exe"))) {
    & python -m venv $venvDir
    if ($LASTEXITCODE -ne 0) {
        throw "A standard Windows CPython 3.10+ installation is required to create backend\.venv."
    }
}
$python = Join-Path $venvDir "Scripts\python.exe"
$platform = & $python -c "import sysconfig; print(sysconfig.get_platform())"
if ($LASTEXITCODE -ne 0 -or $platform -notmatch '^win[-_](amd64|arm64)$') {
    throw "Use standard Windows CPython (win_amd64 or win_arm64); the existing MinGW Python environment cannot load ONNX Runtime wheels."
}
$versionText = & $python -c "import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}')"
if ($LASTEXITCODE -ne 0 -or $versionText -notmatch '^3\.(10|11|12|13|14)$') {
    throw "Python 3.10 through 3.14 is supported by this setup."
}

Write-Host "Installing backend requirements with $python"
& $python -m pip install --upgrade pip
if ($LASTEXITCODE -ne 0) { throw "Could not upgrade pip." }
& $python -m pip install -r (Join-Path $backendDir "requirements.txt")
if ($LASTEXITCODE -ne 0) { throw "Dependency installation failed." }
& $python -c "from rapidocr import RapidOCR; RapidOCR(); import onnxruntime; print('RapidOCR and ONNX Runtime ready (' + onnxruntime.__version__ + ')')"
if ($LASTEXITCODE -ne 0) { throw "OCR initialization failed. See the error above, then rerun .\setup.ps1." }
Write-Host "Setup complete. Start the service with .\run.ps1"
