param([string]$Python = "python")

$ErrorActionPreference = "Stop"
Push-Location $PSScriptRoot
try {
    & $Python -m PyInstaller --noconfirm --onefile --windowed --name WiFiAnalyzer --exclude-module PyQt6 --exclude-module PyQt5 --exclude-module PySide2 main.py
    if ($LASTEXITCODE -ne 0) { throw "PyInstaller failed (exit $LASTEXITCODE)." }
} finally {
    Pop-Location
}
