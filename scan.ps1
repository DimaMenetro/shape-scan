# shape-scan runner
# Usage: .\scan.ps1 <file-or-directory> [options]
# Examples:
#   .\scan.ps1 C:\some\file.exe
#   .\scan.ps1 C:\some\folder -r
#   .\scan.ps1 C:\some\file.exe -f json

$env:PATH = "$env:USERPROFILE\.cargo\bin;C:\msys64\mingw64\bin;$env:PATH"

$exe = ".\target\debug\shape-scan.exe"
if (!(Test-Path $exe)) {
    Write-Host "[TEM] Binary not found. Building first..." -ForegroundColor Yellow
    cargo build
    if ($LASTEXITCODE -ne 0) { exit 2 }
}

& $exe scan @args
