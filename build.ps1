# shape-scan build script
# Usage: .\build.ps1          (debug build)
#        .\build.ps1 release  (optimized release build)
#        .\build.ps1 run      (build and run --help)

$env:PATH = "$env:USERPROFILE\.cargo\bin;C:\msys64\mingw64\bin;$env:PATH"

$mode = $args[0]

if ($mode -eq "release") {
    Write-Host "[TEM] Building release..." -ForegroundColor Cyan
    cargo build --release
    if ($LASTEXITCODE -eq 0) {
        Write-Host "[TEM] Release binary: .\target\release\shape-scan.exe" -ForegroundColor Green
    }
} elseif ($mode -eq "run") {
    cargo build
    if ($LASTEXITCODE -eq 0) {
        Write-Host ""
        & .\target\debug\shape-scan.exe --help
    }
} else {
    Write-Host "[TEM] Building debug..." -ForegroundColor Cyan
    cargo build
    if ($LASTEXITCODE -eq 0) {
        Write-Host "[TEM] Debug binary: .\target\debug\shape-scan.exe" -ForegroundColor Green
    }
}
