param(
    [Parameter(Position = 0)]
    [ValidateSet("help", "build", "test", "fmt", "vet", "clean", "run")]
    [string]$Task = "help",

    [string]$Manifest,
    [string]$Out
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

function Invoke-Cargo {
    param(
        [Parameter(Mandatory = $true)]
        [string[]]$Arguments
    )

    & cargo @Arguments
    if ($LASTEXITCODE -ne 0) {
        exit $LASTEXITCODE
    }
}

$taskAliases = @{
    build = "ox-build"
    test = "ox-test"
    fmt = "ox-fmt"
    vet = "ox-vet"
    clean = "ox-clean"
}

if ($Task -eq "help") {
    Write-Host "Canonical tasks live in .cargo/config.toml and run everywhere via cargo aliases:"
    Write-Host "  cargo ox-build"
    Write-Host "  cargo ox-test"
    Write-Host "  cargo ox-fmt"
    Write-Host "  cargo ox-vet"
    Write-Host "  cargo ox-clean"
    Write-Host "  cargo ox-run --manifest fixtures/minimal.manifest.json"
    Write-Host ""
    Write-Host "PowerShell convenience wrapper:"
    Write-Host "  ./scripts/dev.ps1 build"
    Write-Host "  ./scripts/dev.ps1 test"
    Write-Host "  ./scripts/dev.ps1 fmt"
    Write-Host "  ./scripts/dev.ps1 vet"
    Write-Host "  ./scripts/dev.ps1 clean"
    Write-Host "  ./scripts/dev.ps1 run -Manifest fixtures/minimal.manifest.json"
    Write-Host "  ./scripts/dev.ps1 run -Manifest fixtures/api.manifest.json -Out delta.json"
    Write-Host ""
    Write-Host "If execution policy blocks direct script invocation, use:"
    Write-Host "  powershell -ExecutionPolicy Bypass -File .\\scripts\\dev.ps1 help"
}
elseif ($Task -eq "run") {
    if ([string]::IsNullOrWhiteSpace($Manifest)) {
        throw "run requires -Manifest <path>"
    }

    $arguments = @("ox-run", "--manifest", $Manifest)
    if (-not [string]::IsNullOrWhiteSpace($Out)) {
        $arguments += @("--out", $Out)
    }
    Invoke-Cargo $arguments
}
else {
    Invoke-Cargo @($taskAliases[$Task])
}
