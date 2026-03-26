param(
    [string]$SourceRoot
)

$ErrorActionPreference = "Stop"
Set-Location $PSScriptRoot

$cmd = @("run", "aliyun-sync-rules")
if ($SourceRoot) {
    $cmd += @("--source-root", $SourceRoot)
}

$poetryCmd = Get-Command poetry -ErrorAction SilentlyContinue
function Invoke-Poetry {
    param(
        [Parameter(Mandatory = $true)]
        [string[]]$Args
    )

    if ($poetryCmd) {
        & poetry @Args
    } else {
        & py -m poetry @Args
    }
}

# Ensure dependencies and local package entrypoints are installed.
Invoke-Poetry @("install", "--no-interaction")

if ($LASTEXITCODE -ne 0) {
    throw "poetry install failed. Please fix install errors and run again."
}

Invoke-Poetry $cmd
