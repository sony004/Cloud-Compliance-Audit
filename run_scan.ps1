param(
    [string]$Compliance = "cis_2.0_alibabacloud",
    [string[]]$Region = @("cn-beijing"),
    [switch]$IgnoreExitCode3,
    [switch]$UseLocalChecks
)

$ErrorActionPreference = "Stop"

Set-Location $PSScriptRoot

if (-not (Test-Path ".env") -and (Test-Path ".env.example")) {
    Copy-Item ".env.example" ".env"
    Write-Host "Created .env from .env.example. Please fill your Alibaba Cloud credentials in aliyun/.env"
    exit 1
}

$cmd = @("run", "aliyun-audit", "scan", "--region") + $Region

if ($UseLocalChecks) {
    $cmd += "--use-local-checks"
} else {
    $cmd += @("--compliance", $Compliance)
}

if ($IgnoreExitCode3) {
    $cmd += "--ignore-exit-code-3"
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
