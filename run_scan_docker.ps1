param(
    [string]$Compliance = "cis_2.0_alibabacloud",
    [string[]]$Region = @("cn-beijing"),
    [switch]$IgnoreExitCode3,
    [switch]$UseLocalChecks,
    [string]$Image = "toniblyx/prowler:stable"
)

$ErrorActionPreference = "Stop"
Set-Location $PSScriptRoot

if (-not (Test-Path ".env") -and (Test-Path ".env.example")) {
    Copy-Item ".env.example" ".env"
    Write-Host "Created .env from .env.example. Please fill your Alibaba Cloud credentials in aliyun/.env"
    exit 1
}

if (-not (Get-Command docker -ErrorAction SilentlyContinue)) {
    throw "Docker is not available in PATH."
}

$scanArgs = @("alibabacloud", "--region") + $Region
if ($UseLocalChecks) {
    $scanArgs += @("--checks-file", "/scan/rules/checks/alibabacloud_all_checks.json")
} else {
    $scanArgs += @("--compliance", $Compliance)
}
$scanArgs += @("-o", "/scan/output")

$dockerArgs = @(
    "run", "--rm",
    "--env-file", ".env",
    "-v", "${PSScriptRoot}:/scan",
    $Image
) + $scanArgs

& docker @dockerArgs

if ($LASTEXITCODE -eq 3 -and $IgnoreExitCode3) {
    Write-Host "Ignoring prowler exit code 3 by request."
    exit 0
}

exit $LASTEXITCODE
