param(
    [string]$Compliance = "cis_2.0_alibabacloud",
    [string[]]$Region = @("cn-beijing"),
    [switch]$IgnoreExitCode3,
    [switch]$UseLocalChecks,
    [string]$Image = "aliyun-prowler-patched:latest",
    [switch]$BuildImage,
    [switch]$SkipNistMap,
    [string]$TargetInstanceId = ""
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

function Test-DockerImageExists {
    param(
        [Parameter(Mandatory = $true)]
        [string]$ImageName
    )
    & docker image inspect $ImageName *> $null
    return ($LASTEXITCODE -eq 0)
}

function Build-PatchedImage {
    param(
        [Parameter(Mandatory = $true)]
        [string]$ImageName
    )
    Write-Host "Building patched image: $ImageName"
    & docker build -f Dockerfile.prowler-patched -t $ImageName .
    if ($LASTEXITCODE -ne 0) {
        throw "Failed to build Docker image '$ImageName'."
    }
}

$isDefaultPatchedImage = $Image -eq "aliyun-prowler-patched:latest"
if ($BuildImage -or ($isDefaultPatchedImage -and -not (Test-DockerImageExists -ImageName $Image))) {
    Build-PatchedImage -ImageName $Image
}

function Export-TargetInstanceCsv {
    param(
        [Parameter(Mandatory = $true)]
        [string]$OutputDir,
        [Parameter(Mandatory = $true)]
        [string]$InstanceId
    )
    $latestCsv = Get-ChildItem $OutputDir -Filter "prowler-output-*.csv" -File |
        Where-Object { $_.BaseName -notlike "*_alibabacloud" } |
        Sort-Object LastWriteTime -Descending |
        Select-Object -First 1

    if (-not $latestCsv) {
        Write-Warning "No scan CSV found under $OutputDir, skipping instance filter."
        return $null
    }

    $allRows = Import-Csv $latestCsv.FullName -Delimiter ';'
    $filteredRows = $allRows | Where-Object {
        $_.RESOURCEID -eq $InstanceId -or ($_.RESOURCE_UID -like "*$InstanceId*")
    }

    $safeInstanceId = ($InstanceId -replace "[^A-Za-z0-9_-]", "_")
    $targetCsv = Join-Path $OutputDir ($latestCsv.BaseName + "_instance_" + $safeInstanceId + ".csv")

    if (($filteredRows | Measure-Object).Count -eq 0) {
        Write-Warning "Target instance '$InstanceId' not found in $($latestCsv.Name). Exporting header-only CSV."
        $allRows | Select-Object -First 0 | Export-Csv $targetCsv -NoTypeInformation -Encoding UTF8 -Delimiter ';'
        return $targetCsv
    }

    $filteredRows | Export-Csv $targetCsv -NoTypeInformation -Encoding UTF8 -Delimiter ';'
    Write-Host "Target instance filter applied: $InstanceId"
    Write-Host "Filtered CSV: $targetCsv"
    return $targetCsv
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
$scanExitCode = $LASTEXITCODE

if (-not $SkipNistMap -and ($scanExitCode -eq 0 -or $scanExitCode -eq 3)) {
    $targetMapCsv = $null
    if ($TargetInstanceId) {
        $targetMapCsv = Export-TargetInstanceCsv -OutputDir (Join-Path $PSScriptRoot "output") -InstanceId $TargetInstanceId
    }

    Write-Host "Running NIST SP 800-53 mapping..."

    $mapArgs = @(
        "run", "--rm",
        "-v", "${PSScriptRoot}:/scan",
        "-w", "/scan",
        "-e", "PYTHONPATH=/scan/src",
        "--entrypoint", "python",
        $Image,
        "-m", "aliyun_project.cli", "nist-map",
        "--output-dir", "/scan/output",
        "--report-dir", "/scan/output/nist"
    )
    if ($targetMapCsv) {
        $targetMapCsvName = [System.IO.Path]::GetFileName($targetMapCsv)
        $mapArgs += @("--file", "/scan/output/$targetMapCsvName")
    }

    & docker @mapArgs
    if ($LASTEXITCODE -ne 0) {
        throw "NIST mapping failed with exit code $LASTEXITCODE."
    }
}

if ($scanExitCode -eq 3 -and $IgnoreExitCode3) {
    Write-Host "Ignoring prowler exit code 3 by request."
    exit 0
}

exit $scanExitCode
