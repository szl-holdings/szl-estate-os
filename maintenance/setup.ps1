#requires -Version 5.1
<#
.SYNOPSIS
Install the SZL maintenance runner into this workspace's isolated Python runtime.
.DESCRIPTION
Uses the exact dependency lock when available. Does not change system packages,
provider credentials, execution policy, scheduled tasks, or provider state.
#>
[CmdletBinding()]
param(
    [string]$PythonPath,
    [switch]$SkipTests
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
$deliveryDirectory = $PSScriptRoot
$workspaceDirectory = Split-Path -Parent $deliveryDirectory
$runtimeDirectory = Join-Path $workspaceDirectory 'work\runtime'
$runtimePython = Join-Path $runtimeDirectory 'Scripts\python.exe'
$requirementsLock = Join-Path $deliveryDirectory 'runtime-requirements.lock.txt'
$requirementsSource = Join-Path $deliveryDirectory 'requirements-dev.txt'

function Find-BootstrapPython {
    if ($PythonPath) {
        if (-not (Test-Path -LiteralPath $PythonPath -PathType Leaf)) {
            throw 'The supplied PythonPath is not an existing executable.'
        }
        return (Resolve-Path -LiteralPath $PythonPath).Path
    }
    $launcher = Get-Command py.exe -ErrorAction SilentlyContinue
    if ($launcher) {
        $candidate = & $launcher.Source -3.11 -c 'import sys; print(sys.executable)' 2>$null
        if ($LASTEXITCODE -eq 0 -and $candidate -and (Test-Path -LiteralPath $candidate -PathType Leaf)) {
            return $candidate
        }
    }
    $systemPython = Get-Command python.exe -ErrorAction SilentlyContinue
    if ($systemPython -and $systemPython.Source -notlike '*\Microsoft\WindowsApps\*') {
        return $systemPython.Source
    }
    $bundledPython = Join-Path $env:USERPROFILE '.cache\codex-runtimes\codex-primary-runtime\dependencies\python\python.exe'
    if (Test-Path -LiteralPath $bundledPython -PathType Leaf) {
        return $bundledPython
    }
    throw 'Python 3.11 or newer was not found. Install Python, then rerun setup.ps1 with -PythonPath pointing to python.exe.'
}

if (-not (Test-Path -LiteralPath $runtimePython -PathType Leaf)) {
    if (Test-Path -LiteralPath $runtimeDirectory) {
        throw 'work\runtime already exists without its expected Python executable. Inspect that directory before repairing it; setup does not delete existing files.'
    }
    $bootstrapPython = Find-BootstrapPython
    & $bootstrapPython -c 'import sys; raise SystemExit(0 if sys.version_info >= (3, 11) else 1)'
    if ($LASTEXITCODE -ne 0) { throw 'The selected Python version is older than 3.11.' }
    Write-Host 'Creating isolated Python runtime in work\runtime ...'
    & $bootstrapPython -m venv $runtimeDirectory
    if ($LASTEXITCODE -ne 0) { throw 'Virtual environment creation failed.' }
}

& $runtimePython -c 'import sys; raise SystemExit(0 if sys.version_info >= (3, 11) and sys.prefix != sys.base_prefix else 1)'
if ($LASTEXITCODE -ne 0) { throw 'The selected runtime is not an isolated Python 3.11+ virtual environment.' }

$selectedRequirements = if (Test-Path -LiteralPath $requirementsLock -PathType Leaf) {
    $requirementsLock
} else {
    $requirementsSource
}
Write-Host ('Installing dependencies from ' + (Split-Path -Leaf $selectedRequirements) + ' ...')
& $runtimePython -m pip install --disable-pip-version-check --quiet -r $selectedRequirements
if ($LASTEXITCODE -ne 0) { throw 'Dependency installation failed. No provider operation was attempted.' }
& $runtimePython -m pip check
if ($LASTEXITCODE -ne 0) { throw 'Installed dependency consistency check failed.' }

if (-not $SkipTests) {
    Push-Location -LiteralPath $deliveryDirectory
    try {
        & $runtimePython -B -m pytest -q
        if ($LASTEXITCODE -ne 0) { throw 'Offline regression tests failed.' }
    } finally {
        Pop-Location
    }
}

Write-Host 'SZL maintenance runner is installed. Provider credentials were not changed.'
Write-Host 'Run .\run-szl.ps1 --help, then .\run-szl.ps1 --providers github for a read-only audit.'
