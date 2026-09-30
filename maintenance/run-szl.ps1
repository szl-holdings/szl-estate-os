#requires -Version 5.1
# Forward arguments as an array; never compose a shell command from user input.
$ErrorActionPreference = 'Stop'
$runtimePython = Join-Path (Split-Path -Parent $PSScriptRoot) 'work\runtime\Scripts\python.exe'
$entryPoint = Join-Path $PSScriptRoot 'szl_operational.py'
if (-not (Test-Path -LiteralPath $runtimePython -PathType Leaf)) {
    [Console]::Error.WriteLine('The isolated runtime is missing. Run setup.ps1 in this outputs directory first.')
    exit 3
}
if (-not (Test-Path -LiteralPath $entryPoint -PathType Leaf)) {
    [Console]::Error.WriteLine('szl_operational.py is missing beside this launcher.')
    exit 3
}
Push-Location -LiteralPath $PSScriptRoot
try {
    & $runtimePython -B $entryPoint @args
    $runnerExitCode = $LASTEXITCODE
} finally {
    Pop-Location
}
exit $runnerExitCode
