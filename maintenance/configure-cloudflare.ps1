#requires -Version 5.1
# Enter the token only at the hidden prompt. Never pass credentials as arguments.
$ErrorActionPreference = 'Stop'
if ($args.Count -gt 0) {
    [Console]::Error.WriteLine('This setup accepts no arguments. Enter the token only at its hidden prompt.')
    exit 3
}
$runtimePython = Join-Path (Split-Path -Parent $PSScriptRoot) 'work\runtime\Scripts\python.exe'
if (-not (Test-Path -LiteralPath $runtimePython -PathType Leaf)) {
    [Console]::Error.WriteLine('Run setup.ps1 before configuring Cloudflare.')
    exit 3
}
Push-Location -LiteralPath $PSScriptRoot
try {
    & $runtimePython -B -m szl_estate.cloudflare_ops --setup-credential
    $setupExitCode = $LASTEXITCODE
} finally {
    Pop-Location
}
exit $setupExitCode
