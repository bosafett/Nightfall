# Starts the BLACKSITE console on this machine, bound to 127.0.0.1:8443 only.
#   powershell -ExecutionPolicy Bypass -File .\start-blacksite.ps1      (from infra\lab)
# First run creates a Python environment (needs Python 3.13: winget install Python.Python.3.13).
$ErrorActionPreference = "Stop"
$here = Split-Path -Parent $MyInvocation.MyCommand.Path
$root = Resolve-Path (Join-Path $here "..\..")
$envFile = Join-Path $here "blacksite.env"
if (-not (Test-Path $envFile)) { throw "Copy blacksite.env.example to blacksite.env and fill it in first." }
$venv = Join-Path $root "api\.venv-blacksite"
if (-not (Test-Path (Join-Path $venv "Scripts\nightfall-blacksite.exe"))) {
    Write-Host "Setting up Python environment (one time)..."
    py -3.13 -m venv $venv
    & (Join-Path $venv "Scripts\pip.exe") install --quiet -r (Join-Path $root "api\requirements.lock")
    & (Join-Path $venv "Scripts\pip.exe") install --quiet --no-deps (Join-Path $root "api")
}
Get-Content $envFile | ForEach-Object {
    $line = $_.Trim()
    if ($line -and -not $line.StartsWith("#") -and $line.Contains("=")) {
        $name, $value = $line.Split("=", 2)
        [Environment]::SetEnvironmentVariable($name.Trim(), $value.Trim(), "Process")
    }
}
Write-Host "BLACKSITE: open http://127.0.0.1:8443/ on this machine. Ctrl+C stops it."
& (Join-Path $venv "Scripts\nightfall-blacksite.exe")
