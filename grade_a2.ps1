# grade_a2.ps1 — Windows wrapper for the rubric-oriented E2E test.
# Requires Python 3 to be on PATH (installed from python.org or via the
# Microsoft Store — both register the 'python' / 'py' launchers).
#
# Usage:
#   .\grade_a2.ps1 [submission_dir] [extra args...]
#
# Examples:
#   .\grade_a2.ps1 .
#   $env:MAIN_SERVER="Server"; $env:MAIN_HOST="IntermediateHost"; $env:MAIN_CLIENT="Client"; .\grade_a2.ps1 .
#   $env:JAVA_OPTS="-Xmx256m"; $env:TIMEOUT_SECONDS="35"; .\grade_a2.ps1 .
#   .\grade_a2.ps1 . --seed 123 --no-color

param(
    [string]$Root = ".",
    [Parameter(ValueFromRemainingArguments = $true)]
    [string[]]$ExtraArgs = @()
)

$ErrorActionPreference = "Stop"

$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Definition

# Prefer the Python Launcher (py) when available; fall back to 'python'.
if (Get-Command py -ErrorAction SilentlyContinue) {
    $pythonExe = "py"
} elseif (Get-Command python -ErrorAction SilentlyContinue) {
    $pythonExe = "python"
} else {
    Write-Error "Python 3 not found. Install it from https://www.python.org/downloads/ and ensure it is on your PATH."
    exit 1
}

& $pythonExe "$scriptDir\grade_a2.py" --root $Root --keep-logs @ExtraArgs
exit $LASTEXITCODE
