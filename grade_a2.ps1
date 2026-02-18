# grade_a2.ps1 - Windows wrapper for single-submission and bulk A2 grading.
# Requires Python 3 to be on PATH (installed from python.org or via the
# Microsoft Store - both register the 'python' / 'py' launchers).
#
# Usage:
#   Single submission: .\grade_a2.ps1 [submission_dir] [extra args...]
#   Bulk evaluation:   .\grade_a2.ps1 -Bulk [bulk_root] [extra args...]
#
# Examples:
#   .\grade_a2.ps1 .
#   $env:MAIN_SERVER="Server"; $env:MAIN_HOST="IntermediateHost"; $env:MAIN_CLIENT="Client"; .\grade_a2.ps1 .
#   $env:JAVA_OPTS="-Xmx256m"; $env:TIMEOUT_SECONDS="35"; .\grade_a2.ps1 .
#   .\grade_a2.ps1 -Bulk "D:\exports\a2" --report ".\bulk_report.html"

param(
    [switch]$Bulk,
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

# Ensure pywinpty is present for better Windows pseudo-terminal behavior.
# If install fails, grade_a2.py will fall back to pipe-based behavior.
& $pythonExe -c "import winpty" *> $null
if ($LASTEXITCODE -ne 0) {
    Write-Host "pywinpty not found. Installing with pip..."
    & $pythonExe -m pip install --user pywinpty
    if ($LASTEXITCODE -ne 0) {
        Write-Warning "Could not install pywinpty; continuing with built-in fallback."
    } else {
        & $pythonExe -c "import winpty" *> $null
        if ($LASTEXITCODE -ne 0) {
            Write-Warning "pywinpty install completed but import still fails; continuing with fallback."
        }
    }
}

if ($Bulk) {
    & $pythonExe "$scriptDir\grade_a2_bulk.py" --bulk-root $Root @ExtraArgs
} else {
    & $pythonExe "$scriptDir\grade_a2.py" --root $Root --keep-logs @ExtraArgs
}
exit $LASTEXITCODE
