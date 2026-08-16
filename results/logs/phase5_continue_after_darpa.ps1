param(
    [string]$ContainerId = "69d6615d20d8",
    [string]$RunnerImage = "projecta-phase5-runner:2026-08-14"
)

$ErrorActionPreference = "Continue"

$KitRoot = (Resolve-Path (Join-Path $PSScriptRoot "..\..")).Path
$LogDir = Join-Path $KitRoot "results\logs"
$RawDir = Join-Path $KitRoot "results\raw"
$Journal = Join-Path $LogDir "continuation_after_darpa_journal.log"

function Add-Journal {
    param([string]$Message)
    "[$(Get-Date -Format o)] $Message" | Add-Content -Path $Journal
}

function Invoke-RunnerStep {
    param(
        [string]$Name,
        [string[]]$PythonArgs
    )

    $outLog = Join-Path $LogDir "continuation_$Name.out.log"
    $errLog = Join-Path $LogDir "continuation_$Name.err.log"
    $exitLog = Join-Path $LogDir "continuation_$Name.exitcode"
    $volume = "${KitRoot}:/work"
    $dockerArgs = @(
        "run", "--rm",
        "-v", $volume,
        "-v", "/var/run/docker.sock:/var/run/docker.sock",
        "-w", "/work",
        $RunnerImage,
        "python"
    ) + $PythonArgs

    Add-Journal "START ${Name}: docker $($dockerArgs -join ' ')"
    & docker @dockerArgs > $outLog 2> $errLog
    $code = $LASTEXITCODE
    Set-Content -Path $exitLog -Value $code
    Add-Journal "END ${Name}: exit=$code"
    return $code
}

New-Item -ItemType Directory -Force -Path $LogDir | Out-Null
Add-Journal "Supervisor started. Waiting for DARPA container $ContainerId."

& docker wait $ContainerId > (Join-Path $LogDir "continuation_darpa_full_rq5.wait.log") 2> (Join-Path $LogDir "continuation_darpa_full_rq5.wait.err.log")
$waitCode = $LASTEXITCODE
Set-Content -Path (Join-Path $LogDir "continuation_darpa_full_rq5.wait.exitcode") -Value $waitCode
Add-Journal "docker wait finished with launcher exit=$waitCode."

$metrics = Join-Path $RawDir "rq5_darpa_cadets_metrics.csv"
if (Test-Path $metrics) {
    Add-Journal "Found $metrics. Running remaining DARPA steps."
    $code = Invoke-RunnerStep "darpa_rq1_degradation" @("experiments/run_darpa_rq1_degradation.py")
    if ($code -eq 0) {
        $code = Invoke-RunnerStep "darpa_rq2_explanations" @("experiments/run_darpa_rq2_explanations.py")
    }
    if ($code -eq 0) {
        $code = Invoke-RunnerStep "darpa_rq4_performance" @("experiments/run_darpa_rq4_perf.py")
    }
    if ($code -ne 0) {
        Add-Journal "A remaining DARPA step failed with exit=$code. Consolidation will preserve gate failure."
    }
} else {
    Add-Journal "Missing $metrics after DARPA container exit. Skipping dependent DARPA steps and consolidating failure."
}

Invoke-RunnerStep "consolidate" @("scripts/consolidate_results.py") | Out-Null
Add-Journal "Supervisor finished."
