# Evaluate QUBIT against every digital twin, through the shipped desktop app.
#
# The app is restarted once per twin. That is not tidiness: `MigrateConfig` reads its sandbox image
# and suite command from the environment at process start, the Tauri shell passes its own
# environment straight to the uvicorn sidecar, and the two settings are per-language. One app
# instance cannot hold a Maven sandbox and a Ruby one at the same time.
#
# Each twin is duplicated into test-output/ first and the COPY is what gets migrated, because a
# migrated twin is a spent twin.

param(
    [string]$RepoRoot = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
)

$ErrorActionPreference = "Stop"
$repo = (Resolve-Path $RepoRoot).Path
$exe  = Join-Path $repo "dashboard\src-tauri\target\release\qubit-desktop.exe"
$py   = Join-Path $repo ".venv\Scripts\python.exe"
if (-not (Test-Path $exe)) { throw "Desktop executable not found: $exe" }
if (-not (Test-Path $py)) { throw "Python executable not found: $py" }
if (Get-Process qubit-desktop -ErrorAction SilentlyContinue) {
    throw "Close the existing QUBIT desktop before evaluation; this script will not stop your session."
}
if (Get-NetTCPConnection -State Listen -LocalPort 8787,9222 -ErrorAction SilentlyContinue) {
    throw "Evaluation ports 8787/9222 are occupied. Stop the conflicting service deliberately first."
}
$desktopProcess = $null

$twins = @(
    @{ name = "medivault-emr";   image = "qubit-eval/medivault:py312"; cmd = "python -m pytest tests -q --continue-on-collection-errors" },
    @{ name = "inkwell-esign";   image = "qubit-eval/inkwell:sandbox"; cmd = "ruby -Ilib -Itest test/crypto_contract_test.rb" },
    @{ name = "sentinel-idp";    image = "qubit-eval/sentinel:sandbox"; cmd = "go test ./..." },
    @{ name = "paymesh-gateway"; image = "qubit-eval/paymesh:sandbox";  cmd = "mvn -B -o test" }
)

function Stop-Engine {
    # Only the process tree started by this invocation is ours to stop. Never kill arbitrary
    # Python/uvicorn processes or a user's independently opened desktop.
    if ($null -ne $script:desktopProcess -and -not $script:desktopProcess.HasExited) {
        & "$env:SystemRoot\System32\taskkill.exe" /PID $script:desktopProcess.Id /T /F | Out-Null
        if ($LASTEXITCODE -ne 0) { throw "Could not stop the evaluation desktop process tree." }
        $script:desktopProcess.WaitForExit(10000) | Out-Null
    }
    $script:desktopProcess = $null
}

$savedEnvironment = @{}
foreach ($name in @('WEBVIEW2_ADDITIONAL_BROWSER_ARGUMENTS', 'QUBIT_MIGRATE_TEST_SANDBOX_IMAGE', 'QUBIT_MIGRATE_TEST_COMMAND')) {
    $savedEnvironment[$name] = [Environment]::GetEnvironmentVariable($name, 'Process')
}
try {
  foreach ($twin in $twins) {
    Write-Output "=============================================================="
    Write-Output "  $($twin.name)   sandbox=$($twin.image)"
    Write-Output "=============================================================="
    Stop-Engine

    # WEBVIEW2_ADDITIONAL_BROWSER_ARGUMENTS is the only spelling WebView2 honours; passing
    # --remote-debugging-port to the exe directly does nothing at all.
    $env:WEBVIEW2_ADDITIONAL_BROWSER_ARGUMENTS = "--remote-debugging-port=9222"
    $env:QUBIT_MIGRATE_TEST_SANDBOX_IMAGE = $twin.image
    $env:QUBIT_MIGRATE_TEST_COMMAND = $twin.cmd
    $script:desktopProcess = Start-Process -FilePath $exe -WorkingDirectory $repo -PassThru -WindowStyle Hidden
    Start-Sleep -Seconds 15

    $ok = $false
    foreach ($attempt in 1..10) {
        try {
            if ((Invoke-RestMethod "http://127.0.0.1:8787/api/v1/health" -TimeoutSec 5).status -eq "ok") {
                $ok = $true; break
            }
        } catch { Start-Sleep -Seconds 3 }
    }
    if (-not $ok) { throw "Engine never became healthy for $($twin.name); evaluation incomplete." }

    $outputDirectory = Join-Path $repo 'test-output\desktop-evaluation'
    New-Item -ItemType Directory -Path $outputDirectory -Force | Out-Null
    & $py "$repo\scripts\twin_app_eval.py" --twin $twin.name --out (Join-Path $outputDirectory "app_eval_$($twin.name).json")
    if ($LASTEXITCODE -ne 0) { throw "Evaluation failed for $($twin.name). Inspect its output." }
  }
} finally {
    try { Stop-Engine } finally {
        foreach ($name in $savedEnvironment.Keys) {
            [Environment]::SetEnvironmentVariable($name, $savedEnvironment[$name], 'Process')
        }
    }
}

Write-Output "done -- per-twin results in test-output\desktop-evaluation\app_eval_*.json"
