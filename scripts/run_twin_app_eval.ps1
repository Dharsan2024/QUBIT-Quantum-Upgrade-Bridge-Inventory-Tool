# Evaluate QUBIT against every digital twin, through the shipped desktop app.
#
# The app is restarted once per twin. That is not tidiness: `MigrateConfig` reads its sandbox image
# and suite command from the environment at process start, the Tauri shell passes its own
# environment straight to the uvicorn sidecar, and the two settings are per-language. One app
# instance cannot hold a Maven sandbox and a Ruby one at the same time.
#
# Each twin is duplicated into test-output/ first and the COPY is what gets migrated, because a
# migrated twin is a spent twin.

$ErrorActionPreference = "Stop"
$repo = "X:\final yaer\main projects"
$exe  = "$repo\dashboard\src-tauri\target\release\qubit-desktop.exe"
$py   = "$repo\.venv\Scripts\python.exe"

$twins = @(
    @{ name = "medivault-emr";   image = "qubit-eval/medivault:py312"; cmd = "python -m pytest tests -q --continue-on-collection-errors" },
    @{ name = "inkwell-esign";   image = "qubit-eval/inkwell:sandbox"; cmd = "ruby -Ilib -Itest test/crypto_contract_test.rb" },
    @{ name = "sentinel-idp";    image = "qubit-eval/sentinel:sandbox"; cmd = "go test ./..." },
    @{ name = "paymesh-gateway"; image = "qubit-eval/paymesh:sandbox";  cmd = "mvn -B -o test" }
)

function Stop-Engine {
    # Filter on the COMMAND LINE, not the image name: matching python.exe or *qubit* also kills
    # background pytest runs, which has cost a full suite mid-flight before.
    Get-CimInstance Win32_Process -Filter "Name='python.exe'" |
        Where-Object { $_.CommandLine -like '*uvicorn*' } |
        ForEach-Object { Stop-Process -Id $_.ProcessId -Force -ErrorAction SilentlyContinue }
    Get-Process qubit-desktop -ErrorAction SilentlyContinue | Stop-Process -Force
    Start-Sleep -Seconds 3
}

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
    Start-Process -FilePath $exe
    Start-Sleep -Seconds 15

    $ok = $false
    foreach ($attempt in 1..10) {
        try {
            if ((Invoke-RestMethod "http://127.0.0.1:8787/api/v1/health" -TimeoutSec 5).status -eq "ok") {
                $ok = $true; break
            }
        } catch { Start-Sleep -Seconds 3 }
    }
    if (-not $ok) { Write-Output "  engine never came up; skipping $($twin.name)"; continue }

    & $py "$repo\scripts\twin_app_eval.py" --twin $twin.name --out "$repo\qubit-v2\data\app_eval_$($twin.name).json"
}

Stop-Engine
Write-Output "done -- per-twin results in qubit-v2\data\app_eval_*.json"
