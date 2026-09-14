# The full evaluation campaign: N independent passes over every twin, through the desktop app.
#
# One pass is an anecdote. The generator is a language model, so the same finding can be handled
# differently on two runs, and a single-run percentage cannot be defended in a paper. This script
# runs the whole four-twin evaluation REPEATEDLY, keeping each pass separate, so the report can
# quote a mean and a spread rather than whichever number came out first.
#
# Each pass:
#   1. restarts the app once per twin (the sandbox image and suite command are per-language, and
#      MigrateConfig reads them from the environment at process start)
#   2. duplicates the twin and migrates the COPY -- a migrated twin is a spent twin
#   3. scores the copy against GROUND_TRUTH.json
#   4. audits what was actually written into the files (verify_migration.py)
#
# Usage:  powershell -ExecutionPolicy Bypass -File scripts\run_evaluation_campaign.ps1 -Passes 3

param([int]$Passes = 3)

$ErrorActionPreference = "Continue"
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
    # Filter on the COMMAND LINE. Matching python.exe or *qubit* also kills background pytest runs,
    # which has taken down a full suite mid-flight before.
    Get-CimInstance Win32_Process -Filter "Name='python.exe'" |
        Where-Object { $_.CommandLine -like '*uvicorn*' } |
        ForEach-Object { Stop-Process -Id $_.ProcessId -Force -ErrorAction SilentlyContinue }
    Get-Process qubit-desktop -ErrorAction SilentlyContinue | Stop-Process -Force
    Start-Sleep -Seconds 3
}

for ($pass = 1; $pass -le $Passes; $pass++) {
    $outDir = "$repo\qubit-v2\data\campaign\pass-$pass"
    New-Item -ItemType Directory -Force -Path $outDir | Out-Null
    Write-Output ""
    Write-Output "##############################################################"
    Write-Output "  PASS $pass of $Passes    $(Get-Date -Format 'HH:mm:ss')"
    Write-Output "##############################################################"

    foreach ($twin in $twins) {
        Write-Output ""
        Write-Output "--- pass $pass : $($twin.name) ---"
        Stop-Engine

        # WEBVIEW2_ADDITIONAL_BROWSER_ARGUMENTS is the only spelling WebView2 honours.
        $env:WEBVIEW2_ADDITIONAL_BROWSER_ARGUMENTS = "--remote-debugging-port=9222"
        $env:QUBIT_MIGRATE_TEST_SANDBOX_IMAGE = $twin.image
        $env:QUBIT_MIGRATE_TEST_COMMAND = $twin.cmd
        Start-Process -FilePath $exe
        Start-Sleep -Seconds 15

        $ok = $false
        foreach ($attempt in 1..12) {
            try {
                if ((Invoke-RestMethod "http://127.0.0.1:8787/api/v1/health" -TimeoutSec 5).status -eq "ok") {
                    $ok = $true; break
                }
            } catch { Start-Sleep -Seconds 3 }
        }
        if (-not $ok) { Write-Output "  engine never came up; skipping"; continue }

        & $py "$repo\scripts\twin_app_eval.py" --twin $twin.name --out "$outDir\app_eval_$($twin.name).json"

        # What actually landed in the files. Runs while the copy still exists, before the next
        # twin's duplication replaces it.
        & $py "$repo\scripts\verify_migration.py" --twin $twin.name --json "$outDir\written_$($twin.name).json" | Out-File -Encoding utf8 "$outDir\written_$($twin.name).txt"
    }
}

Stop-Engine
Write-Output ""
Write-Output "campaign done -- $Passes pass(es) in qubit-v2\data\campaign\"
