param(
    [switch]$Rebuild,
    [int]$ServerPort = 8080,
    [int]$BridgePort = 1425,
    [switch]$NoBrowser
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$repoRoot = Split-Path -Parent $PSScriptRoot
$targetDir = Join-Path $repoRoot "target\x86_64-pc-windows-gnullvm\debug"
$serverExe = Join-Path $targetDir "anvil-server.exe"
$desktopExe = Join-Path $targetDir "anvil-desktop.exe"

$localAppData = if ($env:LOCALAPPDATA) { $env:LOCALAPPDATA } else { Join-Path $env:TEMP "Anvil" }
$dataDir = Join-Path $localAppData "Anvil\local-dev"
New-Item -ItemType Directory -Path $dataDir -Force | Out-Null

$envFile = Join-Path $dataDir "server.env"
$serverDb = Join-Path $dataDir "server.db"
$desktopCacheDb = Join-Path $dataDir "desktop_cache.db"
$serverOutLog = Join-Path $dataDir "anvil-server.out.log"
$serverErrLog = Join-Path $dataDir "anvil-server.err.log"
$desktopOutLog = Join-Path $dataDir "anvil-desktop.out.log"
$desktopErrLog = Join-Path $dataDir "anvil-desktop.err.log"

function Find-LlvmMingwBin {
    if (-not $env:LOCALAPPDATA) { return $null }
    $wingetGlob = Join-Path $env:LOCALAPPDATA "Microsoft\WinGet\Packages\MartinStorsjo.LLVM-MinGW.UCRT_*\llvm-mingw-*\bin"
    $candidate = Get-ChildItem -Path $wingetGlob -Directory -ErrorAction SilentlyContinue | Select-Object -First 1
    if ($candidate) {
        return $candidate.FullName
    }
    $clangCmd = Get-Command x86_64-w64-mingw32-clang.exe -ErrorAction SilentlyContinue
    if ($clangCmd) {
        return Split-Path -Parent $clangCmd.Source
    }
    return $null
}

function Ensure-FrontendToolchain {
    $nodeCmd = Get-Command node -ErrorAction SilentlyContinue
    $pnpmCmd = Get-Command pnpm -ErrorAction SilentlyContinue
    if (-not $nodeCmd -or -not $pnpmCmd) {
        Write-Host ""
        Write-Host "Prerequis frontend manquants pour l'interface Anvil Desktop :" -ForegroundColor Yellow
        if (-not $nodeCmd) {
            Write-Host "  1. Installez Node.js LTS :"
            Write-Host "       winget install OpenJS.NodeJS.LTS" -ForegroundColor Cyan
            Write-Host "     (Fermez puis rouvrez PowerShell apres installation)"
        }
        if (-not $pnpmCmd) {
            Write-Host "  2. Activez pnpm via Corepack :"
            Write-Host "       corepack enable" -ForegroundColor Cyan
            Write-Host "       corepack prepare pnpm@9.15.0 --activate" -ForegroundColor Cyan
        }
        Write-Host ""
        exit 1
    }
}

function Invoke-WorkspaceCargoBuild {
    $cargoCmd = Get-Command cargo -ErrorAction SilentlyContinue
    if (-not $cargoCmd) {
        throw "cargo est introuvable dans le PATH."
    }

    $llvmBin = Find-LlvmMingwBin
    $savedPath = $env:PATH
    $savedIncremental = $env:CARGO_INCREMENTAL
    $savedCc = $env:CC_x86_64_pc_windows_gnullvm
    $savedCxx = $env:CXX_x86_64_pc_windows_gnullvm
    $savedAr = $env:AR_x86_64_pc_windows_gnullvm
    $savedLinker = $env:CARGO_TARGET_X86_64_PC_WINDOWS_GNULLVM_LINKER

    try {
        $env:CARGO_INCREMENTAL = "0"
        if ($llvmBin) {
            $env:PATH = ($env:PATH -split ';' | Where-Object { $_ -and $_ -notmatch 'llvm-mingw' }) -join ';'
            $env:CC_x86_64_pc_windows_gnullvm = Join-Path $llvmBin "x86_64-w64-mingw32-clang.exe"
            $env:CXX_x86_64_pc_windows_gnullvm = Join-Path $llvmBin "x86_64-w64-mingw32-clang++.exe"
            $env:AR_x86_64_pc_windows_gnullvm = Join-Path $llvmBin "llvm-ar.exe"
            $env:CARGO_TARGET_X86_64_PC_WINDOWS_GNULLVM_LINKER = Join-Path $llvmBin "x86_64-w64-mingw32-clang.exe"
        }

        Push-Location $repoRoot
        try {
            Write-Host "[Anvil] Compilation des binaires anvil-server et anvil-desktop..." -ForegroundColor Cyan
            & cargo build --target x86_64-pc-windows-gnullvm --offline --locked -j 2 --bin anvil-server --bin anvil-desktop
            if ($LASTEXITCODE -ne 0) {
                throw "Echec de compilation Cargo (code $LASTEXITCODE)."
            }
        }
        finally {
            Pop-Location
        }
    }
    finally {
        $env:PATH = $savedPath
        $env:CARGO_INCREMENTAL = $savedIncremental
        $env:CC_x86_64_pc_windows_gnullvm = $savedCc
        $env:CXX_x86_64_pc_windows_gnullvm = $savedCxx
        $env:AR_x86_64_pc_windows_gnullvm = $savedAr
        $env:CARGO_TARGET_X86_64_PC_WINDOWS_GNULLVM_LINKER = $savedLinker
    }
}

function Start-ProcessWithEnv {
    param(
        [string]$FilePath,
        [string[]]$ArgumentList,
        [string]$WorkingDirectory,
        [hashtable]$ExtraEnv,
        [string]$OutLog,
        [string]$ErrLog
    )

    $saved = @{}
    foreach ($key in $ExtraEnv.Keys) {
        if (Test-Path "env:$key") {
            $saved[$key] = (Get-Item "env:$key").Value
        }
        else {
            $saved[$key] = $null
        }
        Set-Item -Path "env:$key" -Value ([string]$ExtraEnv[$key])
    }

    try {
        return Start-Process `
            -FilePath $FilePath `
            -ArgumentList $ArgumentList `
            -WorkingDirectory $WorkingDirectory `
            -RedirectStandardOutput $OutLog `
            -RedirectStandardError $ErrLog `
            -WindowStyle Hidden `
            -PassThru
    }
    finally {
        foreach ($key in $saved.Keys) {
            if ($null -eq $saved[$key]) {
                Remove-Item -Path "env:$key" -ErrorAction SilentlyContinue
            }
            else {
                Set-Item -Path "env:$key" -Value $saved[$key]
            }
        }
    }
}

function New-HexToken32 {
    $bytes = New-Object byte[] 32
    $rng = [System.Security.Cryptography.RandomNumberGenerator]::Create()
    try {
        $rng.GetBytes($bytes)
    }
    finally {
        $rng.Dispose()
    }
    return (-join ($bytes | ForEach-Object { $_.ToString("x2") }))
}

function Find-AppBrowser {
    $roots = @($env:ProgramFiles, ${env:ProgramFiles(x86)}, $env:LOCALAPPDATA) | Where-Object { $_ }
    $relPaths = @(
        "Google\Chrome\Application\chrome.exe",
        "BraveSoftware\Brave-Browser\Application\brave.exe",
        "Microsoft\Edge\Application\msedge.exe"
    )
    foreach ($rel in $relPaths) {
        foreach ($root in $roots) {
            $full = Join-Path $root $rel
            if (Test-Path $full) {
                return $full
            }
        }
    }
    return $null
}

Ensure-FrontendToolchain

if ($Rebuild -or -not (Test-Path $serverExe) -or -not (Test-Path $desktopExe)) {
    Invoke-WorkspaceCargoBuild
}

if (-not (Test-Path $envFile)) {
    Write-Host "[Anvil] Generation initiale des cles serveur dans $envFile" -ForegroundColor Cyan
    $generated = & $serverExe keygen
    if ($LASTEXITCODE -ne 0) {
        throw "Impossible de generer les secrets serveur via anvil-server keygen."
    }
    Set-Content -Path $envFile -Value $generated -Encoding UTF8
}

$serverSecrets = @{}
foreach ($line in (Get-Content -Path $envFile -Encoding UTF8)) {
    $trimmed = $line.Trim()
    if (-not $trimmed -or $trimmed.StartsWith("#")) { continue }
    $parts = $trimmed -split '=', 2
    if ($parts.Length -eq 2) {
        $serverSecrets[$parts[0].Trim()] = $parts[1].Trim().Trim('"')
    }
}

$serverUrl = "http://127.0.0.1:$ServerPort"
$bridgeAddr = "127.0.0.1:$BridgePort"
$bridgeUrl = "http://$bridgeAddr"
$serverSqliteUrl = "sqlite:" + ($serverDb -replace '\\', '/')
$bridgeToken = New-HexToken32

$serverProc = $null
$desktopProc = $null
$browserJob = $null
$savedBridgeUrl = $env:ANVIL_DESKTOP_BRIDGE_URL
$savedBridgeToken = $env:ANVIL_DESKTOP_BRIDGE_TOKEN

try {
    Write-Host "[Anvil] Demarrage du serveur local ($serverUrl)..." -ForegroundColor Cyan
    $serverEnv = @{
        ANVIL_DATABASE_URL = $serverSqliteUrl
        ANVIL_BIND_ADDR = "127.0.0.1:$ServerPort"
        ANVIL_ALLOW_SIGNUPS = "true"
        ANVIL_LOG_FORMAT = "pretty"
        ANVIL_CORS_ORIGINS = "http://127.0.0.1:1420"
    }
    foreach ($k in $serverSecrets.Keys) {
        $serverEnv[$k] = $serverSecrets[$k]
    }
    $serverProc = Start-ProcessWithEnv `
        -FilePath $serverExe `
        -ArgumentList @("serve") `
        -WorkingDirectory $repoRoot `
        -ExtraEnv $serverEnv `
        -OutLog $serverOutLog `
        -ErrLog $serverErrLog

    $serverReady = $false
    for ($i = 0; $i -lt 30; $i++) {
        if ($serverProc.HasExited) {
            $errPreview = Get-Content -Path $serverErrLog -Tail 20 -ErrorAction SilentlyContinue
            throw "anvil-server s'est arrete prematurement.`n$($errPreview -join "`n")"
        }
        try {
            $healthResp = Invoke-WebRequest -UseBasicParsing -Uri "$serverUrl/api/v1/health" -TimeoutSec 2
            if ($healthResp.StatusCode -eq 200) {
                $serverReady = $true
                break
            }
        }
        catch {
            Start-Sleep -Milliseconds 500
        }
    }
    if (-not $serverReady) {
        throw "Le serveur Anvil n'a pas repondu sur $serverUrl/api/v1/health apres 15 secondes."
    }

    Write-Host "[Anvil] Demarrage du pont IPC desktop ($bridgeUrl)..." -ForegroundColor Cyan
    $desktopProc = Start-ProcessWithEnv `
        -FilePath $desktopExe `
        -ArgumentList @("--server", $serverUrl, "--cache", $desktopCacheDb, "--http-bridge", $bridgeAddr) `
        -WorkingDirectory $repoRoot `
        -ExtraEnv @{ ANVIL_DESKTOP_BRIDGE_TOKEN = $bridgeToken } `
        -OutLog $desktopOutLog `
        -ErrLog $desktopErrLog

    $bridgeReady = $false
    for ($i = 0; $i -lt 30; $i++) {
        if ($desktopProc.HasExited) {
            $errPreview = Get-Content -Path $desktopErrLog -Tail 20 -ErrorAction SilentlyContinue
            throw "anvil-desktop s'est arrete prematurement.`n$($errPreview -join "`n")"
        }
        try {
            $resp = Invoke-WebRequest -UseBasicParsing -Uri "$bridgeUrl/api/desktop-health" -TimeoutSec 2
            if ($resp.StatusCode -eq 200) {
                $bridgeReady = $true
                break
            }
        }
        catch {
            Start-Sleep -Milliseconds 500
        }
    }
    if (-not $bridgeReady) {
        throw "Le pont IPC desktop n'a pas repondu sur $bridgeUrl/api/desktop-health apres 15 secondes."
    }

    Push-Location $repoRoot
    try {
        if (-not (Test-Path (Join-Path $repoRoot "node_modules")) -or -not (Test-Path (Join-Path $repoRoot "apps\desktop\node_modules"))) {
            Write-Host "[Anvil] Installation des dependances frontend (pnpm install)..." -ForegroundColor Cyan
            & pnpm install
            if ($LASTEXITCODE -ne 0) {
                throw "Echec de pnpm install."
            }
        }

        if (-not $NoBrowser) {
            $browserExe = Find-AppBrowser
            $browserJob = Start-Job -ScriptBlock {
                param($AppUrl, $BrowserPath)
                for ($j = 0; $j -lt 60; $j++) {
                    try {
                        $r = Invoke-WebRequest -UseBasicParsing -Uri $AppUrl -TimeoutSec 2
                        if ($r.StatusCode -eq 200) {
                            if ($BrowserPath) {
                                Start-Process -FilePath $BrowserPath -ArgumentList "--app=$AppUrl"
                            }
                            else {
                                Start-Process $AppUrl
                            }
                            break
                        }
                    }
                    catch {
                        Start-Sleep -Milliseconds 500
                    }
                }
            } -ArgumentList "http://127.0.0.1:1420", $browserExe
        }

        $env:ANVIL_DESKTOP_BRIDGE_URL = $bridgeUrl
        $env:ANVIL_DESKTOP_BRIDGE_TOKEN = $bridgeToken

        Write-Host ""
        Write-Host "[Anvil] Pret ! Interface Desktop sur http://127.0.0.1:1420 (Ctrl+C pour arreter)." -ForegroundColor Green
        Write-Host "[Anvil] URL serveur par defaut : $serverUrl (inscriptions actives en dev)" -ForegroundColor DarkGray
        Write-Host ""

        & pnpm --filter @anvil/desktop dev
    }
    finally {
        Pop-Location
    }
}
finally {
    if ($null -eq $savedBridgeUrl) {
        Remove-Item -Path "env:ANVIL_DESKTOP_BRIDGE_URL" -ErrorAction SilentlyContinue
    }
    else {
        $env:ANVIL_DESKTOP_BRIDGE_URL = $savedBridgeUrl
    }
    if ($null -eq $savedBridgeToken) {
        Remove-Item -Path "env:ANVIL_DESKTOP_BRIDGE_TOKEN" -ErrorAction SilentlyContinue
    }
    else {
        $env:ANVIL_DESKTOP_BRIDGE_TOKEN = $savedBridgeToken
    }

    if ($browserJob) {
        Stop-Job -Job $browserJob -ErrorAction SilentlyContinue
        Remove-Job -Job $browserJob -Force -ErrorAction SilentlyContinue
    }
    foreach ($proc in @($desktopProc, $serverProc)) {
        if ($proc) {
            try {
                if (-not $proc.HasExited) {
                    Stop-Process -Id $proc.Id -Force -ErrorAction SilentlyContinue
                }
            }
            catch {}
        }
    }
}
