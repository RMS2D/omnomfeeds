# oM noM Security Feeds installer for Windows.
#
# Usage:
#   irm https://raw.githubusercontent.com/RMS2D/omnomfeeds/main/install.ps1 | iex
#
# Env vars (set before piping):
#   $env:SECFEED_VERSION   pin a specific version (default: latest)
#   $env:SECFEED_INSTALL   override install dir (default: %LOCALAPPDATA%\secfeed)

$ErrorActionPreference = 'Stop'
$Repo = 'RMS2D/omnomfeeds'
$Version = $env:SECFEED_VERSION
if (-not $Version) { $Version = 'latest' }

# --- Arch detection (windows-arm64 not built; amd64 only). ---
$arch = (Get-CimInstance Win32_Processor | Select-Object -First 1 -ExpandProperty Architecture)
# 9 = x64, 12 = arm64 per WMI
if ($arch -eq 12) {
    Write-Warning "ARM64 Windows builds are not currently published. Aborting."
    exit 1
}

# --- Resolve version ---
if ($Version -eq 'latest') {
    $rel = Invoke-RestMethod -UseBasicParsing "https://api.github.com/repos/$Repo/releases/latest"
    $Version = $rel.tag_name
    if (-not $Version) {
        Write-Error "could not resolve latest version"
        exit 1
    }
}
$Short = $Version.TrimStart('v')
$ArchiveName = "omnomfeeds_${Short}_windows_x86_64.zip"
$Url = "https://github.com/$Repo/releases/download/$Version/$ArchiveName"

# --- Install dir ---
if ($env:SECFEED_INSTALL) {
    $Dest = $env:SECFEED_INSTALL
} else {
    $Dest = Join-Path $env:LOCALAPPDATA 'secfeed'
}
New-Item -ItemType Directory -Path $Dest -Force | Out-Null

# --- Download + extract ---
$Tmp = New-Item -ItemType Directory -Path (Join-Path $env:TEMP "secfeed-install-$(Get-Random)") -Force
try {
    $ArchivePath = Join-Path $Tmp $ArchiveName

    Write-Host "> downloading $ArchiveName..."
    Invoke-WebRequest -UseBasicParsing -Uri $Url -OutFile $ArchivePath

    Write-Host "> extracting..."
    Expand-Archive -Path $ArchivePath -DestinationPath $Tmp -Force

    $BinSrc = Join-Path $Tmp 'secfeed.exe'
    if (-not (Test-Path $BinSrc)) {
        Write-Error "archive did not contain secfeed.exe"
        exit 1
    }

    $BinDest = Join-Path $Dest 'secfeed.exe'
    # If a previous secfeed is running, this will fail with a sensible message.
    Move-Item -Path $BinSrc -Destination $BinDest -Force

    # --- PATH update (User scope, idempotent) ---
    $userPath = [Environment]::GetEnvironmentVariable('Path', 'User')
    if (-not ($userPath -split ';' | Where-Object { $_ -eq $Dest })) {
        [Environment]::SetEnvironmentVariable('Path', "$userPath;$Dest", 'User')
        Write-Host "> added $Dest to User PATH (open a new terminal to pick it up)"
    }

    Write-Host ""
    Write-Host "  oM noM Security Feeds $Version installed at $BinDest"
    Write-Host ""
    Write-Host "  start it:    secfeed"
    Write-Host "  config:      press 'c' in the UI, or edit %APPDATA%\secfeed\config.json"
    Write-Host "  open at:     http://localhost:8080"
    Write-Host ""
}
finally {
    Remove-Item -Path $Tmp -Recurse -Force -ErrorAction SilentlyContinue
}
