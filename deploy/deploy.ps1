# Build linux/amd64 binary on the dev box, atomic-swap on the server,
# restart the systemd unit. Run from the repo root.
#
# Requires:
#   - OpenSSH client on PATH
#   - ssh key at $env:USERPROFILE\.ssh\id_ed25519
#   - $env:OMNOMFEEDS_HOST  set to root@<ip>  (or override below)
#
# The systemd unit (`/etc/systemd/system/omnomfeeds.service`) runs
# `/opt/omnomfeeds/bin/omnomfeeds`, so that's the path we swap. Earlier
# revisions of this script wrote to `/opt/omnomfeeds/omnomfeeds` which
# is NOT what systemd executes, so restarts were silent no-ops.

param(
    [string]$Server  = $(if ($env:OMNOMFEEDS_HOST) { $env:OMNOMFEEDS_HOST } else { throw 'set OMNOMFEEDS_HOST=user@host or pass -Server user@host' }),
    [string]$KeyPath = "$env:USERPROFILE\.ssh\id_ed25519",
    [switch]$SkipBuild
)

$ErrorActionPreference = 'Stop'
$repo = Split-Path -Parent $PSScriptRoot

if (-not $SkipBuild) {
    Write-Host '> build linux/amd64...'
    $env:GOOS = 'linux'
    $env:GOARCH = 'amd64'
    $env:CGO_ENABLED = '0'
    & go -C $repo build -ldflags '-s -w' -o "$repo\deploy\omnomfeeds" .
    if ($LASTEXITCODE -ne 0) { throw 'go build failed' }
}

$binary = "$repo\deploy\omnomfeeds"
if (-not (Test-Path $binary)) { throw "missing binary: $binary" }

Write-Host '> upload binary...'
& scp -i $KeyPath -o StrictHostKeyChecking=accept-new $binary "${Server}:/opt/omnomfeeds/bin/omnomfeeds.new"

Write-Host '> atomic swap + restart...'
$remote = @'
set -e
mv /opt/omnomfeeds/bin/omnomfeeds.new /opt/omnomfeeds/bin/omnomfeeds
chown omnom:omnom /opt/omnomfeeds/bin/omnomfeeds
chmod 0755 /opt/omnomfeeds/bin/omnomfeeds
systemctl restart omnomfeeds
sleep 1
systemctl is-active omnomfeeds
'@
$remote | & ssh -i $KeyPath -o StrictHostKeyChecking=accept-new $Server 'bash -s'

Write-Host '> deploy complete'
