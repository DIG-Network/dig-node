<#
.SYNOPSIS
  Verify, on a real Windows host, that upgrading from a pre-0.99.10 dig-node .msi migrates the
  install off the superseded `%ProgramFiles%\DIG Network\dig-node\` root and never leaves the host
  without the `net.dignetwork.dig-node` service (dig_ecosystem#2251).

.DESCRIPTION
  CI builds the .msi but never installs it, so the migration is unprovable there. This script is the
  manual acceptance test, written down so it is repeatable rather than re-derived. It:

    1. installs -OldMsi (a released pre-0.99.10 package) to RECREATE the old layout,
    2. asserts the old layout is actually present — otherwise the upgrade proves nothing,
    3. installs -NewMsi over it,
    4. asserts the end state: service image under the protected root and RUNNING, both old
       directories gone, no DIG entry left on the machine PATH, exactly one Add/Remove entry,
    5. resolves `dig-node.exe` in a FRESH ENVIRONMENT BLOCK via the Task Scheduler.

  Step 5 cannot be done from the calling shell. The stored machine PATH contains a literal `%PATH%`
  self-reference, so expanding it inside a running shell splices that shell's own PATH in and
  inverts the ordering — that has misled three separate diagnoses of this bug. A scheduled task is
  launched with an environment block composed fresh from the registry, which is what a new logon
  sees.

  MUST be run ELEVATED. It changes machine state; run it on a test host, or on a host you are
  willing to leave with -NewMsi installed.

.EXAMPLE
  powershell -ExecutionPolicy Bypass -File verify-upgrade-migration.ps1 `
    -OldMsi C:\dl\dig-node-0.99.4-windows-x64.msi -NewMsi C:\out\dig-node-0.99.10-windows-x64.msi
#>
[CmdletBinding()]
param(
  [Parameter(Mandatory = $true)][string]$OldMsi,
  [Parameter(Mandatory = $true)][string]$NewMsi,
  [string]$LogDir = "$env:TEMP\dig-node-migration-check"
)

$ErrorActionPreference = 'Stop'

$SERVICE       = 'net.dignetwork.dig-node'
$PROTECTED_DIR = Join-Path $env:ProgramFiles 'DIG\bin'
$OLD_DIR       = Join-Path $env:ProgramFiles 'DIG Network\dig-node'
$OLD_ROOT      = Join-Path $env:ProgramFiles 'DIG Network'

if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
      ).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
  throw 'must be run elevated: installing a perMachine .msi and reading service config require admin'
}
New-Item -ItemType Directory -Force -Path $LogDir | Out-Null

$script:failures = 0
function Assert-That([string]$What, [bool]$Ok, [string]$Detail) {
  if ($Ok) { Write-Host "ok   $What" } else { Write-Host "FAIL $What`n     $Detail"; $script:failures++ }
}

function Get-ServiceImage {
  (Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\$SERVICE" -EA SilentlyContinue).ImagePath
}

# The machine PATH exactly as STORED. Never expand it here (see .DESCRIPTION).
function Get-MachinePathEntries {
  (Get-Item 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Environment').GetValue(
    'Path', '', 'DoNotExpandEnvironmentNames') -split ';'
}

function Get-NodeArpEntries {
  Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*',
                   'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*' -EA SilentlyContinue |
    Where-Object { $_.DisplayName -eq 'DIG NETWORK: NODE' }
}

# Resolve dig-node.exe the way a NEW logon would: a scheduled task gets a fresh environment block.
function Get-FreshSessionResolution {
  $out  = Join-Path $LogDir 'freshpath.txt'
  $name = 'DIGMigrationCheckPathProbe'
  Remove-Item $out -EA SilentlyContinue
  schtasks /delete /tn $name /f 2>&1 | Out-Null
  schtasks /create /tn $name /tr "cmd.exe /c where dig-node.exe > `"$out`" 2>&1" /sc once /st 23:59 /f | Out-Null
  schtasks /run /tn $name | Out-Null
  for ($i = 0; $i -lt 40 -and -not (Test-Path $out); $i++) { Start-Sleep -Milliseconds 500 }
  Start-Sleep -Milliseconds 500
  schtasks /delete /tn $name /f 2>&1 | Out-Null
  if (Test-Path $out) { @(Get-Content $out | Where-Object { $_ -match '\S' }) } else { @() }
}

function Install-Msi([string]$Path, [string]$Tag) {
  $log = Join-Path $LogDir "msi-$Tag.log"
  $p = Start-Process msiexec -Wait -PassThru -ArgumentList @('/i', "`"$Path`"", '/qn', '/l*v', "`"$log`"")
  if ($p.ExitCode -ne 0) { throw "msiexec /i $Path exited $($p.ExitCode); see $log" }
}

Write-Host "== 1. install the OLD package to recreate the superseded layout =="
Install-Msi $OldMsi 'old'

Write-Host "`n== 2. the precondition: the old layout is really present =="
# Without this the upgrade below could pass vacuously on a host that never had the old layout.
Assert-That 'the superseded directory exists' (Test-Path $OLD_DIR) "expected $OLD_DIR"
Assert-That 'the service points into the superseded directory' `
  ((Get-ServiceImage) -like "*DIG Network*") "image is $(Get-ServiceImage)"
if ($script:failures -gt 0) { throw 'precondition not met — the upgrade would prove nothing' }

$before = Get-FreshSessionResolution
Write-Host "     fresh-session resolution before: $($before -join ' | ')"

Write-Host "`n== 3. upgrade with the NEW package =="
Install-Msi $NewMsi 'new'

Write-Host "`n== 4. the end state =="
$image = Get-ServiceImage
Assert-That 'the service image is under the protected root' ($image -like "*$PROTECTED_DIR*") "image is $image"
Assert-That 'the service is RUNNING' `
  ((Get-Service $SERVICE -EA SilentlyContinue).Status -eq 'Running') `
  "status is $((Get-Service $SERVICE -EA SilentlyContinue).Status)"
Assert-That 'the superseded directory is gone'  (-not (Test-Path $OLD_DIR))  "still present: $OLD_DIR"
Assert-That 'the superseded root is gone'       (-not (Test-Path $OLD_ROOT)) "still present: $OLD_ROOT"

$digPath = @(Get-MachinePathEntries | Where-Object { $_ -match 'DIG' })
Assert-That 'no DIG entry remains on the machine PATH' ($digPath.Count -eq 0) "found: $($digPath -join ' | ')"

$arp = @(Get-NodeArpEntries)
Assert-That 'exactly one Add/Remove entry, no orphan' ($arp.Count -eq 1) `
  "found $($arp.Count): $(($arp | ForEach-Object { $_.DisplayVersion }) -join ', ')"

Write-Host "`n== 5. fresh-environment resolution =="
$after = Get-FreshSessionResolution
Write-Host "     $($after -join ' | ')"
Assert-That 'dig-node.exe resolves ONLY to the protected copy in a fresh session' `
  ($after.Count -eq 1 -and $after[0] -like "$PROTECTED_DIR*") "resolved to: $($after -join ' | ')"

if ($script:failures -gt 0) { Write-Host "`n$($script:failures) check(s) FAILED"; exit 1 }
Write-Host "`nall migration checks passed"
