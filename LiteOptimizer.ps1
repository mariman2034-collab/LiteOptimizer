Clear-Host

$logo = @"
██╗     ██╗████████╗███████╗     ██████╗ ██████╗ ████████╗██╗███╗   ███╗██╗███████╗███████╗██████╗ 
██║     ██║╚══██╔══╝██╔════╝    ██╔═══██╗██╔══██╗╚══██╔══╝██║████╗ ████║██║╚══███╔╝██╔════╝██╔══██╗
██║     ██║   ██║   █████╗      ██║   ██║██████╔╝   ██║   ██║██╔████╔██║██║  ███╔╝ █████╗  ██████╔╝
██║     ██║   ██║   ██╔══╝      ██║   ██║██╔═══╝    ██║   ██║██║╚██╔╝██║██║ ███╔╝  ██╔══╝  ██╔══██╗
███████╗██║   ██║   ███████╗    ╚██████╔╝██║        ██║   ██║██║ ╚═╝ ██║██║███████╗███████╗██║  ██║
╚══════╝╚═╝   ╚═╝   ╚══════╝     ╚═════╝ ╚═╝        ╚═╝   ╚═╝╚═╝     ╚═╝╚═╝╚══════╝╚══════╝╚═╝  ╚═╝
"@

Write-Host $logo -ForegroundColor Cyan
Write-Host "Lite Optimizer starting..." -ForegroundColor Gray
Start-Sleep -Seconds 1


# LiteOptimizer.ps1
# console menu with:
# - Profiles (Safe/Balanced/Aggressive)
# - Export/Import selection
# - Real rollback for Registry + Services
# - Debloat section (NOT reliably reversible)
# - "Ultimate LiteOptimizer" power plan creation/activation
#
# LiteOptimizer v1.2 :)
# Run as Admin recommended.

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

# -------------------- Config --------------------
$AppName   = "LiteOptimizer"
$DataDir   = Join-Path $env:ProgramData $AppName
$LogFile   = Join-Path $DataDir "run.log"
$StateFile = Join-Path $DataDir "state.json"
$SelFile   = Join-Path $DataDir "selection.json"

if (-not (Test-Path $DataDir)) { New-Item -ItemType Directory -Path $DataDir | Out-Null }

function Log([string]$msg) {
  $line = "[{0}] {1}" -f (Get-Date -Format "yyyy-MM-dd HH:mm:ss"), $msg
  Add-Content -Path $LogFile -Value $line
}

function Is-Admin {
  $id = [Security.Principal.WindowsIdentity]::GetCurrent()
  $p  = New-Object Security.Principal.WindowsPrincipal($id)
  return $p.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Ensure-Admin {
  if (-not (Is-Admin)) {
    Write-Host "`nRe-launching as Admin..." -ForegroundColor Yellow
    $psi = New-Object System.Diagnostics.ProcessStartInfo
    $psi.FileName  = "powershell.exe"
    $psi.Arguments = "-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`""
    $psi.Verb      = "runas"
    try { [Diagnostics.Process]::Start($psi) | Out-Null } catch { Write-Host "Elevation canceled." -ForegroundColor Red }
    exit
  }
}

function Pause([string]$msg = "Press Enter to continue") {
  Read-Host $msg | Out-Null
}

function Try-SetClipboard([string]$text) {
  try {
    if (Get-Command Set-Clipboard -ErrorAction SilentlyContinue) {
      Set-Clipboard -Value $text
      return $true
    }
  } catch { }
  return $false
}

# -------------------- Rollback State --------------------
# State format:
# {
#   registry: { "HKCU|Path|Name": { exists, type, data } },
#   services: { "ServiceName": { startMode } },
#   debloat:  { removedAppx: [], removedProvisioned: [] }
# }
function Load-State {
  if (Test-Path $StateFile) {
    try { return (Get-Content $StateFile -Raw | ConvertFrom-Json -Depth 10) } catch { }
  }
  return [PSCustomObject]@{
    registry = @{}
    services = @{}
    debloat  = [PSCustomObject]@{ removedAppx = @(); removedProvisioned = @() }
  }
}

function Save-State($state) {
  ($state | ConvertTo-Json -Depth 10) | Set-Content -Path $StateFile -Encoding UTF8
}

$STATE = Load-State

function Reg-KeyString([string]$hive, [string]$path, [string]$name) {
  return "$hive|$path|$name"
}

function Capture-RegistryBefore([string]$hive, [string]$path, [string]$name) {
  $k = Reg-KeyString $hive $path $name
  if ($STATE.registry.ContainsKey($k)) { return } # already captured

  $full = "$hive`:\$path"
  $exists = $false
  $type = $null
  $data = $null

  try {
    if (Test-Path $full) {
      $item = Get-Item -Path $full -ErrorAction Stop
      $val  = $item.GetValue($name, $null, "DoNotExpandEnvironmentNames")
      if ($null -ne $val) {
        $exists = $true
        $type = $item.GetValueKind($name).ToString()
        $data = $val
      }
    }
  } catch { }

  $STATE.registry[$k] = [PSCustomObject]@{ exists = $exists; type = $type; data = $data }
}

function Restore-Registry([string]$hive, [string]$path, [string]$name) {
  $k = Reg-KeyString $hive $path $name
  if (-not $STATE.registry.ContainsKey($k)) { return }

  $snap = $STATE.registry[$k]
  $full = "$hive`:\$path"
  if (-not (Test-Path $full)) { New-Item -Path $full -Force | Out-Null }

  if (-not $snap.exists) {
    try { Remove-ItemProperty -Path $full -Name $name -ErrorAction SilentlyContinue } catch { }
    return
  }

  $t = $snap.type
  $d = $snap.data
  try {
    switch ($t) {
      "DWord" { New-ItemProperty -Path $full -Name $name -PropertyType DWord -Value ([int]$d) -Force | Out-Null }
      "QWord" { New-ItemProperty -Path $full -Name $name -PropertyType QWord -Value ([long]$d) -Force | Out-Null }
      "String" { New-ItemProperty -Path $full -Name $name -PropertyType String -Value ([string]$d) -Force | Out-Null }
      "ExpandString" { New-ItemProperty -Path $full -Name $name -PropertyType ExpandString -Value ([string]$d) -Force | Out-Null }
      "MultiString" { New-ItemProperty -Path $full -Name $name -PropertyType MultiString -Value ([string[]]$d) -Force | Out-Null }
      default { New-ItemProperty -Path $full -Name $name -PropertyType String -Value ([string]$d) -Force | Out-Null }
    }
  } catch { }
}

function Capture-ServiceBefore([string]$serviceName) {
  if ($STATE.services.ContainsKey($serviceName)) { return }
  try {
    $cim = Get-CimInstance Win32_Service -Filter "Name='$serviceName'" -ErrorAction Stop
    $STATE.services[$serviceName] = [PSCustomObject]@{ startMode = $cim.StartMode } # Auto / Manual / Disabled
  } catch { }
}

function Restore-Service([string]$serviceName) {
  if (-not $STATE.services.ContainsKey($serviceName)) { return }
  $mode = $STATE.services[$serviceName].startMode
  try {
    if ($mode -eq "Auto") { Set-Service -Name $serviceName -StartupType Automatic -ErrorAction SilentlyContinue }
    elseif ($mode -eq "Manual") { Set-Service -Name $serviceName -StartupType Manual -ErrorAction SilentlyContinue }
    elseif ($mode -eq "Disabled") { Set-Service -Name $serviceName -StartupType Disabled -ErrorAction SilentlyContinue }
  } catch { }
}

# -------------------- Power plan helpers --------------------
function Get-PowerSchemeGuidByName([string]$name) {
  $out = powercfg /list 2>$null
  foreach ($line in $out) {
    if ($line -match 'Power Scheme GUID:\s+([a-f0-9\-]+)\s+\((.+?)\)') {
      $guid = $Matches[1]
      $n    = $Matches[2]
      if ($n -eq $name) { return $guid }
    }
  }
  return $null
}

function Add-Or-Activate-LiteOptimizerPlan {
  Ensure-Admin

  $planName = "Ultimate LiteOptimizer"
  $existing = Get-PowerSchemeGuidByName $planName
  if ($existing) {
    Log "Power plan exists: $planName ($existing). Setting active."
    powercfg /setactive $existing | Out-Null
    return
  }

  $ultimateGuid = "e9a42b02-d5df-448d-aa00-03f14749eb61"
  $baseGuid = $null

  $list = (powercfg /list) -join "`n"
  if ($list -match $ultimateGuid) {
    $baseGuid = $ultimateGuid
    Log "Using Ultimate Performance as base."
  } else {
    $high = Get-PowerSchemeGuidByName "High performance"
    if ($high) {
      $baseGuid = $high
      Log "Ultimate Performance missing; using High performance as base."
    } else {
      $active = powercfg /getactivescheme | Out-String
      $m = [regex]::Match($active, '([a-f0-9\-]{36})')
      if ($m.Success) { $baseGuid = $m.Value } else { throw "Could not detect active power scheme." }
      Log "High performance missing; using active scheme as base."
    }
  }

  $dupOut = powercfg /duplicatescheme $baseGuid | Out-String
  $m2 = [regex]::Match($dupOut, '([a-f0-9\-]{36})')
  if (-not $m2.Success) { throw "Failed to duplicate power plan." }
  $newGuid = $m2.Value

  powercfg /changename $newGuid $planName | Out-Null
  powercfg /setactive $newGuid | Out-Null

  Log "Created and activated power plan: $planName ($newGuid)"
}

# -------------------- Actions --------------------
function Apply-RegistryAction($a) {
  Capture-RegistryBefore $a.Hive $a.Path $a.Name
  $full = "$($a.Hive):\$($a.Path)"
  if (-not (Test-Path $full)) { New-Item -Path $full -Force | Out-Null }

  switch ($a.Type) {
    "DWord" { New-ItemProperty -Path $full -Name $a.Name -PropertyType DWord -Value ([int]$a.Data) -Force | Out-Null }
    "QWord" { New-ItemProperty -Path $full -Name $a.Name -PropertyType QWord -Value ([long]$a.Data) -Force | Out-Null }
    "String" { New-ItemProperty -Path $full -Name $a.Name -PropertyType String -Value ([string]$a.Data) -Force | Out-Null }
    "ExpandString" { New-ItemProperty -Path $full -Name $a.Name -PropertyType ExpandString -Value ([string]$a.Data) -Force | Out-Null }
    "MultiString" { New-ItemProperty -Path $full -Name $a.Name -PropertyType MultiString -Value ([string[]]$a.Data) -Force | Out-Null }
    default { New-ItemProperty -Path $full -Name $a.Name -PropertyType String -Value ([string]$a.Data) -Force | Out-Null }
  }
}

function Undo-RegistryAction($a) { Restore-Registry $a.Hive $a.Path $a.Name }

function Apply-ServiceAction($a) {
  Capture-ServiceBefore $a.Name
  Set-Service -Name $a.Name -StartupType $a.StartupType -ErrorAction SilentlyContinue
}
function Undo-ServiceAction($a) { Restore-Service $a.Name }

function Apply-CommandAction($a) {
  Log "RUN: $($a.Command)"
  Invoke-Expression $a.Command
}

function Apply-DebloatAction($a) {
  Ensure-Admin
  $removedAppx = @()
  $removedProv = @()

  if ($a.Mode -in @("Appx","Both")) {
    foreach ($pkg in $a.Packages) {
      try {
        $installed = Get-AppxPackage -Name $pkg -AllUsers -ErrorAction SilentlyContinue
        if ($installed) {
          Get-AppxPackage -Name $pkg -AllUsers | ForEach-Object {
            try { Remove-AppxPackage -Package $_.PackageFullName -ErrorAction SilentlyContinue } catch { }
          }
          $removedAppx += $pkg
          Log "Removed Appx: $pkg"
        }
      } catch { }
    }
  }

  if ($a.Mode -in @("Provisioned","Both")) {
    foreach ($pkg in $a.Packages) {
      try {
        $prov = Get-AppxProvisionedPackage -Online | Where-Object { $_.DisplayName -eq $pkg }
        if ($prov) {
          Remove-AppxProvisionedPackage -Online -PackageName $prov.PackageName -ErrorAction SilentlyContinue | Out-Null
          $removedProv += $pkg
          Log "Removed Provisioned: $pkg"
        }
      } catch { }
    }
  }

  $STATE.debloat.removedAppx = @($STATE.debloat.removedAppx + $removedAppx | Select-Object -Unique)
  $STATE.debloat.removedProvisioned = @($STATE.debloat.removedProvisioned + $removedProv | Select-Object -Unique)
}

# -------------------- Tweaks manifest --------------------
$tweaks = @(
  @{
    Id="show_file_ext"
    Name="Show file extensions"
    Category="Explorer"
    Risk="Safe"
    Actions=@(
      @{ Kind="Registry"; Hive="HKCU"; Path="Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced"; Name="HideFileExt"; Type="DWord"; Data=0 }
    )
  },
  @{
    Id="show_hidden_files"
    Name="Show hidden files"
    Category="Explorer"
    Risk="Safe"
    Actions=@(
      @{ Kind="Registry"; Hive="HKCU"; Path="Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced"; Name="Hidden"; Type="DWord"; Data=1 }
    )
  },
  @{
    Id="disable_startup_delay"
    Name="Disable startup delay"
    Category="Performance"
    Risk="Safe"
    Actions=@(
      @{ Kind="Registry"; Hive="HKCU"; Path="Software\Microsoft\Windows\CurrentVersion\Explorer\Serialize"; Name="StartupDelayInMSec"; Type="DWord"; Data=0 }
    )
  },
  @{
    Id="disable_ads_id"
    Name="Disable advertising ID"
    Category="Privacy"
    Risk="Safe"
    Actions=@(
      @{ Kind="Registry"; Hive="HKCU"; Path="Software\Microsoft\Windows\CurrentVersion\AdvertisingInfo"; Name="Enabled"; Type="DWord"; Data=0 }
    )
  },
  @{
    Id="disable_tailored_experiences"
    Name="Disable tailored experiences"
    Category="Privacy"
    Risk="Safe"
    Actions=@(
      @{ Kind="Registry"; Hive="HKCU"; Path="Software\Microsoft\Windows\CurrentVersion\Privacy"; Name="TailoredExperiencesWithDiagnosticDataEnabled"; Type="DWord"; Data=0 }
    )
  },
  @{
    Id="powerplan_liteoptimizer_ultimate"
    Name="Power: Create & enable 'Ultimate LiteOptimizer' power plan"
    Category="Power"
    Risk="Safe"
    Actions=@(
      @{ Kind="Command"; Command="Add-Or-Activate-LiteOptimizerPlan" }
    )
  },

  # Balanced examples
  @{
    Id="disable_xbox_gamebar"
    Name="Disable Xbox Game Bar capture features"
    Category="Gaming"
    Risk="Medium"
    Actions=@(
      @{ Kind="Registry"; Hive="HKCU"; Path="Software\Microsoft\Windows\CurrentVersion\GameDVR"; Name="AppCaptureEnabled"; Type="DWord"; Data=0 },
      @{ Kind="Registry"; Hive="HKCU"; Path="Software\Microsoft\GameBar"; Name="ShowStartupPanel"; Type="DWord"; Data=0 }
    )
  },
  @{
    Id="set_sysmain_manual"
    Name="Service: Set SysMain to Manual"
    Category="Services"
    Risk="Medium"
    Actions=@(
      @{ Kind="Service"; Name="SysMain"; StartupType="Manual" }
    )
  },

  # Debloat (High)
  @{
    Id="debloat_common_appx"
    Name="Debloat: Remove common preinstalled apps (Appx + Provisioned)"
    Category="Debloat"
    Risk="High"
    Actions=@(
      @{ Kind="Debloat"; Mode="Both"; Packages=@(
        "Microsoft.BingNews",
        "Microsoft.BingWeather",
        "Microsoft.GetHelp",
        "Microsoft.Getstarted",
        "Microsoft.MicrosoftOfficeHub",
        "Microsoft.MicrosoftSolitaireCollection",
        "Microsoft.MixedReality.Portal",
        "Microsoft.People",
        "Microsoft.SkypeApp",
        "Microsoft.Todos",
        "Microsoft.XboxApp",
        "Microsoft.XboxGamingOverlay",
        "Microsoft.XboxGameOverlay",
        "Microsoft.XboxSpeechToTextOverlay",
        "Microsoft.YourPhone",
        "Microsoft.ZuneMusic",
        "Microsoft.ZuneVideo"
      ) }
    )
  }
)

# -------------------- Profiles --------------------
$profiles = @{
  "Safe"      = @("show_file_ext","show_hidden_files","disable_startup_delay","disable_ads_id","disable_tailored_experiences","powerplan_liteoptimizer_ultimate")
  "Balanced"  = @("show_file_ext","show_hidden_files","disable_startup_delay","disable_ads_id","disable_tailored_experiences","disable_xbox_gamebar","set_sysmain_manual","powerplan_liteoptimizer_ultimate")
  "Aggressive"= @("show_file_ext","show_hidden_files","disable_startup_delay","disable_ads_id","disable_tailored_experiences","disable_xbox_gamebar","set_sysmain_manual","powerplan_liteoptimizer_ultimate","debloat_common_appx")
}

# Selected IDs
$selected = New-Object System.Collections.Generic.HashSet[string]

# -------------------- UI helpers --------------------
function Print-Header {
  Clear-Host
  Write-Host "=== $AppName (drenzofv tweaks) ===" -ForegroundColor Cyan
  Write-Host "Data: $DataDir"
  Write-Host "Log:  $LogFile"
  Write-Host "State:$StateFile"
  Write-Host ("Admin: {0}" -f (Is-Admin)) -ForegroundColor DarkGray
  Write-Host ""
}

function Grouped-Tweaks { $tweaks | Group-Object Category | Sort-Object Name }

function Print-Menu {
  Print-Header
  $i = 1
  $map = @{}

  foreach ($grp in (Grouped-Tweaks)) {
    Write-Host ("[{0}]" -f $grp.Name) -ForegroundColor Green
    foreach ($t in $grp.Group) {
      $checked = if ($selected.Contains($t.Id)) { "[x]" } else { "[ ]" }
      Write-Host (" {0,2}. {1} {2}  (Risk: {3})" -f $i, $checked, $t.Name, $t.Risk)
      $map[$i] = $t.Id
      $i++
    }
    Write-Host ""
  }

  Write-Host "Commands:" -ForegroundColor Yellow
  Write-Host "  t <num>   Toggle"
  Write-Host "  ps/pb/pa  Profile: Safe / Balanced / Aggressive"
  Write-Host "  a         Apply selected (saves rollback for registry/services)"
  Write-Host "  undo      Undo selected (registry/services only; debloat not reversible)"
  Write-Host "  p         Print + COPY PowerShell command"
  Write-Host "  c         Print + COPY CMD command"
  Write-Host "  e         Export selection"
  Write-Host "  i         Import selection"
  Write-Host "  r         Reset selection"
  Write-Host "  q         Quit"
  Write-Host ""
  return $map
}

function Get-SelectedTweaks { $tweaks | Where-Object { $selected.Contains($_.Id) } }

# Generate runnable PS snippet for selected tweaks
function Get-SelectedCommandLines {
  $sel = Get-SelectedTweaks
  $lines = @()

  foreach ($t in $sel) {
    foreach ($a in $t.Actions) {
      if ($a.Kind -eq "Registry") {
        $path = "{0}:\{1}" -f $a.Hive, $a.Path
        $val = $a.Data
        if ($a.Type -in @("String","ExpandString")) {
          $val = '"' + ([string]$a.Data).Replace('"','`"') + '"'
        } elseif ($a.Type -eq "MultiString") {
          $val = '@("' + (($a.Data | ForEach-Object { ([string]$_).Replace('"','`"') }) -join '","') + '")'
        }
        $lines += "New-Item -Path `"$path`" -Force | Out-Null"
        $lines += "New-ItemProperty -Path `"$path`" -Name `"$($a.Name)`" -PropertyType $($a.Type) -Value $val -Force | Out-Null"
      }
      elseif ($a.Kind -eq "Service") {
        $lines += "Set-Service -Name `"$($a.Name)`" -StartupType $($a.StartupType)"
      }
      elseif ($a.Kind -eq "Command") {
        $lines += $a.Command
      }
      elseif ($a.Kind -eq "Debloat") {
        $pkgList = ($a.Packages | ForEach-Object { '"' + $_ + '"' }) -join ","
        $lines += ('$pkgs=@({0}); foreach($p in $pkgs){{' -f $pkgList)
        $lines += '  Get-AppxPackage -Name $p -AllUsers | ForEach-Object { try { Remove-AppxPackage -Package $_.PackageFullName -ErrorAction SilentlyContinue } catch {} }'
        $lines += ('  if("{0}" -ne "Appx"){{ try {{ $prov = Get-AppxProvisionedPackage -Online | Where-Object {{ $_.DisplayName -eq $p }}; if($prov){{ Remove-AppxProvisionedPackage -Online -PackageName $prov.PackageName -ErrorAction SilentlyContinue | Out-Null }} }} catch {{}} }}' -f $a.Mode)
        $lines += '}'
      }
    }
  }
  return $lines
}

function Build-PowerShellOneLiner([string[]]$lines) {
  $joined = ($lines -join "; ")
  return "& { $joined }"
}

function Build-CmdFromPs([string]$psOneLiner) {
  $escaped = $psOneLiner.Replace('"','""')
  return 'powershell -NoProfile -ExecutionPolicy Bypass -Command "' + $escaped + '"'
}

# -------------------- Profile + import/export --------------------
function Select-Profile([string]$name) {
  $selected.Clear() | Out-Null
  foreach ($id in $profiles[$name]) { $selected.Add($id) | Out-Null }
}

function Export-Selection {
  $obj = [PSCustomObject]@{ selected = @($selected) }
  ($obj | ConvertTo-Json -Depth 4) | Set-Content -Path $SelFile -Encoding UTF8
  Write-Host "Exported selection to $SelFile" -ForegroundColor Green
  Start-Sleep 1
}

function Import-Selection {
  if (-not (Test-Path $SelFile)) {
    Write-Host "No selection file at $SelFile" -ForegroundColor Yellow
    Start-Sleep 1
    return
  }
  try {
    $obj = Get-Content $SelFile -Raw | ConvertFrom-Json
    $selected.Clear() | Out-Null
    foreach ($id in $obj.selected) { $selected.Add([string]$id) | Out-Null }
    Write-Host "Imported selection from $SelFile" -ForegroundColor Green
  } catch {
    Write-Host "Failed to import selection (bad JSON)." -ForegroundColor Red
  }
  Start-Sleep 1
}

# -------------------- Apply / Undo --------------------
function Apply-Selected {
  Ensure-Admin
  $sel = Get-SelectedTweaks
  if (-not $sel) { Write-Host "Nothing selected." -ForegroundColor Yellow; Start-Sleep 1; return }

  Log "Applying: $($sel.Id -join ', ')"

  foreach ($t in $sel) {
    Write-Host "Applying: $($t.Name)" -ForegroundColor Cyan
    foreach ($a in $t.Actions) {
      try {
        switch ($a.Kind) {
          "Registry" { Apply-RegistryAction $a }
          "Service"  { Apply-ServiceAction $a }
          "Command"  { Apply-CommandAction $a }
          "Debloat"  { Apply-DebloatAction $a }
        }
        Save-State $STATE
      } catch {
        Write-Host "  Failed: $($_.Exception.Message)" -ForegroundColor Red
        Log "ERROR $($t.Id): $($_.Exception.Message)"
      }
    }
  }

  Write-Host "`nDone. Some changes may need restart/logoff." -ForegroundColor Green
  if ($STATE.debloat.removedAppx.Count -gt 0 -or $STATE.debloat.removedProvisioned.Count -gt 0) {
    Write-Host "Debloat note: removals are logged, but Undo cannot reliably reinstall Store apps." -ForegroundColor Yellow
  }
  Pause
}

function Undo-Selected {
  Ensure-Admin
  $sel = Get-SelectedTweaks
  if (-not $sel) { Write-Host "Nothing selected." -ForegroundColor Yellow; Start-Sleep 1; return }

  Log "Undo: $($sel.Id -join ', ')"
  foreach ($t in ($sel | Select-Object -Reverse)) {
    Write-Host "Undoing: $($t.Name)" -ForegroundColor Cyan
    foreach ($a in ($t.Actions | Select-Object -Reverse)) {
      try {
        if ($a.Kind -eq "Registry") { Undo-RegistryAction $a }
        elseif ($a.Kind -eq "Service") { Undo-ServiceAction $a }
        elseif ($a.Kind -eq "Debloat") {
          Write-Host "  Skipping debloat undo (not reliably reversible)." -ForegroundColor Yellow
        }
      } catch { }
    }
  }
  Save-State $STATE
  Write-Host "`nUndo complete (where supported)." -ForegroundColor Green
  Pause
}

# -------------------- Print commands (FIXED + copies to clipboard) --------------------
function Print-PowerShell {
  $sel = Get-SelectedTweaks
  if (-not $sel) { Write-Host "Nothing selected." -ForegroundColor Yellow; Start-Sleep 1; return }

  $lines = Get-SelectedCommandLines
  $cmd = Build-PowerShellOneLiner $lines

  Print-Header
  Write-Host "Copy/paste PowerShell (also copied to clipboard):" -ForegroundColor Cyan
  Write-Host ""
  Write-Host $cmd
  Write-Host ""
  $copied = Try-SetClipboard $cmd
  if ($copied) { Write-Host "✔ Copied to clipboard." -ForegroundColor Green } else { Write-Host "Clipboard copy not available." -ForegroundColor Yellow }
  Pause
}

function Print-Cmd {
  $sel = Get-SelectedTweaks
  if (-not $sel) { Write-Host "Nothing selected." -ForegroundColor Yellow; Start-Sleep 1; return }

  $lines = Get-SelectedCommandLines
  $ps = Build-PowerShellOneLiner $lines
  $cmd = Build-CmdFromPs $ps

  Print-Header
  Write-Host "Copy/paste CMD (also copied to clipboard):" -ForegroundColor Cyan
  Write-Host ""
  Write-Host $cmd
  Write-Host ""
  $copied = Try-SetClipboard $cmd
  if ($copied) { Write-Host "✔ Copied to clipboard." -ForegroundColor Green } else { Write-Host "Clipboard copy not available." -ForegroundColor Yellow }
  Pause
}

# -------------------- Main loop --------------------
while ($true) {
  $map = Print-Menu
  $input = Read-Host "Enter command"

  if ($input -match '^\s*q\s*$') { break }
  elseif ($input -match '^\s*r\s*$') { $selected.Clear() | Out-Null }
  elseif ($input -match '^\s*a\s*$') { Apply-Selected }
  elseif ($input -match '^\s*undo\s*$') { Undo-Selected }
  elseif ($input -match '^\s*p\s*$') { Print-PowerShell }
  elseif ($input -match '^\s*c\s*$') { Print-Cmd }
  elseif ($input -match '^\s*e\s*$') { Export-Selection }
  elseif ($input -match '^\s*i\s*$') { Import-Selection }
  elseif ($input -match '^\s*ps\s*$') { Select-Profile "Safe" }
  elseif ($input -match '^\s*pb\s*$') { Select-Profile "Balanced" }
  elseif ($input -match '^\s*pa\s*$') { Select-Profile "Aggressive" }
  elseif ($input -match '^\s*t\s+(\d+)\s*$') {
    $n = [int]$Matches[1]
    if ($map.ContainsKey($n)) {
      $id = $map[$n]
      if ($selected.Contains($id)) { $selected.Remove($id) | Out-Null } else { $selected.Add($id) | Out-Null }
    }
  }
}
