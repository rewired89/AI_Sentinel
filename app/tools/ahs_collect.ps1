param(
  [string]$RepoRoot = ".",
  [int]$Days = 30
)

# -------- helpers (ASCII only) --------
function New-Dir($p){ if(-not(Test-Path $p)){ New-Item -ItemType Directory -Path $p | Out-Null } }
function Short([string]$s, [int]$n=120){ if([string]::IsNullOrEmpty($s)){ return "" }; if($s.Length -le $n){ return $s } else { return ($s.Substring(0,$n) + "...") } }
function MaskKey([string]$k){
  if([string]::IsNullOrWhiteSpace($k)){ return "-" }
  if($k.Length -lt 8){ return "***" }
  $stars = [string]::new([char]42, ($k.Length - 4))
  return $stars + $k.Substring($k.Length - 4)
}

$ErrorActionPreference = "SilentlyContinue"
$start = Get-Date

# -------- paths --------
$RepoRoot = (Resolve-Path $RepoRoot).Path
$DocsDir  = Join-Path $RepoRoot "docs"
$OutDir   = Join-Path $RepoRoot ("AIHunter_Support_" + (Get-Date -Format "yyyyMMdd_HHmmss"))
New-Dir $DocsDir; New-Dir $OutDir

# -------- load optional config --------
$configPath = Join-Path $RepoRoot "tools\ahs_collect.config.json"  # optional alt location
if(-not (Test-Path $configPath)){ $configPath = Join-Path $RepoRoot "app\tools\ahs_collect.config.json" }
$moduleMap = @{}
if(Test-Path $configPath){
  try {
    $cfg = Get-Content $configPath -Raw | ConvertFrom-Json
    if($cfg.module_paths){
      foreach($p in $cfg.module_paths.PSObject.Properties){
        $moduleMap[$p.Name] = $p.Value
      }
    }
  } catch {}
}

# -------- environment --------
try { $os  = Get-CimInstance Win32_OperatingSystem } catch { $os = $null }
$psv = $PSVersionTable.PSVersion.ToString()

$dotnet = "dotnet not found"
if(Get-Command dotnet -ErrorAction SilentlyContinue){ try { $dotnet = (& dotnet --info | Select-Object -First 1) } catch {} }

$python = "python not found"
if(Get-Command python -ErrorAction SilentlyContinue){ try { $python = (& python --version 2>&1) } catch {} }

$sysmonSvc = $null
try { $sysmonSvc = Get-Service -Name "Sysmon*" -ErrorAction SilentlyContinue } catch {}

$defender = $null
try { $defender = Get-MpComputerStatus } catch {}

# API keys presence (redacted)
$VT  = MaskKey([Environment]::GetEnvironmentVariable("VT_API_KEY","User"))
$OTX = MaskKey([Environment]::GetEnvironmentVariable("OTX_API_KEY","User"))

# -------- project inventory --------
$files = Get-ChildItem -Path $RepoRoot -Recurse -File -ErrorAction SilentlyContinue
$codeExts = @("ps1","psm1","py","cs","go","rs","cpp","c","js","ts","tsx","csproj","sln","json","yml","yaml","toml")
$code = $files | Where-Object { $codeExts -contains ($_.Extension.TrimStart('.').ToLower()) }
$loc  = 0
foreach($f in $code){ try { $loc += (Get-Content $f.FullName -ErrorAction SilentlyContinue).Count } catch{} }

# detection heuristics for features (keys single-quoted to avoid parser issues)
$heur = @{
  'Network Identity Guard'      = '(network[_-]?identity|mac|arp|dhcp)'
  'Email/BEC Intent Shield'     = '(email|bec|dmarc|spf|dkim)'
  'Link & Domain Shield'        = '(url|domain|virustotal|vt|otx|whois|nrd)'
  'Attachment Guard'            = '(yara|macro|attachment|sandbox)'
  'Behavior/EDR-lite'           = '(edr|behavior|parent.?child|sysmon)'
  'Egress & DNS Guard'          = '(dns|egress|doh|entropy)'
  'Firewall Forensics'          = '(firewall|pfirewall|5156|5157|5152|5158)'
  'Threat Intel Integration'    = '(virustotal|otx|intel|feeds)'
  'Response Engine'             = '(quarantine|isolate|block|kill)'
  'Evidence & Audit'            = '(audit|evidence|hmac|chain[_-]?of[_-]?custody|sign)'
  'Policy & Memory'             = '(allowlist|blocklist|policy|decision|cache)'
  'UI & Alerts'                 = '(ui|toast|tray|wpf|react|notification)'
}

$has = @{}
foreach($feat in $heur.Keys){
  if($moduleMap.ContainsKey($feat)){
    $present = $false
    foreach($p in $moduleMap[$feat]){
      $pat = Join-Path $RepoRoot $p
      if(Test-Path $pat){ $present = $true; break }
    }
    $has[$feat] = $present
  } else {
    $rx = $heur[$feat]
    $has[$feat] = (($files | Where-Object { $_.FullName -match $rx }).Count -gt 0)
  }
}

# build hint
$buildCmd = ""
if(Test-Path (Join-Path $RepoRoot "AIHunter.sln")){ $buildCmd = "dotnet build .\AIHunter.sln -c Release" }
elseif(Test-Path (Join-Path $RepoRoot "src\main.py")){ $buildCmd = "python -m pip install -r requirements.txt && python .\src\main.py" }
elseif(Test-Path (Join-Path $RepoRoot "requirements.txt")){ $buildCmd = "python -m pip install -r requirements.txt && python .\main.py" }

# -------- collect logs (last N days) --------
$Since = (Get-Date).AddDays(-1 * $Days)

# Windows Firewall text log
$fwLog = "$env:SystemRoot\System32\LogFiles\Firewall\pfirewall.log"
$fwOut = $null
if(Test-Path $fwLog){
  $fwOut = Join-Path $OutDir ("pfirewall_last{0}d.log" -f $Days)
  try{
    $sel = @()
    foreach($ln in Get-Content $fwLog -ErrorAction Stop){
      if($ln -match '^(?<d>\d{4}-\d{2}-\d{2}) (?<t>\d{2}:\d{2}:\d{2})'){
        $ts = Get-Date ($Matches['d']+" "+$Matches['t'])
        if($ts -ge $Since){ $sel += $ln }
      }
    }
    if($sel.Count -eq 0){ $sel = Get-Content $fwLog | Select-Object -Last 50000 }
    $sel | Set-Content $fwOut -Encoding UTF8
  } catch { Copy-Item $fwLog $fwOut -ErrorAction SilentlyContinue }
}

# EVTX slices (Security log)
function Export-Events([int[]]$ids,[string]$name,[string]$logName){
  try{
    Get-WinEvent -FilterHashtable @{LogName=$logName; Id=$ids; StartTime=$Since} |
      Export-Csv (Join-Path $OutDir $name) -NoTypeInformation -Encoding UTF8
  }catch{}
}
Export-Events @(4624,4625) ("Security_Auth_{0}d.csv" -f $Days) "Security"
Export-Events @(5152,5156,5157,5158) ("FilteringPlatform_{0}d.csv" -f $Days) "Security"

# Sysmon (optional)
try{
  if($sysmonSvc){ Get-WinEvent -FilterHashtable @{LogName="Microsoft-Windows-Sysmon/Operational"; StartTime=$Since} |
      Export-Csv (Join-Path $OutDir ("Sysmon_{0}d.csv" -f $Days)) -NoTypeInformation -Encoding UTF8 }
}catch{}

# Defender quick status
try{
  if($defender){ $defender | ConvertTo-Json -Depth 3 | Out-File (Join-Path $OutDir "Defender_Status.json") -Encoding UTF8 }
}catch{}

# Config snippets (redacted)
$cfgOut = Join-Path $OutDir "Config_Snippets.txt"
"== Config snippets (redacted) ==" | Out-File $cfgOut -Encoding UTF8
$maybeCfg = $files | Where-Object { $_.Name -match '(appsettings\.json|config\.json|\.env|settings\.ya?ml)' }
foreach($cf in $maybeCfg){
  try{
    "---- $($cf.FullName) ----" | Out-File $cfgOut -Append
    $content = Get-Content $cf.FullName -ErrorAction Stop
    $red = $content `
      -replace '(?i)(api[_-]?key["\s:]*["\s:]*)([^"\s]{8,})', { $args[0].Groups[1].Value + (MaskKey($args[0].Groups[2].Value)) } `
      -replace '(?i)(token["\s:]*["\s:]*)([^"\s]{8,})', { $args[0].Groups[1].Value + (MaskKey($args[0].Groups[2].Value)) }
    $red | ForEach-Object { Short $_ 200 } | Out-File $cfgOut -Append
  }catch{}
}

# AI Hunter processes/services snapshot
try{
  (Get-Process | Where-Object { $_.ProcessName -match '(ai|hunter|sentinel)' } |
    Select-Object ProcessName,Id,StartTime,Path) |
    Export-Csv (Join-Path $OutDir "AIHunter_Processes.csv") -NoTypeInformation
}catch{}
try{
  (Get-Service | Where-Object { $_.Name -match '(AIHunter|Sentinel|Hunter)' } |
    Select-Object Name,Status,DisplayName) |
    Export-Csv (Join-Path $OutDir "AIHunter_Services.csv") -NoTypeInformation
}catch{}

# -------- STATUS.md --------
$statusPath = Join-Path $DocsDir "AI_Hunter_Sentinel_STATUS.md"
$md = @()
$md += "# AI Hunter Sentinel - Status (Windows MVP)"
$md += ""
$md += "Generated: $($start.ToString('yyyy-MM-dd HH:mm:ss'))"
$md += ""
$md += "## 1) Environment"
$md += "- OS: $([string]::Format("{0} {1} (Build {2})", $os.Caption, $os.Version, $os.BuildNumber))"
$md += "- PowerShell: $psv"
$md += "- .NET: $(Short $dotnet 100)"
$md += "- Python: $python"
$md += "- Sysmon services: $([string]::Join(', ', ($sysmonSvc | ForEach-Object { $_.Status + ' ' + $_.Name })))"
$md += "- Defender RealTime: $([string]($defender -and $defender.RealTimeProtectionEnabled))"
$md += "- VirusTotal key present: $([bool]($VT -ne '-')) ($VT)"
$md += "- OTX key present: $([bool]($OTX -ne '-')) ($OTX)"
$md += ""
$md += "## 2) Project footprint"
$md += "- Files scanned: $($files.Count)"
$md += "- Code files: $($code.Count) - Approx LOC: $loc"
$md += "- Build hint: $((if($buildCmd -ne ''){$buildCmd}else{'<add build/run notes>'}))"
$md += ""
$md += "## 3) Feature presence"
$md += "| Feature | Found |"
$md += "|---|---|"
foreach($k in $has.Keys){ $md += "| $k | $([string]($has[$k])) |" }
$md += ""
$md += "## 4) Collected evidence (last $Days days)"
if($fwOut){ $md += "- $(Split-Path -Leaf $fwOut)" }
$md += "- Security_Auth_${Days}d.csv"
$md += "- FilteringPlatform_${Days}d.csv"
if($sysmonSvc){ $md += "- Sysmon_${Days}d.csv" }
$md += "- Defender_Status.json"
$md += "- Config_Snippets.txt (keys redacted)"
$md += "- AIHunter_Processes.csv, AIHunter_Services.csv"
$md += ""
$md += "## 5) Known issues / TODO (fill these)"
$md += "- [ ] ..."
$md += "- [ ] ..."
$md += ""
$md += "## 6) Runbook (fill/confirm)"
$md += "- Build: $buildCmd"
$md += "- Run/Install: <service/exe/ps1 and args>"
$md += "- Data dir: C:\\ProgramData\\AIHunter\\..."
$md += ""
$mdText = ($md -join "`r`n")
$mdText | Out-File $statusPath -Encoding UTF8

# -------- ZIP package --------
$zipPath = Join-Path $RepoRoot ("AIHunter_SupportPack_" + (Get-Date -Format "yyyyMMdd_HHmmss") + ".zip")
Compress-Archive -Path $OutDir,$statusPath -DestinationPath $zipPath -Force | Out-Null

Write-Host ""
Write-Host "OK: Generated files:"
Write-Host " - $statusPath"
Write-Host " - $zipPath"
Write-Host "Upload the ZIP here."

