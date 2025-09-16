param(
  [Parameter(Mandatory=$true)][string]$BaseUrl,        # e.g.: http://your-host:8081
  [Parameter(Mandatory=$true)][string]$ApiKey,
  [Parameter(Mandatory=$true)][string]$ProjectUuid,    # Project UUID (copy from UI URL)
  [string]$OutDir = ".\out",
  [ValidateSet('None','Info','Low','Medium','High','Critical')]
  [string]$MinSeverity = 'None',
  [bool]$IncludeSuppressed = $false,
  [string]$AnalysisStates = '',                        # e.g.: "EXPLOITABLE,IN_TRIAGE"
  [bool]$Excel = $false,                               # true if ImportExcel module is installed
  [bool]$Pdf = $false                                  # true if wkhtmltopdf is installed
)

# ---------- Standardize log encoding (aesthetic only) ----------
try {
  chcp 65001 | Out-Null
  [Console]::OutputEncoding = [Text.UTF8Encoding]::UTF8
} catch {}

$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'

# ===================== Helpers =====================

function Ensure-Dir([string]$p){
  if(-not (Test-Path $p)){ New-Item -ItemType Directory -Path $p | Out-Null }
}

function Sanitize-Name([string]$name){
  if([string]::IsNullOrWhiteSpace($name)){ return "_no_name_" }
  $bad = [IO.Path]::GetInvalidFileNameChars() -join ''
  $rx  = "[{0}]" -f ([Regex]::Escape($bad))
  ($name -replace $rx,'_').Trim().Substring(0,[Math]::Min(100,$name.Length))
}

# Safe nested property access (PS5/PS7 compatible)
function Get-NestedValue { param($obj,[string[]]$path)
  $cur = $obj
  foreach($p in $path){
    if ($null -eq $cur) { return $null }
    $prop = $cur.PSObject.Properties[$p]
    if ($null -eq $prop){ return $null }
    $cur = $prop.Value
  }
  return $cur
}

# Simple coalesce
function Coalesce { param([Parameter(ValueFromRemainingArguments=$true)]$args)
  foreach($a in $args){
    if ($null -ne $a -and -not ($a -is [string] -and $a -eq '')) { return $a }
  }
  return $null
}

function Normalize-Severity([string]$sev){
  if([string]::IsNullOrWhiteSpace($sev)){ return 'Unknown' }
  switch ($sev.ToUpper()) {
    'CRITICAL'{'Critical'}
    'HIGH'    {'High'}
    'MEDIUM'  {'Medium'}
    'LOW'     {'Low'}
    'INFO'    {'Info'}
    'NONE'    {'None'}
    'UNASSIGNED' {'Info'}   # maps findings without severity
    default   {$sev}
  }
}

function Severity-Rank([string]$sev){
  switch ((Normalize-Severity $sev)) { 'Critical'{5} 'High'{4} 'Medium'{3} 'Low'{2} 'Info'{1} default{0} }
}

function Filter-By-Severity($items,[string]$min){
  $minRank = Severity-Rank $min
  $items | Where-Object { (Severity-Rank $_.Severity) -ge $minRank }
}

function Convert-FindingsToRows($findings,[bool]$IncludeSuppressed,[string]$AnalysisStates){
  $stateSet = @()
  if ($AnalysisStates -and $AnalysisStates.Trim() -ne '') {
    $stateSet = $AnalysisStates.Split(',') | ForEach-Object { $_.Trim().ToUpper() } | Where-Object {$_ -ne ''}
  }

  $rows = @()
  foreach ($f in $findings) {
    # extract component fields safely
    $compName    = Coalesce (Get-NestedValue $f @('component','name')) $f.componentName (Get-NestedValue $f @('affectedComponent','name'))
    $compVersion = Coalesce (Get-NestedValue $f @('component','version')) $f.componentVersion (Get-NestedValue $f @('affectedComponent','version'))
    $compPurl    = Coalesce (Get-NestedValue $f @('component','purl')) $f.purl

    # extract vulnerability fields
    $vulnId      = Coalesce (Get-NestedValue $f @('vulnerability','vulnId')) $f.vulnId (Get-NestedValue $f @('vulnerability','id'))
    $vulnSource  = Coalesce (Get-NestedValue $f @('vulnerability','source')) $f.source
    $severityRaw = Coalesce (Get-NestedValue $f @('vulnerability','severity')) $f.severity
    $cvssV3      = Coalesce (Get-NestedValue $f @('vulnerability','cvssV3BaseScore')) $f.cvssV3BaseScore
    $epss        = Coalesce (Get-NestedValue $f @('vulnerability','epssScore')) $f.epssScore
    $published   = Coalesce (Get-NestedValue $f @('vulnerability','published')) $f.published
    $updated     = Coalesce (Get-NestedValue $f @('vulnerability','updated')) $f.updated

    # extract analysis info
    $analysis        = $f.analysis
    $analysisState   = Coalesce (Get-NestedValue $analysis @('state')) $f.analysisState
    $justification   = Coalesce (Get-NestedValue $analysis @('justification')) $f.justification
    $responseVal     = Coalesce (Get-NestedValue $analysis @('response')) $f.response
    if ($responseVal -is [System.Array]) { $responseVal = ($responseVal -join ', ') }

    # suppressed flag
    $isSuppressed = $false
    $supA = Coalesce (Get-NestedValue $f @('suppressed')) (Get-NestedValue $analysis @('isSuppressed'))
    if ($null -ne $supA) { $isSuppressed = [bool]$supA }

    # skip suppressed or not-in-state
    if (-not $IncludeSuppressed -and $isSuppressed) { continue }
    if ($stateSet.Count -gt 0) {
      $st = (Coalesce $analysisState 'NOT_SET').ToString().ToUpper()
      if ($stateSet -notcontains $st) { continue }
    }

    # build normalized row object
    $rows += [pscustomobject]@{
      ProjectName      = Coalesce (Get-NestedValue $f @('project','name'))  $f.projectName
      ProjectVersion   = Coalesce (Get-NestedValue $f @('project','version')) $f.projectVersion
      Component        = $compName
      ComponentVersion = $compVersion
      PURL             = $compPurl
      Vulnerability    = $vulnId
      Source           = $vulnSource
      VulnUrl          = Coalesce (Get-NestedValue $f @('vulnerability','reference')) $f.reference
      Severity         = (Normalize-Severity $severityRaw)
      CVSSv3           = $cvssV3
      EPSS             = $epss
      Published        = $published
      Updated          = $updated
      AnalysisState    = $analysisState
      Justification    = $justification
      Response         = $responseVal
      Suppressed       = $isSuppressed
      AffectedVersion  = $f.affectedVersion
      Alias            = ($((Get-NestedValue $f @('vulnerability','aliases'))) -join ', ')
      CWE              = Coalesce (Get-NestedValue $f @('vulnerability','cwe','name')) $f.cwe
      Description      = Coalesce (Get-NestedValue $f @('vulnerability','description')) $f.description
    }
  }

  $rows | Sort-Object @{Expression={ Severity-Rank $_.Severity };Descending=$true}, @{Expression='CVSSv3';Descending=$true}, 'Component'
}

function Summarize-ByComponent($rows){
  $rows |
    Group-Object Component |
    ForEach-Object {
      $g = $_
      $crit = ($g.Group | Where-Object Severity -eq 'Critical').Count
      $high = ($g.Group | Where-Object Severity -eq 'High').Count
      $med  = ($g.Group | Where-Object Severity -eq 'Medium').Count
      $low  = ($g.Group | Where-Object Severity -eq 'Low').Count
      $info = ($g.Group | Where-Object Severity -eq 'Info').Count
      [pscustomobject]@{
        Componente = $g.Name
        Total      = $g.Count
        Critical   = $crit
        High       = $high
        Medium     = $med
        Low        = $low
        Info       = $info
      }
    } |
    Sort-Object -Property @{Expression='Total';Descending=$true},
                           @{Expression='Componente';Descending=$false}
}

function Write-Excel($rows,[string]$pathXlsx){
  if(-not (Get-Module -ListAvailable -Name ImportExcel)){
    Write-Host "[INFO] ImportExcel module not found - skipping XLSX." -ForegroundColor Yellow
    return
  }
  $rows | Export-Excel -Path $pathXlsx -WorksheetName 'Findings' -AutoSize -FreezeTopRow -BoldTopRow
  $summary = Summarize-ByComponent $rows
  $summary | Export-Excel -Path $pathXlsx -WorksheetName 'SummaryByComponent' -AutoSize -StartRow 1 -ClearSheet
}

function Write-PDF([string]$htmlPath,[string]$pdfPath){
  # Try wkhtmltopdf
  $wk = Get-Command wkhtmltopdf -ErrorAction SilentlyContinue
  if ($wk) {
    & $wk.Source $htmlPath $pdfPath | Out-Null
    if (Test-Path $pdfPath) {
      Write-Host "[OK] PDF (wkhtmltopdf): $pdfPath" -ForegroundColor Green
      return
    } else {
      Write-Warning "[WARN] wkhtmltopdf failed to produce PDF."
    }
  } else {
    Write-Host "[INFO] wkhtmltopdf not found. Trying headless browser..." -ForegroundColor Yellow
  }

  # Try Microsoft Edge headless
  $edgePaths = @(
    "$Env:ProgramFiles (x86)\Microsoft\Edge\Application\msedge.exe",
    "$Env:ProgramFiles\Microsoft\Edge\Application\msedge.exe"
  )
  $edge = $edgePaths | Where-Object { Test-Path $_ } | Select-Object -First 1
  if ($edge) {
    & $edge --headless --disable-gpu --no-sandbox --print-to-pdf="$pdfPath" "file:///$($htmlPath -replace '\\','/')"
    Start-Sleep -Milliseconds 500
    if (Test-Path $pdfPath) {
      Write-Host "[OK] PDF (Edge headless): $pdfPath" -ForegroundColor Green
      return
    } else {
      Write-Warning "[WARN] Edge headless failed to produce PDF."
    }
  }

  # Try Chrome/Chromium headless
  $chromePaths = @(
    "$Env:ProgramFiles\Google\Chrome\Application\chrome.exe",
    "$Env:ProgramFiles(x86)\Google\Chrome\Application\chrome.exe",
    "$Env:LocalAppData\Google\Chrome\Application\chrome.exe"
  )
  $chrome = $chromePaths | Where-Object { Test-Path $_ } | Select-Object -First 1
  if ($chrome) {
    & $chrome --headless=new --disable-gpu --no-sandbox --print-to-pdf="$pdfPath" "file:///$($htmlPath -replace '\\','/')"
    Start-Sleep -Milliseconds 500
    if (Test-Path $pdfPath) {
      Write-Host "[OK] PDF (Chrome headless): $pdfPath" -ForegroundColor Green
      return
    } else {
      Write-Warning "[WARN] Chrome headless failed to produce PDF."
    }
  }

  Write-Warning "[WARN] No PDF engine available. Install wkhtmltopdf or Edge/Chrome."
}

# ===================== Execution =====================

Ensure-Dir $OutDir
Write-Host "[INFO] Exporting project findings: $ProjectUuid" -ForegroundColor Cyan

$headers  = @{ 'X-Api-Key' = $ApiKey; 'Accept' = 'application/json' }
$endpoint = ($BaseUrl.TrimEnd('/') + "/api/v1/finding/project/$ProjectUuid/export?includeSuppressed=$($IncludeSuppressed.ToString().ToLower())")

Write-Host ("[DEBUG] Endpoint: {0}" -f $endpoint) -ForegroundColor DarkGray
Write-Host "[DEBUG] Calling API..." -ForegroundColor DarkGray

# HTTPS self-signed? PS7 allows -SkipCertificateCheck
$skipCert = $PSVersionTable.PSVersion.Major -ge 7

try {
  $invokeParams = @{ Method='GET'; Uri=$endpoint; Headers=$headers; TimeoutSec=120 }
  if ($skipCert) { $invokeParams['SkipCertificateCheck'] = $true }
  $data = Invoke-RestMethod @invokeParams
} catch {
  Write-Error ("Failed to call {0} : {1}" -f $endpoint, $_.Exception.Message)
  exit 1
}

if ($null -eq $data) {
  Write-Warning "API returned null. Verify BaseUrl/UUID and permissions to access the project."
  return
}

# Fail fast if HTML was returned (wrong port or reverse proxy)
if ($data -is [string] -and $data -match '<html') {
  throw "Received HTML instead of JSON. Use the API endpoint (usually port 8081) or a proxy exposing /api."
}

# Normalize payload (either a pure array OR an object with .findings/.project)
if ($data -is [System.Array]) {
  $findingsPayload = $data
  $projectMeta = $null
} elseif ($data.PSObject.Properties.Name -contains 'findings') {
  $findingsPayload = $data.findings
  $projectMeta = $data.project
} else {
  $findingsPayload = @()
  $projectMeta = $null
}
Write-Host ("[DEBUG] Received items (findings): {0}" -f ($findingsPayload.Count)) -ForegroundColor DarkGray

$ts   = Get-Date -Format 'yyyyMMdd_HHmmss'
$base = Join-Path $OutDir ("findings_{0}" -f $ts)

# Raw JSON and findings-only JSON
$jsonRawPath = "$base.raw.json"
$data | ConvertTo-Json -Depth 8 | Out-File -FilePath $jsonRawPath -Encoding UTF8
Write-Host "[OK] Raw JSON: $jsonRawPath" -ForegroundColor Green

$jsonPath = "$base.json"
$findingsPayload | ConvertTo-Json -Depth 8 | Out-File -FilePath $jsonPath -Encoding UTF8
Write-Host "[OK] Findings JSON: $jsonPath" -ForegroundColor Green

# Normalize/filter
$rowsAll = Convert-FindingsToRows -findings $findingsPayload -IncludeSuppressed:$IncludeSuppressed -AnalysisStates $AnalysisStates
$rows    = Filter-By-Severity -items $rowsAll -min $MinSeverity
if ($null -eq $rows) { $rows = @() }

# Title uses project name/version when available
if ($projectMeta -and ($projectMeta.name -or $projectMeta.version)) {
  $projName = $projectMeta.name
  $projVer  = $projectMeta.version
} else {
  $projName = ($rowsAll | Select-Object -First 1 -ExpandProperty ProjectName)
  $projVer  = ($rowsAll | Select-Object -First 1 -ExpandProperty ProjectVersion)
}

if ([string]::IsNullOrWhiteSpace($projName)) {
  $title = "DT - Dependency Vulnerability Report (Project: $ProjectUuid)"
} else {
  $title = "DT - Dependency Vulnerability Report (Project: $projName / $projVer)"
}

# Summary by component
$summary = Summarize-ByComponent $rows

# CSV
$csvPath = "$base.csv"
$rows | Export-Csv -NoTypeInformation -Encoding UTF8 -Path $csvPath
Write-Host ("[OK] CSV: {0} (rows: {1})" -f $csvPath, $rows.Count) -ForegroundColor Green

# HTML (with fallback)
$htmlPath = "$base.html"
if (Get-Command Write-HTML -ErrorAction SilentlyContinue) {
  Write-HTML -rows $rows -htmlPath $htmlPath -title $title -summaryRows $summary
} else {
  $head = @"
<style>
  body{font-family:Segoe UI,Arial,sans-serif;margin:24px}
  table{border-collapse:collapse;width:100%}
  th,td{border:1px solid #e5e5e5;padding:6px 8px;font-size:12px}
  th{background:#fafafa;text-align:left}
</style>
"@
  $rows | ConvertTo-Html -Title $title -Head $head | Out-File -Encoding utf8 $htmlPath
}
Write-Host ("[OK] HTML: {0}" -f $htmlPath) -ForegroundColor Green

# XLSX (optional)
if ($Excel) {
  $xlsxPath = "$base.xlsx"
  Write-Excel -rows $rows -pathXlsx $xlsxPath
  if (Test-Path $xlsxPath){ Write-Host "[OK] XLSX: $xlsxPath" -ForegroundColor Green }
}

# PDF (optional)
if ($Pdf) {
  $pdfPath = "$base.pdf"
  Write-PDF -htmlPath $htmlPath -pdfPath $pdfPath
}

Write-Host ("[DONE] Output at: {0}" -f (Resolve-Path $OutDir)) -ForegroundColor Cyan
