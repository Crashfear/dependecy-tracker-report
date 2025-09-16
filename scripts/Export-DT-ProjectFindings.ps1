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

function Out-DTReportHtml {
  param(
    $rows,
    [string]$htmlPath,
    [string]$title,
    [object]$summaryRows
  )

  # KPIs
  $kpiTotal = @($rows).Count
  $kpiCrit  = @($rows | Where-Object { $_.Severity -eq 'Critical' }).Count
  $kpiHigh  = @($rows | Where-Object { $_.Severity -eq 'High'     }).Count
  $kpiMed   = @($rows | Where-Object { $_.Severity -eq 'Medium'   }).Count
  $kpiLow   = @($rows | Where-Object { $_.Severity -eq 'Low'      }).Count
  $kpiInfo  = @($rows | Where-Object { $_.Severity -eq 'Info'     }).Count

$style = @'
<style>
  :root{
    --bg:#121212; --ink:#eaeaea; --muted:#a9a9a9; --line:#2a2a2a; --card:#1d1d1d;
    --sev-critical:#ef5350; --sev-high:#ff9800; --sev-medium:#ffeb3b; --sev-low:#66bb6a; --sev-info:#42a5f5; --sev-unknown:#777;
    --thead:#1a1a1a; --row-alt:#181818; --link:#64b5f6;
  }
  *{box-sizing:border-box}
  body{margin:24px;background:var(--bg);color:var(--ink);font-family:Segoe UI,Arial,Helvetica,sans-serif}
  .wrap{max-width:1280px;margin:0 auto}
  h1{margin:0 0 6px 0;font-weight:700;color:#fff}
  .meta{color:var(--muted);margin:0 0 16px 0}
  .kpi{display:flex;gap:12px;flex-wrap:wrap;margin:18px 0}
  .kpi .card{background:var(--card);border:1px solid var(--line);border-radius:10px;padding:10px 14px;min-width:120px}
  .kpi .title{font-size:12px;color:var(--muted);margin-bottom:6px}
  .kpi .val{font-size:20px;font-weight:700}
  .section{margin-top:28px}
  .grid{overflow-x:auto;border:1px solid var(--line);border-radius:10px;background:var(--card)}
  table{border-collapse:separate;border-spacing:0;width:100%}
  thead th{position:sticky;top:0;background:var(--thead);border-bottom:1px solid var(--line);font-weight:600;font-size:12px;padding:10px;text-align:left;color:#ddd}
  tbody td{border-bottom:1px solid var(--line);padding:10px;font-size:13px;vertical-align:top;color:#eee}
  tbody tr:nth-child(even){background:var(--row-alt)}
  a{color:var(--link);text-decoration:none}
  a:hover{text-decoration:underline}
  .badge{display:inline-block;padding:3px 8px;border-radius:999px;font-size:12px;font-weight:600;color:#000}
  .sev-critical{background:var(--sev-critical);color:#fff}
  .sev-high{background:var(--sev-high)}
  .sev-medium{background:var(--sev-medium)}
  .sev-low{background:var(--sev-low)}
  .sev-info{background:var(--sev-info)}
  .sev-unknown{background:var(--sev-unknown);color:#fff}
  .epss{display:inline-block;min-width:120px}
  .bar{height:8px;background:#333;border-radius:6px;overflow:hidden}
  .bar > span{display:block;height:100%;background:#7c4dff}
  .epss small{display:inline-block;margin-top:4px;color:var(--muted)}
</style>
'@

   $rowsHtml = ($rows | ForEach-Object {
    $sev = [string]$_.Severity
    $sevClass = if ([string]::IsNullOrWhiteSpace($sev)) { 'sev-unknown' } else { 'sev-' + $sev.ToLower() }
    # PS5: não há operador ?? -> calcula label explicitamente
    $sevLabel = if ([string]::IsNullOrWhiteSpace($sev)) { 'Unknown' } else { $sev }

    $vulnCell = if ($_.VulnUrl) {
      '<a href="' + ($_.VulnUrl) + '" target="_blank" rel="noopener">' + ($_.Vulnerability) + '</a>'
    } else { ($_.Vulnerability) }

    [double]$epssVal = 0.0
    if ($_.EPSS -ne $null -and $_.EPSS -ne '') {
      [double]$epssVal = $_.EPSS
      if ($epssVal -gt 1) { $epssVal = $epssVal/100 } # aceita 0..1 ou 0..100
    }
    $epssPct = [math]::Round($epssVal*100,1)
    $epssBar = '<div class="epss"><div class="bar"><span style="width:'+$epssPct+'%"></span></div><small>'+ $epssPct +'%</small></div>'

    '<tr>' +
      '<td>' + ($_.ProjectName)      + '</td>' +
      '<td>' + ($_.Component)        + '</td>' +
      '<td>' + ($_.ComponentVersion) + '</td>' +
      '<td>' + $vulnCell             + '</td>' +
      '<td>' + ($_.Source)           + '</td>' +
      '<td><span class="badge ' + $sevClass + '">' + $sevLabel + '</span></td>' +
      '<td>' + ($_.CVSSv3)           + '</td>' +
      '<td>' + $epssBar              + '</td>' +
      '<td>' + ($_.AnalysisState)    + '</td>' +
      '<td>' + ($_.Suppressed)       + '</td>' +
    '</tr>'
  }) -join "`r`n"

  $summaryHtml = ""
  if ($summaryRows -and $summaryRows.Count -gt 0) {
    $summaryHtml = ($summaryRows | ForEach-Object {
      '<tr>' +
        '<td>' + ($_.Componente) + '</td>' +
        '<td>' + ($_.Total)      + '</td>' +
        '<td><span class="badge sev-critical">' + ($_.Critical) + '</span></td>' +
        '<td><span class="badge sev-high">'     + ($_.High)     + '</span></td>' +
        '<td><span class="badge sev-medium">'   + ($_.Medium)   + '</span></td>' +
        '<td><span class="badge sev-low">'      + ($_.Low)      + '</span></td>' +
        '<td><span class="badge sev-info">'     + ($_.Info)     + '</span></td>' +
      '</tr>'
    }) -join "`r`n"
  }

$head = @'
<!DOCTYPE html>
<html>
<head>
<meta charset="utf-8">
'@

  $nowStr = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
  $html =
    $head + $style + '</head><body><div class="wrap">' +
    '<h1>' + $title + '</h1>' +
    '<p class="meta">Generated at ' + $nowStr + '</p>' +
    '<div class="kpi">' +
      '<div class="card"><div class="title">Total</div><div class="val">'+ $kpiTotal +'</div></div>' +
      '<div class="card"><div class="title">Critical</div><div class="val">'+ $kpiCrit +'</div></div>' +
      '<div class="card"><div class="title">High</div><div class="val">'+ $kpiHigh +'</div></div>' +
      '<div class="card"><div class="title">Medium</div><div class="val">'+ $kpiMed +'</div></div>' +
      '<div class="card"><div class="title">Low</div><div class="val">'+ $kpiLow +'</div></div>' +
      '<div class="card"><div class="title">Info</div><div class="val">'+ $kpiInfo +'</div></div>' +
    '</div>' +
    '<div class="section"><h2>Findings</h2>' +
    '<div class="grid"><table><thead><tr>' +
      '<th>Project</th><th>Component</th><th>Version</th><th>Vulnerability</th><th>Source</th><th>Severity</th><th>CVSSv3</th><th>EPSS</th><th>Analysis</th><th>Suppressed</th>' +
    '</tr></thead><tbody>' + $rowsHtml + '</tbody></table></div></div>'

  if ($summaryRows -and $summaryRows.Count -gt 0) {
    $html +=
      '<div class="section"><h2>Summary by Component</h2>' +
      '<div class="grid"><table><thead><tr>' +
        '<th>Component</th><th>Total</th><th>Critical</th><th>High</th><th>Medium</th><th>Low</th><th>Info</th>' +
      '</tr></thead><tbody>' + $summaryHtml + '</tbody></table></div></div>'
  }

  $html += '</div></body></html>'
  $html | Out-File -FilePath $htmlPath -Encoding UTF8
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

# HTML
$htmlPath = "$base.html"
Out-DTReportHtml -rows $rows -htmlPath $htmlPath -title $title -summaryRows $summary
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
