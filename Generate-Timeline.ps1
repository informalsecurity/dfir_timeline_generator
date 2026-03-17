<#
.SYNOPSIS
    Generates an XMind-style HTML tree timeline from a CSV, with entity colour-coding and tags.

.DESCRIPTION
    Timeline CSV columns:  DateTime, EventHeader, EventDescription, Tags
    Entity CSV columns:    Entity, RealEmail, SpoofedEmails   (SpoofedEmails = semicolon-separated)

    - Each entity row gets a unique colour.
    - Any email address found in event text is replaced with: Entity <email>
      Real emails are shown in the entity colour.
      Spoofed emails are shown in the entity colour PLUS a red SPOOFED badge.
    - Tags (up to 5, semicolon-separated) appear as small pill badges on the event card.

    The template must contain: <!-- TIMELINE_DATA_PLACEHOLDER -->

.PARAMETER CsvPath        Path to the timeline CSV.
.PARAMETER TemplatePath   Path to the HTML template.
.PARAMETER OutputPath     Output HTML path. Default: timeline_output.html
.PARAMETER EntityCsvPath  Optional path to the entity/email CSV.
.PARAMETER DateTimeFormat DateTime parse format. Default: 'yyyy-MM-dd HH:mm:ss'

.EXAMPLE
    .\Generate-Timeline.ps1 -CsvPath timeline.csv -TemplatePath timeline_template.html -EntityCsvPath entities.csv
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)]
    [ValidateScript({ Test-Path $_ -PathType Leaf })]
    [string]$CsvPath,

    [Parameter(Mandatory=$true)]
    [ValidateScript({ Test-Path $_ -PathType Leaf })]
    [string]$TemplatePath,

    [Parameter(Mandatory=$false)]
    [string]$OutputPath = "timeline_output.html",

    [Parameter(Mandatory=$false)]
    [string]$EntityCsvPath = "",

    [Parameter(Mandatory=$false)]
    [string]$DateTimeFormat = "yyyy-MM-dd HH:mm:ss"
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

# ── Palette of distinct soft colours for entities ─────────────────────────────
$PALETTE = @(
    '#1565c0','#6a1b9a','#00695c','#e65100','#4527a0',
    '#ad1457','#2e7d32','#0277bd','#c62828','#37474f',
    '#558b2f','#f57f17','#4e342e','#00838f','#283593'
)

function Escape-Html([string]$t) {
    if (-not $t) { return "" }
    $t -replace '&','&amp;' -replace '<','&lt;' -replace '>','&gt;' -replace '"','&quot;' -replace "'","&#39;"
}

# ── Load entity CSV if provided ───────────────────────────────────────────────
# Build two lookup tables:
#   $realMap[email]    = @{ Entity; Colour }
#   $spoofMap[email]   = @{ Entity; Colour }

$realMap        = @{}
$spoofMap       = @{}
$threatActorMap = @{}  # RealEmail -> {Entity;Colour} for entities whose SpoofedEmails = THREAT_ACTOR
$entityColours  = @{}  # Entity -> colour (for legend if needed)

if ($EntityCsvPath -ne "" -and (Test-Path $EntityCsvPath)) {
    Write-Host "[+] Loading entities: $EntityCsvPath" -ForegroundColor Cyan
    $entData = Import-Csv -Path $EntityCsvPath
    $ei = 0
    foreach ($row in $entData) {
        $colour = $PALETTE[$ei % $PALETTE.Count]
        $entity = $row.Entity.Trim()
        $entityColours[$entity] = $colour

        # Real emails (semicolon-separated)
        foreach ($addr in ($row.RealEmail -split ';')) {
            $addr = $addr.Trim().ToLower()
            if ($addr) { $realMap[$addr] = @{ Entity=$entity; Colour=$colour } }
        }

        # Spoofed emails (semicolon-separated)
        # If SpoofedEmails contains THREAT_ACTOR, register this entity as a threat actor identity
        if ($row.PSObject.Properties.Name -contains 'SpoofedEmails') {
            foreach ($addr in ($row.SpoofedEmails -split ';')) {
                $addr = $addr.Trim()
                if ($addr.ToUpper() -eq 'THREAT_ACTOR') {
                    # Map the literal token THREAT_ACTOR -> this entity's real email(s)
                    # Store in threatActorMap keyed by entity for lookup in Format-Description
                    foreach ($real in ($row.RealEmail -split ';')) {
                        $real = $real.Trim().ToLower()
                        if ($real) {
                            $script:threatActorMap[$real] = @{ Entity=$entity; Colour=$colour }
                        }
                    }
                } else {
                    if ($addr) { $spoofMap[$addr.ToLower()] = @{ Entity=$entity; Colour=$colour } }
                }
            }
        }
        $ei++
    }
    Write-Host "[+] $($entData.Count) entities loaded." -ForegroundColor Cyan
}

# ── Replace email addresses in text with coloured HTML spans ──────────────────
function Format-Description([string]$text) {
    if (-not $text) { return "" }

    # Collect all known addresses sorted longest-first to avoid partial replacements.
    # THREAT_ACTOR emails are included here for legitimate use matches — no badge emitted for those.
    # The THREAT_ACTOR literal token replacement (with purple badge) runs separately below.
    $allAddrs = @()
    foreach ($k in $realMap.Keys)  { $allAddrs += $k }
    foreach ($k in $spoofMap.Keys) { $allAddrs += $k }
    $allAddrs = $allAddrs | Select-Object -Unique | Sort-Object { $_.Length } -Descending

    # Work on the raw text; we'll HTML-escape segments as we go
    # Strategy: find leftmost match, emit escaped text before it, then emit styled span, repeat
    $result = [System.Text.StringBuilder]::new()
    $remaining = $text

    while ($remaining.Length -gt 0) {
        # Find the earliest occurrence of any address (case-insensitive)
        $bestIdx  = $remaining.Length
        $bestAddr = $null

        foreach ($addr in $allAddrs) {
            $idx = $remaining.ToLower().IndexOf($addr)
            if ($idx -ge 0 -and $idx -lt $bestIdx) {
                $bestIdx  = $idx
                $bestAddr = $addr
            }
        }

        if ($bestAddr -eq $null) {
            # No more matches — emit rest escaped
            [void]$result.Append((Escape-Html $remaining))
            break
        }

        # Emit text before match
        if ($bestIdx -gt 0) {
            [void]$result.Append((Escape-Html $remaining.Substring(0, $bestIdx)))
        }

        # Determine real or spoof
        $isSpoof = $spoofMap.ContainsKey($bestAddr)
        $info    = if ($isSpoof) { $spoofMap[$bestAddr] } else { $realMap[$bestAddr] }
        $colour  = $info.Colour
        $entity  = Escape-Html $info.Entity
        $dispAddr= Escape-Html $bestAddr

        # Emit styled entity+email span
        [void]$result.Append("<span class=`"entity-ref`" style=`"color:$colour;font-weight:600;`">$entity &lt;$dispAddr&gt;</span>")
        if ($isSpoof) {
            if ($info.Entity -eq 'THREAT_ACTOR') {
                [void]$result.Append(" <span class=`"threat-actor-badge`">THREAT ACTOR</span>")
            } else {
                [void]$result.Append(" <span class=`"spoof-badge`">SPOOFED</span>")
            }
        }

        # Advance past the match
        $remaining = $remaining.Substring($bestIdx + $bestAddr.Length)
    }

    # Replace THREAT_ACTOR tokens AFTER email scan so they don't get double-processed
    $html = $result.ToString()
    foreach ($real in $script:threatActorMap.Keys) {
        $info     = $script:threatActorMap[$real]
        $entity   = Escape-Html $info.Entity
        $colour   = $info.Colour
        $dispAddr = Escape-Html $real
        $span     = "<span class=`"entity-ref`" style=`"color:$colour;font-weight:600;`">$entity &lt;$dispAddr&gt;</span> <span class=`"threat-actor-badge`">THREAT ACTOR</span>"
        $html     = $html -replace '(?i)THREAT_ACTOR', $span
    }
    return $html
}

# ── Tag colour map (built on first pass through all events) ──────────────────
$TAG_COLOUR_MAP = @{}
$TAG_PALETTE = @(
    '#7b1fa2','#1565c0','#00695c','#e65100','#c62828',
    '#2e7d32','#0277bd','#ad1457','#4527a0','#37474f',
    '#f57f17','#558b2f','#4e342e','#00838f','#283593'
)

function Get-TagColour([string]$tag) {
    $key = $tag.ToLower().Trim()
    if (-not $script:TAG_COLOUR_MAP.ContainsKey($key)) {
        $idx = $script:TAG_COLOUR_MAP.Count % $script:TAG_PALETTE.Count
        $script:TAG_COLOUR_MAP[$key] = $script:TAG_PALETTE[$idx]
    }
    return $script:TAG_COLOUR_MAP[$key]
}

# ── Build tag pills HTML ──────────────────────────────────────────────────────
function Format-Tags([string]$tagStr) {
    if (-not $tagStr -or $tagStr.Trim() -eq "") { return "" }
    $tags = ($tagStr -split ';') | ForEach-Object { $_.Trim() } | Where-Object { $_ -ne "" } | Select-Object -First 5
    if (-not $tags) { return "" }
    $html = '<div class="event-tags">'
    foreach ($tag in $tags) {
        $colour = Get-TagColour $tag
        $html += "<span class=`"event-tag`" style=`"border-color:$colour;color:$colour;`">$(Escape-Html $tag)</span>"
    }
    $html += '</div>'
    return $html
}

# ── Load & parse timeline CSV ─────────────────────────────────────────────────
Write-Host "[+] Loading CSV: $CsvPath" -ForegroundColor Cyan
$rawData = Import-Csv -Path $CsvPath
foreach ($col in @('DateTime','EventHeader','EventDescription')) {
    if ($col -notin $rawData[0].PSObject.Properties.Name) { throw "CSV missing column: '$col'" }
}
$hasTags = 'Tags' -in $rawData[0].PSObject.Properties.Name

$events = [System.Collections.Generic.List[PSCustomObject]]::new()
foreach ($row in $rawData) {
    $dtRaw = $row.DateTime.Trim(); $dt = $null
    try   { $dt = [datetime]::ParseExact($dtRaw, $DateTimeFormat, $null) }
    catch { try { $dt = [datetime]::Parse($dtRaw) } catch { Write-Warning "Skip: '$dtRaw'"; continue } }
    $events.Add([PSCustomObject]@{
        DateTime    = $dt
        Header      = $row.EventHeader.Trim()
        Description = $row.EventDescription.Trim()
        Tags        = if ($hasTags) { $row.Tags.Trim() } else { "" }
    })
}
$events   = $events | Sort-Object DateTime
$baseDate = ($events | Select-Object -First 1).DateTime.Date
Write-Host "[+] $($events.Count) events." -ForegroundColor Cyan

# ── Pre-build tag colour map in chronological order ──────────────────────────
foreach ($evt in $events) {
    if ($evt.Tags) {
        foreach ($tag in ($evt.Tags -split ';')) {
            $tag = $tag.Trim()
            if ($tag) { [void](Get-TagColour $tag) }
        }
    }
}

# ── Build HTML ────────────────────────────────────────────────────────────────
$byDay = $events | Group-Object { $_.DateTime.Date.ToString("yyyy-MM-dd") } | Sort-Object Name
$sb = [System.Text.StringBuilder]::new()
$dayIndex = 0

foreach ($dayGroup in $byDay) {
    $dayDate = [datetime]::ParseExact($dayGroup.Name, "yyyy-MM-dd", $null)
    $dayNum  = ($dayDate.Date - $baseDate).Days
    $side    = if ($dayIndex % 2 -eq 0) { "side-right" } else { "side-left" }
    $dayIndex++
    $byHour = $dayGroup.Group | Group-Object { $_.DateTime.ToString("HH") } | Sort-Object Name

    [void]$sb.AppendLine("  <div class=`"tl-day-row $side`">")
    [void]$sb.AppendLine("    <div class=`"tl-day-panel`">")
    [void]$sb.AppendLine("      <div class=`"day-badge-row`">")
    [void]$sb.AppendLine("        <div class=`"day-h-line`"></div>")
    [void]$sb.AppendLine("        <div class=`"day-badge`">Day $dayNum</div>")
    [void]$sb.AppendLine("      </div>")
    [void]$sb.AppendLine("      <div class=`"hours-branch`">")
    [void]$sb.AppendLine("        <div class=`"hour-tree`">")

    foreach ($hourGroup in $byHour) {
        $hourDisplay = "{0:D2}:00" -f ([int]$hourGroup.Name)

        [void]$sb.AppendLine("          <div class=`"hour-row`">")
        [void]$sb.AppendLine("            <div class=`"hour-h-line`"></div>")
        [void]$sb.AppendLine("            <div class=`"hour-content`">")
        [void]$sb.AppendLine("              <div class=`"hour-badge`">$hourDisplay</div>")
        [void]$sb.AppendLine("              <div class=`"events-branch`">")
        [void]$sb.AppendLine("                <div class=`"event-tree`">")

        foreach ($evt in ($hourGroup.Group | Sort-Object DateTime)) {
            $safeTs   = Escape-Html $evt.DateTime.ToString("M/d/yyyy  HH:mm:ss")
            $safeHdr  = Escape-Html $evt.Header
            $fmtDesc  = Format-Description $evt.Description
            $tagsHtml = Format-Tags $evt.Tags

            [void]$sb.AppendLine("                  <div class=`"event-row`">")
            [void]$sb.AppendLine("                    <div class=`"event-h-line`"></div>")
            [void]$sb.AppendLine("                    <div class=`"event-card`">")
            [void]$sb.AppendLine("                      <div class=`"event-ts`">$safeTs</div>")
            [void]$sb.AppendLine("                      <div class=`"event-header`">$safeHdr</div>")
            [void]$sb.AppendLine("                      <div class=`"event-desc`">$fmtDesc</div>")
            if ($tagsHtml) {
            [void]$sb.AppendLine("                      $tagsHtml")
            }
            [void]$sb.AppendLine("                    </div>")
            [void]$sb.AppendLine("                  </div>")
        }

        [void]$sb.AppendLine("                </div>")
        [void]$sb.AppendLine("              </div>")
        [void]$sb.AppendLine("            </div>")
        [void]$sb.AppendLine("          </div>")
    }

    [void]$sb.AppendLine("        </div>")
    [void]$sb.AppendLine("      </div>")
    [void]$sb.AppendLine("    </div>")
    [void]$sb.AppendLine("  </div>")
}

# ── Inject & write ────────────────────────────────────────────────────────────
$template = Get-Content -Path $TemplatePath -Raw
$placeholder = "<!-- TIMELINE_DATA_PLACEHOLDER -->"
if ($template -notlike "*$placeholder*") { throw "Template missing: $placeholder" }
($template -replace [regex]::Escape($placeholder), $sb.ToString()) | Set-Content -Path $OutputPath -Encoding UTF8
Write-Host "[+] Done: $OutputPath  (Events: $($events.Count), Days: $($byDay.Count))" -ForegroundColor Green
