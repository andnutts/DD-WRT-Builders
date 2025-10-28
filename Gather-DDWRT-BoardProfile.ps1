<#
  .SYNOPSIS
    Gather DD-WRT board profile with expanded mappings, interactive confirmation, and a menu-driven UI.
    Supply devices Boot Log
  .DESCRIPTION
  - Clone/update repo, parse boot log and NVRAM blobs, score candidate mappings, allow interactive menu-driven review and editing, then save profile JSON.
  - Works in DryRun and Force modes.
  .PARAMETER RepoUrl
    Git repo to clone (default dd-wrt mirror).
  .PARAMETER WorkDir
    Working directory for clone and profiles.
  .PARAMETER BootLog
    Path to device boot log (required).
  .PARAMETER NvramFiles
    One or more NVRAM blob paths.
  .PARAMETER MappingsFile
    Path to mappings JSON (default ./mappings/ddwrt-mappings.json).
  .PARAMETER DryRun
    Do not write files or modify repo.
  .PARAMETER Force
    Overwrite existing profile without prompting.
  .PARAMETER Verbose
    Show debug logs.
#>

param(
  [string]$RepoUrl = 'https://github.com/dd-wrt/dd-wrt.git',
  [string]$WorkDir = "$PWD/ddwrt-build",
  [Parameter(Mandatory=$true)][string]$BootLog,
  [string[]]$NvramFiles = @(),
  [string]$MappingsFile = "$PWD/mappings/ddwrt-mappings.json",
  [switch]$DryRun,
  [switch]$Force,
  [switch]$Verbose
)

#==================================================================#
#region * Helpers *
function Write-Log { param([string]$Msg, [string]$Level='INFO') if ($Level -eq 'DEBUG' -and -not $Verbose) { return }; $ts=(Get-Date).ToString('s'); Write-Output "[$ts] [$Level] $Msg" }

function Safe-ReadFile { param([string]$Path); if (-not (Test-Path $Path)) { throw "File not found: $Path" }; Get-Content -Raw -ErrorAction Stop $Path }

function Load-Mappings {
  param([string]$Path)
  if (-not (Test-Path $Path)) { Write-Log "Mappings file not found at $Path" 'DEBUG'; return @() }
  try { return (Get-Content -Raw -Path $Path | ConvertFrom-Json) } catch { Write-Log "Failed to load mappings: $_" 'DEBUG'; return @() }
}

function Ensure-GitClone {
  param([string]$RepoUrl, [string]$Path)
  if (Test-Path $Path) {
    pushd $Path > $null
    try {
      if (git rev-parse --is-inside-work-tree 2>$null) { git fetch --all --prune --quiet; git reset --hard origin/HEAD --quiet; $c=git rev-parse --short HEAD; popd > $null; Write-Log "Updated repo to $c"; return $c }
      else { popd > $null; Remove-Item -Recurse -Force $Path -ErrorAction SilentlyContinue }
    } catch { popd > $null; Remove-Item -Recurse -Force $Path -ErrorAction SilentlyContinue }
  }
  if ($DryRun) { Write-Log "Dry-run: would clone $RepoUrl to $Path" 'INFO'; return 'dry-run-commit' }
  Write-Log "Cloning $RepoUrl to $Path" 'INFO'
  git clone --depth 1 $RepoUrl $Path --quiet
  pushd $Path > $null
  $commit = git rev-parse --short HEAD
  popd > $null
  Write-Log "Cloned repo at commit $commit" 'INFO'
  return $commit
}

function Extract-Strings {
  param([string]$File)
  $stringsCmd = (Get-Command strings -ErrorAction SilentlyContinue)
  if ($stringsCmd) { try { return (& strings -a -n 4 $File) -join "`n" } catch { } }
  $bytes=[System.IO.File]::ReadAllBytes($File)
  $sb=New-Object System.Text.StringBuilder; $run=New-Object System.Text.StringBuilder
  foreach ($b in $bytes) {
    if ($b -ge 32 -and $b -le 126) { $run.Append([char]$b) > $null } else { if ($run.Length -ge 4) { $sb.AppendLine($run.ToString()) > $null }; $run.Clear() > $null }
  }
  if ($run.Length -ge 4) { $sb.AppendLine($run.ToString()) > $null }
  return $sb.ToString()
}

function Parse-BootLog {
  param([string]$Text)
  $out=[ordered]@{ Raw=$Text; Lines=0; Detected=[ordered]@{} }
  $lines=$Text -split "`n"; $out.Lines=$lines.Count
  foreach ($l in $lines) {
    $t=$l.Trim()
    if ($t -match 'Model\s*:?\s*(.+)$') { $out.Detected.Model=$Matches[1].Trim() }
    if ($t -match 'Machine\s*:?\s*(.+)$') { $out.Detected.Machine=$Matches[1].Trim() }
    if ($t -match 'Board\s*:?\s*(.+)$') { $out.Detected.Board=$Matches[1].Trim() }
    if ($t -match 'SoC|soc|Atheros|Qualcomm|Broadcom') { if (-not $out.Detected.SOC) { $out.Detected.SOC=($t -replace '\s+',' ') } }
    if ($t -match '(mtd|nand|spi|flash|NOR|NAND|SPI)\b') { $out.Detected.Flash=($out.Detected.Flash+';'+$t).Trim(';') }
    if ($t -match '([0-9A-Fa-f]{2}(:|-)){5}[0-9A-Fa-f]{2}') { $mac=($t -match '([0-9A-Fa-f]{2}(:|-)){5}[0-9A-Fa-f]{2}').Value; if (-not $out.Detected.MACs) { $out.Detected.MACs=@() }; $out.Detected.MACs+=$mac }
    if ($t -match 'kernel.*cmdline.*') { $out.Detected.Cmdline=$t }
  }
  if ($out.Detected.MACs) { $out.Detected.MACs=$out.Detected.MACs|Select-Object -Unique }
  return $out
}

function Parse-NvramStrings {
  param([string]$Strings)
  $kv=@{}
  foreach ($line in ($Strings -split "`n")) {
    $l=$line.Trim()
    if ($l -match '^\s*([^=\s]+)\s*=\s*(.+)$') { $k=$Matches[1].Trim(); $v=$Matches[2].Trim(); if ($kv.ContainsKey($k)) { $kv[$k]=$kv[$k]+';'+$v } else { $kv[$k]=$v } }
    elseif ($l -match '^(productid|model|board|boardid)\s*[:\-]\s*(.+)$') { $k=$Matches[1].Trim(); $v=$Matches[2].Trim(); $kv[$k]=$v }
  }
  return $kv
}

function Try-Match-InTree {
  param([string]$WorkDir, [string[]]$Candidates)
  $matches=@{}
  foreach ($c in $Candidates | Where-Object { $_ }) {
    $clean=[Regex]::Escape($c) -replace '\\\s+','.*'
    $found=Get-ChildItem -Path $WorkDir -Recurse -Depth 4 -ErrorAction SilentlyContinue |
      Where-Object { $_.Name -match $clean -or $_.FullName -match $clean } | Select-Object -First 20
    if ($found) { $matches[$c]=$found | ForEach-Object { $_.FullName } }
  }
  return $matches
}

function Score-With-Mappings {
  param([array]$Mappings, [string[]]$SearchStrings)
  $scores=@{}
  foreach ($m in $Mappings) {
    $id=$m.id
    $scores[$id]=[ordered]@{ Mapping=$m; Score=0; Matches=@() }
    foreach ($k in $m.keys) {
      foreach ($s in $SearchStrings) {
        if (-not $s) { continue }
        if ($s.ToLower().Contains($k.ToLower())) { $scores[$id].Score += 10; $scores[$id].Matches += $k }
      }
    }
  }
  return $scores.Values | Sort-Object -Property Score -Descending
}

function Prompt-EditField {
  param([string]$Label, [string]$Current)
  $prompt = "$Label [$Current] (enter to keep, 'clear' to empty): "
  $input = Read-Host $prompt
  if ($input -eq '') { return $Current }
  if ($input -eq 'clear') { return '' }
  return $input
}

#endregion
#==================================================================#
#region * Menu Rendering and Key Handling Functions *
function Render-Menu {
    param(
        [hashtable]$Context,
        [array]$Actions,
        [string]$Mode,
        [int]$SelectedIndex
    )

    Clear-Host
    Write-Output "=== DD-WRT Board Profile Menu ==="
    Write-Output ("Mode: " + $Mode + "    (Toggle with Ctrl+M)")
    Write-Output ""

    for ($i = 0; $i -lt $Actions.Count; $i++) {
        $label = $Actions[$i].Label
        $num   = $Actions[$i].Number
        if ($Mode -eq 'ARROW' -and $i -eq $SelectedIndex) {
            Write-Output ("> {0}) {1}" -f $num, $label)
        } else {
            Write-Output ("  {0}) {1}" -f $num, $label)
        }
    }

    Write-Output ""
    Write-Output ("Current final guess: Board=" + ($Context.Profile.FinalGuess.Board) + " Target=" + ($Context.Profile.FinalGuess.Target) + " Confidence=" + ($Context.Profile.FinalGuess.Confidence))
    Write-Output ""
    if ($Mode -eq 'NUMBER') {
        Write-Output "Enter the number corresponding to an option, or press Ctrl+M to switch to arrow navigation:"
    } else {
        Write-Output "Use Up/Down to move, Enter to select, Esc to return to menu, Ctrl+M to switch to numbered input:"
    }
}

function Handle-KeyPress {
    param(
        [hashtable]$Context,
        [array]$Actions,
        [string]$Mode,
        [ref]$SelectedIndex
    )

    # Reads one key and returns:
    #  - a hashtable @{ Result = <'CONTINUE'|'SAVE'|'ABORT'|'ACTION'>; ActionResult = <value> }
    #  - if Result is 'ACTION' then ActionResult contains the return from the action (may be 'SAVE' or 'ABORT' as special)
    $key = [System.Console]::ReadKey($true)

    # Toggle on Ctrl+M
    if ($key.Modifiers -band [System.ConsoleModifiers]::Control -and $key.Key -eq 'M') {
        return @{ Result = 'TOGGLE' ; ActionResult = $null }
    }

    if ($Mode -eq 'NUMBER') {
        # Try to capture a number input; allow single-digit immediate or full-line fallback
        $raw = $null
        if ($key.Key -ge 'D0' -and $key.Key -le 'D9') {
            $first = $key.KeyChar
            Write-Host -NoNewline $first
            $rest = Read-Host
            $raw = $first + $rest
        } else {
            $raw = Read-Host "Selection (enter number)"
        }
        if (-not [string]::IsNullOrWhiteSpace($raw) -and [int]::TryParse($raw, [ref]$selNum)) {
            $actionItem = $Actions | Where-Object { $_.Number -eq $selNum } | Select-Object -First 1
            if (-not $actionItem) { return @{ Result = 'CONTINUE'; ActionResult = $null } }
            # invoke action and return result
            $res = & $actionItem.Action $Context
            return @{ Result = 'ACTION'; ActionResult = $res }
        } else {
            return @{ Result = 'CONTINUE'; ActionResult = $null }
        }
    }

    # ARROW mode handling
    switch ($key.Key) {
        'UpArrow' {
            if ($SelectedIndex.Value -gt 0) { $SelectedIndex.Value-- } else { $SelectedIndex.Value = $Actions.Count - 1 }
            return @{ Result = 'CONTINUE'; ActionResult = $null }
        }
        'DownArrow' {
            if ($SelectedIndex.Value -lt ($Actions.Count - 1)) { $SelectedIndex.Value++ } else { $SelectedIndex.Value = 0 }
            return @{ Result = 'CONTINUE'; ActionResult = $null }
        }
        'Enter' {
            $actionItem = $Actions[$SelectedIndex.Value]
            $res = & $actionItem.Action $Context
            return @{ Result = 'ACTION'; ActionResult = $res }
        }
        'Escape' {
            return @{ Result = 'CONTINUE'; ActionResult = $null }
        }
        default {
            return @{ Result = 'CONTINUE'; ActionResult = $null }
        }
    }
}

#endregion
#==================================================================#
#region * Show-Menu Orchestration *
function Show-Menu {
    param([hashtable]$Context)

    $Actions = $menuActions
    $Mode = 'NUMBER'   # NUMBER or ARROW
    $SelectedIndex = [ref]0

    while ($true) {
        Render-Menu -Context $Context -Actions $Actions -Mode $Mode -SelectedIndex $SelectedIndex.Value

        $hp = Handle-KeyPress -Context $Context -Actions $Actions -Mode $Mode -SelectedIndex $SelectedIndex

        if ($hp.Result -eq 'TOGGLE') {
            $Mode = if ($Mode -eq 'NUMBER') { 'ARROW' } else { 'NUMBER' }
            continue
        }

        if ($hp.Result -eq 'ACTION') {
            $ret = $hp.ActionResult
            if ($ret -eq 'SAVE')   { return 'SAVE' }
            if ($ret -eq 'ABORT')  { return 'ABORT' }
            # otherwise continue loop (action executed in-place)
            continue
        }

        # CONTINUE -> re-render and continue loop
    }
}
#endregion
#==================================================================#
#region * Menu Actions Definitions *
$ViewDetectedSummary = {
    param($Context)
    Clear-Host
    Write-Output "=== Detected Summary ==="
    $bd = $Context.BootParsed.Detected
    if ($bd) { $bd.GetEnumerator() | ForEach-Object { Write-Output ("{0}: {1}" -f $_.Key, $_.Value) } } else { Write-Output "No detected boot items." }
    Write-Output ""; Read-Host "Press Enter to return to menu"
}
$ViewBootLogExcerpt = {
    param($Context)
    Clear-Host
    Write-Output "=== Boot Log Excerpt (first 200 lines) ==="
    ($Context.BootParsed.Raw -split "`n" | Select-Object -First 200) | ForEach-Object { Write-Output $_ }
    Write-Output ""; Read-Host "Press Enter to return to menu"
}
$ViewNVRAMPreviews = {
    param($Context)
    Clear-Host
    Write-Output "=== NVRAM Previews ==="
    if ($Context.NvramProfiles.Count -eq 0) { Write-Output "No NVRAM files provided." } else {
      $i=0
      foreach ($n in $Context.NvramProfiles) {
        $i++; Write-Output "File $i: $($n.Path) (size $($n.Size) bytes)"
        Write-Output "Preview (first 30 strings):"
        ($n.StringsPreview -split "`n" | Select-Object -First 30) | ForEach-Object { Write-Output ("  " + $_) }
        Write-Output ""
      }
    }
    Read-Host "Press Enter to return to menu"
}
$ViewMappingMatches = {
    param($Context)
    Clear-Host
    Write-Output "=== Mapping Matches (Top 10) ==="
    if ($Context.MappingScores.Count -eq 0) { Write-Output "No mapping matches found." } else {
      $Context.MappingScores | Select-Object -First 10 | ForEach-Object {
        $m = $_.Mapping
        Write-Output ("Id: {0} Score: {1} Board: {2} Target: {3} Notes: {4}" -f $m.id, $_.Score, ($m.board -or '-'), ($m.target -or '-'), ($m.notes -or '-'))
        if ($_.Matches.Count -gt 0) { Write-Output ("  Matched keys: " + ($_.Matches -join ', ')) }
      }
    }
    Read-Host "Press Enter to return to menu"
}
$ViewTreeMatches = {
    param($Context)
    Clear-Host
    Write-Output "=== Tree Matches Summary ==="
    if ($Context.TreeMatches.Count -eq 0) { Write-Output "No tree matches found." } else {
      Write-Output ("Candidates matched: " + ($Context.TreeMatches.Keys.Count))
      $Context.TreeMatches.GetEnumerator() | Select-Object -First 20 | ForEach-Object { Write-Output ("Candidate: " + $_.Key + " -> " + ($_.Value | Select-Object -First 3 -Join ',')) }
    }
    Read-Host "Press Enter to return to menu"
}
$EditFinalGuess = {
    param($Context)
    Clear-Host
    Write-Output "=== Edit Final Guess ==="
    $newBoard = Prompt-EditField -Label "Board" -Current $Context.Profile.FinalGuess.Board
    $newTarget = Prompt-EditField -Label "Target" -Current $Context.Profile.FinalGuess.Target
    $newConfidence = Prompt-EditField -Label "Confidence (low/medium/high)" -Current $Context.Profile.FinalGuess.Confidence
    Write-Output "Edit notes: current notes below. Enter blank to keep, or type new notes (single line)."
    $curNotes = ($Context.Profile.FinalGuess.Notes -join "; ")
    $newNotes = Read-Host "Notes [$curNotes]"
    if ($newNotes -ne '') { $Context.Profile.FinalGuess.Notes = @($newNotes) }
    $Context.Profile.FinalGuess.Board = $newBoard
    $Context.Profile.FinalGuess.Target = $newTarget
    $Context.Profile.FinalGuess.Confidence = $newConfidence
    Write-Output "Final guess updated."
    Read-Host "Press Enter to return to menu"
}
$ToggelConfidence = {
    param($Context)
    Clear-Host
    $curr = $Context.Profile.FinalGuess.Confidence
    $next = switch ($curr) { 'low' { 'medium' } 'medium' { 'high' } 'high' { 'low' } default { 'medium' } }
    $Context.Profile.FinalGuess.Confidence = $next
    Write-Output ("Confidence toggled from {0} to {1}" -f $curr, $next)
    Read-Host "Press Enter to return to menu"
}
$PreviewJSON = {
    param($Context)
    Clear-Host
    Write-Output "=== Profile JSON Preview ==="
    try {
        $json = $Context.Profile | ConvertTo-Json -Depth 12
        Write-Output $json
    } catch {
        Write-Output "Failed to serialize profile to JSON: $_"
    }
    Write-Output ""
    Read-Host "Press Enter to return to menu"
}
#endregion
#==================================================================#
#region * Menu Configuration & Options *
$menuActions = @(
    @{ Number = 1;  Label = "View detected summary";      Action = { param($C) & $ViewDetectedSummary $C } }
    @{ Number = 2;  Label = "View boot log excerpt";      Action = { param($C) & $ViewBootLogExcerpt $C } }
    @{ Number = 3;  Label = "View NVRAM previews";        Action = { param($C) & $ViewNVRAMPreviews $C } }
    @{ Number = 4;  Label = "View mapping matches";       Action = { param($C) & $ViewMappingMatches $C } }
    @{ Number = 5;  Label = "View tree matches (count)";  Action = { param($C) & $ViewTreeMatches $C } }
    @{ Number = 6;  Label = "Edit final guess";           Action = { param($C) & $EditFinalGuess $C } }
    @{ Number = 7;  Label = "Toggle confidence";          Action = { param($C) & $ToggelConfidence $C } }
    @{ Number = 8;  Label = "Preview JSON";               Action = { param($C) & $PreviewJSON $C } }
    @{ Number = 9;  Label = "Save profile";               Action = { return 'SAVE' } }
    @{ Number = 0;  Label = "Abort (do not save)";        Action = { return 'ABORT' } }
    # @{ Number = 0;  Label = "";                           Action = {  } }
)
#endregion
#==================================================================#

# --- Main flow
Write-Log "Begin gather process" 'INFO'
if ($DryRun) { Write-Log "Dry-run mode enabled" 'INFO' }
if (-not (Test-Path $BootLog)) { throw "Boot log not found: $BootLog" }

$commit = Ensure-GitClone -RepoUrl $RepoUrl -Path $WorkDir
$mappings = Load-Mappings -Path $MappingsFile
if ($mappings.Count -gt 0) { Write-Log "Loaded $($mappings.Count) mappings" 'DEBUG' }

$bootText = Safe-ReadFile -Path $BootLog
$bootParsed = Parse-BootLog -Text $bootText
Write-Log "Boot log parsed" 'DEBUG'

$nvramProfiles=@(); $allNvramStrings=@()
foreach ($f in $NvramFiles) {
  if (-not (Test-Path $f)) { Write-Log "Skipping missing nvram file: $f" 'DEBUG'; continue }
  Write-Log "Extracting strings from $f" 'INFO'
  $s = Extract-Strings -File $f
  $kv = Parse-NvramStrings -Strings $s
  $nvramProfiles += [ordered]@{ Path=(Resolve-Path $f).Path; Size=(Get-Item $f).Length; StringsPreview=($s -split "`n" | Select-Object -First 30) -join "`n"; KV=$kv }
  $allNvramStrings += ($s -split "`n")
  foreach ($v in $kv.Values) { $allNvramStrings += $v }
}

# Candidates
$candidates=@()
if ($bootParsed.Detected.Model) { $candidates += $bootParsed.Detected.Model }
if ($bootParsed.Detected.Board) { $candidates += $bootParsed.Detected.Board }
if ($bootParsed.Detected.Machine) { $candidates += $bootParsed.Detected.Machine }
foreach ($nv in $nvramProfiles) {
  foreach ($k in $nv.KV.Keys) {
    if ($k -match '^(model|productid|board|boardid|boardrev|product)') { $candidates += $nv.KV[$k] }
  }
}
$candidates = $candidates | Where-Object { $_ } | Select-Object -Unique

# Tree matches
$treeMatches = @{}
if (-not $DryRun) { Write-Log "Searching build tree for candidate identifiers" 'INFO'; $treeMatches = Try-Match-InTree -WorkDir $WorkDir -Candidates $candidates } else { Write-Log "Dry-run: skipping tree search" 'DEBUG' }

# Mapping scoring
$searchPool=@()
$searchPool += $candidates
$searchPool += ($bootParsed.Raw -split "`n") | Select-Object -First 300
$searchPool += $allNvramStrings
$searchPool = $searchPool | Where-Object { $_ } | Select-Object -Unique
$mappingScores = @()
if ($mappings.Count -gt 0) { $mappingScores = Score-With-Mappings -Mappings $mappings -SearchStrings $searchPool; if ($mappingScores.Count -gt 0) { Write-Log "Top mapping: $($mappingScores[0].Mapping.id) score $($mappingScores[0].Score)" 'DEBUG' } }

# Build profile
$profile=[ordered]@{
  ProfileId=[System.Guid]::NewGuid().ToString()
  CollectedAt=(Get-Date).ToString('o')
  SourceRepo=$RepoUrl
  SourceCommit=$commit
  WorkDir=(Resolve-Path $WorkDir).Path
  BootLog=@{ Path=(Resolve-Path $BootLog).Path; Extracted=$bootParsed.Detected }
  Nvram=$nvramProfiles
  Candidates=$candidates
  TreeMatches=$treeMatches
  MappingsUsed=@()
  MappingScores=$mappingScores
  FinalGuess=@{ Board=$null; Target=$null; Confidence='low'; Notes=@() }
  RawInputs=@{ BootLogRaw=$bootParsed.Raw; NvramRawFiles=($NvramFiles | ForEach-Object { if (Test-Path $_) { (Resolve-Path $_).Path } else { $_ } }) }
}

# Apply best mapping
if ($mappingScores -and $mappingScores.Count -gt 0) {
  $top = $mappingScores | Where-Object { $_.Score -gt 0 } | Select-Object -First 1
  if ($top) {
    $m=$top.Mapping
    $profile.MappingsUsed += [ordered]@{ MappingId=$m.id; Score=$top.Score; Matches=$top.Matches; Notes=$m.notes }
    if ($m.board) { $profile.FinalGuess.Board = $m.board }
    if ($m.target) { $profile.FinalGuess.Target = $m.target }
    $profile.FinalGuess.Confidence = $m.confidence
    $profile.FinalGuess.Notes += "Mapped via mappings file id $($m.id)"
  }
}

# Increase confidence if matched in tree
if ($profile.FinalGuess.Board -and $treeMatches.Count -gt 0) {
  foreach ($k in $treeMatches.Keys) {
    if ($k.ToLower().Contains($profile.FinalGuess.Board.ToLower())) {
      $profile.FinalGuess.Confidence='high'
      $profile.FinalGuess.Notes += "Board string also matched files in cloned tree"
      break
    }
  }
}

# Fallback: top candidate
if (-not $profile.FinalGuess.Board -and $candidates.Count -gt 0) {
  $profile.FinalGuess.Board = $candidates | Select-Object -First 1
  $profile.FinalGuess.Confidence='medium'
  $profile.FinalGuess.Notes += "Board guessed from top detected candidate"
}

# Prepare context for menu
$context = @{
  BootParsed = $bootParsed
  NvramProfiles = $nvramProfiles
  Candidates = $candidates
  TreeMatches = $treeMatches
  MappingScores = $mappingScores
  Profile = $profile
}

# If Force -> skip menu and save; if DryRun -> show summary and skip save
if ($Force) {
  Write-Log "Force: skipping interactive menu and saving" 'INFO'
  $menuResult = 'SAVE'
} elseif ($DryRun) {
  Write-Output "DryRun mode - interactive preview only. No files will be written."
  $menuResult = Show-Menu -Context $context
  if ($menuResult -eq 'SAVE') { Write-Output "DryRun: save requested but skipped because DryRun is enabled."; $menuResult = 'ABORT' }
} else {
  $menuResult = Show-Menu -Context $context
}

if ($menuResult -eq 'ABORT') { Write-Log "User aborted; exiting without saving" 'INFO'; throw "User aborted" }

# Save profile
$profilesDir = Join-Path $WorkDir 'profiles'
if (-not (Test-Path $profilesDir)) { if ($DryRun) { Write-Log "Dry-run: would create profiles directory $profilesDir" 'DEBUG' } else { New-Item -ItemType Directory -Path $profilesDir | Out-Null } }
$boardIdSafe = ($profile.FinalGuess.Board -replace '[^A-Za-z0-9_\-]','_')
if (-not $boardIdSafe) { $boardIdSafe = "unknown_board_$($profile.ProfileId.Substring(0,8))" }
$profilePath = Join-Path $profilesDir "$boardIdSafe.json"

if (Test-Path $profilePath -and -not $Force) { Write-Log "Profile already exists at $profilePath. Use -Force to overwrite." 'ERROR'; throw "Profile already exists: $profilePath" }

$json = $profile | ConvertTo-Json -Depth 12

if ($DryRun) {
  Write-Log "Dry-run: profile JSON would be written to $profilePath" 'INFO'
  Write-Log $json 'DEBUG'
} else {
  $json | Out-File -FilePath $profilePath -Encoding UTF8
  Write-Log "Profile saved to $profilePath" 'INFO'
}

Write-Log "Gather process complete" 'INFO'
return $profilePath
