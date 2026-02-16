[Diagnostics.CodeAnalysis.SuppressMessageAttribute( "PSAvoidUsingWriteHost", "", Justification = "Write-Host is acceptable for this script's UX output" )]
[Diagnostics.CodeAnalysis.SuppressMessageAttribute( "PSUseDeclaredVarsMoreThanAssignments", "", Justification = "Variables are intentionally declared for clarity and onboarding" )]
<#
  .SYNOPSIS
    Create a ddwrt-pipeline directory scaffold with templates and tests.
  .PARAMETER RootPath
    Root folder for the scaffold. This parameter is now mandatory. If not supplied, you will be prompted to enter the path (e.g., './ddwrt-pipeline').
  .PARAMETER Force
    Overwrite existing files if present.
  .PARAMETER WhatIf
    Dry-run mode: shows actions without writing files. (Handled by CmdletBinding)
  .EXAMPLE
    .\New-DDWRTScaffold.ps1 C:\work\ddwrt-pipeline
  .EXAMPLE (Force overwrite)
    .\New-DDWRTScaffold.ps1 C:\work\ddwrt-pipeline -Force
  .EXAMPLE (Dry run using standard parameter)
    .\New-DDWRTScaffold.ps1 -RootPath .\new-project -WhatIf
  .NOTES
    Idempotent: will create folders if missing and won't overwrite files unless -Force is used.
    Uses Write-Verbose for progress, which can be seen by running the script with -Verbose.
    Includes interactive pre-execution preview and post-execution summary.
#>
[CmdletBinding(SupportsShouldProcess=$true, ConfirmImpact='High')]
param(
    [Parameter(Mandatory=$true, Position=0)]
    [string]$RootPath,
    [switch]$Force
)
#==================================================================#
#region * Helpers (Private Scope) *
#==================================================================#
function Private:Write-Action {
    [CmdletBinding(SupportsShouldProcess=$true)]
    param([string]$Text)
    # Using Write-Verbose for standard progress logging
    Write-Verbose $Text

    # Custom colored output remains for visibility, but runs only if not in WhatIf
    # This must call ShouldProcess from the calling cmdlet ($PSCmdlet) scope.
    if ($PSCmdlet.ShouldProcess($Text, "Executing Action")) {
        Write-Host $Text -ForegroundColor Green
    }
}

function Private:Ensure-ScaffoldPath {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute(
        'PSUseApprovedVerbs',
        '',
        Justification = 'This function name is intentionally using a non-approved verb'
    )]
    [CmdletBinding(SupportsShouldProcess=$true)]
    [OutputType([pscustomobject])]
    param([string]$Dir, [switch]$Force)

    Private:Write-Action "Ensuring directory exists: $Dir"

    if (Test-Path $Dir) {
        return [PSCustomObject]@{ Path = $Dir; Status = "Exists" }
    }

    if ($PSCmdlet.ShouldProcess("Creating directory $Dir", "New-Item")) {
        try {
            New-Item -Path $Dir -ItemType Directory -Force:$Force | Out-Null
            return [PSCustomObject]@{ Path = $Dir; Status = "Created" }
        } catch {
            Write-Error "Failed to create directory ${Dir}: $($_.Exception.Message)"
            return [PSCustomObject]@{ Path = $Dir; Status = "Failed" }
        }
    }

    return [PSCustomObject]@{ Path = $Dir; Status = "Skipped" }
}

function Private:Write-FileIfMissing {
    [CmdletBinding(SupportsShouldProcess=$true)]
    [OutputType([string])]
    param([string]$Path, [string]$Content, [switch]$Force)
    Private:Write-Action "Writing file (if missing or forced): $Path"

    $exists = Test-Path $Path

    if ($PSCmdlet.ShouldProcess("Writing $Path", "Set-Content")) {
        if ($Force -or -not $exists) {
            try {
                # Use Set-Content to write file, -Force is necessary for overwrite
                $Content | Set-Content -Path $Path -Force:$Force
                return if ($exists -and $Force) { "Overwritten" } else { "Created" }
            } catch {
                Write-Error "Failed to write file ${Path}: $($_.Exception.Message)"
                return "Failed"
            }
        } else {
            return "Skipped"
        }
    }
    return "Skipped" # ShouldProcess returned false, likely due to WhatIf or user cancel
}

function Private:Get-ScaffoldPlan {
    param([string]$Root)

    $plan = @()

    # --- DEFINE PROJECT STRUCTURE AND CONTENT ---
    $structure = @(
        # Folders
        @{ Path = "parse"; Type = 'Directory' },
        @{ Path = "tools"; Type = 'Directory' },
        @{ Path = "ci"; Type = 'Directory' },

        # Files in Folders
        @{ Path = "parse\tests.ps1"; Type = 'File'; Content = "# Pester tests go here" },
        @{ Path = "tools\menu-config.json"; Type = 'File'; Content = "{ 'default_board': 'r8000' }" },

        # Root Files
        @{ Path = "mappings-db.yaml"; Type = 'File'; Content = 'vendor:board -> ddwrt-target' },
        @{ Path = "collect-bootlog.ps1"; Type = 'File'; Content = 'Implement serial capture logic' },
        @{ Path = "build-helper.sh"; Type = 'File'; Content = '#!/bin/bash`n# Replace with actual build logic' },
        # Placeholder README.md will be created here and then overwritten later with NEXT STEPS
        @{ Path = "README.md"; Type = 'File'; Content = "# DD-WRT Pipeline Project" }
    )

    # Determine initial status (WillCreate or Exists)
    foreach ($item in $structure) {
        $path = Join-Path $Root $item.Path
        $status = if (Test-Path $path) { "Exists" } else { "WillCreate" }

        $plan += [PSCustomObject]@{
            Path = $path
            Type = $item.Type
            Content = $item.Content # Only for files
            Status = $status       # Initial status for preview (WillCreate or Exists)
            FinalStatus = $null    # Final status after execution
        }
    }
    return $plan
}

function Private:Format-StatusList {
    param($Plan, [switch]$PreExecution, [string]$RootPath)

    Write-Host "`nProject Path: $RootPath" -ForegroundColor Cyan
    Write-Host "Planned/Actual Status (`n[✓]: Will Create/Created, [-]: Already Exists/Skipped, [X]: Failed):" -ForegroundColor White

    # Sort for better readability
    $Plan | Sort-Object Path | ForEach-Object {
        $path = $_.Path
        $status = if ($PreExecution) { $_.Status } else { $_.FinalStatus }

        # Determine marker and color
        $marker = switch ($status) {
            "WillCreate"  { $color="Green"; "[✓]" }
            "Exists"      { $color="Yellow"; "[-]" }
            "Created"     { $color="Green"; "[✓]" }
            "Overwritten" { $color="Green"; "[✓]" }
            "Skipped"     { $color="Yellow"; "[-]" }
            "Failed"      { $color="Red"; "[X]" }
            default       { $color="Gray"; "[?]" }
        }

        # Create a simple relative path for display
        $relPath = $path.Replace("$RootPath\", "").Replace("$RootPath/", "")

        # Indent for a basic tree-like view (based on number of path separators)
        $pathParts = $relPath.Split('/', '\')
        $indent = if ($pathParts.Count -gt 1) { ("  " * ($pathParts.Count - 2)) + "L-- " } else { "" }

        Write-Host "$marker $indent$relPath ($($item.Type))" -ForegroundColor $color
    }
    Write-Host ""
}
#endregion
#==================================================================#
#region * Template Content Variables *
#==================================================================#
#region -- LicenseText --
$LicenseText = @'
Copyright 2024 [Your Name/Company]

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
'@
#endregion
#region -- MappingsDb --
$MappingsDb = @'
# mappings-db.yaml
# Stores the mapping from vendor/board name to the official DD-WRT target name (e.g., 'buffalo_wzr-hp-g300nh').
# This is used by your build/ingest logic to correctly pull files and build manifests.

# Example:
# netgear_wndr4500:
#   target: netgear_wndr4500
#   platform: broadcom
#   notes: "Primary development board."
# tplink_c7-v2:
#   target: tplink_c7
#   platform: qualcomm-ath
#   notes: "Common testing board."

# Add your supported boards here:
netgear_wndr4500:
  target: netgear_wndr4500
  platform: broadcom
  notes: "Primary development board."
'@
#endregion
#region -- BuildHelperSh --
$BuildHelperSh = @'
#!/usr/bin/env bash
# build/build-helper.sh
# Entry point for building a DD-WRT image from a manifest.
# Usage: ./build-helper.sh <path/to/manifest.yaml> <target-dir>
set -euo pipefail

MANIFEST_FILE="$1"
TARGET_DIR="${2:-work/output}"
BOARD_NAME=$(basename "$MANIFEST_FILE" .yaml)

echo "--- Building DD-WRT image for $BOARD_NAME ---"
echo "Reading manifest: $MANIFEST_FILE"

# 1. Clone/Update DD-WRT source (Example: replace with your actual source handling)
# git clone --depth 1 https://github.com/dd-wrt/dd-wrt.git source
# cd source
# git pull

# 2. Apply Custom Patches (if applicable)
# for patch in ../patches/*.patch; do
#     patch -p1 < "$patch"
# done

# 3. Configure and Build (Placeholder - replace with actual build system calls)
# make $BOARD_NAME_config
# make V=1 -j$(nproc)

echo "--- Build sequence complete (Placeholder) ---"
echo "Output image should be in $TARGET_DIR"
# Exit non-zero if build fails
# exit 1
'@
#endregion
#region -- IngestConfigJson --
$IngestConfigJson = @'
{
  "remote_source_url": "http://ddwrt.com/raw/latest/",
  "local_raw_dir": "profiles/raw",
  "data_types": [
    "bootlog",
    "nvram"
  ],
  "download_boards": [
    "netgear_wndr4500",
    "tplink_c7"
  ]
}
'@
#endregion
#region -- IngestRunPs1 --
$IngestRunPs1 = @'
<#
  .SYNOPSIS
    Downloads and prepares raw data (bootlogs, nvram dumps) for analysis.
#>
param(
  [Parameter(Mandatory=$false)][string]$Board = "netgear_wndr4500"
)

Write-Host "Simulating ingest for board: $Board..." -ForegroundColor Yellow
# Placeholder for actual download/collection logic.
# This script would typically:
# 1. Read ingest-config.json.
# 2. Check for local serial capture tools (e.g., collect-bootlog.ps1).
# 3. Use BITS/Invoke-WebRequest to download remote files into profiles/raw.

$bootlogContent = @"
# Bootlog start for $Board on $(Get-Date)
U-Boot 1.1.4 (Aug 15 2024 - 12:34:56)

CPU:   BCM4706 700MHz
Board: $Board
DDR:   256 MB
Flash: 32 MB
...
Environment: nvram set
nvram:
bootflags=0
restore_defaults=0
model=WNDR4500
...
# Bootlog end
"@

$rawDir = Join-Path (Split-Path -Parent $MyInvocation.MyCommand.Definition) "profiles\raw"
if (-not (Test-Path $rawDir)) { New-Item -ItemType Directory -Path $rawDir -Force | Out-Null }
$timestamp = (Get-Date -Format "yyyyMMdd-HHmmss")
$targetFile = Join-Path $rawDir "bootlog-$Board-$timestamp.log"

$bootlogContent | Out-File $targetFile -Encoding UTF8 -Force

Write-Host "Ingest complete. Raw bootlog saved to: $targetFile" -ForegroundColor Green
'@
#endregion
#region -- ParsersPs1 --
$ParsersPs1 = @'
<#
  .SYNOPSIS
    Contains functions to parse raw data (bootlogs, nvram) into structured profiles.
#>
#region * Bootlog Parser *
function Parse-BootLog {
  param(
    [Parameter(Mandatory=$true)][string]$LogPath,
    [Parameter(Mandatory=$true)][string]$OutDir
  )
  Write-Host "Starting Bootlog parsing for: $LogPath" -ForegroundColor Cyan

  $content = Get-Content -Path $LogPath -Raw

  $profileData = @{
    logFile = (Split-Path $LogPath -Leaf);
    deviceName = "Unknown";
    memory = 0;
    flash = 0;
    nvramEntries = @{}
  }

  # Example: Extract device name (simple regex, needs refinement for real logs)
  if ($content -match 'Board: ([a-zA-Z0-9_-]+)') {
    $profileData.deviceName = $Matches[1]
  }

  # Example: Extract memory
  if ($content -match 'DDR:   (\d+ MB)') {
    $profileData.memory = $Matches[1]
  }

  # Example: Extract NVRAM key/values
  $nvramBlock = $content -split 'nvram:' | Select-Object -Skip 1 | Out-String
  $nvramBlock.Split([System.Environment]::NewLine) | ForEach-Object {
    if ($_ -match '^(\w+)\s*=\s*(.*)$') {
      $profileData.nvramEntries[$Matches[1]] = $Matches[2].Trim()
    }
  }

  $targetBoard = $profileData.deviceName -replace '\s+', '_' # Simple sanitization
  $outFile = Join-Path $OutDir "$targetBoard-profile.json"

  # Convert NVRAM to a flat list for better JSON readability if needed, but keeping it as map for now.
  $profileData | ConvertTo-Json -Depth 5 | Out-File $outFile -Encoding UTF8 -Force

  Write-Host "Parsed profile saved to: $outFile" -ForegroundColor Green
}
#endregion

#region * NVRAM Parser (Placeholder) *
function Parse-NvramDump {
  param(
    [Parameter(Mandatory=$true)][string]$DumpPath,
    [Parameter(Mandatory=$true)][string]$OutDir
  )
  Write-Host "NVRAM dump parser is a placeholder." -ForegroundColor Yellow
  # Real implementation would parse the dump format (often a simple list)
  # and output a structured JSON file.
}
#endregion
'@
#endregion
#region -- ValidateImagePs1 --
$ValidateImagePs1 = @'
<#
  .SYNOPSIS
    Validates a compiled DD-WRT image against its manifest requirements.
  .PARAMETER ImagePath
    Path to the compiled firmware image (.bin).
  .PARAMETER Manifest
    Path to the YAML manifest file (e.g., build/manifests/board.yaml).
  .PARAMETER Mode
    Validation mode (e.g., V1, V2, V3).
#>
param(
  [Parameter(Mandatory=$true)][string]$ImagePath,
  [Parameter(Mandatory=$true)][string]$Manifest,
  [Parameter(Mandatory=$true)][string]$Mode = "V2"
)

Write-Host "--- Starting Image Validation (Mode: $Mode) ---" -ForegroundColor Yellow
Write-Host "Image: $ImagePath"
Write-Host "Manifest: $Manifest"

# 1. Read Manifest (requires a YAML parser, e.g., powershell-yaml module)
# This is a simulation since we can't guarantee external module availability.
Write-Host "Simulating manifest check..." -ForegroundColor DarkGray
$manifestData = @{
    "board_name" = "netgear_wndr4500"
    "required_size_bytes" = 33554432 # 32MB
    "required_features" = @("usb", "vpn", "mini-klog")
}

# 2. Check Image Existence and Size
if (-not (Test-Path $ImagePath)) {
  Write-Error "Image file not found at $ImagePath"
  exit 1
}
$imageSize = (Get-Item $ImagePath).Length
Write-Host "Image size: $($imageSize) bytes."

# 3. Simulate Binwalk analysis (requires binwalk to be installed)
# The `string-extract.ps1` helper can be used here for simple checks.
Write-Host "Simulating firmware header check (Binwalk equivalent)..." -ForegroundColor DarkGray
if ($imageSize -lt $manifestData.required_size_bytes) {
  Write-Host "FAIL: Image size is too small ($imageSize B) vs required size ($($manifestData.required_size_bytes) B)." -ForegroundColor Red
  # The actual check would look at the contents, not just size.
} else {
  Write-Host "PASS: Basic size check OK." -ForegroundColor Green
}

# 4. Feature Check (Simulated)
Write-Host "Validating required features..." -ForegroundColor DarkGray
# Logic to check for the presence of required strings/modules inside the image
# (This usually requires extracting the filesystem and checking binaries/configs)

Write-Host "Validation complete." -ForegroundColor Yellow
# Exit 0 for success, non-zero for failure
exit 0
'@
#endregion
#region -- SmokeTestPlanMd --
$SmokeTestPlanMd = @'
# DD-WRT Firmware Smoke Test Plan

This document outlines the standard tests to perform immediately after flashing a new DD-WRT build to ensure basic functionality (Smoke Test).

| Level | Description | Focus |
| :---: | :--- | :--- |
| **S1** | **Critical Boot** | Does the device boot and provide basic connectivity? |
| **S2** | **Core Functionality** | Does routing, Wi-Fi, and basic configuration work? |
| **S3** | **Advanced Features** | Do non-essential features (USB, VPN, QoS) work? |

## S1: Critical Boot (Required for any release)

1.  **Boot Success:**
    * Flash firmware.
    * Device boots without looping or crashing.
2.  **Web Interface Access:**
    * Connect via wired Ethernet.
    * Access the web interface (default IP is usually `192.168.1.1`).
3.  **Basic Connectivity:**
    * Verify the device obtains an IP address from the WAN side (if connected to a modem).
    * Verify a connected client can ping external addresses (e.g., `8.8.8.8`).

## S2: Core Functionality (Required for most releases)

1.  **Wi-Fi 2.4GHz:**
    * Configure a basic WPA2-PSK network.
    * Connect a client device.
    * Verify internet access via Wi-Fi.
2.  **Wi-Fi 5GHz (if applicable):**
    * Repeat 2.4GHz steps.
3.  **Basic Routing/NAT:**
    * Verify internal clients can access the internet simultaneously.
4.  **NVRAM/Config Persistence:**
    * Change the router's hostname and save settings.
    * Reboot and verify the new hostname is preserved.

## S3: Advanced Features (As needed per manifest)

1.  **USB Storage:**
    * Insert a USB drive.
    * Verify the drive is mounted and accessible via the web UI.
2.  **VPN (e.g., OpenVPN Client):**
    * Configure a connection.
    * Verify connection successful and traffic is routed.
3.  **QoS/Bandwidth Management:**
    * Apply a simple rule (e.g., throttle a specific IP).
    * Verify the rule takes effect.

---
**BOARD: [BOARD_NAME]**
**DATE: [YYYY-MM-DD]**
**TESTER: [NAME]**
'@
#endregion
#region -- PesterExampleTest --
$PesterExampleTest = @'
# tests/Example.Tests.ps1
# Example Pester tests for validating parser output.
# To run: Open PowerShell, navigate to /parse, and run `Invoke-Pester`

Describe "Parse-BootLog" {
    # Prepare a mock log file for testing
    $scriptRoot = Split-Path -Parent $MyInvocation.MyCommand.Definition
    $testLogContent = @"
U-Boot 1.1.4
Board: example_board
DDR:   128 MB
Flash: 16 MB
nvram:
bootflags=1
model=TEST_MODEL
"@

    # Create a temporary raw log file
    $tempDir = Join-Path $scriptRoot "temp_test"
    $testLogPath = Join-Path $tempDir "test-bootlog.log"
    $outDir = Join-Path $scriptRoot "temp_output"

    BeforeAll {
        if (-not (Test-Path $tempDir)) { New-Item -ItemType Directory -Path $tempDir -Force | Out-Null }
        if (-not (Test-Path $outDir)) { New-Item -ItemType Directory -Path $outDir -Force | Out-Null }
        $testLogContent | Out-File $testLogPath -Encoding UTF8 -Force
        . (Join-Path $scriptRoot "parsers.ps1")
    }

    AfterAll {
        Remove-Item $tempDir -Recurse -Force
        Remove-Item $outDir -Recurse -Force
    }

    It "Should extract basic hardware info correctly" {
        Parse-BootLog -LogPath $testLogPath -OutDir $outDir

        $outputFile = Join-Path $outDir "example_board-profile.json"
        $profile = Get-Content $outputFile | ConvertFrom-Json

        $profile.deviceName | Should Be "example_board"
        $profile.memory | Should Be "128 MB"
        $profile.flash | Should Be "16 MB"
    }

    It "Should extract nvram variables correctly" {
        Parse-BootLog -LogPath $testLogPath -OutDir $outDir

        $outputFile = Join-Path $outDir "example_board-profile.json"
        $profile = Get-Content $outputFile | ConvertFrom-Json

        $profile.nvramEntries.bootflags | Should Be "1"
        $profile.nvramEntries.model | Should Be "TEST_MODEL"
    }
}
'@
#endregion
#endregion
#==================================================================#
#region * Project Structure Definition and File Content *
#==================================================================#
$structure = @{
    #region -- .gitmodules --
    ".gitmodules" = @'
[submodule "dd-wrt"]
    path = dd-wrt
    url = <DD-WRT-FORK-URL>
    branch = master
'@
    #endregion
    #region -- .gitignore --
    ".gitignore" = @'
# Generated outputs (should not be committed)
/4_build_outputs/
/dd-wrt/build/*
/dd-wrt/dl/*
# IDE/OS files
.vscode/
.DS_Store
# Submodule is tracked but not committed directly
dd-wrt/
!dd-wrt/
'@
    #endregion
    #region -- README.md --
    "README.md" = @'
# DD-WRT Pipeline Project

This repository manages the entire lifecycle for a specific DD-WRT target device:
1. **1_device_data**: Immutable raw captures (bootlogs, nvram blobs).
2. **2_scripts**: The processing pipeline (parsers, mappers, generators, build wrappers).
3. **3_build_artifacts**: Generated configuration files (profiles, patches, manifests) checked into the repository.
4. **4_build_outputs**: Firmware images, build logs, and temporary artifacts (ignored by Git).
5. **5_validation**: Unit tests and firmware integrity checks.

## Getting Started

1. **Initialize Submodule:** `git submodule update --init --recursive`
2. **Review Mappings:** Update `2_scripts/mappers/device-to-target-map.yaml`.
3. **Ingest Data:** Use `2_scripts/ingest/ingest-run.ps1` to capture and generate an initial profile.
'@
    #endregion
    #region -- dd-wrt --
    "dd-wrt" = @{ # Submodule dir
        ".keep" = "" # Placeholder to ensure directory creation
    }
    #endregion

    #region ----- 1_device_data -----
    "1_device_data" = @{
        #region --- 1_device_data/README.md ---
        "README.md" = @'
# 1_device_data: Immutable Raw Captures

**Purpose:** Store immutable, raw data captured from target devices.
**Structure:** One folder per device, named using a convention like `vendor-model-sn-###`.
**Retention:** This data should be retained indefinitely as the source of truth.
**Redaction:** Ensure sensitive data (e.g., PSKs, serial numbers) is properly managed.
'@
        #endregion
        #region --- 1_device_data/netgear-r7000-sn-123 ---
        "netgear-r7000-sn-123" = @{ # Example dir
            "bootlog_2025-10-25T09-12-33Z.log" = "# Example boot log content"
            "nvram.bin" = "# Example binary nvram blob"
            "nvram.ascii" = "# Example ASCII nvram content"
        }
        #endregion
    }
    #endregion

    #region ----- 2_scripts -----
    "2_scripts" = @{
        #region --- 2_scripts/ingest/collect-bootlog.ps1 ---
        "ingest/collect-bootlog.ps1" = @'
<#
  .SYNOPSIS
    Capture device serial (UART) bootlog and optional SSH-collected logs.
  .DESCRIPTION
    Captures full serial console from power-on, saves raw and cleaned copies, runs strings extraction,
    and optionally connects via SSH to pull dmesg/journal and merges logs.
    Designed for Windows 11 PowerShell 7+.
  .PARAMETER ComPort
    COM port for UART capture (e.g. COM5). If omitted, UART capture is skipped.
  .PARAMETER BaudRate
    Baud rate for serial capture. Default 115200.
  .PARAMETER SshHost
    Optional SSH host (ip or hostname) to pull later-stage logs.
  .PARAMETER SshUser
    SSH username for remote collection (key-based auth recommended).
  .PARAMETER OutDir
    Output directory for saved files. If omitted, a timestamped folder under ./ingest/ is created.
  .PARAMETER TimeoutSeconds
    Max seconds to capture before auto-stop. Default 300 (5 minutes).
  .PARAMETER KernelMatch
    Regex pattern to look for to detect kernel boot finished and stop capture. Default matches "Kernel panic|Linux version|Kernel command line|Booting Linux".
  .EXAMPLE
    .\collect-bootlog.ps1 -ComPort COM5 -BaudRate 115200 -OutDir .\ingest\device1 -SshHost 192.168.1.100 -SshUser root
#>
param(
    [string]$ComPort = $null,
    [int]$BaudRate = 115200,
    [string]$SshHost = $null,
    [string]$SshUser = 'root',
    [string]$OutDir = $null,
    [int]$TimeoutSeconds = 300,
    [string]$KernelMatch = 'Kernel panic|Linux version|Kernel command line|Booting Linux'
)

Set-StrictMode -Version Latest

function New-IngestFolder {
    param([string]$base = '.\ingest')
    $ts = Get-Date -Format 'yyyyMMdd_HHmmss'
    $dir = Join-Path $base "$($env:COMPUTERNAME)_$ts"
    New-Item -ItemType Directory -Path $dir -Force | Out-Null
    return (Resolve-Path $dir).Path
}

if (-not $OutDir) { $OutDir = New-IngestFolder }

# Serial capture
$serialLog = Join-Path $OutDir "bootlog.raw.txt"
$serialStrings = Join-Path $OutDir "bootlog.strings.txt"
$serialClean = Join-Path $OutDir "bootlog.cleaned.txt"

if ($ComPort) {
    Write-Host "[+] Starting UART capture on $ComPort @ $BaudRate -> $serialLog"
    try {
        $port = new-Object System.IO.Ports.SerialPort $ComPort, $BaudRate, "None", 8, [System.IO.Ports.StopBits]::One
        $port.ReadTimeout = 1000
        $port.Open()

        $sw = [System.IO.File]::OpenWrite($serialLog)
        $writer = New-Object System.IO.StreamWriter($sw)
        $writer.AutoFlush = $true

        $start = Get-Date
        $matchedKernel = $false

        while ((Get-Date) -lt $start.AddSeconds($TimeoutSeconds)) {
            try {
                $line = $port.ReadLine()
            } catch {
                Start-Sleep -Milliseconds 50
                continue
            }
            $writer.WriteLine($line)

            if (-not $matchedKernel) {
                if ($line -match $KernelMatch) {
                    Write-Host "[+] Kernel marker found, stopping UART capture."
                    $matchedKernel = $true
                    break
                }
            }
        }

        $writer.Close()
        $port.Close()
    } catch {
        Write-Warning "UART capture failed: $_"
    }
} else {
    Write-Host "[-] No ComPort provided, skipping UART capture."
}

# SSH collection (later-stage logs)
$sshLog = Join-Path $OutDir "ssh.dmesg.txt"
if ($SshHost) {
    Write-Host "[+] Attempting SSH log collection from $SshHost"
    # Prefer native ssh if available
    $sshCmd = "ssh -o StrictHostKeyChecking=no $SshUser@$SshHost dmesg --ctime --kernel"
    try {
        $dmesg = & bash -c $sshCmd 2>&1
        if ($LASTEXITCODE -ne 0) { throw "ssh command failed: $dmesg" }
        $dmesg | Out-File -FilePath $sshLog -Encoding utf8
        Write-Host "[+] Saved SSH dmesg to $sshLog"
    } catch {
        Write-Warning "SSH dmesg failed: $_"
    }
} else {
    Write-Host "[-] No SshHost provided, skipping SSH collection."
}

# Post-process: strings and cleaning (basic UTF-8 sanitization)
if (Test-Path $serialLog) {
    Write-Host "[+] Extracting printable strings from serial log"
    Get-Content $serialLog -Raw |
      Select-String -Pattern '\p{C}' -NotMatch | Out-File -FilePath $serialClean -Encoding utf8

    # Use .NET regex to extract MAC-like and printable tokens as "strings"
    $content = Get-Content $serialLog -Raw
    $stringMatches = [regex]::Matches($content, "[\x20-\x7E]{4,}") | ForEach-Object { $_.Value }
    $stringMatches | Out-File -FilePath $serialStrings -Encoding utf8
}

# Merge SSH and serial into unified bootlog
$merged = Join-Path $OutDir "bootlog.merged.txt"
Get-ChildItem -Path $OutDir -Filter "bootlog*.txt" | Sort-Object Name | Get-Content | Out-File -FilePath $merged -Encoding utf8
Write-Host "[+] Merged bootlogs written to $merged"

# Summary
Write-Host "[+] Capture complete. Files in: $OutDir"
Write-Host "    - Raw serial: $serialLog"
Write-Host "    - Strings: $serialStrings"
Write-Host "    - Clean: $serialClean"
Write-Host "    - SSH dmesg: $sshLog"
Write-Host "    - Merged: $merged"
'@
        #endregion
        #region --- 2_scripts/ingest/collect-nvram.ps1 ---
        "ingest/collect-nvram.ps1" = @'
<#
  .SYNOPSIS
    Pull or ingest NVRAM blobs and produce secure+structured outputs.
  .DESCRIPTION
    Accepts any of: a local binary file, remote pull via SSH (nvram show or nvram -p), or a serial command to run nvram and capture output.
    Produces:
      - raw binary backup (if provided)
      - nvram.ascii (key=value lines)
      - nvram.json (structured key/value with metadata)
      - nvram.secure.json (same as nvram.json but with sensitive fields redacted; passwords and PSKs removed or masked)
  .PARAMETER InputFile
    Path to a provided nvram binary or ascii dump. If omitted, will attempt SSH or serial pull.
  .PARAMETER SshHost
    Optional SSH host to run `nvram show` or `nvram -p`.
  .PARAMETER SshUser
    SSH username.
  .PARAMETER ComPort
    Optional COM port to send a command to read nvram (operator must ensure device prompt and command availability).
  .PARAMETER OutDir
    Output directory.
  .EXAMPLE
    .\collect-nvram.ps1 -InputFile .\nvram.bin -OutDir .\ingest\device1
#>
param(
    [string]$InputFile = $null,
    [string]$SshHost = $null,
    [string]$SshUser = 'root',
    [string]$ComPort = $null,
    [string]$OutDir = $null
)

if (-not $OutDir) { $OutDir = (Get-Location).Path }
$nvramRaw = Join-Path $OutDir "nvram.raw.bin"
$nvramAscii = Join-Path $OutDir "nvram.ascii"
$nvramJson = Join-Path $OutDir "nvram.json"
$nvramSecure = Join-Path $OutDir "nvram.secure.json"

function Parse-KeyValueText {
    param([string]$text)
    $h = @{}
    $lines = $text -split "\r?\n"
    foreach ($l in $lines) {
        if ($l -match '^\s*#') { continue }
        if ($l -match '^(.*?)=(.*)$') {
            $k = $matches[1].Trim()
            $v = $matches[2].Trim()
            $h[$k] = $v
        }
    }
    return $h
}

# Acquire nvram source
if ($InputFile) {
    Write-Host "[+] Using provided NVRAM file: $InputFile"
    Copy-Item -Path $InputFile -Destination $nvramRaw -Force
    # Try to detect ascii vs binary
    $rawBytes = Get-Content -Path $nvramRaw -Encoding Byte -ReadCount 0
    $text = -join ([System.Text.Encoding]::UTF8.GetString($rawBytes) -split "\0")
    $kv = Parse-KeyValueText -text $text
    $kv.GetEnumerator() | ForEach-Object { "{0}={1}" -f $_.Key,$_.Value } | Out-File -FilePath $nvramAscii -Encoding utf8
} elseif ($SshHost) {
    Write-Host "[+] Pulling nvram via SSH from $SshHost"
    try {
        $cmd = "ssh -o StrictHostKeyChecking=no $SshUser@$SshHost nvram show"
        $out = & bash -c $cmd 2>&1
        $out | Out-File -FilePath $nvramAscii -Encoding utf8
        $kv = Parse-KeyValueText -text ($out -join "`n")
    } catch {
        Write-Warning "SSH nvram pull failed: $_"
        $kv = @{}
    }
} elseif ($ComPort) {
    Write-Host "[+] Attempting serial nvram pull on $ComPort (operator interaction may be required)"
    try {
        $port = new-Object System.IO.Ports.SerialPort $ComPort,115200,"None",8,[System.IO.Ports.StopBits]::One
        $port.ReadTimeout = 2000
        $port.Open()
        # Send nvram command (operator must ensure correct prompt and that 'nvram' exists)
        $port.WriteLine("nvram show")
        Start-Sleep -Milliseconds 200
        $buffer = New-Object System.Text.StringBuilder
        $end = Get-Date.AddSeconds((Get-Date),5)
        $stopAt = (Get-Date).AddSeconds(5)
        $start = Get-Date
        while ((Get-Date) -lt $start.AddSeconds(10)) {
            try { $line = $port.ReadLine(); $buffer.AppendLine($line) } catch { Start-Sleep -Milliseconds 100 }
        }
        $text = $buffer.ToString()
        $text | Out-File -FilePath $nvramAscii -Encoding utf8
        $kv = Parse-KeyValueText -text $text
        $port.Close()
    } catch {
        Write-Warning "Serial nvram pull failed: $_"
        $kv = @{}
    }
} else {
    Write-Warning "No source provided for NVRAM. Provide -InputFile or -SshHost or -ComPort."
    exit 1
}

# Save structured JSON
$meta = @{ collected_at = (Get-Date).ToString('o'); source = @() }
if ($InputFile) { $meta.source += @{type='file'; path=(Resolve-Path $InputFile).Path} }
if ($SshHost) { $meta.source += @{type='ssh'; host=$SshHost; user=$SshUser} }
if ($ComPort) { $meta.source += @{type='serial'; port=$ComPort} }

$profile = @{ metadata = $meta; nvram = $kv }
$profile | ConvertTo-Json -Depth 5 | Out-File -FilePath $nvramJson -Encoding utf8

# Secure redact: rules
$redactKeys = @('ssid','wpa_psk','wpa_passphrase','wpa_key','psk','password','passwd','key')
$secureKv = @{}
foreach ($k in $profile.nvram.Keys) {
    $lk = $k.ToLower()
    $v = $profile.nvram[$k]
    $isSensitive = $false
    foreach ($rk in $redactKeys) { if ($lk -like "*$rk*") { $isSensitive = $true; break } }
    if ($isSensitive) {
        $secureKv[$k] = 'REDACTED'
    } else {
        # Mask MAC addresses partially but keep last octet for identification
        if ($v -match '([0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}') {
            $secureKv[$k] = ($v -replace '([0-9A-Fa-f]{2}[:-]){4}([0-9A-Fa-f]{2}[:-])([0-9A-Fa-f]{2})','$1$2**')
        } else { $secureKv[$k] = $v }
    }
}
$secureProfile = @{ metadata = $meta; nvram = $secureKv }
$secureProfile | ConvertTo-Json -Depth 5 | Out-File -FilePath $nvramSecure -Encoding utf8

Write-Host "[+] NVRAM structured saved: $nvramJson"
Write-Host "[+] NVRAM secure copy saved: $nvramSecure"
Write-Host "[+] Raw ascii (if any): $nvramAscii"
'@
        #endregion
        #region --- 2_scripts/ingest/ingest-run.ps1 ---
        "ingest/ingest-run.ps1" = @'
<#
  .SYNOPSIS
    High-level ingest orchestration: runs bootlog and nvram collectors, runs string extraction, calls parser, and produces a preview JSON.
  .DESCRIPTION
    Orchestrates the ingest workflow for a device. Accepts parameters to collect both UART and SSH logs, pulls nvram securely, and then invokes parser scripts (parse/parsers.ps1) if available.
  .PARAMETER ComPort
  .PARAMETER SshHost
  .PARAMETER OutBase
  .PARAMETER DeviceName
#>
param(
    [string]$ComPort = $null,
    [int]$BaudRate = 115200,
    [string]$SshHost = $null,
    [string]$SshUser = 'root',
    [string]$OutBase = '.\ingest',
    [string]$DeviceName = $null
)

Set-StrictMode -Version Latest

if (-not $DeviceName) { $DeviceName = "$($SshHost -replace '[^a-zA-Z0-9]','')_$((Get-Date).ToString('yyyyMMdd_HHmmss'))" }
$outdir = Join-Path $OutBase $DeviceName
New-Item -ItemType Directory -Path $outdir -Force | Out-Null

Write-Host "[+] Ingest run starting for $DeviceName -> $outdir"

# Call bootlog collector
& "$PSScriptRoot\collect-bootlog.ps1" -ComPort $ComPort -BaudRate $BaudRate -SshHost $SshHost -SshUser $SshUser -OutDir $outdir

# Call nvram collector (secure+structured). Prefer SSH pull if SshHost provided
if ($SshHost) {
    & "$PSScriptRoot\collect-nvram.ps1" -SshHost $SshHost -SshUser $SshUser -OutDir $outdir
} elseif ($ComPort) {
    & "$PSScriptRoot\collect-nvram.ps1" -ComPort $ComPort -OutDir $outdir
} else {
    Write-Warning "No SshHost or ComPort: Please provide an input nvram file into $outdir and re-run collect-nvram.ps1 with -InputFile."
}

# Run parsers if available
$parsersRoot = Join-Path $PSScriptRoot '..\parsers'
$bootParserPath = Join-Path $parsersRoot 'Parse-DdWrtBootlog.ps1'
$nvramParserPath = Join-Path $parsersRoot 'Parse-DdWrtNvram.ps1'

$mergedBootlog = Join-Path $outdir 'bootlog.merged.txt'
$nvramSecureJson = Join-Path $outdir 'nvram.secure.json'

if (Test-Path $bootParserPath -and Test-Path $nvramParserPath) {
    Write-Host "[+] Invoking parsers..."

    # Dot source parsers
    . $bootParserPath
    . $nvramParserPath

    try {
        $bootResult = Parse-DdWrtBootlog -Path $mergedBootlog
        $nvResult = Parse-DdWrtNvram -Path $nvramSecureJson

        $preview = @{
            boot_summary = $bootResult;
            nvram_summary = @{ count = $nvResult.Keys.Count; keys = $nvResult.Keys.Keys }
        }
        $previewFile = Join-Path $outdir 'profile_preview.json'

        $preview | ConvertTo-Json -Depth 6 | Out-File -FilePath $previewFile -Encoding utf8
        Write-Host "[+] Preview generated: $previewFile"

    } catch {
        Write-Warning "Parser invocation failed: $_"
    }
} else {
    Write-Warning "Required parser scripts not found. Skipping parse stage."
}

Write-Host "[+] Ingest-run complete. Review files in $outdir"
'@
        #endregion
        #region --- 2_scripts/ingest/README.md ---
        "ingest/README.md" = @'
<## Ingest/ README

This folder contains the collection utilities for capturing bootlogs and NVRAM from target devices.

Files:
- collect-bootlog.ps1   - Capture UART and optionally SSH logs. Produces bootlog.raw.txt, bootlog.strings.txt, bootlog.cleaned.txt, ssh.dmesg.txt and bootlog.merged.txt
- collect-nvram.ps1     - Pulls NVRAM from file, SSH, or serial, produces nvram.ascii, nvram.json, nvram.secure.json
- ingest-run.ps1        - High-level orchestrator that runs the collectors and invokes parsers (parse/parsers.ps1) if available.

Usage examples:

1) UART-only capture and manual nvram file:
   .\ingest-run.ps1 -ComPort COM5 -DeviceName myrouter1

2) Full capture (UART + SSH) and automated nvram pull via SSH:
   .\ingest-run.ps1 -ComPort COM5 -SshHost 192.168.1.100 -SshUser root -DeviceName myrouter1

Notes & security:
- collect-nvram.ps1 creates a secure redacted JSON (nvram.secure.json) which masks sensitive keys (WiFi PSKs, passwords).
- Full raw copies are kept when an InputFile is provided; treat these as sensitive and store them in backups/ with restricted access.
- The scripts assume an operator is present for physical power-cycling to capture early boot if needed.
'@
        #endregion
        #region --- parsers/Parse-DdWrtBootlog.ps1 ---
        "parsers/Parse-DdWrtBootlog.ps1" = @'
<#
  .SYNOPSIS
    PowerShell parser for DD-WRT boot logs.
#>
function Parse-DdWrtBootlog {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Path
    )
    Write-Host "Parsing bootlog: $Path"
    # Placeholder: Actual implementation extracts hardware details, MACs, etc.
    return [PSCustomObject]@{
        Model = "R7000"
        SoC = "Broadcom BCM4709"
        FlashType = "NAND"
        MACs = @("00:11:22:33:44:55")
    }
}
'@
        #endregion
        #region --- parsers/Parse-DdWrtNvram.ps1 ---
        "parsers/Parse-DdWrtNvram.ps1" = @'
<#
  .SYNOPSIS
    PowerShell parser for DD-WRT NVRAM blobs.
#>
function Parse-DdWrtNvram {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Path
    )
    Write-Host "Parsing NVRAM ASCII: $Path"
    $pairs = @{}
    # Placeholder: Actual implementation reads and extracts key/value pairs
    # Note: This function now expects the secure JSON file created by collect-nvram.ps1
    try {
        $json = Get-Content -Path $Path | ConvertFrom-Json -ErrorAction Stop
        # The secure JSON structure is: { metadata: {}, nvram: {key: value, ...} }
        $pairs = $json.nvram
    } catch {
        Write-Warning "Could not load or parse NVRAM JSON: $_"
    }

    return [PSCustomObject]@{
        Keys = $pairs
        Count = $pairs.Count
    }
}
'@
        #endregion
        #region --- parsers/tests/parsers.sample.tests.ps1 ---
        "parsers/tests/parsers.sample.tests.ps1" = "# Pester tests for parsers, referencing sample_data"
        #endregion

        #region --- mappers/device-to-target-map.yaml ---
        "mappers/device-to-target-map.yaml" = @'
# Vendor/board → DD-WRT target mappings
# canonical mapping DB (single source of truth)
- model: "R7000"
  vendor: "netgear"
  ddwrt_targets:
    - "broadcom-r7000"
  hints:
    - "boardid=0x1234"
    - "productid=R7000"
'@
        #endregion
        #region --- mappers/Get-TargetMapping.ps1 ---
        "mappers/Get-TargetMapping.ps1" = @'
<#
  .SYNOPSIS
    Looks up a board profile against device-to-target-map.yaml to suggest DD-WRT targets.
#>
function Get-TargetMapping {
    # Placeholder logic
    param(
        [Parameter(Mandatory=$true)]
        [string]$Model
    )
    Write-Host "Mapping board profile to DD-WRT target for model '$Model'..."
    return @("broadcom-r7000")
}
'@
        #endregion

        #region --- generators/New-BoardProfileJson.ps1 ---
        "generators/New-BoardProfileJson.ps1" = @'
<#
  .SYNOPSIS
    Generates a canonical JSON profile from parsed bootlog and nvram data.
#>
function New-BoardProfileJson {
    param(
        [Parameter(Mandatory)]$BootData,
        [Parameter(Mandatory)]$NvramData, # Should be the key/value hashtable from the secure NVRAM
        [Parameter(Mandatory)]$DeviceName
    )
    $ProfilePath = Join-Path (Split-Path $PSScriptRoot -Parent) "3_build_artifacts\profiles\$($DeviceName).json"

    # Placeholder for Get-TargetMapping. We must dot-source it if we want to call it here.
    # . "$PSScriptRoot\..\mappers\Get-TargetMapping.ps1"

    $Profile = @{
        device = $DeviceName
        hardware = $BootData
        nvram_snapshot = $NvramData # Secure, redacted key/value pairs
        target = Get-TargetMapping -Model $BootData.Model # Using mappers function
    }
    $Profile | ConvertTo-Json -Depth 5 | Out-File $ProfilePath -Encoding utf8
    Write-Host "Generated profile: $ProfilePath"
}
'@
        #endregion
        #region --- generators/New-BoardPatch.ps1 ---
        "generators/New-BoardPatch.ps1" = @'
# Placeholder for patch generation script
# Accepts profile and generates diff/patch file in 3_build_artifacts/patches/
'@
        #endregion
        #region --- generators/New-BuildManifest.ps1 ---
        "generators/New-BuildManifest.ps1" = @'
# Placeholder for build manifest generation script
# Accepts profile, target, and patch to generate manifest in 3_build_artifacts/manifests/
'@
        #endregion

        #region --- build/build-helper.sh ---
        "build/build-helper.sh" = @'
#!/usr/bin/env bash
# DD-WRT Build Helper: Run inside the dd-wrt submodule directory
# Expects: $1 = MANIFEST_PATH (e.g., ../3_build_artifacts/manifests/r7000.yaml)
set -eo pipefail
MANIFEST_PATH="$1"
LOG_DIR="../../4_build_outputs/logs"
PATCH_DIR="../../3_build_artifacts/patches"

# 1. Read manifest for build variables (board, target, commit)
# ...

# 2. Apply patch
# patch -p1 < "$PATCH_DIR/${BOARD}-inject.patch"

# 3. Invoke DD-WRT build system
# make -C tools/config ...
# make -C src ...

echo "[+] Build completed. Logs in $LOG_DIR"
'@
        #endregion
        #region --- build/Invoke-DdWrtBuild.ps1 ---
        "build/Invoke-DdWrtBuild.ps1" = @'
<#
  .SYNOPSIS
    Invokes build-helper.sh, handling environment setup (e.g., WSL, Docker).
#>
param(
    [string]$ManifestPath
)
Write-Host "Invoking build for manifest: $ManifestPath"
# Implementation should call build-helper.sh, potentially inside WSL or container.
# e.g., wsl bash.exe "$PSScriptRoot\build\build-helper.sh" $ManifestPath
'@
        #endregion
    } # End 2_scripts
    #endregion

    #region ----- 3_build_artifacts -----
    "3_build_artifacts" = @{
        #region --- 3_build_artifacts/profiles/r7000.json ---
        "profiles/r7000.json" = @'
{
  "device": "netgear-r7000-sn-123",
  "hardware": { "Model": "R7000", "SoC": "Broadcom BCM4709" },
  "target": ["broadcom-r7000"]
}
'@
        #endregion
        #region --- 3_build_artifacts/patches/r7000-inject.patch ---
        "patches/r7000-inject.patch" = "# Placeholder: patch file for R7000 board configuration"
        #endregion
        #region --- 3_build_artifacts/manifests/r7000.yaml ---
        "manifests/r7000.yaml" = @'
repo_commit: "abc123def456"
target: "broadcom"
board: "r7000"
'@
        #endregion
    } # End 3_build_artifacts
    #endregion

    #region ----- 4_build_outputs -----
    "4_build_outputs" = @{
        #region --- 4_build_outputs/.gitignore ---
        ".gitignore" = @'
# Ignore all build outputs
*
!/.gitignore
/images/
/logs/
/artifacts/
'@
        #endregion
    } # End 4_build_outputs
    #endregion

    #region ----- 5_validation -----
    "5_validation" = @{
        #region --- 5_validation/tests/parsers.tests.ps1 ---
        "tests/parsers.tests.ps1" = @'
# Pester tests for 2_scripts/parsers/*.ps1
Describe "Parse-DdWrtBootlog" {
    # ... test cases ...
}
'@
        #endregion
        #region --- 5_validation/tests/generators.tests.ps1 ---
        "tests/generators.tests.ps1" = @'
# Pester tests for 2_scripts/generators/*.ps1
Describe "New-BoardProfileJson" {
    # ... test cases ...
}
'@
        #endregion
        #region --- 5_validation/sample_data/sample-nand-boot.log ---
        "sample_data/sample-nand-boot.log" = "# Fixture: Small, scrubbed NAND boot log"
        #endregion
        #region --- 5_validation/sample_data/sample-nor-nvram.ascii ---
        "sample_data/sample-nor-nvram.ascii" = "# Fixture: Small, scrubbed NOR NVRAM ASCII export"
        #endregion
        #region --- 5_validation/scripts/Test-FirmwareImage.ps1 ---
        "scripts/Test-FirmwareImage.ps1" = @'
<#
  .SYNOPSIS
    Checks image integrity (offsets, headers, signatures) post-build.
#>
param(
    [Parameter(Mandatory)]$ImagePath
)
Write-Host "Testing firmware image: $ImagePath"
# Implementation should verify headers, checksums, and potentially run QEMU smoke tests.
'@
        #endregion
    } # End 5_validation
    #endregion

    #region ----- docs -----
    "docs" = @{
        #region --- docs/add-new-device.md ---
        "add-new-device.md" = @'
# How to Onboard a New Device

1. **Capture Data:** Use `2_scripts/ingest/ingest-run.ps1` to get raw logs into `1_device_data/`.
2. **Review Profile:** Manually verify the generated JSON profile in `3_build_artifacts/profiles/`.
3. **Map Target:** Update `2_scripts/mappers/device-to-target-map.yaml`.
4. **Generate Artifacts:** Run the generator scripts to create the patch and manifest in `3_build_artifacts/`.
5. **Build & Test:** Use `2_scripts/build/Invoke-DdWrtBuild.ps1` and `5_validation/scripts/Test-FirmwareImage.ps1`.
'@
        #endregion
        #region --- docs/recovery-procedures/serial-unbrick-r7000.md ---
        "recovery-procedures/serial-unbrick-r7000.md" = "# Step-by-step serial recovery guide for R7000"
        #endregion
        #region --- docs/recovery-procedures/tftp-recovery.md ---
        "recovery-procedures/tftp-recovery.md" = "# General TFTP recovery guide"
        #endregion
        #region --- docs/test-plan.md ---
        "test-plan.md" = @'
# Hardware Smoke Test Plan

This document outlines the acceptance criteria for physical device testing (Minimal, Guided, Deep Test).
- Verify basic boot sequence.
- Confirm wireless functionality.
- Test NVRAM variables persistency.
'@
        #endregion
    } # End docs
    #endregion
    #region ----- tools -----
    "tools" = @{
        #region --- Menu.ps1 ---
        "Menu.ps1" = @'
<#
  .SYNOPSIS
    Centered interactive menu for ddwrt-pipeline.
  .DESCRIPTION
    Features
    - Centered box rendering that adapts to terminal size
    - Arrow keys / j/k navigation, Enter to execute, Esc/q to quit
    - Optional single-key shortcuts mapped to action hints
    - Themeable via tools/menu-theme.json or tools/themes/*.json
    - Actions execute synchronously and return to menu
    - Integrates tools/menu-config.json for defaults
#>

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# -----------------------------------------------
#region * Script root and config *
# -----------------------------------------------
$scriptRoot = Split-Path -Parent $MyInvocation.MyCommand.Definition
$configFile = Join-Path $scriptRoot "menu-config.json"
$themeFile = Join-Path $scriptRoot "menu-theme.json"
$themesDir = Join-Path $scriptRoot "themes"
$setThemeScript = Join-Path $scriptRoot "set-theme.ps1"

# Load config (best-effort)
$config = $null
if (Test-Path $configFile) {
  try { $config = Get-Content -Raw -Path $configFile | ConvertFrom-Json -ErrorAction Stop } catch { $config = $null }
}
if (-not $config) {
  $config = @{
    project = "ddwrt-pipeline"; defaultTheme = "dark"; defaultBoard = "netgear_wndr4500"
    editor = "notepad"; shell = "pwsh"
    build = @{ parallelism = 8; wslPreferred = $true; dryRunByDefault = $true; workDir = "build/work"; manifestsDir = "build/manifests" }
    ui = @{ themeFile = "tools/menu-theme.json"; themeDir = "tools/themes"; showHints = $true; singleKeyShortcuts = $true }
  }
}

$DefaultBoard = $config.defaultBoard
$Editor = $config.editor

#endregion
# -----------------------------------------------
#region * Default theme values *
# -----------------------------------------------
$defaultTheme = @{
  name = "dark"
  mode = "dark"
  boxWidth = "60%"
  borderStyle = "rounded"
  unicode = $true
  border = @{
    top = "─"; bottom = "─"; left = "│"; right = "│"
    cornerTL = "╭"; cornerTR = "╮"; cornerBL = "╰"; cornerBR = "╯"
  }
  accent = "Cyan"
  accentBright = "White"
  background = "Black"
  text = "White"
  muted = "DarkGray"
  selectedPrefix = "→ "
  hintStyle = "bracket"
  showHints = $true
  logo = " ddwrt-pipeline "
  padding = 1
  timestamp = $true
  singleKeyShortcuts = $true
  persistFile = "tools/menu-theme.json"
}

#endregion
# -----------------------------------------------
#region * Theme loader *
# -----------------------------------------------
$theme = $null
if (Test-Path $themeFile) {
  try { $theme = Get-Content -Raw -Path $themeFile | ConvertFrom-Json -ErrorAction Stop } catch { $theme = $null }
}
if (-not $theme) { $theme = $defaultTheme }

# Normalize missing keys
foreach ($k in $defaultTheme.Keys) {
  if (-not ($theme.PSObject.Properties.Name -contains $k)) { $theme | Add-Member -NotePropertyName $k -NotePropertyValue $defaultTheme[$k] }
}

function Map-ConsoleColor($name) {
  try { return [System.Enum]::Parse([System.ConsoleColor], $name, $true) } catch { return [System.ConsoleColor]::White }
}
$AccentColor = Map-ConsoleColor $theme.accent
$AccentBright = Map-ConsoleColor $theme.accentBright
$TextColor = Map-ConsoleColor $theme.text
$MutedColor = Map-ConsoleColor $theme.muted

#endregion
# -----------------------------------------------
#region * Menu actions - customize as needed *
# -----------------------------------------------
$actions = @(
  @{ key="ingest";   label="Run Ingest (collect + parse)"; action={ & (Join-Path $scriptRoot "ingest\ingest-run.ps1") } ; hint="I" }
  @{ key="parse";    label="Run Parsers (bootlog / nvram)"; action={ . (Join-Path $scriptRoot "parse\parsers.ps1"); $log = Get-ChildItem (Join-Path $scriptRoot 'profiles\raw') -Filter "bootlog-*.log" -ErrorAction SilentlyContinue | Sort-Object LastWriteTime -Descending | Select-Object -First 1; if ($log) { Parse-BootLog -LogPath $log.FullName -OutDir (Join-Path $scriptRoot 'profiles') } else { Write-Host "No bootlog found in profiles/raw" -ForegroundColor Yellow } } ; hint="P" }
  @{ key="build";    label="Start Build Helper (WSL recommended)"; action={ bash -c "cd `"$scriptRoot/build`" && ./build-helper.sh build/manifests/$($DefaultBoard).yaml" } ; hint="B" }
  @{ key="validate"; label="Validate latest image"; action={ $img = Get-ChildItem (Join-Path $scriptRoot 'build\work') -Recurse -Filter '*ddwrt*.bin' -ErrorAction SilentlyContinue | Sort-Object LastWriteTime -Descending | Select-Object -First 1; if ($img) { & (Join-Path $scriptRoot 'validation\validate-image.ps1') -ImagePath $img.FullName -Manifest (Join-Path $scriptRoot "build\manifests\$($DefaultBoard).yaml") -Mode "V2" } else { Write-Host "No image found under build/work" -ForegroundColor Yellow } } ; hint="V" }
  @{ key="smoke";    label="Open Smoke Test Plan (S1/S2/S3)"; action={ & $Editor (Join-Path $scriptRoot 'validation\smoke-test-plan.md') } ; hint="S" }
  @{ key="themes";   label="Switch theme"; action={ Invoke-ThemeSwitch } ; hint="T" }
  @{ key="config";   label="Open menu config"; action={ & $Editor (Join-Path $scriptRoot 'menu-config.json') } ; hint="C" }
  @{ key="quit";     label="Quit"; action={ } ; hint="Q" }
)

#endregion
# -----------------------------------------------
#region * Theme switch helper *
# -----------------------------------------------
function Invoke-ThemeSwitch {
  if (-not (Test-Path $themesDir)) { New-Item -ItemType Directory -Path $themesDir -Force | Out-Null }
  $themeFiles = Get-ChildItem -Path $themesDir -Filter '*.json' -ErrorAction SilentlyContinue
  if (-not $themeFiles) {
    Write-Host "No themes found in $themesDir. Use tools/set-theme.ps1 to create one." -ForegroundColor Yellow
    return
  }
  $names = $themeFiles | ForEach-Object { $_.BaseName }
  $choice = $host.UI.PromptForChoice("Theme switch", "Select a theme to apply", ($names), 0)
  $selected = $names[$choice]
  Copy-Item -Path (Join-Path $themesDir ("$selected.json")) -Destination (Join-Path $scriptRoot "menu-theme.json") -Force
  Write-Host "Switched theme to $selected. Restarting menu..." -ForegroundColor Green
  Start-Sleep -Milliseconds 300
  & $MyInvocation.MyCommand.Path
  Exit
}

#endregion
# -----------------------------------------------
#region * Rendering helpers *
# -----------------------------------------------
function Get-BoxWidth {
  $w = $Host.UI.RawUI.WindowSize.Width
  $bw = $theme.boxWidth.ToString()
  if ($bw -match '%$') {
    $pct = [int]($bw.TrimEnd('%'))
    return [Math]::Max(40, [int]([Math]::Floor($w * $pct / 100)))
  } else {
    return [int]$bw
  }
}

function ClearScreenArea { Clear-Host }

function Render-Line($text, [ConsoleColor]$fg = $null, [ConsoleColor]$bg = $null) {
  if ($null -ne $fg -and $null -ne $bg) { Write-Host $text -ForegroundColor $fg -BackgroundColor $bg -NoNewline; Write-Host "" } elseif ($null -ne $fg) { Write-Host $text -ForegroundColor $fg } else { Write-Host $text }
}

function Render-Menu([int]$selectedIndex) {
  $w = $Host.UI.RawUI.WindowSize.Width
  $h = $Host.UI.RawUI.WindowSize.Height
  $boxWidth = Get-BoxWidth
  $padLeft = [int](([Math]::Max(0, $w - $boxWidth)) / 2)
  $content = New-Object System.Collections.Generic.List[string]

  if ($theme.logo -and $theme.logo.Trim() -ne "") {
    $logoLines = $theme.logo -split "`n"
    foreach ($ln in $logoLines) { $content.Add($ln.Trim()) }
  }

  $content.Add("ddwrt-pipeline")
  $content.Add( ($theme.border.top * ([Math]::Max(2, $boxWidth - 2))) )

  for ($i=0; $i -lt $actions.Count; $i++) {
    $entry = $actions[$i]
    $label = $entry.label
    $hint = if ($theme.showHints -and $entry.hint) {
      switch ($theme.hintStyle) {
        "bracket" { " [" + $entry.hint + "]" }
        "inline"  { " - " + $entry.hint }
        default   { "" }
      }
    } else { "" }
    $prefix = if ($i -eq $selectedIndex) { $theme.selectedPrefix } else { "  " }
    $line = "$prefix$label$hint"
    $content.Add($line)
  }

  $content.Add( ($theme.border.bottom * ([Math]::Max(2, $boxWidth - 2))) )
  if ($theme.timestamp) { $content.Add(" " + (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")) }

  ClearScreenArea

  $verticalPad = [int]( ($h - $content.Count) / 2 )
  for ($r = 0; $r -lt $verticalPad; $r++) { Write-Host "" }

  foreach ($line in $content) {
    $lineTrim = $line
    if ($lineTrim.Length -gt $boxWidth) { $lineTrim = $lineTrim.Substring(0, $boxWidth - 3) + "..." }
    $leftPad = " " * $padLeft
    Write-Host -NoNewline $leftPad
    if ($lineTrim -eq "ddwrt-pipeline" -or ($theme.logo -and ($theme.logo -split "`n") -contains $lineTrim)) {
      Write-Host $lineTrim -ForegroundColor $AccentColor
      continue
    }

    if ($lineTrim.StartsWith($theme.selectedPrefix)) {
      $body = $lineTrim.Substring($theme.selectedPrefix.Length)
      Write-Host -NoNewline $theme.selectedPrefix -ForegroundColor $AccentBright
      Write-Host $body -ForegroundColor $AccentColor
    } elseif ($lineTrim -match "^\s*-{2,}\s*$") {
      Write-Host $lineTrim -ForegroundColor $MutedColor
    } else {
      Write-Host $lineTrim -ForegroundColor $TextColor
    }
  }

  for ($r = 0; $r -lt $verticalPad; $r++) { Write-Host "" }
}
#endregion
# -----------------------------------------------
#region * Input loop *
# -----------------------------------------------
function Run-Menu {
  $selected = 0
  $count = $actions.Count
  while ($true) {
    Render-Menu -selectedIndex $selected
    $key = [System.Console]::ReadKey($true)
    switch ($key.Key) {
      'UpArrow' { if ($selected -gt 0) { $selected-- } else { $selected = $count - 1 } ; continue }
      'DownArrow' { if ($selected -lt $count - 1) { $selected++ } else { $selected = 0 } ; continue }
      'J' { if ($selected -lt $count - 1) { $selected++ } else { $selected = 0 } ; continue }
      'K' { if ($selected -gt 0) { $selected-- } else { $selected = $count - 1 } ; continue }
      'Enter' {
        $entry = $actions[$selected]
        if ($entry.key -eq "quit") { break }
        Clear-Host
        Write-Host "Running: $($entry.label)" -ForegroundColor $AccentColor
        try {
          & $entry.action.Invoke()
        } catch {
          Write-Host "Action failed: $_" -ForegroundColor Red
        }
        Write-Host ""
        Write-Host "Press any key to return to menu..." -ForegroundColor $MutedColor
        [System.Console]::ReadKey($true) | Out-Null
        continue
      }
      'Escape' { break }
      default {
        if ($theme.singleKeyShortcuts) {
          $ch = $key.KeyChar.ToString().ToUpper()
          if ($ch) {
            $found = $actions | Where-Object { $_.hint -and $_.hint.ToString().ToUpper() -eq $ch }
            if ($found) {
              $entry = $found[0]
              if ($entry.key -eq "quit") { break }
              Clear-Host
              Write-Host "Running: $($entry.label)" -ForegroundColor $AccentColor
              try {
                & $entry.action.Invoke()
              } catch {
                Write-Host "Action failed: $_" -ForegroundColor Red
              }
              Write-Host ""
              Write-Host "Press any key to return to menu..." -ForegroundColor $MutedColor
              [System.Console]::ReadKey($true) | Out-Null
              continue
            }
          }
        }
        if ($key.KeyChar -in @('q','Q')) { break }
      }
    }
  }
  Clear-Host
  Write-Host "Exiting ddwrt-pipeline menu." -ForegroundColor $MutedColor
}

#endregion
# -----------------------------------------------
# Entrypoint
# -----------------------------------------------
try {
  Run-Menu
  exit 0
} catch {
  Write-Host "Menu encountered an error: $_" -ForegroundColor Red
  exit 1
}
'@
        #endregion
        #region --- menu.sh ---
        "menu.sh" = @'
#!/usr/bin/env bash
# tools/menu.sh
# Centered interactive menu for ddwrt-pipeline (WSL/Linux/macOS)
# Features:
# - Centered box rendering that adapts to terminal size
# - fzf picker preferred, falls back to pure-TTY numbered menu
# - Themeable via tools/menu-theme.json (requires jq) or defaults
# - Integrates tools/menu-config.json for defaults
# - Single-key shortcuts when using TTY fallback
# - Actions execute and return to menu
set -euo pipefail

# ---------- script / repo layout ----------
SCRIPT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
THEME_FILE="$SCRIPT_ROOT/menu-theme.json"
THEMES_DIR="$SCRIPT_ROOT/themes"
CONFIG_FILE="$SCRIPT_ROOT/menu-config.json"
SET_THEME_SH="$SCRIPT_ROOT/set-theme.sh"

# ---------- load config ----------
if command -v jq >/dev/null 2>&1 && [ -f "$CONFIG_FILE" ]; then
  DEFAULT_THEME=$(jq -r '.defaultTheme // "dark"' "$CONFIG_FILE")
  DEFAULT_BOARD=$(jq -r '.defaultBoard // "netgear_wndr4500"' "$CONFIG_FILE")
  EDITOR=$(jq -r '.editor // "nano"' "$CONFIG_FILE")
  BUILD_PARALLELISM=$(jq -r '.build.parallelism // 8' "$CONFIG_FILE")
  DRY_RUN_BY_DEFAULT=$(jq -r '.build.dryRunByDefault // true' "$CONFIG_FILE")
  ALLOW_MUTATE=false
  if jq -e '.safety.allowMutatingActions == true' "$CONFIG_FILE" >/dev/null 2>&1; then
    if [ "${DDWRT_PIPELINE_ALLOW_MUTATE:-0}" = "1" ]; then ALLOW_MUTATE=true; fi
  fi
else
  DEFAULT_THEME="dark"
  DEFAULT_BOARD="netgear_wndr4500"
  EDITOR="${EDITOR:-nano}"
  BUILD_PARALLELISM=8
  DRY_RUN_BY_DEFAULT=true
  ALLOW_MUTATE=false
fi

# ---------- load theme ----------
if command -v jq >/dev/null 2>&1 && [ -f "$THEME_FILE" ]; then
  UNICODE=$(jq -r '.unicode // true' "$THEME_FILE")
  BOX_WIDTH_RAW=$(jq -r '.boxWidth // "60%"' "$THEME_FILE")
  SHOW_HINTS=$(jq -r '.showHints // true' "$THEME_FILE")
  TIMESTAMP=$(jq -r '.timestamp // true' "$THEME_FILE")
  BORDER_STYLE=$(jq -r '.borderStyle // "rounded"' "$THEME_FILE")
  LOGO=$(jq -r '.logo // ""' "$THEME_FILE")
  ACCENT=$(jq -r '.accent // "cyan"' "$THEME_FILE")
  SINGLE_KEY_SHORTCUTS=$(jq -r '.singleKeyShortcuts // true' "$THEME_FILE")
else
  UNICODE=true
  BOX_WIDTH_RAW="60%"
  SHOW_HINTS=true
  TIMESTAMP=true
  BORDER_STYLE="rounded"
  LOGO=""
  ACCENT="cyan"
  SINGLE_KEY_SHORTCUTS=true
fi

# ---------- terminal dims ----------
COLUMNS=${COLUMNS:-$(tput cols 2>/dev/null || 80)}
LINES=${LINES:-$(tput lines 2>/dev/null || 24)}

# ---------- compute box width ----------
if [[ "$BOX_WIDTH_RAW" == *% ]]; then
  PCT=${BOX_WIDTH_RAW%\%}
  BOX_WIDTH=$(( COLUMNS * PCT / 100 ))
else
  BOX_WIDTH=$BOX_WIDTH_RAW
fi
BOX_WIDTH=$(( BOX_WIDTH < 40 ? 40 : BOX_WIDTH > COLUMNS-2 ? COLUMNS-2 : BOX_WIDTH ))

# ---------- color helpers ----------
tput_color() {
  case "${1,,}" in
    black) echo "$(tput setaf 0)" ;;
    red) echo "$(tput setaf 1)" ;;
    green) echo "$(tput setaf 2)" ;;
    yellow) echo "$(tput setaf 3)" ;;
    blue) echo "$(tput setaf 4)" ;;
    magenta) echo "$(tput setaf 5)" ;;
    cyan) echo "$(tput setaf 6)" ;;
    white) echo "$(tput setaf 7)" ;;
    *) echo "" ;;
  esac
}
COLOR_ACCENT="$(tput_color "$ACCENT")"
COLOR_RESET="$(tput sgr0)"

# ---------- border glyphs ----------
if [ "$UNICODE" = "true" ] || [ "$UNICODE" = "True" ]; then
  case "$BORDER_STYLE" in
    rounded) TL="╭"; TR="╮"; BL="╰"; BR="╯"; H="─"; V="│" ;;
    double)  TL="╔"; TR="╗"; BL="╚"; BR="╝"; H="═"; V="║" ;;
    ascii)   TL="+"; TR="+"; BL="+"; BR="+"; H="-"; V="|" ;;
    *)       TL="+"; TR="+"; BL="+"; BR="+"; H="-"; V="|" ;;
  esac
else
  TL="+"; TR="+"; BL="+"; BR="+"; H="-"; V="|"
fi

# ---------- menu items ----------
MENU_ITEMS=(
  "Run Ingest (collect + parse)|pwsh \"$SCRIPT_ROOT/ingest/ingest-run.ps1\"|I"
  "Run Parsers (bootlog / nvram)|pwsh -c '. \"$SCRIPT_ROOT/parse/parsers.ps1\"; Parse-BootLog -LogPath \"$SCRIPT_ROOT/profiles/raw/bootlog-*.log\" -OutDir \"$SCRIPT_ROOT/profiles\"'|P"
  "Start Build Helper (WSL recommended)|bash -lc 'cd \"$SCRIPT_ROOT/build\" && ./build-helper.sh build/manifests/$DEFAULT_BOARD.yaml'|B"
  "Validate latest image|pwsh -c '\$img = Get-ChildItem \"$SCRIPT_ROOT/build/work\" -Recurse -Filter \"*ddwrt*.bin\" -ErrorAction SilentlyContinue | Sort-Object LastWriteTime -Descending | Select-Object -First 1; if (\$img) { & \"$SCRIPT_ROOT/validation/validate-image.ps1\" -ImagePath \$img.FullName -Manifest \"$SCRIPT_ROOT/build/manifests/$DEFAULT_BOARD.yaml\" -Mode ${DDWRT_VALIDATION_MODE:-V2} } else { Write-Host \"No image found under build/work\" }'|V"
  "Open Smoke Test Plan|$EDITOR \"$SCRIPT_ROOT/validation/smoke-test-plan.md\"|S"
  "Switch theme|bash \"$SET_THEME_SH\" --list && read -rp 'Theme name or path: ' t && bash \"$SET_THEME_SH\" \"\$t\" || true|T"
  "Open config (menu-config.json)|$EDITOR \"$CONFIG_FILE\"|C"
  "Quit|exit 0|Q"
)

# ---------- helpers ----------
_center_pad() {
  local text="$1"
  local pad=$(( (COLUMNS - ${#text}) / 2 ))
  [ $pad -lt 0 ] && pad=0
  printf "%*s" $pad ""
}

clear_screen() { printf "\033c"; }

# ---------- render primitives ----------
draw_horizontal_line() {
  local n=$(( BOX_WIDTH - 2 ))
  printf "%s" "$H"
  for ((i=0;i<n;i++)); do printf "%s" "$H"; done
  printf "%s" "$H"
}

draw_box_title() {
  local title="$1"
  _center_pad ""
  printf "%s" "$TL"
  for ((i=0;i<BOX_WIDTH-2;i++)); do printf "%s" "$H"; done
  printf "%s\n" "$TR"
  _center_pad ""
  printf "%s" "$V"
  local padding=$(( (BOX_WIDTH - 2 - ${#title}) / 2 ))
  printf "%*s%s%*s" $padding "" "$COLOR_ACCENT$title$COLOR_RESET" $(( BOX_WIDTH - 2 - padding - ${#title} )) ""
  printf "%s\n" "$V"
  _center_pad ""
  printf "%s" "$V"
  for ((i=0;i<BOX_WIDTH-2;i++)); do printf " "; done
  printf "%s\n" "$V"
}

draw_box_footer() {
  _center_pad ""
  printf "%s" "$BL"
  for ((i=0;i<BOX_WIDTH-2;i++)); do printf "%s" "$H"; done
  printf "%s\n" "$BR"
}

render_menu_list() {
  local selected=${1:-0}
  local i=0
  for item in "${MENU_ITEMS[@]}"; do
    IFS='|' read -r label cmd hint <<< "$item"
    local prefix="  "
    if [ "$i" -eq "$selected" ]; then
      prefix="> "
    fi
    local line="${prefix}${label}"
    if [ ${#line} -gt $((BOX_WIDTH-8)) ]; then
      line="${line:0:$((BOX_WIDTH-11))}..."
    fi
    _center_pad ""
    printf "%s" "$V "
    if [ "$i" -eq "$selected" ]; then
      printf "%s" "$COLOR_ACCENT$line$COLOR_RESET"
      if [ "$SHOW_HINTS" = "true" ] && [ -n "$hint" ]; then
        printf "%*s" $((BOX_WIDTH - 6 - ${#line})) ""
        printf "%s" " [$hint]"
      fi
    else
      printf "%s" "$line"
      if [ "$SHOW_HINTS" = "true" ] && [ -n "$hint" ]; then
        printf "%*s" $((BOX_WIDTH - 6 - ${#line})) ""
        printf "%s" " [$hint]"
      fi
    fi
    printf "%s\n" " $V"
    ((i++))
  done
}

# ---------- interactive modes ----------
if command -v fzf >/dev/null 2>&1; then
  while true; do
    choices=()
    for item in "${MENU_ITEMS[@]}"; do
      IFS='|' read -r label cmd hint <<< "$item"
      if [ "$SHOW_HINTS" = "true" ] && [ -n "$hint" ]; then
        choices+=("$label [$hint]")
      else
        choices+=("$label")
      fi
    done

    selected=$(printf '%s\n' "${choices[@]}" | fzf --height 40% --reverse --ansi --prompt="ddwrt-pipeline> ")
    [ -z "$selected" ] && exit 0

    idx=0
    for item in "${MENU_ITEMS[@]}"; do
      IFS='|' read -r label cmd hint <<< "$item"
      display="$label"
      [ "$SHOW_HINTS" = "true" ] && [ -n "$hint" ] && display="$label [$hint]"
      if [ "$display" = "$selected" ]; then
        chosen_cmd="$cmd"
        break
      fi
      ((idx++))
    done

    clear
    echo -e "${COLOR_ACCENT}Running:${COLOR_RESET} ${choices[$idx]}"
    bash -lc "$chosen_cmd"
    read -n1 -r -p "Press any key to continue..."
    clear
  done
else
  if ! test -t 0; then
    echo "Non-interactive terminal; available commands:"
    for item in "${MENU_ITEMS[@]}"; do IFS='|' read -r label cmd hint <<< "$item"; echo "- $label"; done
    exit 0
  fi

  selected=0
  total=${#MENU_ITEMS[@]}
  while true; do
    clear_screen
    if [ -n "$LOGO" ]; then
      _center_pad ""
      echo "$LOGO"
    fi
    draw_box_title "ddwrt-pipeline"
    render_menu_list "$selected"
    draw_box_footer
    if [ "$TIMESTAMP" = "true" ]; then
      _center_pad ""
      printf "%s\n" " $(date '+%Y-%m-%d %H:%M:%S')"
    fi

    IFS= read -rsn1 key 2>/dev/null || { read -rsn1 key; }
    case "$key" in
      $'\x1b')
        read -rsn2 -t 0.001 rest 2>/dev/null || true
        case "$rest" in
          '[A') selected=$(( (selected - 1 + total) % total )) ;;
          '[B') selected=$(( (selected + 1) % total )) ;;
        esac
        ;;
      '') # Enter
        IFS='|' read -r label cmd hint <<< "${MENU_ITEMS[$selected]}"
        clear
        echo -e "${COLOR_ACCENT}Running:${COLOR_RESET} $label"
        bash -lc "$cmd"
        read -n1 -r -p "Press any key to continue..."
        ;;
      k|K) selected=$(( (selected - 1 + total) % total )) ;;
      j|J) selected=$(( (selected + 1) % total )) ;;
      q|Q) clear; exit 0 ;;
      *)
        if [ "$SINGLE_KEY_SHORTCUTS" = "true" ]; then
          ch="${key^^}"
          found=false
          idx=0
          for item in "${MENU_ITEMS[@]}"; do
            IFS='|' read -r label cmd hint <<< "$item"
            if [ -n "${hint:-}" ] && [ "${hint^^}" = "$ch" ]; then
              found=true
              break
            fi
            ((idx++))
          done
          if [ "$found" = true ]; then
            IFS='|' read -r label cmd hint <<< "${MENU_ITEMS[$idx]}"
            clear
            echo -e "${COLOR_ACCENT}Running:${COLOR_RESET} $label"
            bash -lc "$cmd"
            read -n1 -r -p "Press any key to continue..."
          fi
        fi
        ;;
    esac
  done
fi
'@
        #endregion
        #region --- menu-config.json ---
        "menu-config.json" = @'
{
  "project": "ddwrt-pipeline",
  "defaultTheme": "dark",
  "defaultBoard": "netgear_wndr4500",
  "repoRoot": ".",
  "editor": "notepad",
  "shell": "pwsh",
  "build": {
    "parallelism": 8,
    "wslPreferred": true,
    "dryRunByDefault": true,
    "workDir": "build/work",
    "manifestsDir": "build/manifests"
  },
  "artifacts": {
    "profilesDir": "profiles",
    "rawDir": "profiles/raw",
    "patchesDir": "patches",
    "imagesDir": "build/work/output",
    "validationReportsDir": "build/validation"
  },
  "validation": {
    "defaultMode": "V2",
    "strictModeOnRelease": "V3",
    "allowedModes": ["V1","V2","V3"]
  },
  "smokeTest": {
    "defaultLevel": "S2",
    "allowedLevels": ["S1","S2","S3"]
  },
  "serial": {
    "defaultBaud": 115200,
    "autoDetectPorts": true,
    "serialCaptureTimeoutSec": 300
  },
  "safety": {
    "allowMutatingActions": false,
    "mutateEnvVar": "DDWRT_PIPELINE_ALLOW_MUTATE"
  },
  "ui": {
    "themeFile": "tools/menu-theme.json",
    "themeDir": "tools/themes",
    "showHints": true,
    "singleKeyShortcuts": true
  },
  "logging": {
    "level": "info",
    "retainReportsDays": 90
  },
  "backups": {
    "firmwareBackupDir": "backups/firmware",
    "keepLocalCopies": true
  }
}
'@
        #endregion
        #region --- set-theme.ps1 ---
        "set-theme.ps1" = @'
<#
  Usage: .\tools\set-theme.ps1 dark
        .\tools\set-theme.ps1 C:\path\to\custom.json
  Applies theme to tools/menu-theme.json (creates or overwrites).
#>
param(
  [Parameter(Mandatory)][string] $Theme
)

$scriptRoot = Split-Path -Parent $MyInvocation.MyCommand.Definition
$themesDir = Join-Path $scriptRoot "themes"
$target = Join-Path $scriptRoot "menu-theme.json"

if (Test-Path $Theme) {
  Copy-Item -Path $Theme -Destination $target -Force
  Write-Output "Applied theme from $Theme"
  exit 0
}

$candidate = Join-Path $themesDir ($Theme + ".json")
if (Test-Path $candidate) {
  Copy-Item -Path $candidate -Destination $target -Force
  Write-Output "Switched theme to '$Theme'"
  exit 0
}

Write-Error "Theme not found: $Theme"
exit 1
'@
        #endregion
        #region --- set-theme.sh ---
        "set-theme.sh" = @'
#!/usr/bin/env bash
# tools/set-theme.sh
# Usage: ./tools/set-theme.sh dark|light|retro OR ./tools/set-theme.sh path/to/theme.json
set -euo pipefail
THEME_DIR="$(cd "$(dirname "$0")" && pwd)/themes"
TARGET="./tools/menu-theme.json"

if [ $# -ne 1 ]; then
  echo "Usage: $(basename $0) <theme-name|path-to-json>"
  echo "Available:" $(ls "$THEME_DIR" | sed -e 's/.json//g')
  exit 2
fi

ARG="$1"
if [ -f "$ARG" ]; then
  cp -f "$ARG" "$TARGET"
  echo "Applied theme from $ARG"
  exit 0
fi

CAND="$THEME_DIR/$ARG.json"
if [ -f "$CAND" ]; then
  cp -f "$CAND" "$TARGET"
  echo "Switched theme to '$ARG'"
  exit 0
fi

echo "Theme not found: $ARG" >&2
exit 3
'@
        #endregion
        #region --- themes Directory ---
        "themes" = @{
            #region ---- dark.json ----
            "dark.json" = @'
{
  "name": "dark",
  "mode": "dark",
  "boxWidth": "60%",
  "borderStyle": "rounded",
  "unicode": true,
  "border": { "top": "─", "bottom": "─", "left": "│", "right": "│", "cornerTL": "╭", "cornerTR": "╮", "cornerBL": "╰", "cornerBR": "╯" },
  "accent": "Cyan",
  "accentBright": "White",
  "background": "Black",
  "text": "White",
  "muted": "DarkGray",
  "selectedPrefix": "→ ",
  "hintStyle": "bracket",
  "showHints": true,
  "logo": " ddwrt-pipeline ",
  "padding": 1,
  "timestamp": true,
  "singleKeyShortcuts": true,
  "persistFile": "tools/menu-theme.json"
}
'@
            #endregion
            #region ---- light.json ----
            "light.json" = @'
{
  "name": "light",
  "mode": "light",
  "boxWidth": 80,
  "borderStyle": "single",
  "unicode": false,
  "border": { "top": "-", "bottom": "-", "left": "|", "right": "|" },
  "accent": "Blue",
  "accentBright": "Black",
  "background": "White",
  "text": "Black",
  "muted": "DarkGray",
  "selectedPrefix": ">> ",
  "hintStyle": "inline",
  "showHints": true,
  "logo": "DD-WRT",
  "padding": 0,
  "timestamp": false,
  "singleKeyShortcuts": true,
  "persistFile": "tools/menu-theme.json"
}
'@
            #endregion
            #region ---- retro.json ----
            "retro.json" = @'
{
  "name": "retro",
  "mode": "dark",
  "boxWidth": 72,
  "borderStyle": "ascii",
  "unicode": false,
  "border": { "top": "=", "bottom": "=", "left": "|", "right": "|" },
  "accent": "Yellow",
  "accentBright": "Magenta",
  "background": "Black",
  "text": "LightGray",
  "muted": "DarkGray",
  "selectedPrefix": "=> ",
  "hintStyle": "none",
  "showHints": false,
  "logo": "==== ddwrt-pipeline ====",
  "padding": 1,
  "timestamp": true,
  "singleKeyShortcuts": false,
  "persistFile": "tools/menu-theme.json"
}
'@
            #endregion
        }
        #endregion
        #region --- string-extract.ps1 ---
        "string-extract.ps1" = @'
# minimal helper for extracting tokens by regex
param([string]$File, [string]$Pattern)
Select-String -Path $File -Pattern $Pattern | ForEach-Object { $_.Matches } | ForEach-Object { $_.Value }
'@
        #endregion
        #region --- README.md ---
        "README.md" = @'
# tools
Utilities used across pipeline: string-extract helpers, binwalk wrappers, formatters.
'@
        #endregion
    }
    #endregion
}
#endregion
#==================================================================#
#region * Execution *
#==================================================================#
try {
    Write-Host "Starting DD-WRT Scaffold Creation..." -ForegroundColor Yellow

    # 1. Generate the initial plan
    $plan = Private:Get-ScaffoldPlan -Root $RootPath

    # Use ShouldProcess only for WhatIf check
    if (-not $PSCmdlet.ShouldProcess("Scaffold project in '$RootPath'", "New-DDWRTScaffold")) {
        Write-Host "Dry-run mode: no files were written." -ForegroundColor Cyan
        exit
    }

    # --- PRE-EXECUTION INTERACTION ---

    # Determine if user wants to see the plan (skip interactive prompt if -WhatIf is used)
    if ($PSCmdlet.MyInvocation.BoundParameters.ContainsKey('WhatIf')) {
        Write-Host "WhatIf parameter used. Displaying planned actions (no files will be written)." -ForegroundColor Gray
        $showPlan = $true
    } else {
        $showPlan = (Read-Host "Do you want to preview the project structure and planned actions? (y/n)") -eq 'y'
    }

    if ($showPlan) {
        Private:Format-StatusList -Plan $plan -PreExecution $true -RootPath $RootPath
    }

    # Ask for final confirmation to proceed (only if not WhatIf)
    if (-not $PSCmdlet.MyInvocation.BoundParameters.ContainsKey('WhatIf')) {
        $confirm = (Read-Host "Are you sure you want to continue with scaffold creation? (y/n)") -eq 'y'
        if (-not $confirm) {
            Write-Host "Operation cancelled by user." -ForegroundColor Red
            exit
        }
    }

    # --- EXECUTION ---

    Write-Host "Executing scaffold creation..." -ForegroundColor Yellow

    # Iterate through the plan and perform actions
    for ($i = 0; $i -lt $plan.Count; $i++) {
        $item = $plan[$i]

        $result = $null

        if ($item.Type -eq 'Directory') {
            $result = Private:Ensure-ScaffoldPath -Dir $item.Path -Force $Force
        } elseif ($item.Type -eq 'File') {
            $result = Private:Write-FileIfMissing -Path $item.Path -Content $item.Content -Force $Force
        }

        # Update the final status
        $plan[$i].FinalStatus = $result
    }

    # Post-creation advice manifest (Overwrites the README.md)
    # Find the README item in the plan and update its content
    $readmeItem = $plan | Where-Object { $_.Path.EndsWith("README.md") }
    if ($readmeItem) {
        $adviceContent = @'
# NEXT STEPS
- Fill mappings-db.yaml with vendor/board -> ddwrt-target entries.
- Implement serial capture in collect-bootlog.ps1 as needed (powershell serial modules or external tools).
- Replace placeholders in build-helper.sh with the actual clone/apply/build sequence; prefer running inside WSL2 or Linux.
- Add Pester module to CI for tests/; run `Invoke-Pester` in parse/tests.
- Configure default settings in **tools/menu-config.json**.
- Run the interactive menu using **tools/Menu.ps1** (PowerShell) or **tools/menu.sh** (Linux/WSL).
'@
        # Perform the overwrite and update status
        $result = Private:Write-FileIfMissing -Path $readmeItem.Path -Content $adviceContent -Force $true
        $readmeItem.FinalStatus = $result # Update final status of README overwrite
    }

    # --- POST-EXECUTION SUMMARY ---

    Write-Host "----------------------------------------------------" -ForegroundColor Yellow
    Write-Host "Scaffold creation complete!" -ForegroundColor Yellow

    # Show the final status list
    Private:Format-StatusList -Plan $plan -PreExecution $false -RootPath $RootPath

    # Check if the build-helper.sh needs executable permissions (only relevant in Linux/WSL)
    $helperPath = Join-Path $RootPath "build-helper.sh"
    if (Test-Path $helperPath) {
        Write-Host "NOTE: If you run this project on Linux/WSL, you may need to make the .sh files executable:" -ForegroundColor Magenta
        Write-Host "chmod +x $helperPath" -ForegroundColor Cyan
    }

} catch {
    Write-Error "An unexpected error occurred during scaffold creation: $($_.Exception.Message)"
}
#endregion
#==================================================================#
