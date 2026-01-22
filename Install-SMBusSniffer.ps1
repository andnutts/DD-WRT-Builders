# Install-SMBusSniffer.ps1
# Interactive helper for Windows SMBus/I2C sniffer setup and execution
# Run as Administrator

function Assert-Admin {
    if (-not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator)) {
        Write-Error "This script must be run as Administrator. Right-click PowerShell and choose Run as Administrator."
        exit 1
    }
}

function Get-SecureBootStatus {
    try {
        $sb = Confirm-SecureBootUEFI 2>$null
        if ($sb) { "SecureBoot: Enabled" } else { "SecureBoot: Disabled" }
    } catch {
        "SecureBoot: Unknown (UEFI API not available on this host)"
    }
}

function List-SMBusControllers {
    Write-Host "`nScanning for SMBus / I2C controllers..." -ForegroundColor Cyan
    # Common device name tokens: SMBus, I2C, i2c, SMB
    $tokens = @('SMBus','SMB','I2C','i2c','i801')
    $found = @()
    foreach ($t in $tokens) {
        $devs = Get-PnpDevice -Status OK -ErrorAction SilentlyContinue | Where-Object { $_.FriendlyName -like "*$t*" -or $_.InstanceId -like "*$t*" }
        if ($devs) { $found += $devs }
    }
    if ($found.Count -eq 0) {
        Write-Warning "No SMBus/I2C controllers detected by name tokens. Listing all System devices for manual inspection."
        Get-PnpDevice -Class System | Format-Table -AutoSize
    } else {
        $found | Select-Object InstanceId, FriendlyName, Manufacturer, Class | Format-Table -AutoSize
    }
}

function Download-SnifferPackage {
    param(
        [string]$Url,
        [string]$OutDir = "$env:USERPROFILE\Downloads\SMBusSniffer"
    )
    if (-not $Url) {
        Write-Host "No URL provided. Skipping download." -ForegroundColor Yellow
        return $null
    }
    New-Item -Path $OutDir -ItemType Directory -Force | Out-Null
    $fileName = Split-Path $Url -Leaf
    $outPath = Join-Path $OutDir $fileName
    Write-Host "Downloading $Url to $outPath ..." -ForegroundColor Cyan
    Invoke-WebRequest -Uri $Url -OutFile $outPath -UseBasicParsing
    Write-Host "Downloaded to: $outPath" -ForegroundColor Green
    return $outPath
}

function Unpack-IfZip {
    param([string]$ZipPath, [string]$Dest)
    if (-not $ZipPath) { return $null }
    if ($ZipPath -like "*.zip") {
        $Dest = $Dest ?? (Join-Path (Split-Path $ZipPath -Parent) (Split-Path $ZipPath -LeafBase))
        Write-Host "Extracting $ZipPath -> $Dest" -ForegroundColor Cyan
        Expand-Archive -Path $ZipPath -DestinationPath $Dest -Force
        return $Dest
    }
    return (Split-Path $ZipPath -Parent)
}

function Enable-TestSigning {
    Write-Warning "Enabling Windows test-signing mode will disable driver signature enforcement until you disable it again. This requires a reboot."
    $confirm = Read-Host "Type YES to enable test-signing and reboot now (anything else will cancel)"
    if ($confirm -ne 'YES') { Write-Host "Cancelled enabling test-signing."; return }
    bcdedit /set testsigning on
    Write-Host "Test-signing enabled. Reboot required. Reboot now? (Y/N)"
    $r = Read-Host
    if ($r -match '^[Yy]') {
        Restart-Computer
    } else {
        Write-Host "Remember to reboot before installing unsigned drivers."
    }
}

function Disable-TestSigning {
    Write-Host "Disabling test-signing and rebooting" -ForegroundColor Cyan
    bcdedit /set testsigning off
    Restart-Computer
}

function Run-Sniffer {
    param(
        [string]$ExePath,
        [int]$DurationSeconds = 60,
        [string]$OutDir = "$env:USERPROFILE\Desktop\SMBusCapture"
    )
    if (-not (Test-Path $ExePath)) {
        Write-Error "Sniffer executable not found at: $ExePath"
        return
    }
    New-Item -Path $OutDir -ItemType Directory -Force | Out-Null
    $timestamp = (Get-Date).ToString("yyyyMMdd-HHmmss")
    $log = Join-Path $OutDir "capture-$timestamp.log"
    Write-Host "Starting sniffer: $ExePath" -ForegroundColor Cyan
    Write-Host "Capturing for $DurationSeconds seconds. Output -> $log" -ForegroundColor Cyan
    $psi = New-Object System.Diagnostics.ProcessStartInfo
    $psi.FileName = $ExePath
    $psi.Arguments = "--capture --out `"$log`" --duration ${DurationSeconds}s"
    $psi.RedirectStandardOutput = $true
    $psi.RedirectStandardError  = $true
    $psi.UseShellExecute = $false
    $proc = [System.Diagnostics.Process]::Start($psi)
    $proc.WaitForExit($DurationSeconds*1000 + 5000)
    if (-not $proc.HasExited) {
        Write-Host "Capture exceeded timeout, attempting to stop process..." -ForegroundColor Yellow
        $proc.Kill()
    }
    Write-Host "Capture finished. Log: $log" -ForegroundColor Green
}
#endregion
# ==========================================
#region * Menu Options *
# ==========================================
$MenuOptions = @(
    [PSCustomObject]@{  Id      = '1';  Name = 'Detect SMBus/I2C controllers';  Enabled = $true
                        Key     = '1'
                        Help    = 'Scan PnP devices for SMBus/I2C controllers'
                        Type    = 'Action'
                        Action  = { List-SMBusControllers } }
    [PSCustomObject]@{  Id      = '2';  Name = 'Download sniffer package';      Enabled = $true
                        Key     = '2'
                        Help    = 'Download a sniffer zip or exe to Downloads'
                        Type    = 'Action'
                        Action  = {
                            $url = Read-Host "Enter download URL (example: https://example.com/sniffer.zip)"
                            if ($url) {
                                $zip = Download-SnifferPackage -Url $url
                                if ($zip) { $dest = Unpack-IfZip -ZipPath $zip; Write-Host "Package available at: $dest" -ForegroundColor Green }
                            } else { Write-Host "No URL supplied. Aborting." }
                        } }
    [PSCustomObject]@{  Id      = '3';  Name = 'Enable Windows test-signing';   Enabled = $true
                        Key     = '3'
                        Help    = 'Allow unsigned driver installs (requires reboot)'
                        Type    = 'Action'
                        Action  = { Enable-TestSigning } }
    [PSCustomObject]@{  Id      = '4';  Name = 'Run local sniffer executable';  Enabled = $true
                        Key     = '4'
                        Help    = 'Run a sniffer exe and capture to Desktop'
                        Type    = 'Action'
                        Action  = {
                            $exe = Read-Host "Enter full path to sniffer executable (eg: C:\tools\sniffer\sniffer.exe)"
                            if (-not (Test-Path $exe)) { Write-Warning "Executable not found: $exe"; return }
                            $dur = Read-Host "Capture duration seconds (default 60)"; if (-not [int]::TryParse($dur,[ref]$null)) { $dur = 60 }
                            Run-Sniffer -ExePath $exe -DurationSeconds $dur
                        } }
    [PSCustomObject]@{ Id       = 'Q';  Name = 'Quit Menu';                     Enabled = $true
                      Key     = 'Q'
                      Help    = 'Exit menu'
                      Type    = 'Meta'
                      Action  = { return 'quit' } }
)
#endregion

# ---------- Main interactive flow ----------
Clear-Host
Assert-Admin
Write-Host "Windows SMBus/I2C Sniffer helper" -ForegroundColor Magenta
Write-Host "Secure Boot status: $(Get-SecureBootStatus)"

List-SMBusControllers

Write-Host "`nChoose an action by number:" -ForegroundColor Cyan
Write-Host "1. Download and unpack sniffer package (edit URL when prompted)"
Write-Host "2. Run local sniffer executable and capture log"
Write-Host "3. Enable Windows test-signing (unsigned driver support) and optionally reboot"
Write-Host "4. Disable test-signing and reboot"
Write-Host "5. Exit"

$choice = Read-Host "Selection (1-5)"
switch ($choice) {
    '1' {
        $url = Read-Host "Enter download URL for sniffer package (zip or exe). Leave blank to cancel"
        if (-not $url) { Write-Host "Cancelled."; break }
        $zip = Download-SnifferPackage -Url $url
        $dest = Unpack-IfZip -ZipPath $zip
        Write-Host "Package available at: $dest" -ForegroundColor Green
        Write-Host "If the package contains a driver installer, follow vendor README to install drivers. This script does not auto-install kernel drivers." -ForegroundColor Yellow
    }
    '2' {
        $exe = Read-Host "Enter full path to sniffer executable (example: C:\tools\sniffer\sniffer.exe)"
        if (-not (Test-Path $exe)) {
            Write-Warning "Executable not found. Provide correct path or use option 1 to download a package."
            break
        }
        $dur = Read-Host "Duration in seconds (default 60)"
        if (-not [int]::TryParse($dur,[ref]$null)) { $dur = 60 }
        Run-Sniffer -ExePath $exe -DurationSeconds $dur
    }
    '3' { Enable-TestSigning }
    '4' { Disable-TestSigning }
    default { Write-Host "Exiting." }
}


$MenuOptions = @(
    [PSCustomObject]@{  Id      = '1';  Name = ''; Enabled = $true
                        Key     = ''
                        Help    = ''
                        Type    = ''
                        Action  = {  } }
    [PSCustomObject]@{  Id      = '';  Name = ''; Enabled = $true
                        Key     = ''
                        Help    = ''
                        Type    = ''
                        Action  = {  } }
    [PSCustomObject]@{  Id      = '';  Name = ''; Enabled = $true
                        Key     = ''
                        Help    = ''
                        Type    = ''
                        Action  = {  } }
    [PSCustomObject]@{  Id      = '';  Name = ''; Enabled = $true
                        Key     = ''
                        Help    = ''
                        Type    = ''
                        Action  = {  } }
    [PSCustomObject]@{ Id     = 'Q'; Name = 'Quit Menu';                        Enabled = $true
                      Key     = 'Q'
                      Help    = 'Exit menu'
                      Type    = 'Meta'
                      Action  = { return 'quit' } }
)
