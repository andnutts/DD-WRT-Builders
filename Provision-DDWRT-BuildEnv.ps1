# Ubuntu DD‑WRT build environment setup for Hyper-V or WSL2
#
# Hyper-V Mode: Creates VM, configures, sets up static MAC, and mounts a host SMB share.
# WSL2 Mode: Configures an existing WSL2 distribution (default Ubuntu) with necessary build tools and host folder access.
#
#==================================================================#
#region * Parameters *
[CmdletBinding()]
param(
    [switch]$DryRun,
    [ValidateSet('HyperV', 'WSL2')][string]$Environment, # Target environment: HyperV or WSL2
    [switch]$AutoProvision,        # if set, attempt automated provisioning via SSH (Hyper-V) or wsl (WSL2)
    [string]$SshUser = "builder",    # SSH user/Linux user to connect as
    [string]$SshHost = "",         # VM IP or hostname (Hyper-V only)
    [string]$SshKeyPath = $null,   # optional path to private key for SSH (Hyper-V only)
    [string]$PubKeyPath = "",      # optional path to public key to install on VM (defaults to $env:USERPROFILE\.ssh\id_rsa.pub)
    [string]$HostForVm = "",       # Windows host IP/name as reachable from VM for SMB mount (Hyper-V only)
    [string]$hostShareName = "ddwrt-src", # SMB share name / Local folder name on host
    [string]$hostSharePath = "",   # path on host for share/local folder (defaults to a VHD subfolder for HyperV, or is prompted for WSL2)
    [string]$SmbUsername = "",     # SMB username (if empty script will prompt - Hyper-V only)
    [string]$SmbPasswordPlain = "",# SMB password plain (or use $SmbPasswordSecure - Hyper-V only)
    [System.Security.SecureString]$SmbPasswordSecure = $null, # optional secure string password (Hyper-V only)
    [string]$defaultNewAdapterName = "BuildNet", # Set a default name for the new network adapter (Hyper-V only)
    [string]$WslDistroName = "Ubuntu-22.04" # Name of the WSL distribution to provision (WSL2 only, assumes Debian-based)
)

#endregion
#==================================================================#
#region * User-configurable variables *
# --- Hyper-V Configuration (ignored if Environment is WSL2) ---
$vmName    = "ubuntu-ddwrt"
$vhdFolder = "E:\VMs\$vmName"
$vhdPath   = "$vhdFolder\$vmName.vhdx"
$isoPath   = "F:\ISO\ubuntu-22.04-live-server-amd64.iso"
$vhdSize   = 80GB
$cpuCount  = 4
$ram       = 10GB
$ramDynamic = $false
$ramMin    = 4GB
$ramMax    = 16GB

# --- Global Cache for WSL Online Distros ---
$global:WSLOnlineDistrosCache = $null

#endregion
#==================================================================#
#region * Files *
# Define the standard menu options with their corresponding distro names
$standardDistros = @(
    "Ubuntu",
    "Ubuntu-24.04",
    "Ubuntu-22.04", # Default
    "Ubuntu-20.04"
)
#-----------------------------------------------#
$linuxAptUpgrade = @"
sudo apt-get upgrade -y
"@
#region -- For Mount SMB share inside VM --
#-----------------------------------------------#
#region --- bootstrapScript ---
$bootstrapScript = @'
set -e
sudo apt update
sudo apt install -y openssh-server sudo
if ! id -u build >/dev/null 2>&1; then
  sudo useradd -m -s /bin/bash build
fi
echo "build ALL=(ALL) NOPASSWD:ALL" | sudo tee /etc/sudoers.d/99-build >/dev/null
sudo mkdir -p /home/build/.ssh
sudo chmod 700 /home/build/.ssh
if [ -n "__PUBKEY__" ]; then
  sudo bash -c "cat >> /home/build/.ssh/authorized_keys" <<KEY
__PUBKEY__
KEY
fi
sudo chown -R build:build /home/build/.ssh
sudo chmod 600 /home/build/.ssh/authorized_keys || true
sudo systemctl enable --now ssh
'@
#endregion

#region --- vmMountScript ---
$vmMountScript = @'
set -e
sudo apt update
sudo apt install -y cifs-utils
sudo mkdir -p /srv/ddwrt-src
sudo chown build:build /srv/ddwrt-src
sudo tee /root/.smbddwrtcreds >/dev/null <<CRED
username=__SMBUSER__
password=__SMBPASS__
domain=WORKGROUP
CRED
sudo chmod 600 /root/.smbddwrtcreds
grep -F "//__HOST__/__SHARE__" /etc/fstab >/dev/null 2>&1 || sudo bash -c 'cat >> /etc/fstab' <<FST
//__HOST__/__SHARE__ /srv/ddwrt-src cifs credentials=/root/.smbddwrtcreds,iocharset=utf8,uid=1000,gid=1000,file_mode=0644,dir_mode=0755,nounix 0 0
FST
sudo mount -a
'@
#endregion

#endregion
#-----------------------------------------------#
#region -- For Invoke-WSL2Provisioning --
#-----------------------------------------------#
#region --- userSetupScript Template ---
$userSetupScriptTemplate = @"
if ! id -u ##LINUX_USER## >/dev/null 2>&1; then sudo useradd -m -s /bin/bash ##LINUX_USER##; fi
"@
#endregion

#region --- sudoersConfigScriptTemplate ---
$sudoersConfigScriptTemplate = @"
if ! grep -q "##LINUX_USER## ALL=(ALL) NOPASSWD:ALL" /etc/sudoers.d/99-##LINUX_USER##; then echo "##LINUX_USER## ALL=(ALL) NOPASSWD:ALL" | sudo tee /etc/sudoers.d/99-##LINUX_USER## >/dev/null; fi; sudo chmod 440 /etc/sudoers.d/99-##LINUX_USER##
"@
#endregion

#region --- keySetupScript Template ---
$keySetupScriptTemplate = @"
sudo mkdir -p /home/##LINUX_USER##/.ssh; sudo chmod 700 /home/##LINUX_USER##/.ssh; echo "##PUB_KEY_CONTENT##" | sudo tee /home/##LINUX_USER##/.ssh/authorized_keys > /dev/null; sudo chmod 600 /home/##LINUX_USER##/.ssh/authorized_keys; sudo chown -R ##LINUX_USER##:##LINUX_USER## /home/##LINUX_USER##/.ssh
"@
#endregion

#region --- packageScript ---
$packageScript = "sudo apt update && sudo apt install -y build-essential git automake libtool make g++ flex bison libncurses5-dev zlib1g-dev gawk rsync subversion"
#endregion

#region --- installAppsScript ---
$installAppsScript = @"
#!/bin/bash
#
# Script to install the necessary packages for building DD-WRT on Ubuntu 22.04 (Jammy Jellyfish).
#
# NOTE: The specific legacy package 'libstdc++6-4.9-dev' has been removed
# as it is not available in the Ubuntu 22.04 repository. The general
# build-essential and development packages are used instead.

echo "--- 1. Updating package lists..."
# Use an explicit update
sudo apt update

# Check exit status of update
if [ $? -ne 0 ]; then
    echo "ERROR: Failed to update package lists. Check your internet connection or repository settings."
    exit 1
fi

echo "--- 2. Installing DD-WRT build prerequisites..."

# List of packages to install.
# 'g++' is included in 'build-essential', but listing it explicitly doesn't hurt.
# 'libstdc++6-4.9-dev' is intentionally excluded.
PACKAGES="build-essential git automake libtool make g++ flex bison libncurses5-dev zlib1g-dev gawk rsync subversion"

# Use the -y flag for non-interactive installation
sudo apt install -y build-essential git automake libtool make g++ flex bison libncurses5-dev zlib1g-dev gawk rsync subversion

# Check exit status of install command
if [ $? -ne 0 ]; then
    echo "ERROR: One or more packages failed to install."
    exit 2
fi

echo "--- 3. Installation complete!"
echo "The following packages were successfully installed: "

exit 0
"@
#endregion

#region --- linkScript Template ---
$linkScriptTemplate = @"
sudo mkdir -p /home/##LINUX_USER##/##HOST_SHARE_NAME##; if [ ! -L "/home/##LINUX_USER##/##HOST_SHARE_NAME##" ]; then sudo ln -s "##WSL_HOST_PATH##" /home/##LINUX_USER##/##HOST_SHARE_NAME##; sudo chown -h ##LINUX_USER##:##LINUX_USER## /home/##LINUX_USER##/##HOST_SHARE_NAME##; echo "Created symlink to host directory: ##WSL_HOST_PATH##"; else echo "Symlink /home/##LINUX_USER##/##HOST_SHARE_NAME## already exists."; fi
"@
#endregion

#endregion
#-----------------------------------------------#
#endregion
#==================================================================#
#region * Helper functions *
function Write-Log {
    param(
        [ValidateSet('DEBUG','INFO','WARN','ERROR')][string]$Level = 'INFO',
        [string]$Message
    )
    $ts = (Get-Date).ToString('s')
    switch ($Level) {
        'DEBUG' { Write-Verbose "$ts [DEBUG] $Message" ; break }
        'INFO'  { Write-Output  "$ts [INFO]  $Message" ; break }
        'WARN'  { Write-Warning "$ts [WARN]  $Message" ; break }
        'ERROR' { Write-Error   "$ts [ERROR] $Message" ; break }
    }
}

function Retry-Command {
    param(
        [Parameter(Mandatory)][ScriptBlock]$Action,
        [int]$MaxAttempts = 3,
        [int]$InitialDelaySeconds = 2,
        [ValidateSet('Continue','Throw')][string]$OnFailure = 'Throw'
    )

    $attempt = 0
    $delay = $InitialDelaySeconds
    while ($attempt -lt $MaxAttempts) {
        try {
            $attempt++
            return & $Action
        } catch {
            Write-Log -Level 'WARN' -Message "Attempt $attempt failed: $($_.Exception.Message)"
            if ($attempt -ge $MaxAttempts) {
                Write-Log -Level 'ERROR' -Message "All $MaxAttempts attempts failed."
                if ($OnFailure -eq 'Throw') { throw $_ }
                return $null
            }
            Start-Sleep -Seconds $delay
            $delay = [Math]::Min($delay * 2, 30)
        }
    }
}

function Format-MacDashed {
    param([string]$macRaw)
    $mac = $macRaw -replace '[:-]', ''
    return ($mac -replace '(.{2})(?!$)', '$1-').ToUpper()
}

function Exec {
    param(
        [Parameter(Mandatory=$true)][ScriptBlock]$Action,
        [Parameter(Mandatory=$true)][string]$Description
    )
    if ($DryRun) {
        Write-Output "DRY-RUN: $Description"
    } else {
        Write-Verbose "Executing: $Description"
        try {
            & $Action
        } catch {
            Write-Error "Action failed: $Description`nError: $_"
            throw
        }
    }
}

function Write-StepProgress {
    param(
        [Parameter(Mandatory=$true)][int]$Step,
        [Parameter(Mandatory=$true)][int]$Total,
        [Parameter(Mandatory=$true)][string]$Activity,
        [Parameter(Mandatory=$true)][string]$Status
    )
    $percent = [int](($Step / $Total) * 100)
    Write-Progress -Activity $Activity -Status $Status -PercentComplete $percent -CurrentOperation "Step $Step of $Total" -Id 1
}

function Test-SshAvailable {
    return (Get-Command ssh -ErrorAction SilentlyContinue) -ne $null
}

#endregion
#==================================================================#
#region * WSL Helpers *
function Invoke-WslCommand {
    param(
        [Parameter(Mandatory=$true)][string]$Command,
        [Parameter(Mandatory=$true)][string]$Description,
        [string]$DistroName,
        [string]$User = $null
    )

    $wslArgs = @('-d', $DistroName, '--')
    if ($User) {
        # Execute as the specified user using sudo/su from the default WSL user context
        $wslArgs += ('exec', 'sudo', '-u', $User, 'bash', '-c', $Command)
    } else {
        # Execute as the default user
        $wslArgs += ('bash', '-c', $Command)
    }

    Exec -Action {
        # Execute the command directly, capturing all output (stdout and stderr) into $output.
        # This allows us to display the verbose error messages if the command fails.
        $output = & wsl.exe $wslArgs 2>&1
        $exitCode = $LASTEXITCODE

        if ($exitCode -ne 0) {
            # Build a detailed error message
            $fullCommand = "wsl.exe $($wslArgs -join ' ')"
            $errorMessage = "WSL command failed with exit code $exitCode."
            $errorMessage += "`n--- Command Description ---`n$Description"
            $errorMessage += "`n--- Full Command Invoked ---`n$fullCommand"
            $errorMessage += "`n--- WSL Output (Error Stream) ---`n$($output -join "`n")"
            throw $errorMessage
        }

        # If successful and output exists, log it verbosely
        if ($output) {
            Write-Verbose "WSL Command Output for '$Description':`n$($output -join "`n")"
        }

    } -Description $Description
}

function Test-WslDistroExists {
    param(
        [Parameter(Mandatory=$true)][string]$DistroName
    )
    # Check if 'wsl.exe --list' can be run (basic WSL check)
    try {
        $distroList = wsl.exe --list --quiet | Out-String -ErrorAction Stop
    } catch {
        Write-Error "Could not execute 'wsl.exe --list --quiet'. Ensure WSL is installed and running."
        throw
    }

    # Check the output for an exact match of the distribution name
    $distroList -split "`r?`n" | ForEach-Object {
        if ($_.Trim() -eq $DistroName) {
            return $true
        }
    }
    return $false
}

function Test-WslDistroRunning {
    param(
        [Parameter(Mandatory=$true)][string]$DistroName
    )
    try {
        # Use wsl.exe -l -v to get a table of distros and their state
        $wslStatus = wsl.exe -l -v | Out-String -ErrorAction Stop

        # Split into lines and find the line matching the distro name and 'Running' state.
        # This regex looks for: Start of line -> (Optional asterisk/space) -> DistroName -> (Whitespace) -> 'Running'
        $line = $wslStatus -split "`r?`n" | Where-Object {
            $_ -match "^\s*(\*|\s+)\s*$($DistroName)\s+Running"
        }

        # If any line matches, the count will be > 0
        return $line.Count -gt 0
    } catch {
        Write-Verbose "Could not check WSL running status: $_"
        return $false
    }
}

function Install-WslDistro {
    param(
        [Parameter(Mandatory=$true)][string]$DistroName
    )

    Write-Output "Attempting to install WSL distribution '$DistroName'..."
    Write-Output "This process may take some time and requires a connection to the internet."

    Exec -Action {
        # The wsl.exe --install command is interactive and needs to be run directly.
        # Running it without capturing output ensures the user sees the interactive installer process.
        & wsl.exe --install $DistroName
        if ($LASTEXITCODE -ne 0) {
            throw "Installation of '$DistroName' failed with exit code $LASTEXITCODE."
        }
    } -Description "Install WSL distribution '$DistroName'"

    Write-Output "Installation of '$DistroName' completed."

    # After install, it usually starts and sets up a user. We want to ensure it's stopped before provisioning starts.
    Write-Output "Shutting down the distribution to ensure a clean start for provisioning..."
    Exec -Action {
        # The terminate command is safer than shutdown as it only affects the target distro
        & wsl.exe --terminate $DistroName
    } -Description "Terminate distribution '$DistroName' after installation"
}

function Get-WSLOnlineDistros {
    [CmdletBinding()]
    param(
        [switch] $UseCache,
        [int] $TimeoutSeconds = 30
    )

    if ($UseCache -and $global:WSLOnlineDistrosCache) {
        return $global:WSLOnlineDistrosCache
    }

    try {
        $psi = New-Object System.Diagnostics.ProcessStartInfo
        $psi.FileName = "wsl.exe"
        $psi.Arguments = "--list --online"
        $psi.RedirectStandardOutput = $true
        $psi.RedirectStandardError  = $true
        $psi.UseShellExecute      = $false
        $psi.CreateNoWindow       = $true

        $proc = New-Object System.Diagnostics.Process
        $proc.StartInfo = $psi
        $proc.Start() | Out-Null

        if (-not $proc.WaitForExit($TimeoutSeconds * 1000)) {
            $proc.Kill()
            throw "wsl.exe timed out after $TimeoutSeconds seconds."
        }

        $raw = $proc.StandardOutput.ReadToEnd()
        $err  = $proc.StandardError.ReadToEnd()
        if ($proc.ExitCode -ne 0) {
            throw "wsl.exe exited with code $($proc.ExitCode): $err"
        }

        if ([string]::IsNullOrWhiteSpace($raw)) { return @() }

        $lines = $raw -split "\r?\n" | ForEach-Object { $_.Trim() } | Where-Object { $_ -ne "" }

        $blacklist = @('Install','NAME','Available','Index:','The')

        $cleanLines = $lines | Where-Object {
            $_ -notmatch '^(?i)(NAME|Install|Available|NAME\s+RELEASE|--|Index:)$'
        }

        $distroNames = @()
        foreach ($line in $cleanLines) {
            if ($blacklist -contains $line) { continue }

            if ($line -match '^\s*(\S+)') {
               $token = $Matches[1].Trim()

                 # drop tokens that are numeric-only or blacklisted
                 if ($token -match '^\d+$') { continue }
                 if ($blacklist -contains $token) { continue }

                 # accept tokens that match allowed distro-name chars and contain at least one letter
                 if ($token -match '^[A-Za-z0-9._-]+$' -and $token -match '[A-Za-z]') {
                     $distroNames += $token
                 }
            }
        }

        # Deduplicate while preserving order
        $seen = @{}
        $unique = @()
        foreach ($n in $distroNames) {
            if (-not $seen.ContainsKey($n)) {
                $seen[$n] = $true
                $unique += $n
            }
        }

        if ($UseCache) { $global:WSLOnlineDistrosCache = $unique }
        return ,$unique
    } catch {
        Write-Error "Failed to list online WSL distros: $_"
        return @()
    }
}

function Select-WSLDistro {
    param(
        [string] $DefaultDistro = "Ubuntu-22.04",
        [string[]] $StandardDistros = @("Ubuntu-22.04","Ubuntu-20.04","Ubuntu","Debian","archlinux","kali-linux","FedoraLinux-42")
    )

    if (-not (Get-Command Get-WSLOnlineDistros -ErrorAction SilentlyContinue)) {
        throw "Get-WSLOnlineDistros must be defined before calling Select-WSLDistro."
    }

    $online = Get-WSLOnlineDistros
    if (-not $online) { $online = @() }

    # Build menu: standard first, then online extras
    $menu = New-Object System.Collections.ArrayList
    foreach ($d in $StandardDistros) { if ($d -and -not $menu.Contains($d)) { [void]$menu.Add($d) } }
    foreach ($d in $online)           { if ($d -and -not $menu.Contains($d)) { [void]$menu.Add($d) } }

    do {
        Write-Output "`n--- WSL Distribution Selection ---"
        $menuOptions = @{}
        for ($i = 0; $i -lt $menu.Count; $i++) {
            $idx = $i + 1
            $entry = $menu[$i]
            $desc = ""
            if ($entry -eq $DefaultDistro) { $desc = " (Default / Recommended)" }
            Write-Output "$idx. $entry$desc"
            $menuOptions.Add($idx, $entry)
        }

        $listOption   = $menu.Count + 1
        $retryOption  = $menu.Count + 2
        $customOption = $menu.Count + 3

        Write-Output "$listOption. List online available distributions (from wsl --list --online)"
        Write-Output "$retryOption. Retry fetching online distributions"
        Write-Output "$customOption. Enter a custom distribution name"

        $prompt = "Enter 1-$customOption, or press Enter to use default ($DefaultDistro)"
        $choice = Read-Host $prompt

        if ([string]::IsNullOrWhiteSpace($choice)) { return $DefaultDistro }

        if ($choice -as [int] -and $menuOptions.ContainsKey([int]$choice)) {
            return $menuOptions[[int]$choice]
        }

        if ($choice -as [int] -and [int]$choice -eq $listOption) {
            if ($online.Count -eq 0) { Write-Warning "No online distributions available right now."; continue }
            Write-Output "`n--- Online Distributions ---"
            $onlineMenu = @{}
            for ($j = 0; $j -lt $online.Count; $j++) {
                $num = $j + 1
                Write-Output "$num. $($online[$j])"
                $onlineMenu.Add($num, $online[$j])
            }
            $sel = Read-Host "Enter number to select (or press Enter to return)"
            if ([string]::IsNullOrWhiteSpace($sel)) { continue }
            if ($sel -as [int] -and $onlineMenu.ContainsKey([int]$sel)) { return $onlineMenu[[int]$sel] }
            Write-Warning "Invalid selection from online list."
            continue
        }

        if ($choice -as [int] -and [int]$choice -eq $retryOption) {
            Write-Output "Retrying to fetch online distributions..."
            $online = Get-WSLOnlineDistros
            if ($online -and $online.Count -gt 0) {
                foreach ($d in $online) { if (-not $menu.Contains($d)) { [void]$menu.Add($d) } }
                Write-Output "Fetched $($online.Count) online distributions."
            } else {
                Write-Warning "Still no online distributions found."
            }
            continue
        }

        if ($choice -as [int] -and [int]$choice -eq $customOption) {
            $customName = Read-Host "Enter exact, case-sensitive WSL distribution name"
            if (-not [string]::IsNullOrWhiteSpace($customName)) { return $customName }
            Write-Warning "Custom name cannot be empty."
            continue
        }

        Write-Warning "Invalid selection. Try again."
    } while ($true)
}

#endregion
#==================================================================#
#region * Environment Provisioning Functions *

function Invoke-WSL2Provisioning {
    <#
        .SYNOPSIS
            Provision a WSL2 distribution for DD-WRT builds.
        .DESCRIPTION
            Installs build prerequisites, creates a build user with NOPASSWD sudo, optionally adds an SSH public key, and creates a symlink to a Windows-hosted source directory.
        .PARAMETER DistroName
            WSL distribution name (e.g., Ubuntu-22.04).
        .PARAMETER LinuxUser
            Build user to create/configure inside WSL.
        .PARAMETER HostShareName
            Folder link name under the user's home.
        .PARAMETER HostSharePath
            Windows path to source code; converted to /mnt/<drive>/... for linking.
        .PARAMETER PubKeyPath
            Optional public key path to add to the user's authorized_keys.
        .PARAMETER WslSourceMountPoint
            Target mount/link location inside WSL (e.g., /home/builder/ddwrt-src).
        .PARAMETER AutoProvision
            If specified, proceeds without prompting for distro installation.
        .EXAMPLE
            Invoke-WSL2Provisioning -DistroName Ubuntu-22.04 -LinuxUser build -HostShareName src -HostSharePath C:\DDWRT_Source -WslSourceMountPoint /home/build/src
    #>
    param(
        [string]$DistroName,
        [string]$LinuxUser,
        [string]$HostShareName,
        [string]$HostSharePath,
        [string]$PubKeyPath,
        [string]$WslSourceMountPoint,
        [switch]$AutoProvision
    )

    Write-Output "--- Starting WSL2 Provisioning for Distro: $DistroName ---"
    Write-Output "Windows Source Path: $HostSharePath"

    # Define total steps for progress bar
    # 1. Check/Install Distro | 2. Sudo Validation | 3. User Setup | 4. Sudoers Config | 5. Install Prerequisites | 6. SSH Key Setup | 7. Symlink Setup
    $totalSteps = 7
    $currentStep = 1

    # 1. Check/Install WSL distribution
    Write-StepProgress -Step $currentStep -Total $totalSteps -Activity "WSL Distro Setup" -Status "Checking if WSL distribution '$DistroName' exists and installing if necessary..."

    $distroFound = Test-WslDistroExists -DistroName $DistroName

    if (-not $distroFound) {

        Write-Warning "WSL distribution '$DistroName' was not found."

        $installPrompt = $true
        if (-not $AutoProvision) {
            $response = Read-Host -Prompt "Do you want to install '$DistroName' now via 'wsl --install $DistroName'? (Y/N)"
            $installPrompt = $response -match '(?i)y'
        }

        if ($AutoProvision -or $installPrompt) {

            Write-Output "Attempting to install distribution '$DistroName'..."
            Install-WslDistro -DistroName $DistroName

            # Re-check existence after installation
            $distroFound = Test-WslDistroExists -DistroName $DistroName

            if (-not $distroFound) {
                Write-Error "The installation completed, but the distribution is still not listed. Please check your WSL setup manually."
                throw "Installation failed to register distribution."
            }
        } else {
            Write-Error "Installation cancelled by user or -AutoProvision not set. Cannot continue without distribution."
            throw "Configuration Error: WSL distribution '$DistroName' not found."
        }
    }
    Write-Verbose "WSL distribution found."


    # 1.5. Ensure the distribution is terminated/stopped for clean provisioning (NEWLY ADDED LOGIC)
    if (Test-WslDistroRunning -DistroName $DistroName) {
        Write-Output "Distro '$DistroName' is running. Terminating it for clean provisioning..."
        Exec -Action {
            & wsl.exe --terminate $DistroName
        } -Description "Terminate running distribution '$DistroName' after installation"
    }
    $currentStep++

    # 2. Validate sudo access by prompting for password
    # NOTE: 'sudo -v' caches the password timestamp for subsequent commands.
    Write-StepProgress -Step $currentStep -Total $totalSteps -Activity "WSL Distro Provisioning" -Status "Validating and caching sudo credentials (requires your WSL password once)..."
    Write-Warning "A sudo password prompt may appear. Please enter your WSL password for the default user."
    try {
        # Call wsl directly to allow interactive password prompt in the current console
        # 'sudo -v' validates the password and caches the sudo timestamp for a few minutes,
        # allowing the subsequent user creation commands to run non-interactively.
        wsl -d $DistroName -- sudo -v
        if ($LASTEXITCODE -ne 0) {
            throw "sudo validation failed. Exit code: $LASTEXITCODE"
        }
        Write-Verbose "Sudo credentials validated and cached."
    } catch {
        Write-Error "Action failed: Sudo password validation failed."
        Write-Error "Could not get sudo credentials. This is required to install packages and create the '$LinuxUser' user."
        Write-Error "Please ensure you can run 'sudo -v' inside 'wsl -d $DistroName' and try again."
        Write-Error "Error: $_"
        throw "Sudo validation failed." # Stop script execution
    }
    $currentStep++

    # 3. Setup Build User (Isolated Step 1)
    Write-StepProgress -Step $currentStep -Total $totalSteps -Activity "WSL Distro Provisioning" -Status "Creating user '$LinuxUser' if it doesn't exist..."
    # Replace placeholder with runtime user value
    $userScript = $userSetupScriptTemplate -replace "##LINUX_USER##", $LinuxUser
    # Execute the command as root to ensure privileges and avoid interactive password prompts.
    Exec -Action {
        & wsl.exe -d $DistroName -u root -- bash -c $userScript
    } -Description "Create user '$LinuxUser' as root"
    $currentStep++

    # 4. Configure NOPASSWD Sudoers (Isolated Step 2)
    Write-StepProgress -Step $currentStep -Total $totalSteps -Activity "WSL Distro Provisioning" -Status "Configuring NOPASSWD sudo access for '$LinuxUser'..."
    # Replace placeholder with runtime user value
    $sudoersScript = $sudoersConfigScriptTemplate -replace "##LINUX_USER##", $LinuxUser
    # Execute the command as root, which bypasses the need for interactive password-based sudo.
    Exec -Action {
        & wsl.exe -d $DistroName -u root -- bash -c $sudoersScript
    } -Description "Grant NOPASSWD sudo access to '$LinuxUser' as root"
    $currentStep++

    # 5. Setup Build Prerequisites
    Write-StepProgress -Step $currentStep -Total $totalSteps -Activity "Installing Build Prerequisites (Long Running)" -Status "Installing build-essential, git, automake, and other dependencies..."
    # $packageScript is defined globally
    Invoke-WslCommand -Command $packageScript -Description "Install DD-WRT build prerequisites" -DistroName $DistroName
    $currentStep++

    # 6. Setup SSH Public Key for 'build' user (Optional)
    Write-StepProgress -Step $currentStep -Total $totalSteps -Activity "WSL Distro Provisioning" -Status "Installing SSH public key (if path provided)..."
    if ($PubKeyPath -and (Test-Path $PubKeyPath)) {

        $pubKey = (Get-Content $PubKeyPath -Raw) -split "`r?`n" | Where-Object { -not [string]::IsNullOrWhiteSpace($_) } | Select-Object -First 1

        if (-not [string]::IsNullOrWhiteSpace($pubKey)) {
            # Use the global template and replace the placeholders
            $keyScript = $keySetupScriptTemplate -replace "##PUB_KEY_CONTENT##", $pubKey
            $keyScript = $keyScript -replace "##LINUX_USER##", $LinuxUser

            # Note: This executes the commands as root/default user, then uses chown to fix permissions.
            Invoke-WslCommand -Command $keyScript -Description "Install SSH public key for user '$LinuxUser'" -DistroName $DistroName
        } else {
            Write-Warning "Public key file was empty. Skipping SSH key installation."
        }

    } else {
        Write-Warning "Public key not found at $PubKeyPath. Skipping SSH key installation."
    }
    $currentStep++

    # 7. Set up Source Code Directory (Symlink to Windows host)
    Write-StepProgress -Step $currentStep -Total $totalSteps -Activity "WSL Distro Provisioning" -Status "Creating source code symlink..."

    # Calculate the WSL path (requires $HostSharePath, a function parameter)
    # Convert Windows path to WSL mount path (e.g., C:\DDWRT_Source -> /mnt/c/DDWRT_Source)
    $hostDrive = [string]$HostSharePath[0]
    $hostPathNormalized = $HostSharePath.Substring(2) -replace '\\', '/'
    $wslHostPath = "/mnt/$($hostDrive.ToLower())$hostPathNormalized"

    # Use the global template and replace the placeholders
    $linkScript = $linkScriptTemplate -replace "##WSL_HOST_PATH##", $wslHostPath
    $linkScript = $linkScript -replace "##LINUX_USER##", $LinuxUser
    $linkScript = $linkScript -replace "##HOST_SHARE_NAME##", $HostShareName

    Invoke-WslCommand -Command $linkScript -Description "Create symlink from $WslSourceMountPoint to host folder $wslHostPath" -DistroName $DistroName

    # Final progress cleanup (to ensure 100% completion is shown)
    Write-Progress -Activity "WSL Distro Provisioning" -Status "Provisioning Complete." -PercentComplete 100 -Completed -Id 1

    Write-Output "--- WSL2 Provisioning complete ---"
    Write-Output "To enter the environment and start building, run: wsl -d $DistroName --user $LinuxUser"
    Write-Output "The source directory is available at: $WslSourceMountPoint"
}




function Invoke-HyperVProvisioning {
    <#
        .SYNOPSIS
            Provision a Hyper-V Ubuntu VM for DD-WRT builds.
        .DESCRIPTION
            Creates and configures a Generation 2 VM, sets CPU and memory, mounts an ISO, configures networking and a static MAC,
            creates an SMB share on the host for the VM to mount, and optionally prepares post-installation SSH/SMB steps for
            automated provisioning inside the VM.
        .PARAMETER VmName
            Name of the VM to create or configure.
        .PARAMETER VhdFolder
            Folder on the host to store VM assets and the VHDX.
        .PARAMETER VhdPath
            Path to the VHDX file to create or reuse.
        .PARAMETER IsoPath
            Path to the Ubuntu ISO to attach for OS installation.
        .PARAMETER HostShareName
            Name of the SMB share to create on the host for sharing source files with the VM.
        .PARAMETER HostSharePath
            Absolute Windows path for the SMB share; the script will create this folder if missing.
        .PARAMETER SshUser
            Linux username expected/created inside the VM for build operations and optional SSH provisioning.
        .PARAMETER SshHost
            IP or hostname of the VM reachable via SSH (required for -AutoProvision).
        .PARAMETER SshKeyPath
            Optional path to a private SSH key used for SSH automation (Hyper-V only).
        .PARAMETER PubKeyPath
            Optional public key path to copy into the VM during provisioning.
        .PARAMETER HostForVm
            Host IP or hostname as visible from the VM; used in CIFS mount entries inside the VM (required for -AutoProvision).
        .PARAMETER DefaultNewAdapterName
            Logical name for a new network adapter if one is created externally or referenced in future enhancements.
        .PARAMETER SmbUsername
            Username the VM should use to authenticate to the host SMB share (if required).
        .PARAMETER SmbPasswordSecure
            SMB password as a SecureString (preferred for sensitive input).
        .PARAMETER SmbPasswordPlain
            SMB password in plain text (alternative to SecureString).
        .PARAMETER VhdSize
            Size for the VHD to create (e.g., 80GB). Required if creating a new VHD.
        .PARAMETER CpuCount
            Number of virtual processors to assign to the VM.
        .PARAMETER Ram
            Startup memory for the VM (e.g., 10GB).
        .PARAMETER RamDynamic
            Switch to enable dynamic memory on the VM.
        .PARAMETER RamMin
            Minimum memory when dynamic memory is enabled.
        .PARAMETER RamMax
            Maximum memory when dynamic memory is enabled.
        .PARAMETER AutoProvision
            If specified, the function will attempt to start the VM and provide guidance/commands for SSH-based provisioning.
        .EXAMPLE
            Invoke-HyperVProvisioning -VmName ubuntu-ddwrt -VhdFolder D:\VMs\ubuntu-ddwrt -VhdPath D:\VMs\ubuntu-ddwrt\disk.vhdx `
                -IsoPath D:\ISOs\ubuntu-22.04.iso -HostShareName src -HostSharePath D:\src -SshUser build -CpuCount 4 -VhdSize 80GB -Ram 10GB
    #>
    param(
        [string]$VmName,
        [string]$VhdFolder,
        [string]$VhdPath,
        [string]$IsoPath,
        [string]$HostShareName,
        [string]$HostSharePath,
        [string]$SshUser,
        [string]$SshHost,
        [string]$SshKeyPath,
        [string]$PubKeyPath,
        [string]$HostForVm,
        [string]$DefaultNewAdapterName,
        [string]$SmbUsername,
        [securestring]$SmbPasswordSecure,
        [string]$SmbPasswordPlain,
        $VhdSize,
        $CpuCount,
        $Ram,
        $RamDynamic,
        $RamMin,
        $RamMax,
        [switch]$AutoProvision
    )

    Write-Output "--- Starting Hyper-V Provisioning for VM: $VmName ---"

    $totalSteps = 6
    $currentStep = 1

    if (-not (Get-Module -ListAvailable -Name Hyper-V)) {
        Write-Error "The Hyper-V PowerShell module is not available. Please ensure the Hyper-V Management Tools or the Hyper-V role is installed."
        throw "Hyper-V module not found."
    }

    #region * Host File System Setup *
    Write-StepProgress -Step $currentStep -Total $totalSteps -Activity "Hyper-V VM Setup" -Status "Creating host file system directories..."
    Exec -Action {
        New-Item -ItemType Directory -Path $VhdFolder -Force | Out-Null
    } -Description "Create VM configuration folder ($VhdFolder)"

    Exec -Action {
        New-Item -ItemType Directory -Path $HostSharePath -Force | Out-Null
    } -Description "Create host source path for SMB share ($HostSharePath)"
    $currentStep++

    $vmExists = (Get-VM -Name $VmName -ErrorAction SilentlyContinue)

    $vhdExists = Test-Path $VhdPath
    if (-not $vhdExists) {
        Exec -Action { New-VHD -Path $VhdPath -SizeBytes $VhdSize -Dynamic -ErrorAction Stop | Out-Null } -Description "Create VHD at $VhdPath ($VhdSize)"
    } else {
        Write-Verbose "VHD already exists at $VhdPath"
    }
    #endregion

    #region * 2. Creat and Config *
    Write-StepProgress -Step $currentStep -Total $totalSteps -Activity "Hyper-V VM Setup" -Status "Checking/Creating Virtual Machine '$VmName'..."
    if (-not $vmExists) {
        Write-Output "Creating new VM: $VmName..."
        Exec -Action {
            New-VM -Name $VmName -MemoryStartupBytes $Ram -VHDPath $VhdPath -Generation 2 | Out-Null
        } -Description "Create Generation 2 VM with VHD"

        Exec -Action {
            Set-VMMemory $VmName -DynamicMemoryEnabled:$RamDynamic -MinimumBytes $RamMin -MaximumBytes $RamMax | Out-Null
        } -Description "Configure VM memory (Dynamic: $RamDynamic, Max: $RamMax)"

        Write-Output "VM '$VmName' created and configured. Ready for OS installation."

    } else {
        Write-Output "VM '$VmName' already exists. Skipping VM creation."
    }
    $currentStep++
    #endregion

    #region * 3. Config Details *
    Write-StepProgress -Step $currentStep -Total $totalSteps -Activity "Hyper-V VM Configuration" -Status "Configuring CPU, DVD, and Networking..."

    Exec -Action {
        Set-VMProcessor $VmName -Count $CpuCount | Out-Null
    } -Description "Set VM processor count to $CpuCount"

    if (Test-Path $IsoPath) {
        Exec -Action {
            Add-VMDvdDrive -VMName $VmName -ControllerNumber 0 -ControllerLocation 0 -ErrorAction SilentlyContinue | Out-Null
            Set-VMDvdDrive -VMName $VmName -Path $IsoPath | Out-Null
        } -Description "Add DVD drive and mount ISO ($IsoPath)"
    } else {
        Write-Warning "ISO not found at $IsoPath. You will need to attach an OS installation media manually."
    }

    $macAddress = "00-11-22-33-44-55"
    Exec -Action {
        Set-VMNetworkAdapter -VMName $VmName -StaticMacAddress $macAddress | Out-Null
    } -Description "Set Static MAC Address to $macAddress"

    $defaultSwitch = Get-VMSwitch -SwitchType Internal -Name 'Default Switch' -ErrorAction SilentlyContinue
    if ($defaultSwitch) {
        $switchName = $defaultSwitch.Name
        Exec -Action {
            Connect-VMNetworkAdapter -VMName $VmName -SwitchName $switchName | Out-Null
        } -Description "Connect VM to the 'Default Switch'"
    } else {
        Write-Warning "Default Switch not found. VM network adapter is not connected. Connect it manually."
    }
    $currentStep++
    #endregion

    #region * 4. Host SMBShare Config *
    Write-StepProgress -Step $currentStep -Total $totalSteps -Activity "Hyper-V Host Share Setup" -Status "Configuring host SMB share '$HostShareName'..."

    $existingShare = Get-SmbShare -Name $HostShareName -ErrorAction SilentlyContinue

    if ($existingShare) {
        if ($existingShare.Path -ne $HostSharePath) {
            Write-Error "A share named '$HostShareName' already exists but points to a different path ($($existingShare.Path)). Please delete the existing share or choose a different HostShareName."
            throw "SMB Share conflict."
        }
        Write-Verbose "Share '$HostShareName' already exists and points to $HostSharePath."
    } else {
        Exec -Action {
            New-SmbShare -Name $HostShareName -Path $HostSharePath -FullAccess Everyone -ErrorAction Stop | Out-Null
        } -Description "Create SMB Share '$HostShareName' for path '$HostSharePath' with 'Everyone' access"
    }

    $password = $null

    if ([string]::IsNullOrWhiteSpace($SmbUsername)) {
        Write-Warning "No SmbUsername provided. SMB mount in the VM might require manual configuration or use of default Windows credentials."
    } else {
        if ($SmbPasswordSecure -ne $null) {
            $password = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto([System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($SmbPasswordSecure))
        } elseif (-not [string]::IsNullOrWhiteSpace($SmbPasswordPlain)) {
            $password = $SmbPasswordPlain
        } else {
            $securePwd = Read-Host -Prompt "Enter SMB Password for user '$SmbUsername'" -AsSecureString
            $password = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto([System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($securePwd))
        }

        Write-Verbose "SMB credentials collected for user '$SmbUsername'."
    }
    #endregion

    Write-Progress -Activity "Hyper-V Host Share Setup" -Status "Configuration Complete." -PercentComplete 100 -Completed -Id 1

    #region * 5. Post-Setup Instructions *
    Write-Output "--- VM Configuration Summary ---"
    Write-Output "1. VM Name: $VmName"
    Write-Output "2. VHD Path: $VhdPath"
    Write-Output "3. Host Share Name (for VM access): \\\\$env:COMPUTERNAME\$HostShareName"
    Write-Output "4. Build User: $SshUser"
    Write-Output "5. Host IP (for VM access): $HostForVm (MUST be set if using AutoProvision/SSH)"
    Write-Output "---"

    if (-not $AutoProvision) {
        Write-Output "Provisioning is now paused. Please manually install Ubuntu Server 22.04+ on the VM '$VmName'."
        Write-Output "Important steps during installation:"
        Write-Output " - Create the user '$SshUser' (or your desired user)."
        Write-Output " - Ensure 'Install OpenSSH server' is checked to allow remote access."
        Write-Output "After installation, run the script again with the necessary -SshHost and -AutoProvision parameters to complete the setup."
    } else {
        Write-Warning "Automated SSH Provisioning is enabled (-AutoProvision). This requires the VM to be ON, have the OS installed, and be reachable at '$SshHost' with SSH running."

        if ([string]::IsNullOrWhiteSpace($SshHost) -or [string]::IsNullOrWhiteSpace($HostForVm)) {
            Write-Error "Cannot proceed with auto-provisioning. Both -SshHost (VM's IP) and -HostForVm (Host's IP from VM's perspective) must be provided for SSH and SMB mounting."
        } elseif (-not (Test-SshAvailable)) {
            Write-Error "The 'ssh' command is not available on this host. Cannot proceed with auto-provisioning."
        } elseif ([string]::IsNullOrWhiteSpace($SmbUsername) -or [string]::IsNullOrWhiteSpace($password)) {
             Write-Error "Cannot proceed with auto-provisioning. SMB Username and Password must be explicitly provided for file share mounting."
        } else {
            Write-Output "Attempting to start VM '$VmName'..."
            Exec -Action { Start-VM $VmName | Out-Null } -Description "Start Hyper-V VM"

            Write-Warning "Full SSH automation (especially IP discovery and retries) is omitted for script simplicity, as it is highly complex and environment-specific. Please run the commands below manually *after* you have successfully installed the Linux OS and verified SSH connectivity to the VM."

            $remoteSharePath = "/home/$SshUser/$HostShareName"
            $remoteCommands = @(
                "sudo apt update",
                "sudo apt install -y cifs-utils",
                "$packageScript",

                "sudo mkdir -p $remoteSharePath",
                "sudo chown ${SshUser}:$SshUser $remoteSharePath",

                "if [ ! -f '/etc/smb-credentials' ]; then",
                "  echo 'username=$SmbUsername' | sudo tee /etc/smb-credentials > /dev/null",
                "  echo 'password=$password' | sudo tee -a /etc/smb-credentials > /dev/null",
                "  sudo chmod 600 /etc/smb-credentials",
                "fi",

                "if ! grep -q '$HostShareName' /etc/fstab; then",
                "  echo '//${HostForVm}/${HostShareName} $remoteSharePath cifs uid=$SshUser,credentials=/etc/smb-credentials,iocharset=utf8,noperm,vers=3.0 0 0' | sudo tee -a /etc/fstab > /dev/null",
                "fi",

                "sudo mount -a"
            ) -join ";"

            Write-Output "Manual SSH Commands to run as user '$SshUser' (Connect to $SshHost):"
            Write-Output "--------------------------------------------------------"
            $remoteCommands -split ";" | ForEach-Object { Write-Output "  $_" }
            Write-Output "--------------------------------------------------------"
        }
    }
    #endregion
}

#endregion
#==================================================================#
#region * Main Script Execution *
if (-not $Environment) {
    Write-Output "--- DD-WRT Build Environment Setup ---"
    Write-Output "Please choose your target environment:"
    Write-Output "1. HyperV (Creates a dedicated Ubuntu VM with full isolation)"
    Write-Output "2. WSL2 (Configures an existing Ubuntu distribution for high performance)"

    $choice = Read-Host "Enter 1 or 2"

    switch ($choice) {
        "1" { $Environment = "HyperV" }
        "2" { $Environment = "WSL2" }
        default {
            Write-Error "Invalid choice. Exiting script."
            exit 1
        }
    }
    Write-Output "Selected environment: $Environment"
}

if ([string]::IsNullOrWhiteSpace($SshUser)) {
    Write-Output "--- Linux User Configuration ---"
    Write-Output "The Linux user to be created for the build environment is currently empty."
    $promptUser = Read-Host "Please enter the desired Linux username (e.g., builder)"
    if ([string]::IsNullOrWhiteSpace($promptUser)) {
        Write-Error "Linux username cannot be empty. Exiting script."
        exit 1
    }
    $SshUser = $promptUser
    Write-Output "Using Linux user: $SshUser"
}

# Set the HostSharePath based on the chosen environment if not explicitly set
if (-not $hostSharePath -or [string]::IsNullOrWhiteSpace($hostSharePath)) {
    if ($Environment -eq 'HyperV') {
        $hostSharePath = Join-Path $vhdFolder $hostShareName
    } elseif ($Environment -eq 'WSL2') {
        $defaultDistroName = "Ubuntu-22.04"

        if ($WslDistroName -eq $defaultDistroName) {

            Write-Output "--- WSL Distribution Selection ---"
            Write-Output "The current default distribution is set to '$defaultDistroName'. (Recommended)"
            Write-Output "Please select the WSL distribution you want to provision:"
            Write-Output ""

            $i = 1
            $menuOptions = @{}
            $standardDistros | ForEach-Object {
                $description = ""
                if ($_ -eq $defaultDistroName) { $description = " (Default / Recommended)" }
                elseif ($_ -eq "Ubuntu") { $description = " (Standard Microsoft Store install)" }
                Write-Output "$i. $_$description"
                $menuOptions.Add($i, $_)
                $i++
            }

            $listOption = $i
            $customOption = $i + 1

            Write-Output "$listOption. List **available online** WSL distributions and select a NAME"
            Write-Output "$customOption. Enter a Custom Name (e.g., 'Kali-Linux')"

            $newDistroName = $defaultDistroName
            $validChoice = $false

            do {
                $choice = Read-Host "Enter 1-$customOption, or just press Enter to use default ($defaultDistroName)"

                if ([string]::IsNullOrWhiteSpace($choice)) {
                    $validChoice = $true
                } elseif ($menuOptions.ContainsKey([int]$choice)) {
                    $newDistroName = $menuOptions[[int]$choice]
                    $validChoice = $true
                } elseif ([int]$choice -eq $listOption) {

                    Write-Output "`n--- Available WSL Distributions (Online) ---"
                    Write-Output "Note: Selecting a distro here will only set the name. It **must** be installed via 'wsl --install <Name>' before running the script with -AutoProvision."

                    $onlineDistroNames = Get-WSLOnlineDistros

                    if (-not $onlineDistroNames) {
                        Write-Warning "No online distributions found or the command failed. Returning to main selection."
                        continue
                    }

                    $onlineMenuOptions = @{}
                    $j = 1
                    Write-Output ""
                    $onlineDistroNames | ForEach-Object {
                        $name = $_.Trim()
                        Write-Output "$j. $name"
                        $onlineMenuOptions.Add($j, $name)
                        $j++
                    }

                    $onlineChoice = Read-Host "Enter the number corresponding to the distro you want to use (must be installed first)"

                    if ($onlineMenuOptions.ContainsKey([int]$onlineChoice)) {
                        $newDistroName = $onlineMenuOptions[[int]$onlineChoice]
                        $validChoice = $true
                    } else {
                        Write-Warning "Invalid selection. Please choose a number from the online list or return to the main menu."
                    }

                } elseif ([int]$choice -eq $customOption) {
                    $customName = Read-Host "Enter the exact, case-sensitive name of your WSL Distribution"
                    if (-not [string]::IsNullOrWhiteSpace($customName)) {
                        $newDistroName = $customName
                        $validChoice = $true
                    } else {
                        Write-Warning "Custom name cannot be empty. Please choose again."
                    }
                } else {
                    Write-Warning "Invalid selection. Please enter a number from 1 to $customOption."
                }
            } while (-not $validChoice)

            $WslDistroName = $newDistroName
            Write-Output "Using selected WSL distribution: $WslDistroName"
        }

        Write-Output "Please specify the absolute path on your Windows drive where the DD-WRT source code will be stored."
        Write-Output "Example: C:\DDWRT_Source"
        $promptPath = Read-Host "Enter Windows Source Code Path"
        if (-not $promptPath -or [string]::IsNullOrWhiteSpace($promptPath)) {
            Write-Error "Source code path is mandatory for WSL2 provisioning. Exiting."; return
        }
        $hostSharePath = $promptPath
        Write-Verbose "Using Windows host path for source code: $hostSharePath"
    }
}

# Recalculate derived variable now that $SshUser is finalized
$wslSourceMountPoint = "/home/$SshUser/$hostShareName"


switch ($Environment) {
    'HyperV' {
        Invoke-HyperVProvisioning -VmName $vmName `
            -VhdFolder $vhdFolder -VhdPath $vhdPath -IsoPath $isoPath -HostShareName $hostShareName `
            -HostSharePath $hostSharePath -SshUser $SshUser -SshHost $SshHost -SshKeyPath $SshKeyPath `
            -PubKeyPath $PubKeyPath -HostForVm $HostForVm -DefaultNewAdapterName $defaultNewAdapterName `
            -SmbUsername $SmbUsername -SmbPasswordSecure $SmbPasswordSecure -SmbPasswordPlain $SmbPasswordPlain `
            -VhdSize $vhdSize -CpuCount $cpuCount -Ram $ram -RamDynamic $ramDynamic -RamMin $ramMin `
            -RamMax $ramMax -AutoProvision:$AutoProvision -DryRun:$DryRun
    }
    'WSL2' {
        Invoke-WSL2Provisioning -DistroName $WslDistroName `
            -LinuxUser $SshUser -HostShareName $hostShareName -HostSharePath $hostSharePath `
            -PubKeyPath $PubKeyPath -WslSourceMountPoint $wslSourceMountPoint -AutoProvision:$AutoProvision -DryRun:$DryRun
    }
    default {
        Write-Error "Invalid Environment specified: $Environment. Must be 'HyperV' or 'WSL2'."
        exit 1
    }
}

#endregion
#==================================================================#
#region * Final notes *
Write-Output "Script execution finished."
#endregion
#==================================================================#
