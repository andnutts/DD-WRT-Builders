# Ubuntu DD‑WRT build VM setup for Hyper-V
# Creates VM, configures CPU/RAM/disk, selects or creates an External virtual switch,
# attaches the VM NIC (prompts for adapter name only when adding), boots the VM once
# to obtain the assigned MAC, then locks that MAC as static.
#==================================================================#
#region * Parameters *
[CmdletBinding()] # Add CmdletBinding for common parameters like -Verbose
param(
    [switch]$DryRun,
    [switch]$Verbose,
    [switch]$AutoProvision,        # if set, attempt automated provisioning via SSH
    [string]$SshUser = "build",    # SSH user to connect as for AutoProvision
    [string]$SshHost = "",         # replace with VM IP or hostname (script will prompt if empty)
    [string]$SshKeyPath = $null,   # optional path to private key for SSH; if null uses default ssh agent/keys
    [string]$PubKeyPath = "",      # optional path to public key to install on VM (defaults to $env:USERPROFILE\.ssh\id_rsa.pub)
    [string]$HostForVm = "",       # Windows host IP/name as reachable from VM for SMB mount
    [string]$hostShareName = "ddwrt-src", # SMB share name on host
    [string]$hostSharePath = "",   # path on host for SMB share (defaults to $vhdFolder\$hostShareName)
    [string]$SmbUsername = "",     # SMB username (if empty script will prompt)
    [string]$SmbPasswordPlain = "",# SMB password plain (or use $SmbPasswordSecure)
    [System.Security.SecureString]$SmbPasswordSecure = $null, # optional secure string password
    [string]$defaultNewAdapterName = $null
)
#endregion
#==================================================================#
#region * User-configurable variables *
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

$defaultNewAdapterName = $null
#endregion
#==================================================================#
#region * Helper functions *
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
        if ($Verbose) { Write-Verbose "Executing: $Description" }
        try {
            & $Action
        } catch {
            Write-Error "Action failed: $Description`nError: $_"
            throw # Re-throwing the error stops the script, preventing further failures
        }
    }
}

function Test-SshAvailable {
    return (Get-Command ssh -ErrorAction SilentlyContinue) -ne $null
}
#endregion
#==================================================================#
#region * Create VHD folder and VHD if missing *
Exec -Action {
    New-Item -ItemType Directory -Path (Split-Path $vhdPath) -Force -ErrorAction Stop | Out-Null
} -Description "Create folder $(Split-Path $vhdPath)"

if (-not (Test-Path $vhdPath)) {
    Exec -Action { New-VHD -Path $vhdPath -SizeBytes $vhdSize -Dynamic -ErrorAction Stop | Out-Null } -Description "Create VHD at $vhdPath ($vhdSize)"
} else {
    Write-Verbose "VHD already exists at $vhdPath"
}
#endregion
#==================================================================#
#region * Create VM if it doesn't exist *
if (-not (Get-VM -Name $vmName -ErrorAction SilentlyContinue)) {
    Exec -Action {
        New-VM -Name $vmName -MemoryStartupBytes $ram -Generation 2 -NewVHDPath $vhdPath -NewVHDSizeBytes $vhdSize -ErrorAction Stop | Out-Null
        Set-VMProcessor -VMName $vmName -Count $cpuCount -ErrorAction Stop
        Add-VMDvdDrive -VMName $vmName -Path $isoPath -ErrorAction Stop | Out-Null
        Set-VMFirmware -VMName $vmName -EnableSecureBoot Off -ErrorAction Stop
    } -Description "Create VM $vmName with $cpuCount CPUs, $ram RAM and VHD $vhdPath"
} else {
    Write-Verbose "VM $vmName already exists"
}
#endregion
#==================================================================#
#region * Memory configuration (static or dynamic) *
if ($ramDynamic -eq $false) {
    Exec -Action { Set-VMMemory -VMName $vmName -DynamicMemory $false -StartupBytes $ram -MinimumBytes $ram -MaximumBytes $ram -ErrorAction Stop } -Description "Set static memory $ram for $vmName"
} else {
    Exec -Action { Set-VMMemory -VMName $vmName -DynamicMemory $true -StartupBytes $ram -MinimumBytes $ramMin -MaximumBytes $ramMax -ErrorAction Stop } -Description "Enable DynamicMemory for $vmName (Startup:$ram Min:$ramMin Max:$ramMax)"
}
#endregion
#==================================================================#
#region * Select or create External virtual switch *
$externalSwitches = Get-VMSwitch | Where-Object { $_.SwitchType -eq 'External' }

if ($externalSwitches.Count -eq 1) {
    $switchName = $externalSwitches[0].Name
    Write-Verbose "Using external switch: $switchName"
}
elseif ($externalSwitches.Count -gt 1) {
    Write-Output "Multiple external switches found. Choose one by number:"
    for ($i = 0; $i -lt $externalSwitches.Count; $i++) {
        $idx = $i + 1
        $sw = $externalSwitches[$i]
        $desc = $sw.NetAdapterInterfaceDescription -join ';'
        Write-Output ("{0}. {1} (Adapter: {2})" -f $idx, $sw.Name, $desc)
    }
    $selection = Read-Host "Enter number (1..$($externalSwitches.Count))"
    if (-not [int]::TryParse($selection, [ref]$null)) { Write-Error "Invalid selection. Exiting."; return }
    $selIndex = [int]$selection - 1
    if ($selIndex -lt 0 -or $selIndex -ge $externalSwitches.Count) { Write-Error "Selection out of range. Exiting."; return }
    $switchName = $externalSwitches[$selIndex].Name
    Write-Verbose "Selected external switch: $switchName"
}
else {
    Write-Output "No external virtual switches found."
    $create = Read-Host "Create an external switch now? (Y/N)"
    if ($create -match '^[Yy]') {
        $newName = Read-Host "Enter name for new external switch"
        $netAdapter = Read-Host "Enter host network adapter name to bind (use Get-NetAdapter to list)"
        try {
            Exec -Action { New-VMSwitch -Name $newName -NetAdapterName $netAdapter -AllowManagementOS $true -ErrorAction Stop | Out-Null } -Description "Create external switch $newName bound to adapter $netAdapter"
            $switchName = $newName
            Write-Verbose "Created external switch: $switchName"
        } catch {
            Write-Error "Failed to create switch: $($_.Exception.Message)"; return
        }
    } else {
        Write-Output "No external switch selected. Please create or configure a switch and re-run the script."; return
    }
}
#endregion
#==================================================================#
#region * Attach or connect VM network adapter to chosen switch *
$vmAdapters = Get-VMNetworkAdapter -VMName $vmName -ErrorAction SilentlyContinue
if (-not $vmAdapters) {
    # Only prompt when adding a new adapter
    if ($null -ne $defaultNewAdapterName -and -not [string]::IsNullOrWhiteSpace($defaultNewAdapterName)) {
        $newAdapterName = $defaultNewAdapterName
    } else {
        $promptName = Read-Host "Enter a name for the VM network adapter to add (example: 'Network Adapter')"
        if (-not $promptName -or [string]::IsNullOrWhiteSpace($promptName)) {
            Write-Error "No adapter name provided. Exiting."; return
        }
        $newAdapterName = $promptName
    }

    Exec -Action { Add-VMNetworkAdapter -VMName $vmName -Name $newAdapterName -ErrorAction Stop | Out-Null } -Description "Add network adapter '$newAdapterName' to VM $vmName"
    Exec -Action { Connect-VMNetworkAdapter -VMName $vmName -Name $newAdapterName -SwitchName $switchName -ErrorAction Stop } -Description "Connect adapter '$newAdapterName' to switch '$switchName'"
    $adapterName = $newAdapterName
    Write-Verbose "Added adapter '$adapterName' and connected to switch '$switchName'"
} else {
    $adapter = $vmAdapters | Select-Object -First 1
    $adapterName = $adapter.Name
    Exec -Action { Connect-VMNetworkAdapter -VMName $vmName -Name $adapterName -SwitchName $switchName -ErrorAction SilentlyContinue } -Description "Connect existing adapter '$adapterName' to switch '$switchName'"
    Write-Verbose "Connected existing adapter '$adapterName' to switch '$switchName'"
}
#endregion
#==================================================================#
#region * Start VM and wait until running to let Hyper-V assign a MAC *
$vm = Get-VM -Name $vmName
if ($vm.State -ne 'Running') {
    Exec -Action { Start-VM -Name $vmName -ErrorAction Stop | Out-Null } -Description "Start VM $vmName"
    while ((Get-VM -Name $vmName).State -ne 'Running') {
        Write-Verbose "Waiting for VM to reach Running state..."
        Start-Sleep -Seconds 1
    }
    Start-Sleep -Seconds 2
}
#endregion
#==================================================================#
#region * Read current MAC as reported by Hyper-V *
$adapterObj = Get-VMNetworkAdapter -VMName $vmName -Name $adapterName
$currentMacRaw = $adapterObj.MacAddress
$formattedMac = Format-MacDashed -macRaw $currentMacRaw
Write-Output "Observed MAC for adapter '$adapterName': $formattedMac"
#endregion
#==================================================================#
#region * Stop VM before setting static MAC *
Exec -Action { Stop-VM -Name $vmName -Force -ErrorAction Stop } -Description "Stop VM $vmName"
while ((Get-VM -Name $vmName).State -ne 'Off') {
    Write-Verbose "Waiting for VM to stop..."
    Start-Sleep -Seconds 1
}
#endregion
#==================================================================#
#region * Apply static MAC if not already set *
$existing = Get-VMNetworkAdapter -VMName $vmName -Name $adapterName
$existingMacDashed = Format-MacDashed -macRaw $existing.MacAddress
if ($existing.StaticMacAddress -and ($existingMacDashed -eq $formattedMac)) {
    Write-Output "Static MAC already set to $formattedMac"
} else {
    Exec -Action { Set-VMNetworkAdapter -VMName $vmName -Name $adapterName -StaticMacAddress $formattedMac -ErrorAction Stop } -Description "Set static MAC $formattedMac for adapter '$adapterName'"
    Write-Output "Set static MAC to $formattedMac for adapter '$adapterName'"
}
#endregion
#==================================================================#
#region * Start VM again *
Exec -Action { Start-VM -Name $vmName -ErrorAction Stop } -Description "Start VM $vmName"
Write-Output "VM '$vmName' started with adapter '$adapterName' on switch '$switchName' and MAC locked to $formattedMac"
#endregion
#==================================================================#
#region * Provision SSH inside VM (non-interactive with interactive fallback) *
if ($AutoProvision) {
    if (-not (Test-SshAvailable)) {
        Write-Warning "SSH client not found on host. Skipping AutoProvision SSH bootstrap."
    } else {
        if (-not $SshHost -or [string]::IsNullOrWhiteSpace($SshHost)) {
            Write-Output "Waiting for VM to boot and get an IP via Guest Services..."
            $vmIp = $null
            $timeout = (Get-Date).AddMinutes(5)
            while ((-not $vmIp) -and ((Get-Date) -lt $timeout)) {
                Start-Sleep -Seconds 5
                $vmObj = Get-VM -Name $vmName
                if ($vmObj.GuestServicesStatus -ne 'Ok') {
                    Write-Verbose "Waiting for Guest Services..."
                    continue
                }
                $ipAddresses = (Get-VMNetworkAdapter -VMName $vmName -Name $adapterName).IPAddresses
                # Find the first valid, non-loopback IPv4 address
                $vmIp = $ipAddresses | Where-Object { $_ -match '^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$' -and $_ -ne '127.0.0.1' } | Select-Object -First 1

                if ($vmIp) {
                    Write-Output "Discovered VM IP: $vmIp"
                    $SshHost = $vmIp
                } else {
                    Write-Verbose "No IPv4 address found yet... (IPs: $($ipAddresses -join ', '))"
                }
            }
            if (-not $vmIp) {
                Write-Error "Failed to get VM IP address via Guest Services within 5 minutes. Stopping."
                return
            }
            #$SshHost = Read-Host "Enter VM IP or hostname for SSH provisioning"
        }
        if (-not $SshUser -or [string]::IsNullOrWhiteSpace($SshUser)) { $SshUser = "ubuntu" }

        if (-not $PubKeyPath -or [string]::IsNullOrWhiteSpace($PubKeyPath)) {
            $PubKeyPath = Join-Path $env:USERPROFILE ".ssh\id_rsa.pub"
        }
        if (Test-Path $PubKeyPath) {
            $pubKey = Get-Content $PubKeyPath -Raw
        } else {
            $pubKey = ""
            Write-Warning "Public key not found at $PubKeyPath. The bootstrap will still run but key won't be installed."
        }

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

        $safePub = $pubKey -replace '\$','`$'
        $bootstrapScript = $bootstrapScript -replace '__PUBKEY__', ($safePub -replace "`r`n", "`n")

        $sshArgs = @()
        if ($SshKeyPath) { $sshArgs += "-i"; $sshArgs += $SshKeyPath }
        $sshArgs += "-o"; $sshArgs += "StrictHostKeyChecking=no"
        $sshArgs += "$SshUser@$SshHost"

        Write-Verbose "Waiting for SSH to be available on $SshHost..."
        $sshReady = $false
        $timeout = (Get-Date).AddMinutes(2)
        while ((-not $sshReady) -and ((Get-Date) -lt $timeout)) {
            try {
                ssh $sshArgs -o ConnectTimeout=5 "exit" 2>$null
                $sshReady = $true
                Write-Verbose "SSH connection successful."
            } catch {
                Write-Verbose "SSH not ready, retrying..."
                Start-Sleep -Seconds 5
            }
        }
        if (-not $sshReady) {
            Write-Error "SSH connection to $SshHost timed out. Stopping."
            return
        }

        Exec -Action {
            $startInfo = New-Object System.Diagnostics.ProcessStartInfo
            $startInfo.FileName = "ssh"
            $startInfo.Arguments = $sshArgs -join ' '
            $startInfo.RedirectStandardInput = $true
            $startInfo.UseShellExecute = $false
            $startInfo.CreateNoWindow = $true
            $proc = [System.Diagnostics.Process]::Start($startInfo)
            $proc.StandardInput.Write($bootstrapScript)
            $proc.StandardInput.Close()
            $proc.WaitForExit()
            if ($proc.ExitCode -ne 0) { throw "SSH bootstrap failed with exit code $($proc.ExitCode)" }
        } -Description "Bootstrap SSH, create build user, install pubkey on $SshHost"
    }
}
#endregion
#==================================================================#
#region * Create SMB share on host (non-interactive with interactive fallback) *
if (-not $hostSharePath -or [string]::IsNullOrWhiteSpace($hostSharePath)) { $hostSharePath = Join-Path $vhdFolder $hostShareName }

Exec -Action {
    New-Item -ItemType Directory -Path $hostSharePath -Force -ErrorAction Stop | Out-Null
} -Description "Create host share folder $hostSharePath"

if ($AutoProvision) {
    Exec -Action {
        try {
            if (Get-SmbShare -Name $hostShareName -ErrorAction SilentlyContinue) {
                Remove-SmbShare -Name $hostShareName -Force -ErrorAction Stop
            }
            New-SmbShare -Name $hostShareName -Path $hostSharePath -FullAccess $SmbUsername -ErrorAction Stop
        } catch {
            throw "Failed to create SMB share. Run script as Administrator or create share manually. $_"
        }
    } -Description "Create SMB share '$hostShareName' at $hostSharePath"
}
#endregion
#==================================================================#
#region * Mount SMB share inside VM (non-interactive with interactive fallback) *
if ($AutoProvision) {
    if (-not (Test-SshAvailable)) {
        Write-Warning "SSH client not found on host. Skipping SMB mount inside VM."
    } else {
        if (-not $SshHost -or [string]::IsNullOrWhiteSpace($SshHost)) {
            $SshHost = Read-Host "Enter VM IP or hostname for SSH provisioning"
        }

        if (-not $HostForVm -or [string]::IsNullOrWhiteSpace($HostForVm)) {
            $HostForVm = Read-Host "Enter Windows host IP or name as reachable from VM (example: 192.168.1.10)"
        }

        if (-not $SmbUsername -or [string]::IsNullOrWhiteSpace($SmbUsername)) {
            $SmbUsername = Read-Host "Enter Windows share username"
        }

        if ($null -eq $SmbPasswordPlain -or [string]::IsNullOrWhiteSpace($SmbPasswordPlain)) {
            if ($SmbPasswordSecure) {
                $SmbPasswordPlain = [Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR($SmbPasswordSecure))
            } else {
                $secure = Read-Host -AsSecureString "Enter password for $SmbUsername"
                $SmbPasswordPlain = [Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR($secure))
            }
        }
        # SECURITY WARNING: The plain text password is being embedded in the script below.
        # A more secure alternative is to use SSHFS, which leverages the SSH key
        # you've already set up, avoiding passwords entirely.
        # Example SSHFS commands for the VM:
        # sudo apt install -y sshfs
        # sudo mkdir -p /srv/ddwrt-src
        # sudo sshfs -o allow_other,default_permissions,identityfile=/home/build/.ssh/id_rsa $SshUser@$HostForVm:$hostSharePath /srv/ddwrt-src
        # (This would require the 'build' user on the VM to have its own key authorized on the *host*)

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

        $vmMountScript = $vmMountScript -replace '__HOST__', $HostForVm
        $vmMountScript = $vmMountScript -replace '__SHARE__', $hostShareName
        $vmMountScript = $vmMountScript -replace '__SMBUSER__', ($SmbUsername -replace '\$','`$')
        $vmMountScript = $vmMountScript -replace '__SMBPASS__', ($SmbPasswordPlain -replace '\$','`$')

        $sshArgs = @()
        if ($SshKeyPath) { $sshArgs += "-i"; $sshArgs += $SshKeyPath }
        $sshArgs += "-o"; $sshArgs += "StrictHostKeyChecking=no"
        $sshArgs += "$SshUser@$SshHost"

        Exec -Action {
            $startInfo = New-Object System.Diagnostics.ProcessStartInfo
            $startInfo.FileName = "ssh"
            $startInfo.Arguments = $sshArgs -join ' '
            $startInfo.RedirectStandardInput = $true
            $startInfo.UseShellExecute = $false
            $startInfo.CreateNoWindow = $true
            $proc = [System.Diagnostics.Process]::Start($startInfo)
            $proc.StandardInput.Write($vmMountScript)
            $proc.StandardInput.Close()
            $proc.WaitForExit()
            if ($proc.ExitCode -ne 0) { throw "SMB mount script failed with exit code $($proc.ExitCode)" }
        } -Description "Install cifs-utils and mount host SMB share //${HostForVm}/${hostShareName} inside VM at /srv/ddwrt-src"
    }
}
#endregion
#==================================================================#
#region * Final notes *
Write-Output "Script completed. If AutoProvision was used, confirm SSH connectivity and that /srv/ddwrt-src is mounted inside the VM."
#endregion
#==================================================================#
