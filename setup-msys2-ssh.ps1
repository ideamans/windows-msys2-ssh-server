# Windows MSYS2 + SSH Setup Script
# Run with Administrator privileges

param(
    [string]$InstallPath = "C:\msys64",
    [string]$Username = $env:USERNAME,
    [switch]$SkipFirewall
)

# Color output function
function Write-ColorOutput($ForegroundColor) {
    $fc = $host.UI.RawUI.ForegroundColor
    $host.UI.RawUI.ForegroundColor = $ForegroundColor
    if ($args) {
        Write-Output $args
    }
    $host.UI.RawUI.ForegroundColor = $fc
}

Write-ColorOutput Green "=== Windows MSYS2 + SSH Auto Setup ==="

# Check administrator privileges
if (-NOT ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
    Write-ColorOutput Red "This script must be run as Administrator"
    Write-ColorOutput Yellow "Please run PowerShell as Administrator and execute this script again"
    exit 1
}

# 1. Install MSYS2
Write-ColorOutput Yellow "`n[1/5] Installing MSYS2"

# Check for existing MSYS2 installations in common locations
$possiblePaths = @("C:\msys64", "C:\msys2", "C:\tools\msys64", "$env:ProgramFiles\msys64")
$foundPath = $null
foreach ($path in $possiblePaths) {
    if (Test-Path "$path\msys2_shell.cmd") {
        $foundPath = $path
        break
    }
}

if ($foundPath -and $foundPath -ne $InstallPath) {
    Write-ColorOutput Yellow "Found existing MSYS2 installation at: $foundPath"
    $response = Read-Host "Use this installation instead? (Y/N)"
    if ($response -eq 'Y' -or $response -eq 'y') {
        $InstallPath = $foundPath
    }
}

if (Test-Path $InstallPath) {
    Write-ColorOutput Cyan "MSYS2 is already installed at: $InstallPath"
} else {
    # Download MSYS2 installer
    $msys2Url = "https://github.com/msys2/msys2-installer/releases/download/nightly-x86_64/msys2-x86_64-latest.exe"
    $installerPath = "$env:TEMP\msys2-installer.exe"
    
    Write-ColorOutput White "Downloading MSYS2..."
    Invoke-WebRequest -Uri $msys2Url -OutFile $installerPath -UseBasicParsing
    
    Write-ColorOutput White "Installing MSYS2..."
    # Run installer with proper arguments
    $installProcess = Start-Process -FilePath $installerPath -ArgumentList @("--root", $InstallPath, "--confirm-command", "--accept-messages") -PassThru -Wait
    
    if ($installProcess.ExitCode -ne 0) {
        Write-ColorOutput Red "MSYS2 installation failed with exit code: $($installProcess.ExitCode)"
        Write-ColorOutput Yellow "Trying alternative installation method..."
        # Try running without arguments for interactive install
        Start-Process -FilePath $installerPath -Wait
    }
    
    # Verify installation
    if (-not (Test-Path "$InstallPath\msys2_shell.cmd")) {
        Write-ColorOutput Red "MSYS2 installation failed. msys2_shell.cmd not found."
        Write-ColorOutput Yellow "Please install MSYS2 manually from https://www.msys2.org/"
        exit 1
    }
    
    # Initial launch and update
    Write-ColorOutput White "Initializing MSYS2..."
    try {
        & "$InstallPath\msys2_shell.cmd" -defterm -no-start -ucrt64 -c "pacman -Syu --noconfirm"
        Start-Sleep -Seconds 5
        & "$InstallPath\msys2_shell.cmd" -defterm -no-start -ucrt64 -c "pacman -Su --noconfirm"
        
        # Install basic development tools
        Write-ColorOutput White "Installing development tools..."
        & "$InstallPath\msys2_shell.cmd" -defterm -no-start -ucrt64 -c "pacman -S --noconfirm base-devel mingw-w64-ucrt-x86_64-toolchain git vim"
    } catch {
        Write-ColorOutput Yellow "Failed to run initial setup. This might be normal on first install."
        Write-ColorOutput Yellow "You may need to run 'pacman -Syu' manually in MSYS2."
    }
    
    Remove-Item $installerPath -Force
}

# Add to PATH
$ucrtBinPath = "$InstallPath\ucrt64\bin"
$msysBinPath = "$InstallPath\usr\bin"
$currentPath = [Environment]::GetEnvironmentVariable("Path", "Machine")
if ($currentPath -notlike "*$ucrtBinPath*") {
    [Environment]::SetEnvironmentVariable("Path", "$currentPath;$ucrtBinPath;$msysBinPath", "Machine")
    Write-ColorOutput Green "Added to PATH"
}

# 2. Install OpenSSH Server
Write-ColorOutput Yellow "`n[2/5] Installing OpenSSH Server"

# Function to download and install OpenSSH manually
function Install-OpenSSHManually {
    Write-ColorOutput White "Attempting manual OpenSSH installation..."
    
    $opensshUrl = "https://github.com/PowerShell/Win32-OpenSSH/releases/download/v9.5.0.0p1-Beta/OpenSSH-Win64-v9.5.0.0.msi"
    $installerPath = "$env:TEMP\OpenSSH-Win64.msi"
    
    try {
        # Download OpenSSH installer
        Write-ColorOutput White "Downloading OpenSSH from GitHub..."
        Invoke-WebRequest -Uri $opensshUrl -OutFile $installerPath -UseBasicParsing
        
        # Install using MSI
        Write-ColorOutput White "Installing OpenSSH..."
        $installArgs = @(
            "/i",
            "`"$installerPath`"",
            "/quiet",
            "/norestart",
            "ADDLOCAL=Server"
        )
        Start-Process -FilePath "msiexec.exe" -ArgumentList $installArgs -Wait -NoNewWindow
        
        # Clean up installer
        Remove-Item $installerPath -Force -ErrorAction SilentlyContinue
        
        return $true
    } catch {
        Write-ColorOutput Red "Manual installation failed: $_"
        return $false
    }
}

# Check if OpenSSH Server is already installed
$sshServiceExists = Get-Service -Name sshd -ErrorAction SilentlyContinue
$sshExePath = "C:\Windows\System32\OpenSSH\sshd.exe"
$sshProgramFilesPath = "C:\Program Files\OpenSSH\sshd.exe"

if ($sshServiceExists) {
    Write-ColorOutput Cyan "OpenSSH Server service already exists"
} elseif (Test-Path $sshExePath) {
    Write-ColorOutput Cyan "OpenSSH Server executable found at system location"
} elseif (Test-Path $sshProgramFilesPath) {
    Write-ColorOutput Cyan "OpenSSH Server executable found at Program Files"
} else {
    # Try to install using Windows capability
    try {
        Write-ColorOutput White "Checking Windows capability for OpenSSH Server..."
        $sshCapability = Get-WindowsCapability -Online -ErrorAction Stop | Where-Object Name -like 'OpenSSH.Server*'
        
        if ($sshCapability -and $sshCapability.State -ne "Installed") {
            Write-ColorOutput White "Installing OpenSSH Server via Windows capability..."
            $result = Add-WindowsCapability -Online -Name $sshCapability.Name -ErrorAction Stop
            
            if ($result.RestartNeeded) {
                Write-ColorOutput Yellow "Installation successful but restart is required"
            } else {
                Write-ColorOutput Green "OpenSSH Server installed successfully"
            }
        } elseif ($sshCapability -and $sshCapability.State -eq "Installed") {
            Write-ColorOutput Cyan "OpenSSH Server capability is already installed"
        } else {
            throw "OpenSSH Server capability not found"
        }
    } catch {
        Write-ColorOutput Yellow "Windows capability installation failed: $_"
        Write-ColorOutput Yellow "Attempting alternative installation method..."
        
        # Try manual installation
        if (-not (Install-OpenSSHManually)) {
            Write-ColorOutput Red "Failed to install OpenSSH Server"
            Write-ColorOutput Yellow "Please install OpenSSH Server manually from:"
            Write-ColorOutput White "  Settings > Apps > Optional Features > Add a feature > OpenSSH Server"
            Write-ColorOutput White "  Or download from: https://github.com/PowerShell/Win32-OpenSSH/releases"
            exit 1
        }
    }
}

# Configure and start SSH service
Write-ColorOutput White "Configuring SSH service..."

# Check if service exists before trying to start it
$sshService = Get-Service -Name sshd -ErrorAction SilentlyContinue

if (-not $sshService) {
    # Try to find sshd.exe and install the service
    $sshdLocations = @(
        "C:\Windows\System32\OpenSSH\sshd.exe",
        "C:\Program Files\OpenSSH\sshd.exe",
        "$env:ProgramFiles\OpenSSH\sshd.exe"
    )
    
    $sshdPath = $null
    foreach ($location in $sshdLocations) {
        if (Test-Path $location) {
            $sshdPath = $location
            break
        }
    }
    
    if ($sshdPath) {
        Write-ColorOutput White "Installing SSH service from $sshdPath..."
        try {
            & $sshdPath install
            $sshService = Get-Service -Name sshd -ErrorAction Stop
        } catch {
            Write-ColorOutput Red "Failed to install SSH service: $_"
            exit 1
        }
    } else {
        Write-ColorOutput Red "Cannot find sshd.exe to install service"
        exit 1
    }
}

# Start the service
try {
    if ($sshService.Status -ne 'Running') {
        Write-ColorOutput White "Starting SSH service..."
        Start-Service sshd -ErrorAction Stop
    } else {
        Write-ColorOutput Cyan "SSH service is already running"
    }
    
    # Set service to automatic startup
    Set-Service -Name sshd -StartupType 'Automatic' -ErrorAction Stop
    Write-ColorOutput Green "SSH service configured to start automatically"
} catch {
    Write-ColorOutput Red "Failed to start or configure SSH service: $_"
    Write-ColorOutput Yellow "You may need to start the service manually"
}

# 3. Set MSYS2 as default shell
Write-ColorOutput Yellow "`n[3/5] Setting MSYS2 as default shell"

# Check if SSH service is running
$sshService = Get-Service -Name sshd -ErrorAction SilentlyContinue
if (-not $sshService) {
    Write-ColorOutput Red "SSH service not found. Skipping SSH configuration."
    Write-ColorOutput Yellow "Please install OpenSSH Server manually and run this script again."
} else {
    # Registry setting
    $bashPath = "$InstallPath\usr\bin\bash.exe"
    if (Test-Path $bashPath) {
        New-ItemProperty -Path "HKLM:\SOFTWARE\OpenSSH" -Name DefaultShell -Value $bashPath -PropertyType String -Force | Out-Null
        Write-ColorOutput Green "Set default shell to MSYS2"
    } else {
        Write-ColorOutput Red "MSYS2 bash.exe not found at: $bashPath"
    }

    # Configure sshd_config
    $sshdConfig = "C:\ProgramData\ssh\sshd_config"
    
    # Create config directory if it doesn't exist
    $configDir = Split-Path $sshdConfig -Parent
    if (-not (Test-Path $configDir)) {
        New-Item -ItemType Directory -Path $configDir -Force | Out-Null
        Write-ColorOutput White "Created SSH configuration directory"
    }
    
    # Check if config file exists
    if (Test-Path $sshdConfig) {
        $configContent = Get-Content $sshdConfig -Raw

        # Check and add Subsystem configuration
        if ($configContent -notmatch "Subsystem\s+msys2") {
            Add-Content -Path $sshdConfig -Value "`nSubsystem msys2 $bashPath -l"
            Write-ColorOutput Green "Added MSYS2 subsystem to sshd_config"
        }

        # Disable password authentication (public key only)
        if ($configContent -match "PasswordAuthentication yes") {
            $configContent = $configContent -replace "PasswordAuthentication yes", "PasswordAuthentication no"
            Set-Content -Path $sshdConfig -Value $configContent
            Write-ColorOutput White "Disabled password authentication (public key only)"
        }

        # Explicitly enable public key authentication
        if ($configContent -notmatch "PubkeyAuthentication yes") {
            Add-Content -Path $sshdConfig -Value "PubkeyAuthentication yes"
            Write-ColorOutput White "Enabled public key authentication"
        }

        # Restart SSH service if it's running
        if ($sshService.Status -eq 'Running') {
            try {
                Write-ColorOutput White "Restarting SSH service to apply configuration changes..."
                Restart-Service sshd -ErrorAction Stop
                Write-ColorOutput Green "SSH service restarted successfully"
            } catch {
                Write-ColorOutput Yellow "Failed to restart SSH service: $_"
                Write-ColorOutput Yellow "You may need to restart the service manually: Restart-Service sshd"
            }
        }
    } else {
        Write-ColorOutput Yellow "SSH configuration file not found at: $sshdConfig"
        Write-ColorOutput Yellow "Creating basic configuration file..."
        
        # Create a basic sshd_config
        $basicConfig = @"
# Basic OpenSSH Server Configuration
Port 22
PubkeyAuthentication yes
PasswordAuthentication no
Subsystem sftp /usr/lib/openssh/sftp-server
Subsystem msys2 $bashPath -l
"@
        Set-Content -Path $sshdConfig -Value $basicConfig
        Write-ColorOutput Green "Created basic SSH configuration"
    }
}

# 4. Firewall configuration
if (-not $SkipFirewall) {
    Write-ColorOutput Yellow "`n[4/5] Configuring firewall"
    
    $firewallRule = Get-NetFirewallRule -Name sshd -ErrorAction SilentlyContinue
    if (-not $firewallRule) {
        New-NetFirewallRule -Name sshd -DisplayName 'OpenSSH Server (sshd)' `
            -Enabled True -Direction Inbound -Protocol TCP -Action Allow -LocalPort 22
        Write-ColorOutput Green "Added firewall rule"
    } else {
        Write-ColorOutput Cyan "Firewall rule already exists"
    }
}

# 5. SSH public key setup
Write-ColorOutput Yellow "`n[5/6] Setting up SSH public key"

# Create .ssh directory
$sshDir = "$env:USERPROFILE\.ssh"
if (-not (Test-Path $sshDir)) {
    New-Item -ItemType Directory -Path $sshDir -Force | Out-Null
    Write-ColorOutput White "Created .ssh directory"
}

# Create/update authorized_keys file
$authorizedKeysPath = "$sshDir\authorized_keys"
$publicKey = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIHkmHnRJhSPn5Zd619XIwxOk9uODhL3MNOtO6FdeKXJk miyanaga@miyanaga-pro.local"

# Check existing keys
$keyExists = $false
if (Test-Path $authorizedKeysPath) {
    $existingKeys = Get-Content $authorizedKeysPath
    if ($existingKeys -contains $publicKey) {
        $keyExists = $true
        Write-ColorOutput Cyan "Public key is already registered"
    }
}

if (-not $keyExists) {
    Add-Content -Path $authorizedKeysPath -Value $publicKey
    Write-ColorOutput Green "Added public key"
}

# Set permissions for authorized_keys (important)
$acl = Get-Acl $authorizedKeysPath
$acl.SetAccessRuleProtection($true, $false)
$administratorsRule = New-Object System.Security.AccessControl.FileSystemAccessRule("Administrators", "FullControl", "Allow")
$systemRule = New-Object System.Security.AccessControl.FileSystemAccessRule("SYSTEM", "FullControl", "Allow")
$userRule = New-Object System.Security.AccessControl.FileSystemAccessRule($env:USERNAME, "Read,Write", "Allow")

$acl.SetAccessRule($administratorsRule)
$acl.SetAccessRule($systemRule)
$acl.SetAccessRule($userRule)
Set-Acl -Path $authorizedKeysPath -AclObject $acl

Write-ColorOutput Green "Set permissions for authorized_keys"

# 6. Display connection information
Write-ColorOutput Yellow "`n[6/7] Setup complete"

$ipAddresses = Get-NetIPAddress -AddressFamily IPv4 | Where-Object {
    $_.InterfaceAlias -notlike "*Loopback*" -and $_.IPAddress -notlike "169.254.*"
}

Write-ColorOutput Green "`n===== Setup Complete ====="
Write-ColorOutput White "`nConnection information:"
Write-ColorOutput Cyan "Username: $Username"
Write-ColorOutput Cyan "IP addresses:"
foreach ($ip in $ipAddresses) {
    Write-ColorOutput White "  - $($ip.IPAddress) ($($ip.InterfaceAlias))"
}

Write-ColorOutput White "`nConnect from Mac using:"
Write-ColorOutput Yellow "ssh $Username@<IP_ADDRESS>"
Write-ColorOutput Green "(Public key authentication is configured, no password needed)"

# Generate Mac-side setup script
$macScript = @"
#!/bin/bash
# Mac-side setup script

WINDOWS_IP="$($ipAddresses[0].IPAddress)"
WINDOWS_USER="$Username"

echo "=== Mac Setup ==="

# SSH configuration
mkdir -p ~/.ssh
cat >> ~/.ssh/config << EOF

Host windows-msys2
    HostName \$WINDOWS_IP
    User \$WINDOWS_USER
    RequestTTY yes
    ServerAliveInterval 60
    ServerAliveCountMax 3
EOF

echo "Added SSH configuration"

# Create aliases and scripts
mkdir -p ~/bin

# msys2 command
cat > ~/bin/msys2 << 'EOF'
#!/bin/bash
WINDOWS_HOST="windows-msys2"

if [ \$# -eq 0 ]; then
    ssh -t \$WINDOWS_HOST
else
    ssh \$WINDOWS_HOST "cd /c/Users/$Username/projects 2>/dev/null; \$*"
fi
EOF

chmod +x ~/bin/msys2

# msys2-sync command (with file sync)
cat > ~/bin/msys2-sync << 'EOF'
#!/bin/bash
PROJECT_NAME=`$(basename `$(pwd))
WINDOWS_HOST="windows-msys2"
REMOTE_PATH="/c/Users/$Username/projects/\$PROJECT_NAME"

# Initial sync
echo "Syncing project..."
ssh \$WINDOWS_HOST "mkdir -p /c/Users/$Username/projects"
rsync -av --exclude='.git' --exclude='node_modules' ./ \${WINDOWS_HOST}:\${REMOTE_PATH}/

# File watching and auto sync
if command -v fswatch &> /dev/null; then
    echo "Starting file watch..."
    fswatch -o . | while read f; do
        rsync -av --exclude='.git' --exclude='node_modules' ./ \${WINDOWS_HOST}:\${REMOTE_PATH}/
    done &
    SYNC_PID=\$!
    trap "kill \$SYNC_PID 2>/dev/null" EXIT
else
    echo "fswatch not installed. Auto-sync disabled."
    echo "To install: brew install fswatch"
fi

# Start MSYS2 shell
ssh -t \$WINDOWS_HOST "cd \$REMOTE_PATH && bash"
EOF

chmod +x ~/bin/msys2-sync

# Add to PATH
if [[ ":`$PATH:" != *":`$HOME/bin:"* ]]; then
    echo 'export PATH="`$HOME/bin:`$PATH"' >> ~/.zshrc
    echo 'export PATH="`$HOME/bin:`$PATH"' >> ~/.bash_profile
fi

echo ""
echo "===== Setup Complete ====="
echo ""
echo "Usage:"
echo "  msys2              - Connect to MSYS2 shell"
echo "  msys2 <command>    - Execute command"
echo "  msys2-sync         - Start MSYS2 with file sync"
echo ""
echo "First connection:"
echo "  ssh windows-msys2"
echo ""
echo "Note: Install fswatch to enable auto-sync:"
echo "  brew install fswatch"
"@

$macScriptPath = "$env:USERPROFILE\Desktop\setup-mac.sh"
$macScript | Out-File -FilePath $macScriptPath -Encoding UTF8
Write-ColorOutput White "`nGenerated Mac setup script:"
Write-ColorOutput Yellow $macScriptPath

Write-ColorOutput Green "`nAll setup complete!"

# 7. Create MSYS2 Terminal shortcuts and PATH setup
Write-ColorOutput Yellow "`n[7/7] Setting up MSYS2 terminal access"

# Check if MSYS2 executables exist
if (-not (Test-Path "$InstallPath\ucrt64.exe")) {
    Write-ColorOutput Yellow "MSYS2 executables not found. Checking alternative locations..."
    
    # Try using msys2_shell.cmd instead
    if (Test-Path "$InstallPath\msys2_shell.cmd") {
        # Create desktop shortcut for MSYS2 using shell command
        $desktopPath = [Environment]::GetFolderPath("Desktop")
        $shortcutPath = "$desktopPath\MSYS2 UCRT64.lnk"
        
        try {
            $WshShell = New-Object -ComObject WScript.Shell
            $Shortcut = $WshShell.CreateShortcut($shortcutPath)
            $Shortcut.TargetPath = "cmd.exe"
            $Shortcut.Arguments = "/c `"$InstallPath\msys2_shell.cmd`" -ucrt64"
            $Shortcut.WorkingDirectory = "$env:USERPROFILE"
            $Shortcut.IconLocation = "$InstallPath\msys2.ico,0"
            $Shortcut.Description = "MSYS2 UCRT64 Terminal"
            $Shortcut.Save()
            Write-ColorOutput Green "Created desktop shortcut: MSYS2 UCRT64"
        } catch {
            Write-ColorOutput Yellow "Failed to create desktop shortcut: $_"
        }
    } else {
        Write-ColorOutput Red "MSYS2 installation appears incomplete. Cannot create shortcuts."
    }
} else {
    # Create desktop shortcut for MSYS2 UCRT64
    $desktopPath = [Environment]::GetFolderPath("Desktop")
    $shortcutPath = "$desktopPath\MSYS2 UCRT64.lnk"
    
    try {
        $WshShell = New-Object -ComObject WScript.Shell
        $Shortcut = $WshShell.CreateShortcut($shortcutPath)
        $Shortcut.TargetPath = "$InstallPath\ucrt64.exe"
        $Shortcut.WorkingDirectory = "$env:USERPROFILE"
        $Shortcut.IconLocation = "$InstallPath\ucrt64.exe,0"
        $Shortcut.Description = "MSYS2 UCRT64 Terminal"
        $Shortcut.Save()
        Write-ColorOutput Green "Created desktop shortcut: MSYS2 UCRT64"
    } catch {
        Write-ColorOutput Yellow "Failed to create desktop shortcut: $_"
    }
}

# Create Start Menu shortcuts if msys2_shell.cmd exists
if (Test-Path "$InstallPath\msys2_shell.cmd") {
    $startMenuPath = "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\MSYS2"
    if (-not (Test-Path $startMenuPath)) {
        New-Item -ItemType Directory -Path $startMenuPath -Force | Out-Null
    }
    
    try {
        # UCRT64 shortcut
        $Shortcut = $WshShell.CreateShortcut("$startMenuPath\MSYS2 UCRT64.lnk")
        $Shortcut.TargetPath = "cmd.exe"
        $Shortcut.Arguments = "/c `"$InstallPath\msys2_shell.cmd`" -ucrt64"
        $Shortcut.WorkingDirectory = "$env:USERPROFILE"
        if (Test-Path "$InstallPath\msys2.ico") {
            $Shortcut.IconLocation = "$InstallPath\msys2.ico,0"
        }
        $Shortcut.Description = "MSYS2 UCRT64 Terminal"
        $Shortcut.Save()
        
        # MINGW64 shortcut
        $Shortcut = $WshShell.CreateShortcut("$startMenuPath\MSYS2 MINGW64.lnk")
        $Shortcut.TargetPath = "cmd.exe"
        $Shortcut.Arguments = "/c `"$InstallPath\msys2_shell.cmd`" -mingw64"
        $Shortcut.WorkingDirectory = "$env:USERPROFILE"
        if (Test-Path "$InstallPath\msys2.ico") {
            $Shortcut.IconLocation = "$InstallPath\msys2.ico,0"
        }
        $Shortcut.Description = "MSYS2 MINGW64 Terminal"
        $Shortcut.Save()
        
        # MSYS shortcut
        $Shortcut = $WshShell.CreateShortcut("$startMenuPath\MSYS2 MSYS.lnk")
        $Shortcut.TargetPath = "cmd.exe"
        $Shortcut.Arguments = "/c `"$InstallPath\msys2_shell.cmd`" -msys"
        $Shortcut.WorkingDirectory = "$env:USERPROFILE"
        if (Test-Path "$InstallPath\msys2.ico") {
            $Shortcut.IconLocation = "$InstallPath\msys2.ico,0"
        }
        $Shortcut.Description = "MSYS2 MSYS Terminal"
        $Shortcut.Save()
        
        Write-ColorOutput Green "Created Start Menu shortcuts"
    } catch {
        Write-ColorOutput Yellow "Failed to create Start Menu shortcuts: $_"
    }
}

# Add MSYS2 to PATH
$msys2BinPaths = @(
    "$InstallPath\usr\bin",
    "$InstallPath\ucrt64\bin",
    "$InstallPath\mingw64\bin"
)

$currentPath = [Environment]::GetEnvironmentVariable("PATH", "User")
$pathUpdated = $false

foreach ($binPath in $msys2BinPaths) {
    if ($currentPath -notlike "*$binPath*") {
        $currentPath = "$binPath;$currentPath"
        $pathUpdated = $true
        Write-ColorOutput White "Added to PATH: $binPath"
    }
}

if ($pathUpdated) {
    [Environment]::SetEnvironmentVariable("PATH", $currentPath, "User")
    Write-ColorOutput Green "Updated user PATH environment variable"
    Write-ColorOutput Yellow "Please restart your terminal or log out/in for PATH changes to take effect"
}

# Create a batch file for easy MSYS2 terminal launch
$msys2CmdPath = "$env:USERPROFILE\msys2.cmd"
if (Test-Path "$InstallPath\msys2_shell.cmd") {
    $msys2CmdContent = @"
@echo off
"$InstallPath\msys2_shell.cmd" -ucrt64
"@
} else {
    $msys2CmdContent = @"
@echo off
echo MSYS2 not found at $InstallPath
echo Please install MSYS2 from https://www.msys2.org/
pause
"@
}
Set-Content -Path $msys2CmdPath -Value $msys2CmdContent
Write-ColorOutput Green "Created quick launch command: $msys2CmdPath"

# Add to user PATH for easy access
$userPath = [Environment]::GetEnvironmentVariable("PATH", "User")
$userProfilePath = $env:USERPROFILE
if ($userPath -notlike "*$userProfilePath*") {
    [Environment]::SetEnvironmentVariable("PATH", "$userProfilePath;$userPath", "User")
    Write-ColorOutput Green "Added user profile to PATH for msys2.cmd access"
}

Write-ColorOutput Cyan "`nYou can now launch MSYS2 terminal using:"

# Check desktop shortcut
$desktopPath = [Environment]::GetFolderPath("Desktop")
if (Test-Path "$desktopPath\MSYS2 UCRT64.lnk") {
    Write-ColorOutput White "  - Desktop shortcut: MSYS2 UCRT64"
}

# Check Start Menu shortcuts
$startMenuPath = "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\MSYS2"
if (Test-Path $startMenuPath) {
    Write-ColorOutput White "  - Start Menu: MSYS2 > MSYS2 UCRT64"
}

# Command line access
Write-ColorOutput White "  - Command Prompt/PowerShell: msys2"

# Direct access
if (Test-Path "$InstallPath\msys2_shell.cmd") {
    Write-ColorOutput White "  - Direct: $InstallPath\msys2_shell.cmd -ucrt64"
}

# Check MSYS2 installation status
Write-ColorOutput Yellow "`nMSYS2 Installation Status:"
if (Test-Path "$InstallPath\msys2_shell.cmd") {
    Write-ColorOutput Green "  MSYS2 shell script found at: $InstallPath\msys2_shell.cmd"
} else {
    Write-ColorOutput Red "  MSYS2 not found at: $InstallPath"
    Write-ColorOutput Yellow "  Please install MSYS2 manually from https://www.msys2.org/"
    Write-ColorOutput Yellow "  After installation, run this script again to complete setup."
}