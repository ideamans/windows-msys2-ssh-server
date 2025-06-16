# Windows MSYS2 + SSH セットアップスクリプト
# 管理者権限で実行してください

param(
    [string]$InstallPath = "C:\msys64",
    [string]$Username = $env:USERNAME,
    [switch]$SkipFirewall
)

# 色付き出力
function Write-ColorOutput($ForegroundColor) {
    $fc = $host.UI.RawUI.ForegroundColor
    $host.UI.RawUI.ForegroundColor = $ForegroundColor
    if ($args) {
        Write-Output $args
    }
    $host.UI.RawUI.ForegroundColor = $fc
}

Write-ColorOutput Green "=== Windows MSYS2 + SSH 自動セットアップ ==="

# 管理者権限チェック
if (-NOT ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
    Write-ColorOutput Red "このスクリプトは管理者権限で実行する必要があります"
    Write-ColorOutput Yellow "PowerShellを管理者として実行し、再度このスクリプトを実行してください"
    exit 1
}

# 1. MSYS2のインストール
Write-ColorOutput Yellow "`n[1/5] MSYS2のインストール"

if (Test-Path $InstallPath) {
    Write-ColorOutput Cyan "MSYS2は既にインストールされています: $InstallPath"
} else {
    # MSYS2インストーラーのダウンロード
    $msys2Url = "https://github.com/msys2/msys2-installer/releases/download/nightly-x86_64/msys2-x86_64-latest.exe"
    $installerPath = "$env:TEMP\msys2-installer.exe"
    
    Write-ColorOutput White "MSYS2をダウンロード中..."
    Invoke-WebRequest -Uri $msys2Url -OutFile $installerPath -UseBasicParsing
    
    Write-ColorOutput White "MSYS2をインストール中..."
    Start-Process -FilePath $installerPath -ArgumentList "install", "--root", $InstallPath, "--confirm-command" -Wait
    
    # 初回起動と更新
    Write-ColorOutput White "MSYS2を初期化中..."
    & "$InstallPath\msys2_shell.cmd" -defterm -no-start -ucrt64 -c "pacman -Syu --noconfirm"
    Start-Sleep -Seconds 5
    & "$InstallPath\msys2_shell.cmd" -defterm -no-start -ucrt64 -c "pacman -Su --noconfirm"
    
    # 基本的な開発ツールのインストール
    Write-ColorOutput White "開発ツールをインストール中..."
    & "$InstallPath\msys2_shell.cmd" -defterm -no-start -ucrt64 -c "pacman -S --noconfirm base-devel mingw-w64-ucrt-x86_64-toolchain git vim"
    
    Remove-Item $installerPath -Force
}

# PATHに追加
$ucrtBinPath = "$InstallPath\ucrt64\bin"
$msysBinPath = "$InstallPath\usr\bin"
$currentPath = [Environment]::GetEnvironmentVariable("Path", "Machine")
if ($currentPath -notlike "*$ucrtBinPath*") {
    [Environment]::SetEnvironmentVariable("Path", "$currentPath;$ucrtBinPath;$msysBinPath", "Machine")
    Write-ColorOutput Green "PATHに追加しました"
}

# 2. OpenSSH Serverのインストール
Write-ColorOutput Yellow "`n[2/5] OpenSSH Serverのインストール"

$sshCapability = Get-WindowsCapability -Online | Where-Object Name -like 'OpenSSH.Server*'
if ($sshCapability.State -ne "Installed") {
    Write-ColorOutput White "OpenSSH Serverをインストール中..."
    Add-WindowsCapability -Online -Name OpenSSH.Server~~~~0.0.1.0
} else {
    Write-ColorOutput Cyan "OpenSSH Serverは既にインストールされています"
}

# SSHサービスの起動と自動起動設定
Write-ColorOutput White "SSHサービスを設定中..."
Start-Service sshd
Set-Service -Name sshd -StartupType 'Automatic'

# 3. MSYS2をデフォルトシェルに設定
Write-ColorOutput Yellow "`n[3/5] MSYS2をデフォルトシェルに設定"

# レジストリ設定
$bashPath = "$InstallPath\usr\bin\bash.exe"
New-ItemProperty -Path "HKLM:\SOFTWARE\OpenSSH" -Name DefaultShell -Value $bashPath -PropertyType String -Force | Out-Null
Write-ColorOutput Green "デフォルトシェルをMSYS2に設定しました"

# sshd_configの設定
$sshdConfig = "C:\ProgramData\ssh\sshd_config"
$configContent = Get-Content $sshdConfig -Raw

# Subsystemの設定を確認・追加
if ($configContent -notmatch "Subsystem\s+msys2") {
    Add-Content -Path $sshdConfig -Value "`nSubsystem msys2 $bashPath -l"
    Write-ColorOutput Green "sshd_configにMSYS2 subsystemを追加しました"
}

# パスワード認証を無効化（公開鍵認証のみに）
if ($configContent -match "PasswordAuthentication yes") {
    $configContent = $configContent -replace "PasswordAuthentication yes", "PasswordAuthentication no"
    Set-Content -Path $sshdConfig -Value $configContent
    Write-ColorOutput White "パスワード認証を無効化しました（公開鍵認証のみ）"
}

# PubkeyAuthenticationを明示的に有効化
if ($configContent -notmatch "PubkeyAuthentication yes") {
    Add-Content -Path $sshdConfig -Value "PubkeyAuthentication yes"
    Write-ColorOutput White "公開鍵認証を有効化しました"
}

# SSHサービスを再起動
Restart-Service sshd

# 4. ファイアウォール設定
if (-not $SkipFirewall) {
    Write-ColorOutput Yellow "`n[4/5] ファイアウォール設定"
    
    $firewallRule = Get-NetFirewallRule -Name sshd -ErrorAction SilentlyContinue
    if (-not $firewallRule) {
        New-NetFirewallRule -Name sshd -DisplayName 'OpenSSH Server (sshd)' `
            -Enabled True -Direction Inbound -Protocol TCP -Action Allow -LocalPort 22
        Write-ColorOutput Green "ファイアウォールルールを追加しました"
    } else {
        Write-ColorOutput Cyan "ファイアウォールルールは既に存在します"
    }
}

# 5. SSH公開鍵の設定
Write-ColorOutput Yellow "`n[5/6] SSH公開鍵の設定"

# .sshディレクトリの作成
$sshDir = "$env:USERPROFILE\.ssh"
if (-not (Test-Path $sshDir)) {
    New-Item -ItemType Directory -Path $sshDir -Force | Out-Null
    Write-ColorOutput White ".sshディレクトリを作成しました"
}

# authorized_keysファイルの作成/更新
$authorizedKeysPath = "$sshDir\authorized_keys"
$publicKey = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIHkmHnRJhSPn5Zd619XIwxOk9uODhL3MNOtO6FdeKXJk miyanaga@miyanaga-pro.local"

# 既存のキーをチェック
$keyExists = $false
if (Test-Path $authorizedKeysPath) {
    $existingKeys = Get-Content $authorizedKeysPath
    if ($existingKeys -contains $publicKey) {
        $keyExists = $true
        Write-ColorOutput Cyan "公開鍵は既に登録されています"
    }
}

if (-not $keyExists) {
    Add-Content -Path $authorizedKeysPath -Value $publicKey
    Write-ColorOutput Green "公開鍵を追加しました"
}

# authorized_keysの権限設定（重要）
$acl = Get-Acl $authorizedKeysPath
$acl.SetAccessRuleProtection($true, $false)
$administratorsRule = New-Object System.Security.AccessControl.FileSystemAccessRule("Administrators", "FullControl", "Allow")
$systemRule = New-Object System.Security.AccessControl.FileSystemAccessRule("SYSTEM", "FullControl", "Allow")
$userRule = New-Object System.Security.AccessControl.FileSystemAccessRule($env:USERNAME, "Read,Write", "Allow")

$acl.SetAccessRule($administratorsRule)
$acl.SetAccessRule($systemRule)
$acl.SetAccessRule($userRule)
Set-Acl -Path $authorizedKeysPath -AclObject $acl

Write-ColorOutput Green "authorized_keysの権限を設定しました"

# 6. 接続情報の表示
Write-ColorOutput Yellow "`n[6/6] セットアップ完了"

$ipAddresses = Get-NetIPAddress -AddressFamily IPv4 | Where-Object {
    $_.InterfaceAlias -notlike "*Loopback*" -and $_.IPAddress -notlike "169.254.*"
}

Write-ColorOutput Green "`n===== セットアップが完了しました ====="
Write-ColorOutput White "`n接続情報:"
Write-ColorOutput Cyan "ユーザー名: $Username"
Write-ColorOutput Cyan "IPアドレス:"
foreach ($ip in $ipAddresses) {
    Write-ColorOutput White "  - $($ip.IPAddress) ($($ip.InterfaceAlias))"
}

Write-ColorOutput White "`nMac側から以下のコマンドで接続できます:"
Write-ColorOutput Yellow "ssh $Username@<IPアドレス>"
Write-ColorOutput Green "(公開鍵認証が設定済みのため、パスワードは不要です)"

# Mac側のセットアップスクリプトを生成
$macScript = @"
#!/bin/bash
# Mac側のセットアップスクリプト

WINDOWS_IP="$($ipAddresses[0].IPAddress)"
WINDOWS_USER="$Username"

echo "=== Mac側のセットアップ ==="

# SSH設定
mkdir -p ~/.ssh
cat >> ~/.ssh/config << EOF

Host windows-msys2
    HostName \$WINDOWS_IP
    User \$WINDOWS_USER
    RequestTTY yes
    ServerAliveInterval 60
    ServerAliveCountMax 3
EOF

echo "SSH設定を追加しました"

# エイリアスとスクリプトの作成
mkdir -p ~/bin

# msys2コマンド
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

# msys2-syncコマンド（ファイル同期付き）
cat > ~/bin/msys2-sync << 'EOF'
#!/bin/bash
PROJECT_NAME=\$(basename \$(pwd))
WINDOWS_HOST="windows-msys2"
REMOTE_PATH="/c/Users/$Username/projects/\$PROJECT_NAME"

# 初回同期
echo "プロジェクトを同期中..."
ssh \$WINDOWS_HOST "mkdir -p /c/Users/$Username/projects"
rsync -av --exclude='.git' --exclude='node_modules' ./ \$WINDOWS_HOST:\$REMOTE_PATH/

# ファイル監視と自動同期
if command -v fswatch &> /dev/null; then
    echo "ファイル監視を開始..."
    fswatch -o . | while read f; do
        rsync -av --exclude='.git' --exclude='node_modules' ./ \$WINDOWS_HOST:\$REMOTE_PATH/
    done &
    SYNC_PID=\$!
    trap "kill \$SYNC_PID 2>/dev/null" EXIT
else
    echo "fswatchがインストールされていません。自動同期を無効化します。"
    echo "インストールするには: brew install fswatch"
fi

# MSYS2シェルを起動
ssh -t \$WINDOWS_HOST "cd \$REMOTE_PATH && bash"
EOF

chmod +x ~/bin/msys2-sync

# PATHに追加
if [[ ":$PATH:" != *":$HOME/bin:"* ]]; then
    echo 'export PATH="$HOME/bin:$PATH"' >> ~/.zshrc
    echo 'export PATH="$HOME/bin:$PATH"' >> ~/.bash_profile
fi

echo ""
echo "===== セットアップ完了 ====="
echo ""
echo "使用方法:"
echo "  msys2              - MSYS2シェルに接続"
echo "  msys2 <command>    - コマンドを実行"
echo "  msys2-sync         - ファイル同期付きでMSYS2を起動"
echo ""
echo "初回接続:"
echo "  ssh windows-msys2"
echo ""
echo "注意: fswatchをインストールすると自動同期が有効になります:"
echo "  brew install fswatch"
"@

$macScriptPath = "$env:USERPROFILE\Desktop\setup-mac.sh"
$macScript | Out-File -FilePath $macScriptPath -Encoding UTF8
Write-ColorOutput White "`nMac側のセットアップスクリプトを生成しました:"
Write-ColorOutput Yellow $macScriptPath

Write-ColorOutput Green "`n全ての設定が完了しました！"