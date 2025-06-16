# Windows MSYS2 SSH サーバー セットアップツール

このツールは、Windows環境にMSYS2とOpenSSH Serverを自動でセットアップし、MacからSSH経由でMSYS2環境にアクセスできるようにするPowerShellスクリプトです。

## 機能

- MSYS2の自動インストールと初期設定
- OpenSSH Serverのインストールと設定
- MSYS2をデフォルトシェルとして設定
- SSH公開鍵認証の自動設定
- ファイアウォール設定の自動化
- Mac側のセットアップスクリプト生成

## 必要要件

- Windows 10/11
- PowerShell（管理者権限）
- インターネット接続

## 使用方法

### Windows側のセットアップ

1. PowerShellを管理者として実行
2. スクリプトを実行：

```powershell
.\setup-msys2-ssh.ps1
```

### オプションパラメータ

```powershell
.\setup-msys2-ssh.ps1 -InstallPath "C:\tools\msys64" -Username "myuser" -SkipFirewall
```

- `-InstallPath`: MSYS2のインストール先（デフォルト: C:\msys64）
- `-Username`: SSHユーザー名（デフォルト: 現在のWindowsユーザー）
- `-SkipFirewall`: ファイアウォール設定をスキップ

### Mac側のセットアップ

1. Windows側のセットアップ完了後、デスクトップに生成された `setup-mac.sh` をMacにコピー
2. スクリプトを実行：

```bash
chmod +x setup-mac.sh
./setup-mac.sh
```

## セットアップ後の使用方法

### 基本的な接続

```bash
# SSH接続
ssh windows-msys2

# コマンドの実行
msys2 gcc --version
msys2 python --version
```

### ファイル同期付き接続

```bash
# プロジェクトディレクトリで実行
cd ~/myproject
msys2-sync
```

このコマンドは：
- プロジェクトをWindows側に同期
- ファイルの変更を自動的に検出して同期（fswatchが必要）
- MSYS2シェルを起動

## トラブルシューティング

### SSH接続できない場合

1. Windowsファイアウォールで22番ポートが開いているか確認
2. SSHサービスが起動しているか確認：
   ```powershell
   Get-Service sshd
   ```
3. authorized_keysの権限が正しく設定されているか確認

### MSYS2コマンドが見つからない場合

PowerShellを再起動するか、以下を実行：
```powershell
$env:Path = [System.Environment]::GetEnvironmentVariable("Path","Machine")
```

## セキュリティ設定

- パスワード認証は無効化され、公開鍵認証のみ有効
- デフォルトでmiyanaga@miyanaga-pro.localの公開鍵が登録済み
- 必要に応じて `~/.ssh/authorized_keys` を編集

## アンインストール

1. SSHサービスの停止と削除：
   ```powershell
   Stop-Service sshd
   Set-Service -Name sshd -StartupType 'Disabled'
   ```

2. MSYS2の削除：
   - C:\msys64フォルダを削除
   - 環境変数PATHからMSYS2関連のパスを削除

3. OpenSSH Serverの削除：
   ```powershell
   Remove-WindowsCapability -Online -Name OpenSSH.Server~~~~0.0.1.0
   ```

## ライセンス

このプロジェクトはMITライセンスの下で公開されています。