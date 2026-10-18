$ErrorActionPreference = "Stop"
$source = Join-Path $PSScriptRoot "offsite-backup-pull.ps1"
$installDir = "D:\VeriWorkOffsiteBackups"
$installed = Join-Path $installDir "offsite-backup-pull.ps1"
New-Item -ItemType Directory -Force -Path $installDir | Out-Null
Copy-Item -LiteralPath $source -Destination $installed -Force
$action = New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-NoProfile -ExecutionPolicy Bypass -File `"$installed`""
$trigger = New-ScheduledTaskTrigger -Daily -At "04:30"
$settings = New-ScheduledTaskSettingsSet -StartWhenAvailable -ExecutionTimeLimit (New-TimeSpan -Hours 1)
Register-ScheduledTask -TaskName "VeriWorkOffsiteBackup" -Action $action -Trigger $trigger -Settings $settings -Description "Pull VeriWork backups from the application server every day" -Force | Out-Null
Start-ScheduledTask -TaskName "VeriWorkOffsiteBackup"
Write-Host "Installed D:\VeriWorkOffsiteBackups\offsite-backup-pull.ps1 and daily task VeriWorkOffsiteBackup."
