$ErrorActionPreference = "Stop"
$remoteHost = "root@8.133.222.0"
$keyPath = "$env:USERPROFILE\.ssh\id_rsa"
$knownHosts = "$env:USERPROFILE\.ssh\known_hosts"
$destination = "D:\VeriWorkOffsiteBackups"
New-Item -ItemType Directory -Force -Path $destination | Out-Null
$log = Join-Path $destination "offsite-backup.log"
try {
    $files = & ssh -i $keyPath -o BatchMode=yes -o StrictHostKeyChecking=yes -o UserKnownHostsFile=$knownHosts $remoteHost "find /opt/veriwork-data/backups -maxdepth 1 -type f -mtime -2 -printf '%f\n'"
    foreach ($name in $files) {
        if (-not "$name".Trim()) { continue }
        $name = "$name".Trim()
        & scp -i $keyPath -o BatchMode=yes -o StrictHostKeyChecking=yes -o UserKnownHostsFile=$knownHosts "${remoteHost}:/opt/veriwork-data/backups/$name" (Join-Path $destination $name)
        Add-Content -Path $log -Value "$(Get-Date -Format s) pulled $name"
    }
    $cutoff = (Get-Date).AddDays(-30)
    Get-ChildItem -LiteralPath $destination -File | Where-Object { $_.LastWriteTime -lt $cutoff } | ForEach-Object { $_.Delete() }
    Add-Content -Path $log -Value "$(Get-Date -Format s) OK destination=$destination"
} catch {
    Add-Content -Path $log -Value "$(Get-Date -Format s) ERROR $($_.Exception.Message)"
    throw
}
