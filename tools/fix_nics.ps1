# NIC auto-heal: clears persistent NetworkAddress overrides from every net
# class key, then re-adds (remove + rescan) any present network device that
# is not OK. Fixes Code 31 / "driver not working" network adapters without
# reinstalling anything. Run as administrator.
$log = "$env:USERPROFILE\Desktop\fix_nics_result.txt"
"=== $(Get-Date) NIC auto-heal ===" | Out-File $log -Encoding utf8
function Log($s) { $s | Out-File $log -Append -Encoding utf8 }

$classRoot = "HKLM:\SYSTEM\CurrentControlSet\Control\Class\{4d36e972-e325-11ce-bfc1-08002be10318}"

# 1. scrub NetworkAddress from all adapter instance keys
Get-ChildItem $classRoot -ErrorAction SilentlyContinue | Where-Object { $_.PSChildName -match '^\d{4}$' } | ForEach-Object {
    $p = $_.PSPath
    if ((Get-ItemProperty $p -ErrorAction SilentlyContinue).NetworkAddress) {
        Remove-ItemProperty -Path $p -Name NetworkAddress -Force
        Log ("removed NetworkAddress from " + $_.PSChildName)
    }
}

# 2. re-add every present network device that is not OK. the problem code
# BEFORE the remove is the diagnostic: it tells us what boot actually left
# the adapter as (code 31 = AddDevice fail, code 10 = start fail, ...)
foreach ($d in (Get-PnpDevice -Class Net | Where-Object { $_.Present -and $_.Status -ne 'OK' })) {
    Log ("re-adding: " + $d.FriendlyName + " (" + $d.InstanceId + ") problem=" + $d.Problem)
    $r = pnputil /remove-device "$($d.InstanceId)" 2>&1 | Out-String
    Start-Sleep -Seconds 2
    $r = pnputil /scan-devices 2>&1 | Out-String
    Start-Sleep -Seconds 10
}

# 3. report
Get-PnpDevice -Class Net | Where-Object { $_.Present } | ForEach-Object {
    Log ("  [{0}] status={1} problem={2}" -f $_.FriendlyName, $_.Status, $_.Problem)
}
Log "=== done ==="
Get-Content $log