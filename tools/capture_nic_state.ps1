# NIC state capture (read-only, heals nothing): snapshots everything that
# defines the PnP/registry state of the NIC devnodes so captures taken at
# different moments can be diffed against each other:
#   preboot  - right after a spoof run, before the reboot
#   broken   - at the failed boot, BEFORE running fix_nics.bat
#   healed   - right after fix_nics.bat
# The diff between "broken" and "healed" for the same adapters is the poison
# state the spoof run leaves behind. Run as administrator.
param([string]$Tag = "capture")

$stamp  = Get-Date -Format 'yyyyMMdd_HHmmss'
$dir    = "$env:USERPROFILE\Desktop\nic_state\${Tag}_${stamp}"
New-Item -ItemType Directory -Force -Path $dir | Out-Null
$sum    = "$dir\summary.txt"
$boot   = (Get-CimInstance Win32_OperatingSystem).LastBootUpTime
"=== $Tag capture $stamp - last boot: $boot ===" | Out-File $sum -Encoding utf8
function Log($s) { $s | Out-File $sum -Append -Encoding utf8 }

$classRoot = "HKLM:\SYSTEM\CurrentControlSet\Control\Class\{4d36e972-e325-11ce-bfc1-08002be10318}"

# 1. every net-class device with live status/problem - the broken list
$devs = Get-PnpDevice -Class Net
$devs | Select-Object Status, Problem, Present, FriendlyName, InstanceId |
    Export-Csv "$dir\net_devices.csv" -NoTypeInformation -Encoding utf8
Log ("net-class devices: " + $devs.Count)
$broken = $devs | Where-Object { $_.Present -and $_.Status -ne 'OK' }
foreach ($b in $broken) {
    Log ("BROKEN: " + $b.FriendlyName + " (" + $b.InstanceId + ") problem=" + $b.Problem)
}
if (-not $broken) { Log "no broken (present non-OK) devices" }

# 2. full DEVPKEY property dump for the real adapters + anything broken -
#    ~200 registry-backed properties per device, the richest diff source
$targets = $devs | Where-Object { $_.FriendlyName -match 'Realtek|Personal Area Network' }
$targets = @($targets) + @($broken) | Sort-Object InstanceId -Unique
foreach ($t in $targets) {
    $safe = ($t.InstanceId -replace '[\\&]', '_')
    Get-PnpDeviceProperty -InstanceId $t.InstanceId -ErrorAction SilentlyContinue |
        Export-Csv "$dir\props_$safe.csv" -NoTypeInformation -Encoding utf8
    # 3. hardware key (Enum) export for the same instance
    reg export "HKLM\SYSTEM\CurrentControlSet\Enum\$($t.InstanceId)" "$dir\enum_$safe.reg" /y 2>&1 | Out-Null
    Log ("dumped: " + $t.FriendlyName + " (" + $t.InstanceId + ") status=" + $t.Status + " problem=" + $t.Problem)
}

# 4. whole net software class key (class\{4d36e972...\} incl. all 00xx subkeys)
reg export "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e972-e325-11ce-bfc1-08002be10318}" "$dir\class_net.reg" /y 2>&1 | Out-Null

# 5. per-adapter connection/binding trees + the Tcpip per-interface keys
reg export "HKLM\SYSTEM\CurrentControlSet\Control\Network\{4d36e972-e325-11ce-bfc1-08002be10318}" "$dir\network_adapters.reg" /y 2>&1 | Out-Null
reg export "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces" "$dir\tcpip_interfaces.reg" /y 2>&1 | Out-Null

# 6. setupapi device install log tail (what PnP did recently)
if (Test-Path "$env:SystemRoot\INF\setupapi.dev.log") {
    Get-Content "$env:SystemRoot\INF\setupapi.dev.log" -Tail 3000 |
        Out-File "$dir\setupapi_tail.txt" -Encoding utf8
}

# 7. System event log as of this moment (boot-time device failures live here)
wevtutil epl System "$dir\system.evtx" 2>&1 | Out-Null

Log "=== capture done: $dir ==="
Write-Host ""
Write-Host "capture saved to: $dir"
Get-Content $sum
