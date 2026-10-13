# read-only: NetCfgInstanceId / Linkage\RootDevice / Control-Network key
# triple correlation check for every net-class subkey (ASCII only, PS 5.1)
$class = 'HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e972-e325-11ce-bfc1-08002be10318}'
$net   = 'HKLM\SYSTEM\CurrentControlSet\Control\Network\{4d36e972-e325-11ce-bfc1-08002be10318}'

$out = New-Object System.Collections.Generic.List[string]
$subs = (reg query $class) | Where-Object { $_ -match 'HKEY_LOCAL_MACHINE' }
foreach ($line in $subs) {
    $path = $line -replace '^HKEY_LOCAL_MACHINE', 'HKLM'
    $key = $path -replace '^HKLM', ''
    $name = ($key -split '\\')[-1]
    $nciLine = (reg query "$path" /v NetCfgInstanceId 2>$null) | Where-Object { $_ -match 'NetCfgInstanceId' }
    if (-not $nciLine) { continue }
    $nci = ($nciLine -split '\s+')[-1].Trim()
    $desc = (reg query "$path" /v DriverDesc 2>$null) | Where-Object { $_ -match 'DriverDesc' }
    if ($desc) { $desc = ($desc -split '\s+', 4)[3] } else { $desc = '(no desc)' }
    $rd = (reg query "$path\Linkage" /v RootDevice 2>$null) | Where-Object { $_ -match 'RootDevice' }
    $rootdev = ''
    if ($rd) { $rootdev = ($rd -split '\s+')[-1].Trim() }
    $cnet = reg query ("$net\$nci") > $null 2>&1
    if ($LASTEXITCODE -eq 0) { $cnet = $true } else { $cnet = $false }
    $triple = if ($rootdev) { ($rootdev -ieq $nci) } else { 'no-linkage' }
    $out.Add(("{0,-6} {1,-45} NCI={2} linkage={3} cnetKey={4} tripleOK={5}" -f $name, $desc, $nci, $rootdev, $cnet, $triple))
}
$out | Out-File 'C:\Users\igor\Desktop\spoofersrc\_triple.log' -Encoding ascii
Write-Host ("checked " + $out.Count + " subkeys")