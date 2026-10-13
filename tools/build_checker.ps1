# build_checker.ps1 -- build serial_checker.exe (100% native Win32/C++ usermode hardware-identity checker, no wmic)
param([switch]$NoRun)

$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $MyInvocation.MyCommand.Path
$build = Join-Path $root '..\build'
New-Item -ItemType Directory -Force $build | Out-Null

$vswhere = "${env:ProgramFiles(x86)}\Microsoft Visual Studio\Installer\vswhere.exe"
if (-not (Test-Path $vswhere)) { Write-Error 'vswhere not found'; exit 1 }
$vcvars = & $vswhere -latest -products * -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -find 'VC\Auxiliary\Build\vcvars64.bat' | Select-Object -First 1
if (-not $vcvars -or -not (Test-Path $vcvars)) { Write-Error 'vcvars64.bat not found'; exit 1 }

$objdir = Join-Path ([IO.Path]::GetTempPath()) 'serial_checker-obj'
New-Item -ItemType Directory -Force $objdir | Out-Null
$cmd = "`"$vcvars`" >nul && cl /nologo /MT /O2 /EHsc /std:c++17 /I. /Fo$($objdir)\ checker_main.cxx /Fe$($build)\serial_checker.exe"
Push-Location $root
try {
  cmd /c $cmd
  if ($LASTEXITCODE -ne 0) { Write-Error "compile failed ($LASTEXITCODE)"; exit 1 }
  Write-Host "OK: $($build)\serial_checker.exe"
  if ($NoRun) { exit 0 }
  & (Join-Path $build 'serial_checker.exe')
  exit $LASTEXITCODE
} finally { Pop-Location }
