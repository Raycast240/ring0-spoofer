@echo off
rem build NexusSpooferDrv.sys (mapper-loadable HWID spoofer, WNF transport,
rem no device object). output: ..\build\NexusSpooferDrv.sys
rem requires WDK toolset WindowsKernelModeDriver10.0 + WDK 10.0.26100
setlocal
cd /d "%~dp0"

set "MSBUILD="
where msbuild >nul 2>nul
if not errorlevel 1 for /f "delims=" %%i in ('where msbuild') do (
  set "MSBUILD=%%i"
  goto :have_msbuild
)

rem fall back to VS MSBuild directly (PATH often lacks it)
for %%e in (Community Professional Enterprise BuildTools) do (
  if exist "%ProgramFiles%\Microsoft Visual Studio\2022\%%e\MSBuild\Current\Bin\MSBuild.exe" (
    set "MSBUILD=%ProgramFiles%\Microsoft Visual Studio\2022\%%e\MSBuild\Current\Bin\MSBuild.exe"
    goto :have_msbuild
  )
  if exist "%ProgramFiles%\Microsoft Visual Studio\18\%%e\MSBuild\Current\Bin\MSBuild.exe" (
    set "MSBUILD=%ProgramFiles%\Microsoft Visual Studio\18\%%e\MSBuild\Current\Bin\MSBuild.exe"
    goto :have_msbuild
  )
)

echo ERROR: MSBuild not found. Install VS 2022 + C++ + WDK.
exit /b 1

:have_msbuild
"%MSBUILD%" driver.vcxproj /p:Configuration=Release /p:Platform=x64 /v:m
if errorlevel 1 (
  echo BUILD FAILED
  exit /b 1
)
echo.
echo OK: %~dp0..\build\NexusSpooferDrv.sys
endlocal