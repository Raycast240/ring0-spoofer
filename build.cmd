@echo off
rem build spoofer.exe -- the standalone spoofer client. maps the embedded
rem helper driver (src/core/service/bytes.h) via a temp service, runs all
rem spoof stages, unloads. output: .\build\spoofer.exe
rem requires VS 2022 C++ toolset (v143), Windows SDK 10.0.
setlocal
cd /d "%~dp0"

set "MSBUILD="
where msbuild >nul 2>nul
if not errorlevel 1 for /f "delims= %%i" %%i in ('where msbuild') do (
  set "MSBUILD=%%i"
  goto :have_msbuild
)

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

echo ERROR: MSBuild not found. Install VS 2022 with C++ toolset.
exit /b 1

:have_msbuild
"%MSBUILD%" spoofer.vcxproj /p:Configuration=Release /p:Platform=x64 /v:m
if errorlevel 1 (
  echo BUILD FAILED
  exit /b 1
)
echo.
echo OK: %~dp0build\spoofer.exe
endlocal