@echo off
setlocal
set "SRC=%~dp0"
if "%SRC:~-1%"=="\" set "SRC=%SRC:~0,-1%"
set "VSWHERE=%ProgramFiles(x86)%\Microsoft Visual Studio\Installer\vswhere.exe"
if not exist "%VSWHERE%" set "VSWHERE=%ProgramFiles%\Microsoft Visual Studio\Installer\vswhere.exe"
set "VSINSTALL="
for /f "usebackq delims=" %%i in (`"%VSWHERE%" -latest -products * -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath`) do set "VSINSTALL=%%i"
set "CMAKE=%VSINSTALL%\Common7\IDE\CommonExtensions\Microsoft\CMake\CMake\bin\cmake.exe"
if not exist "%CMAKE%" set "CMAKE=cmake"
call "%VSINSTALL%\VC\Auxiliary\Build\vcvars64.bat" >nul
set "PATH=%VSINSTALL%\VC\Tools\Llvm\x64\bin;%PATH%"
echo === CONFIGURE ===
"%CMAKE%" -S "%SRC%" -B "%SRC%\build_cli" -G Ninja -DCMAKE_C_COMPILER=clang-cl -DCMAKE_CXX_COMPILER=clang-cl -DCMAKE_BUILD_TYPE=Release -DJIT_REPRO_TRACE=ON > "%SRC%\_cfg_repro.log" 2>&1
echo cfg rc=%errorlevel%
echo === BUILD ===
"%CMAKE%" --build "%SRC%\build_cli" --target JitHangRepro > "%SRC%\_build_repro.log" 2>&1
echo build rc=%errorlevel%
exit /b %errorlevel%
