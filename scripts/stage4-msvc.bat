@echo off
REM stage-4: windows_amd64 (MSVC) build + test
REM Based on ci-environment-experience.md section 3.1
setlocal enabledelayedexpansion

set REPO=E:\traeworkspace\duckdb\duckdb-secret-vault
set VCVARS=C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvarsall.bat
set VSCMAKE=C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\Common7\IDE\CommonExtensions\Microsoft\CMake\CMake\bin
set VSNINJA=C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\Common7\IDE\CommonExtensions\Microsoft\CMake\Ninja
set LOG=%REPO%\tmp\phase6\windows-msvc\build.log

mkdir %REPO%\tmp\phase6\windows-msvc 2>nul
echo === stage-4: MSVC build === > %LOG%

call "%VCVARS%" x64 >> %LOG% 2>&1
set PATH=%VSCMAKE%;%VSNINJA%;%USERPROFILE%\.cargo\bin;%PATH%

cmake -G Ninja ^
  -DCMAKE_BUILD_TYPE=Release ^
  -DDUCKDB_EXTENSION_CONFIGS=%REPO%\extension_config.cmake ^
  -DUNITTEST_ROOT_DIRECTORY=%REPO% ^
  -DENABLE_UNITTEST_CPP_TESTS=FALSE ^
  -DENABLE_EXTENSION_AUTOLOADING=1 -DENABLE_EXTENSION_AUTOINSTALL=1 ^
  -DCMAKE_SYSTEM_PROCESSOR=AMD64 ^
  -S %REPO%\duckdb -B %REPO%\build\msvc-release >> %LOG% 2>&1

if errorlevel 1 (
    echo CONFIGURE_EXIT=1 >> %LOG%
    type %LOG% | findstr /C:"error" | head -5
    exit /b 1
)

echo CONFIGURE_EXIT=0 >> %LOG%

cmake --build %REPO%\build\msvc-release --target secret_vault_loadable_extension unittest duckdb_local_extension_repo -j %NUMBER_OF_PROCESSORS% >> %LOG% 2>&1
if errorlevel 1 (
    echo BUILD_EXIT=1 >> %LOG%
    exit /b 1
)
echo BUILD_EXIT=0 >> %LOG%

REM Product type
file %REPO%\build\msvc-release\extension\secret_vault\secret_vault.duckdb_extension >> %LOG% 2>&1

REM Run tests: one filter at a time
set TESTDIR=%REPO%\build\msvc-release\test\unittest\Release
set PASS=0
set FAIL=0
set SKIP=0

for %%T in (spike-storage-registration storage-basics negative-security migrate-rotate export-import fleet-distribute) do (
    %TESTDIR%\unittest.exe test/sql/%%T.test > %REPO%\tmp\phase6\windows-msvc\%%T.log 2>&1
    findstr /C:"No tests ran" /C:"All tests were skipped" %REPO%\tmp\phase6\windows-msvc\%%T.log >nul 2>&1
    if !errorlevel!==0 (
        echo TEST_%%T=SKIP_DETECTED >> %LOG%
        set /a SKIP+=1
    ) else (
        findstr /C:"All tests passed" %REPO%\tmp\phase6\windows-msvc\%%T.log >nul 2>&1
        if !errorlevel!==0 (
            echo TEST_%%T=PASS >> %LOG%
            set /a PASS+=1
        ) else (
            echo TEST_%%T=FAIL >> %LOG%
            set /a FAIL+=1
        )
    )
)

echo TESTS: PASS=!PASS! FAIL=!FAIL! SKIP=!SKIP! >> %LOG%
echo === done === >> %LOG%
type %LOG%
