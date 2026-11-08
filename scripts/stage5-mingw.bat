@echo off
REM stage-5: windows_amd64_mingw (Rtools42) build + test
REM Based on ci-environment-experience.md section 3.5
setlocal enabledelayedexpansion

set REPO=E:\traeworkspace\duckdb\duckdb-secret-vault
set RTOOLS=D:\tools\rtools42\app\x86_64-w64-mingw32.static.posix\bin
set VSCMAKE=C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\Common7\IDE\CommonExtensions\Microsoft\CMake\CMake\bin
set VSNINJA=C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\Common7\IDE\CommonExtensions\Microsoft\CMake\Ninja
set LOG=%REPO%\tmp\phase6\windows-mingw\build.log

mkdir %REPO%\tmp\phase6\windows-mingw 2>nul
echo === stage-5: mingw/rtools42 build === > %LOG%

REM Rtools42 libgcc_eh fix (nats_rw experience)
if not exist %RTOOLS%\libgcc_eh.a (
    copy %RTOOLS%\libgcc.a %RTOOLS%\libgcc_eh.a >> %LOG% 2>&1
    echo libgcc_eh.a copied >> %LOG%
)

set PATH=%VSCMAKE%;%VSNINJA%;%RTOOLS%;%USERPROFILE%\.cargo\bin;%PATH%
set CC=%RTOOLS%\gcc.exe
set CXX=%RTOOLS%\g++.exe

cmake -G Ninja ^
  -DCMAKE_BUILD_TYPE=Release ^
  -DCMAKE_C_COMPILER=%CC% ^
  -DCMAKE_CXX_COMPILER=%CXX% ^
  -DDUCKDB_EXTENSION_CONFIGS=%REPO%\extension_config.cmake ^
  -DUNITTEST_ROOT_DIRECTORY=%REPO% ^
  -DENABLE_UNITTEST_CPP_TESTS=FALSE ^
  -DENABLE_EXTENSION_AUTOLOADING=1 -DENABLE_EXTENSION_AUTOINSTALL=1 ^
  -DOS_NAME=windows -DOS_ARCH=amd64 ^
  -DCMAKE_SYSTEM_PROCESSOR=x86_64 ^
  -S %REPO%\duckdb -B %REPO%\build\mingw-release >> %LOG% 2>&1

if errorlevel 1 (
    echo CONFIGURE_EXIT=1 >> %LOG%
    type %LOG% | findstr /C:"error" | head -5
    exit /b 1
)
echo CONFIGURE_EXIT=0 >> %LOG%

cmake --build %REPO%\build\mingw-release --target secret_vault_loadable_extension unittest duckdb_local_extension_repo -j %NUMBER_OF_PROCESSORS% >> %LOG% 2>&1
if errorlevel 1 (
    echo BUILD_EXIT=1 >> %LOG%
    exit /b 1
)
echo BUILD_EXIT=0 >> %LOG%

file %REPO%\build\mingw-release\extension\secret_vault\secret_vault.duckdb_extension >> %LOG% 2>&1

set TESTDIR=%REPO%\build\mingw-release\test\unittest
set PASS=0
set FAIL=0
set SKIP=0

for %%T in (spike-storage-registration storage-basics negative-security migrate-rotate export-import fleet-distribute) do (
    %TESTDIR%\unittest.exe test/sql/%%T.test > %REPO%\tmp\phase6\windows-mingw\%%T.log 2>&1
    findstr /C:"No tests ran" /C:"All tests were skipped" %REPO%\tmp\phase6\windows-mingw\%%T.log >nul 2>&1
    if !errorlevel!==0 (
        echo TEST_%%T=SKIP_DETECTED >> %LOG%
        set /a SKIP+=1
    ) else (
        findstr /C:"All tests passed" %REPO%\tmp\phase6\windows-mingw\%%T.log >nul 2>&1
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
