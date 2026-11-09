@echo off
setlocal enabledelayedexpansion
call "C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvarsall.bat" x64 >nul 2>&1
set PATH=C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\Common7\IDE\CommonExtensions\Microsoft\CMake\CMake\bin;C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\Common7\IDE\CommonExtensions\Microsoft\CMake\Ninja;D:\tools\rtools42\app\x86_64-w64-mingw32.static.posix\bin;%USERPROFILE%\.cargo\bin;%PATH%
set REPO=E:/traeworkspace/duckdb/duckdb-secret-vault
set RTOOLS=D:\tools\rtools42\app\x86_64-w64-mingw32.static.posix\bin

REM Rtools42 libgcc_eh fix (nats_rw experience)
if not exist %RTOOLS%\libgcc_eh.a (
    copy %RTOOLS%\libgcc.a %RTOOLS%\libgcc_eh.a >nul
    echo libgcc_eh.a created
)

set CC=%RTOOLS%\gcc.exe
set CXX=%RTOOLS%\g++.exe

if exist %REPO%/build/mingw-r2 rmdir /s /q %REPO%/build/mingw-r2

cmake -G Ninja -DCMAKE_BUILD_TYPE=Release ^
  -DCMAKE_C_COMPILER=%CC% ^
  -DCMAKE_CXX_COMPILER=%CXX% ^
  -DDUCKDB_EXTENSION_CONFIGS=%REPO%/extension_config.cmake ^
  -DUNITTEST_ROOT_DIRECTORY=%REPO% ^
  -DENABLE_UNITTEST_CPP_TESTS=FALSE ^
  -DENABLE_EXTENSION_AUTOLOADING=1 -DENABLE_EXTENSION_AUTOINSTALL=1 ^
  -DOS_NAME=windows -DOS_ARCH=amd64 ^
  -DCMAKE_SYSTEM_PROCESSOR=x86_64 ^
  -S %REPO%/duckdb -B %REPO%/build/mingw-r2
echo CFG_RC=%ERRORLEVEL%
if not %ERRORLEVEL%==0 exit /b 1

echo === Verify path ===
findstr /C:"DUCKDB_ROOT_DIRECTORY" %REPO%/build/mingw-r2/build.ninja | find /c "E:/"

cmake --build %REPO%/build/mingw-r2 --target secret_vault_loadable_extension unittest duckdb_local_extension_repo -j %NUMBER_OF_PROCESSORS%
echo BUILD_RC=%ERRORLEVEL%
if not %ERRORLEVEL%==0 exit /b 1

cd /d %REPO%
set SECRET_VAULT_KEY=BwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwc=
set HOME=C:\Users\79162\AppData\Local\Temp\vh-mingw
mkdir %HOME% 2>nul

set P=0
set F=0
for %%T in (spike-storage-registration storage-basics negative-security migrate-rotate export-import fleet-distribute) do (
    build\mingw-r2\test\unittest.exe test/sql/%%T.test > tmp\phase6\windows-mingw\%%T.log 2>&1
    if !errorlevel!==0 (
        echo TEST_%%T=PASS
        set /a P+=1
    ) else (
        echo TEST_%%T=FAIL(rc=!errorlevel!)
        set /a F+=1
    )
)
echo MINGW: PASS=!P! FAIL=!F!
