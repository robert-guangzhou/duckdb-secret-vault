@echo off
setlocal enabledelayedexpansion
set REPO=E:/traeworkspace/duckdb/duckdb-secret-vault
set RTOOLS=D:/tools/rtools42/app/x86_64-w64-mingw32.static.posix/bin
set VSCMAKE=C:/Program Files (x86)/Microsoft Visual Studio/2022/BuildTools/Common7/IDE/CommonExtensions/Microsoft/CMake/CMake/bin
set VSNINJA=C:/Program Files (x86)/Microsoft Visual Studio/2022/BuildTools/Common7/IDE/CommonExtensions/Microsoft/CMake/Ninja
set HOME=C:\Users\79162\AppData\Local\Temp\vh-mingw
set RUSTUP_HOME=C:/Users/79162/.rustup
set PATH=%RTOOLS%;%VSCMAKE%;%VSNINJA%;C:/Users/79162/.cargo/bin;C:\Windows\System32;C:\Windows

echo BUILDING...
cmake --build %REPO%/build/mingw-r3 --target secret_vault_loadable_extension unittest duckdb_local_extension_repo -j %NUMBER_OF_PROCESSORS%
echo BUILD_RC=%ERRORLEVEL%
if not %ERRORLEVEL%==0 exit /b 1

echo TESTING...
cd /d %REPO%
set SECRET_VAULT_KEY=BwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwc=
set P=0
set F=0
for %%T in (spike-storage-registration storage-basics negative-security migrate-rotate export-import fleet-distribute) do (
    build\mingw-r3\test\unittest.exe test/sql/%%T.test > tmp\phase6\windows-mingw\%%T.log 2>&1
    if !errorlevel!==0 (
        echo TEST_%%T=PASS
        set /a P+=1
    ) else (
        echo TEST_%%T=FAIL(rc=!errorlevel!)
        set /a F+=1
    )
)
echo MINGW: PASS=!P! FAIL=!F!
