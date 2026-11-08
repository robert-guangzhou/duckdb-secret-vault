@echo off
call "C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvarsall.bat" x64 >nul 2>&1
set PATH=C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\Common7\IDE\CommonExtensions\Microsoft\CMake\CMake\bin;C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\Common7\IDE\CommonExtensions\Microsoft\CMake\Ninja;%USERPROFILE%\.cargo\bin;%PATH%
set REPO=E:/traeworkspace/duckdb/duckdb-secret-vault

if exist %REPO%/build/msvc-fixed rmdir /s /q %REPO%/build/msvc-fixed
cmake -G Ninja -DCMAKE_BUILD_TYPE=Release ^
  -DDUCKDB_EXTENSION_CONFIGS=%REPO%/extension_config.cmake ^
  -DUNITTEST_ROOT_DIRECTORY=%REPO% ^
  -DENABLE_UNITTEST_CPP_TESTS=FALSE ^
  -DENABLE_EXTENSION_AUTOLOADING=1 ^
  -DENABLE_EXTENSION_AUTOINSTALL=1 ^
  -DCMAKE_SYSTEM_PROCESSOR=AMD64 ^
  -S %REPO%/duckdb -B %REPO%/build/msvc-fixed
echo CFG_RC=%ERRORLEVEL%
if not %ERRORLEVEL%==0 exit /b 1

echo === Verify path in build.ninja ===
findstr /C:"DUCKDB_ROOT_DIRECTORY" %REPO%/build/msvc-fixed/build.ninja | find /c "E:/"
findstr /C:"DUCKDB_ROOT_DIRECTORY" %REPO%/build/msvc-fixed/build.ninja

cmake --build %REPO%/build/msvc-fixed --target secret_vault_loadable_extension unittest duckdb_local_extension_repo -j %NUMBER_OF_PROCESSORS%
echo BUILD_RC=%ERRORLEVEL%
if not %ERRORLEVEL%==0 exit /b 1

cd /d %REPO%
set SECRET_VAULT_KEY=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA==
set HOME=C:\Users\79162\AppData\Local\Temp\vh-fixed
mkdir %HOME% 2>nul

set P=0
set F=0
for %%T in (spike-storage-registration storage-basics negative-security migrate-rotate export-import fleet-distribute) do (
    build\msvc-fixed\test\unittest.exe test\sql\%%T.test > tmp\phase6\windows-msvc\%%T.log 2>&1
    if !errorlevel!==0 (
        echo TEST_%%T=PASS
        set /a P+=1
    ) else (
        echo TEST_%%T=FAIL(rc=!errorlevel!)
        set /a F+=1
    )
)
echo MSVC: PASS=!P! FAIL=!F!
