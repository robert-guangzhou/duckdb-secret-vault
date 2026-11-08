@echo off
call "C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvarsall.bat" x64 >nul 2>&1
set PATH=C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\Common7\IDE\CommonExtensions\Microsoft\CMake\CMake\bin;C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\Common7\IDE\CommonExtensions\Microsoft\CMake\Ninja;%USERPROFILE%\.cargo\bin;%PATH%
set REPO=E:/traeworkspace/duckdb/duckdb-secret-vault
cmake --build %REPO%/build/msvc-fixed --target secret_vault_loadable_extension unittest duckdb_local_extension_repo -j %NUMBER_OF_PROCESSORS%
echo BUILD_RC=%ERRORLEVEL%
if not %ERRORLEVEL%==0 exit /b 1
cd /d %REPO%
set SECRET_VAULT_KEY=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA==
set HOME=C:\Users\79162\AppData\Local\Temp\vh-fixed2
mkdir %HOME% 2>nul
build\msvc-fixed\test\unittest.exe test\sql\storage-basics.test
echo TEST1_RC=%ERRORLEVEL%
build\msvc-fixed\test\unittest.exe test\sql\spike-storage-registration.test
echo TEST2_RC=%ERRORLEVEL%
build\msvc-fixed\test\unittest.exe test\sql\fleet-distribute.test
echo TEST3_RC=%ERRORLEVEL%
