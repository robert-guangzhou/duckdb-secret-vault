@echo off
call "C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvarsall.bat" x64 >nul 2>&1
set PATH=C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\Common7\IDE\CommonExtensions\Microsoft\CMake\CMake\bin;C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\Common7\IDE\CommonExtensions\Microsoft\CMake\Ninja;%USERPROFILE%\.cargo\bin;%PATH%
set REPO=E:/traeworkspace\duckdb\duckdb-secret-vault
cmake --build %REPO%\build\msvc-release --target secret_vault_loadable_extension unittest duckdb_local_extension_repo -j %NUMBER_OF_PROCESSORS% 2>&1 | findstr /C:"error" /C:"Link"
echo BUILD_EXIT=%ERRORLEVEL%
cd /d %REPO%
build\msvc-release\test\unittest.exe duckdb\test\sql\aggregate\sum\sum.test
echo CORE_RC=%ERRORLEVEL%
