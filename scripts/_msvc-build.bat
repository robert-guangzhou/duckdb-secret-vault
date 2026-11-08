@echo off
call "C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvarsall.bat" x64
set PATH=C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\Common7\IDE\CommonExtensions\Microsoft\CMake\CMake\bin;C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\Common7\IDE\CommonExtensions\Microsoft\CMake\Ninja;%USERPROFILE%\.cargo\bin;%PATH%
set REPO=E:\traeworkspace\duckdb\duckdb-secret-vault
cmake --build %REPO%\build\msvc-release --target secret_vault_loadable_extension unittest duckdb_local_extension_repo -j %NUMBER_OF_PROCESSORS%
echo BUILD_EXIT=%ERRORLEVEL%
