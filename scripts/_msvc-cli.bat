@echo off
call "C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvarsall.bat" x64 >nul 2>&1
set PATH=C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\Common7\IDE\CommonExtensions\Microsoft\CMake\CMake\bin;C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\Common7\IDE\CommonExtensions\Microsoft\CMake\Ninja;%PATH%
set REPO=E:\traeworkspace\duckdb\duckdb-secret-vault
cmake --build %REPO%\build\msvc-release --target shell -j %NUMBER_OF_PROCESSORS%
echo BUILD_EXIT=%ERRORLEVEL%
%REPO%\build\msvc-release\duckdb.exe -c "SELECT 42 AS v;"
echo QUERY_EXIT=%ERRORLEVEL%
