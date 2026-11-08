@echo off
call "C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvarsall.bat" x64 >nul 2>&1
set PATH=C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\Common7\IDE\CommonExtensions\Microsoft\CMake\CMake\bin;C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\Common7\IDE\CommonExtensions\Microsoft\CMake\Ninja;%USERPROFILE%\.cargo\bin;%PATH%
set REPO=E:/traeworkspace\duckdb\duckdb-secret-vault

REM Reconfigure (picks up Cargo.toml change)
cmake -G Ninja -DCMAKE_BUILD_TYPE=Release ^
  -DDUCKDB_EXTENSION_CONFIGS=%REPO%\extension_config.cmake ^
  -DUNITTEST_ROOT_DIRECTORY=%REPO% ^
  -DENABLE_UNITTEST_CPP_TESTS=FALSE ^
  -DCMAKE_SYSTEM_PROCESSOR=AMD64 ^
  -S %REPO%\duckdb -B %REPO%\build\msvc-release >>nul 2>&1

cmake --build %REPO%\build\msvc-release --target secret_vault_loadable_extension unittest duckdb_local_extension_repo -j %NUMBER_OF_PROCESSORS% 2>&1 | findstr /C:"error" /C:"BUILD"
echo BUILD_EXIT=%ERRORLEVEL%

cd /d %REPO%
echo RUNNING CORE TEST...
build\msvc-release\test\unittest.exe duckdb\test\sql\aggregate\sum\sum.test
echo CORE_RC=%ERRORLEVEL%
