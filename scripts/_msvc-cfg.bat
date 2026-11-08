@echo off
call "C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvarsall.bat" x64 >nul 2>&1
set PATH=C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\Common7\IDE\CommonExtensions\Microsoft\CMake\CMake\bin;C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\Common7\IDE\CommonExtensions\Microsoft\CMake\Ninja;%USERPROFILE%\.cargo\bin;%PATH%
set REPO=E:\traeworkspace\duckdb\duckdb-secret-vault
if exist %REPO%\build\msvc-fresh rmdir /s /q %REPO%\build\msvc-fresh
cmake -G Ninja -DCMAKE_BUILD_TYPE=Release ^
  -DDUCKDB_EXTENSION_CONFIGS=%REPO%\extension_config.cmake ^
  -DUNITTEST_ROOT_DIRECTORY=%REPO% ^
  -DENABLE_UNITTEST_CPP_TESTS=FALSE ^
  -DENABLE_EXTENSION_AUTOLOADING=1 ^
  -DENABLE_EXTENSION_AUTOINSTALL=1 ^
  -DCMAKE_SYSTEM_PROCESSOR=AMD64 ^
  -S %REPO%\duckdb -B %REPO%\build\msvc-fresh
echo CONFIGURE_EXIT=%ERRORLEVEL%
