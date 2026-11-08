@echo off
call "C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvarsall.bat" x64 >nul 2>&1
set PATH=C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\Common7\IDE\CommonExtensions\Microsoft\CMake\CMake\bin;C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\Common7\IDE\CommonExtensions\Microsoft\CMake\Ninja;%PATH%
set REPO=E:/traeworkspace\duckdb\duckdb-secret-vault

REM Reconfigure WITHOUT our extension to isolate
cmake -G Ninja -DCMAKE_BUILD_TYPE=Release ^
  -DUNITTEST_ROOT_DIRECTORY=%REPO% ^
  -DENABLE_UNITTEST_CPP_TESTS=FALSE ^
  -S %REPO%\duckdb -B %REPO%\build\msvc-noext -DDUCKDB_EXTENSION_CONFIGS= >>nul 2>&1

cmake --build %REPO%\build\msvc-noext --target unittest -j %NUMBER_OF_PROCESSORS% 2>&1 | tail -3
echo BUILD_EXIT=%ERRORLEVEL%

%REPO%\build\msvc-noext\test\unittest.exe %REPO%\duckdb\test\sql\aggregate\sum\sum.test
echo TEST_EXIT=%ERRORLEVEL%
