@echo off
cd /d E:\traeworkspace\duckdb\duckdb-secret-vault
echo STARTING CORE TEST...
build\msvc-release\test\unittest.exe duckdb\test\sql\aggregate\sum\sum.test
echo RC=%ERRORLEVEL%
