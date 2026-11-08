@echo off
cd /d E:\traeworkspace\duckdb\duckdb-secret-vault
build\msvc-release\duckdb.exe -c "SELECT 42 AS v;"
echo DUCKDB_EXIT=%ERRORLEVEL%
build\msvc-release\duckdb.exe -c "SELECT * FROM duckdb_extensions() WHERE loaded;"
echo EXT_EXIT=%ERRORLEVEL%
