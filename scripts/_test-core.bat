@echo off
cd /d E:\traeworkspace\duckdb\duckdb-secret-vault
build\msvc-release\test\unittest.exe test/sql/../..//duckdb/test/sql/aggregate/sum/sum.test
echo EXIT=%ERRORLEVEL%
