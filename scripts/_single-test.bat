@echo off
cd /d E:\traeworkspace\duckdb\duckdb-secret-vault
set SECRET_VAULT_KEY=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA==
echo STARTING TEST...
build\msvc-release\test\unittest.exe test\sql\storage-basics.test
echo RC=%ERRORLEVEL%
