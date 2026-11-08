@echo off
cd /d E:\traeworkspace\duckdb\duckdb-secret-vault
set SECRET_VAULT_KEY=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA==
set HOME=C:\Users\79162\AppData\Local\Temp\vh-msvc
build\msvc-release\test\unittest.exe test/sql/spike-storage-registration.test
echo EXIT=%ERRORLEVEL%
