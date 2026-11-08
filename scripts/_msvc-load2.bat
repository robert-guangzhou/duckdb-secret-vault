@echo off
cd /d E:\traeworkspace\duckdb\duckdb-secret-vault
build\msvc-release\duckdb.exe -unsigned -c "LOAD 'build/msvc-release/extension/secret_vault/secret_vault.duckdb_extension'; SELECT secret_vault_version();"
echo LOAD_EXIT=%ERRORLEVEL%
