@echo off
setlocal enabledelayedexpansion
cd /d E:\traeworkspace\duckdb\duckdb-secret-vault
set SECRET_VAULT_KEY=BwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwc=
set HOME=C:\Users\79162\AppData\Local\Temp\vh-final3
mkdir %HOME% 2>nul
set P=0
set F=0
for %%T in (spike-storage-registration storage-basics negative-security migrate-rotate export-import fleet-distribute) do (
    build\msvc-fixed\test\unittest.exe test/sql/%%T.test > tmp\phase6\windows-msvc\%%T.log 2>&1
    if !errorlevel!==0 (
        echo TEST_%%T=PASS
        set /a P+=1
    ) else (
        echo TEST_%%T=FAIL(rc=!errorlevel!)
        set /a F+=1
    )
)
echo FINAL: PASS=!P! FAIL=!F!
