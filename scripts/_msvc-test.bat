@echo off
call "C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvarsall.bat" x64 >nul 2>&1
set REPO=E:/traeworkspace\duckdb\duckdb-secret-vault
set SECRET_VAULT_KEY=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA==
set PATH=%REPO%\build\msvc-release\test\unittest\Release;%PATH%
cd /d %REPO%

set PASS=0
set FAIL=0
set SKIP=0

for %%T in (spike-storage-registration storage-basics negative-security migrate-rotate export-import fleet-distribute) do (
    build\msvc-release\test\unittest\Release\unittest.exe test/sql/%%T.test > tmp\phase6\windows-msvc\%%T.log 2>&1
    findstr /C:"No tests ran" /C:"All tests were skipped" tmp\phase6\windows-msvc\%%T.log >nul 2>&1
    if !errorlevel!==0 (
        echo TEST_%%T=SKIP_DETECTED
        set /a SKIP+=1
    ) else (
        findstr /C:"All tests passed" tmp\phase6\windows-msvc\%%T.log >nul 2>&1
        if !errorlevel!==0 (
            echo TEST_%%T=PASS
            set /a PASS+=1
        ) else (
            echo TEST_%%T=FAIL
            set /a FAIL+=1
        )
    )
)
echo TESTS: PASS=!PASS! FAIL=!FAIL! SKIP=!SKIP!
