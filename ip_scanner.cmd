@echo OFF
title IP Scanner
setlocal EnableDelayedExpansion

set "ip_first_3=XXX.XXX.XXX" :: HAS TO BE SET BY HAND!
set "max_ping_time=5000"
set "max_concurrent=20"
set "total_ips=255"



echo Starting scan ...
set "scanned=0"
for /L %%b in (0 1 %total_ips%) do (
    start /B cmd /C "ping -n 1 -w !max_ping_time! !ip_first_3!.%%b | findstr /C:"TTL=" /C:"Anforderung" /C:"timed" >nul && echo !ip_first_3!.%%b>> found_%%b.temp"
    call :ProgressBar !scanned! %total_ips%
    set /A "scanned+=1"
    set /A "concurrent_count=(scanned %% max_concurrent) + 1"
    if !concurrent_count! equ %max_concurrent% (
        timeout /t 1 >nul
    )
)

echo.
echo Waiting for all pings to complete...
set /A max_iterations=!max_ping_time!/1000
for /L %%i in (0 1 !max_iterations!) do (
    call :ProgressBar %%i 5
    timeout /t 1 >nul
)

echo.
echo Scanning complete. Processing results...
if exist found_*.temp (
    for %%f in (found_*.temp) do (
        type "%%f"
    )
    del found_*.temp
) else ( echo No results found. )

echo.
echo Process completed.
pause
goto :EOF



:: PROGRESS BAR FUNCTION
:ProgressBar
set "w=50"
set /A filled=(%1*%w%)/%2
set "bar="
for /F %%a in ('copy /Z "%~f0" nul') do set "CR=%%a"
for /L %%A in (1 1 !w!) do (
    if %%A leq %filled% (
        set "bar=!bar!#"
    ) else (
        set "bar=!bar!."
    )
)
<nul set /p "=[!bar!] %1/%2!CR!"
goto :EOF
