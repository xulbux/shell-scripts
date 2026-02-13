@echo OFF
setlocal enabledelayedexpansion

REM ######################################## MAIN SCRIPT ########################################
cls
echo [NEW] Starting operations...
call :rand_delay 100 300
echo.
echo [LOG] Initializing download processes:
call :rand_delay 500 750
call :progress_bar "Downloading nessecary processing files..." 46 10 25
call :progress_bar "Downloading power management software..." 282 1 20
call :progress_bar "Downloading administration tools..." 97 5 30
call :progress_bar "Downloading admin bypass code..." 6 100 300
echo [LOG] Extracting files, tools and code:
call :rand_delay 50 200
call :progress_bar "Extracting disk encryption tools..." 164 1 4
call :progress_bar "Extracting power management software..." 87 0 3
call :progress_bar "Extracting administration tools..." 378 1 7
call :progress_bar "Extracting admin bypass code..." 4 25 75
call :progress_bar "Extracting hardlock code..." 2 25 75
call :progress_bar "Extracting spyware..." 34 20 80
call :progress_bar "Extracting malware..." 93 4 40
echo [LOG] Installing files, tools and code:
call :rand_delay 50 200
call :progress_bar "Installing disk encryption tools..." 164 1 4
call :progress_bar "Installing power management software..." 87 0 3
call :progress_bar "Installing administration tools..." 30 20 50
call :progress_bar "Installing codes..." 6 25 75
call :progress_bar "Installing rest..." 127 3 20
echo [LOG] Running system diagnostics:
call :rand_delay 200 500
call :progress_bar "Injecting admin bypass code..." 4 25 50
call :progress_bar "Injecting hardlock code..." 2 25 50
call :progress_bar "[1] Attempt to get full admin controlls..." 24 10 30
call :progress_bar "[2] Attempt to get full admin controlls..." 24 10 30
call :progress_bar "[3] Attempt to get full admin controlls..." 24 10 30
call :progress_bar "[4] Attempt to get full admin controlls..." 24 10 30
echo [LOG] Succes! Admin permissions granted.
call :rand_delay 500 750
echo [LOG] Initializing system formatter:
call :rand_delay 100 300
call :progress_bar "Rewriting the rights..." 56 5 20
call :progress_bar "Scanning for antivirus issues..." 189 1 25
call :progress_bar "Removing required applications..." 602 1 4
echo [LOG] Collecting important data:
call :rand_delay 50 200
call :progress_bar "[1] Quick scan of drive `D:`..." 21 25 75
call :progress_bar "[2] Quick scan of drive `C:`..." 17 40 80
call :progress_bar "[3] Copying found possibly important files..." 412 1 7
echo [LOG] Sending found data:
call :rand_delay 50 200
call :progress_bar "[1] Uploading files..." 412 1 14
call :progress_bar "[2] Sending files..." 412 0 0
echo [LOG] Running disk formatting:
call :rand_delay 100 300
call :progress_bar "Duplicating temporary files..." 15 20 50
call :progress_bar "Removing information files..." 18 20 50
call :progress_bar "Filling disk space..." 388 1 5
call :progress_bar "Verifying drive encryption..." 20 10 30
call :progress_bar "Formatting drive `C:`..." 128 1 12
call :progress_bar "Formatting drive `D:`..." 67 2 7
call :progress_bar "Encrypting drives..." 195 0 3
echo.
echo [DONE] Operations complete.
call :rand_delay 100 300
echo.
echo [LOG] Now finishing up:
call :progress_bar "Initializing blurring traces..." 13 75 300
call :progress_bar "Blurring traces..." 683 0 2
call :rand_delay 200 500
echo [LOG] Blurred all traces.
call :rand_delay 100 300
echo.
echo [END] Processes ended.
call :fake_bsod
pause > NUL

REM ######################################## FUNCTIONS ########################################
REM OVERWRITE ECHO
:oecho
    set "msg=%~1"
    set "ESC=["
    set "CLEAR=%ESC%2K%ESC%0G"
    <nul set /p=.%CLEAR%!msg!
    goto:eof

REM RANDOM DELAY IN MILLISECONDS USING POWERSHELL
:rand_delay
    set "min=%~1"
    set "max=%~2"
    set /a "delay=(%min% + (%random% %% (%max% - %min% + 1))) / 10"
    if %delay% equ 0 goto :eof
    for /L %%x in (1, 1, %delay%) do (
        ping 10.109.199.199 -n 1 -w >NUL
    )
    goto:eof

REM PROGRESS BAR
:progress_bar
    set "msg=%~1"
    set "steps=%~2"
    set "min_delay=%~3"
    set "max_delay=%~4"
    set "width=50"  REM Adjust width here if needed
    for /L %%A in (1, 1, %steps%) do (
        set /A "percent=(100 * %%A / %steps%)"
        set /A "filled=!percent! * %width% / 100"
        set "progressBar="
        for /L %%B in (1,1,!filled!) do set "progressBar=!progressBar!#"
        set /A "spaces=%width% - !filled!"
        for /L %%C in (1,1,!spaces!) do set "progressBar=!progressBar!."
        call :oecho "[!progressBar!][%%A/%steps%](!percent!%%%%) - %msg%"
        call :rand_delay %min_delay% %max_delay%
    )
    echo.
    goto:eof

REM CREATE AND RUN FAKE-BSOD HTA
:fake_bsod
    set "hta_file=BSOD.hta"
    @echo ^<html^>^<head^>^<title^>BSOD^</title^>^<hta:application applicationname="BSOD" version="1.0" maximizebutton="no" minimizebutton="no" sysmenu="no" Caption="no" windowstate="maximize"/^>^</head^>^<body bgcolor="#0000AA" scroll="no" style="border:0;cursor:default;" border="0" oncontextmenu="return false" onselectstart="return false"^>^<font face="Lucida Console" size="4" color="#FFFFFF"^>^<p^>A problem has been detected and windows has been shutdown to prevent damage to your computer.^</p^>^<p^>DRIVER_IRQL_NOT_LESS_OR_EQUAL^</p^>^<p^>If this is the first time you've seen this stop error screen, restart your computer, If this screen appears again, follow these steps:^</p^>^<p^>Check to make sure any new hardware or software is properly installed. If this is a new installation, ask your hardware or software manufacturer for any windows updates you might need.^</p^>^<p^>If problems continue, disable or remove any newly installed hardware or software. Disable BIOS memory options such as caching or shadowing. If you need to use Safe Mode to remove or disable components, restart your computer, press F8 to select Advanced Startup Options, and then select Safe Mode.^</p^>^<p^>Technical information:^</p^>^<p^>*** STOP: 0x000000D1 (0x0000000C,0x00000002,0x00000000,0xF86B5A89)^</p^>^<p^>***       gv3.sys - Address F86B5A89 base at F86B5000, DateStamp 3dd9919eb^</p^>^<p^>Beginning dump of physical memory^</p^>^<p^>Physical memory dump complete.^</p^>^<p^>Contact your system administrator or technical support group for further assistance.^</p^>^</font^>^</body^>^</html^>>"%hta_file%"
    start "" "%hta_file%"
    goto :eof
