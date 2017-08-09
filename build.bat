@echo off
@set path=%path%;c:\python27\

@echo ------------------------------------------------------------
@echo KICOM Anti-Virus II (for WIN32) Build Tool Ver 0.11
@echo Copyright (C) 1995-2017 Kei Choi. All rights reserved.
@echo ------------------------------------------------------------
@echo.

if "%1" == "erase"    goto START
if "%1" == "build"    goto START

@echo Usage : builder.bat [build][erase]
goto END

:START
@echo [*] Delete all files in Release

if exist Release (
    @rd /Q /S Release > nul
)

if exist "key.skr" @del key.skr > nul
if exist "key.pkr" @del key.pkr > nul
  
if "%1" == "erase" (
    @echo [*] Delete Success
    goto END
)

:BUILD
@echo [*] Engine file copy to the Release folder...
@xcopy Engine\* Release\ /e > nul

if not exist "key.pkr" @python.exe Tools\mkkey.py 
if not exist "key.skr" @python.exe Tools\mkkey.py 

@copy key.* Release\plugins > nul
@rem copy Tools\kmake.py Release\plugins > nul
@cd Release\plugins

@echo [*] Build Engine files...
@python.exe ..\..\Tools\kmake.py kicom.lst

for %%f in (*.py) do (
    if %%f neq kmake.py (
        @python.exe ..\..\Tools\kmake.py %%f
    )    
)

@del /Q *.py > nul
@del kicom.lst > nul
@del key.skr > nul 
@del __init__.kmd > nul 

@cd ..
@echo [*] Build Success

:END
