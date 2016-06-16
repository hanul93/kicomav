@echo off
@set path=%path%;c:\python27\

@echo ------------------------------------------------------------
@echo KICOM Anti-Virus II (for WIN32) Build Tool Ver 0.10
@echo Copyright (C) 1995-2014 Kei Choi. All rights reserved.
@echo ------------------------------------------------------------
@echo.

if "%1" == "erase"    goto START
if "%1" == "build"    goto START
if "%1" == "unittest" goto START

@echo Usage : builder.bat [build][erase][unittest]
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

@python.exe Tool\mkkey.py 
if not exist "key.pkr" goto KEY_NOT_FOUND
if not exist "key.skr" goto KEY_NOT_FOUND

@copy key.* Release\plugins > nul
@copy Tool\kmake.py Release\plugins > nul
@cd Release\plugins

@echo [*] Build Engine files...
@python.exe kmake.py kicom.lst

for %%f in (*.py) do (
    if %%f neq kmake.py (
        @python.exe kmake.py %%f
    )    
)

@ren key.pkr kicomav.pkr > nul
@del /Q *.py > nul
@del kicom.lst > nul
@del key.skr > nul 

@cd ..
@echo [*] Build Success

if "%1" == "unittest" (
    @echo [*] Start Unittest
    @copy ..\Test\* . > nul
    @c:\python27\python.exe -m unittest discover
)

goto END

:KEY_NOT_FOUND
@echo     Key files not Found!!!
goto END

:END
