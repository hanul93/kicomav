@echo off

@mkdir Release
@copy Engine\* Release
@copy Tool\* Release
@cd Release
@kmake.py curemod.py

@del *.pyc
@del curemod.py
@del kmake.py