@echo off

@mkdir Release
@mkdir Release\plugins

@copy Engine\* Release
@copy Engine\plugins\* Release\plugins

@copy Tool\kmake.py Release\plugins
@cd Release\plugins

@kmake.py kicom.lst
@kmake.py kavutil.py
@kmake.py ole.py
@kmake.py dummy.py
@kmake.py eicar.py

@del *.py
@del *.pyc
@del kicom.lst

@cd ..