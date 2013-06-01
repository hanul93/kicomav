@echo off

@mkdir Release
@mkdir Release\plugins

@copy Engine\* Release
@copy Engine\plugins\* Release\plugins

@copy Tool\kmake.py Release\plugins
@copy Sample\* Release
@cd Release\plugins

@c:\python27\python.exe kmake.py kicom.lst
@c:\python27\python.exe kmake.py kavutil.py
@c:\python27\python.exe kmake.py dummy.py
@c:\python27\python.exe kmake.py eicar.py

@del *.pyc
@del kicom.lst

@copy kavutil.py ..
@cd ..

@copy ..\Test\* .
@c:\python27\python.exe -m unittest discover