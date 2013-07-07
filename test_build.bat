@echo off
@set path=%path%;c:\python27\

@mkdir Release
@mkdir Release\plugins

@copy Engine\* Release
@copy Engine\plugins\* Release\plugins

@copy Tool\kmake.py Release\plugins
@copy Sample\* Release
@cd Release\plugins

@python.exe kmake.py kicom.lst
@python.exe kmake.py kernel.py
@python.exe kmake.py kavutil.py
@python.exe kmake.py pefile.py
@python.exe kmake.py emalware.py
@python.exe kmake.py macro.py
@python.exe kmake.py hwp.py
@python.exe kmake.py dummy.py
@python.exe kmake.py eicar.py
@python.exe kmake.py ole.py
@python.exe kmake.py upx.py
@python.exe kmake.py zip.py
@python.exe kmake.py egg.py
@python.exe kmake.py alz.py

@del *.pyc
@del kicom.lst

@copy kavutil.py ..
@cd ..

@copy ..\Test\* .
@c:\python27\python.exe -m unittest discover