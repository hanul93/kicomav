<img src="https://dl.dropboxusercontent.com/u/5806441/safe_image.png">


# KicomAV v0.20b [![Build Status](https://secure.travis-ci.org/hanul93/kicomav.png)](http://travis-ci.org/hanul93/kicomav)

KicomAV is an open source (GPL v2) antivirus engine designed for detecting malware and disinfecting it. This antivirus engine is created and maintained by [Kei Choi](http://twitter.com/hanul93).


## Requirements

* Python 2.7


## Quick start

Three quick start options are available:

* [Download the latest release](https://github.com/hanul93/kicomav/archive/master.zip) and unzip it.
* Clone the repo: `git clone git://github.com/hanul93/kicomav.git`.
* Build KicomAV Engine & Plugins modules : `build.sh` or `build.bat`
* You can see `Release` Directory. Change the `Release` directory and run `k2.py`.



## Usage

```
C:\kicomav\Release> python k2.py [path] [options]
```

**Example 1 :** KicomAV help Options 

```
C:\kicomav\Release> python k2.py
------------------------------------------------------------
KICOM Anti-Virus II (for WIN32) Ver 0.20b (June 1 2013)
Copyright (C) 1995-2013 Kei Choi. All rights reserved.
------------------------------------------------------------

Usage: k2.py path[s] [options]
Options:
        -f,  --files           scan files *
        -I,  --list            display all files
        -?,  --help            this help
                               * = default option

C:\kicomav\Release> _
```

**Example 2 :** Scan for current path

```
C:\kicomav\Release> python k2.py .
------------------------------------------------------------
KICOM Anti-Virus II (for WIN32) Ver 0.20b (June 1 2013)
Copyright (C) 1995-2013 Kei Choi. All rights reserved.
------------------------------------------------------------

Loaded Engine : Dummy Scan Engine
Loaded Engine : EICAR Test Engine

Z:\Dropbox\?? ?? ... \org\k2\dummy.txt infected : Dummy-Test-File (not a virus)
Z:\Dropbox\?? ?? ... \org\k2\eicar.txt infected : EICAR-Test-File (not a virus)


Results:
Folders           :2
Files             :15
Packed            :0
Infected files    :2
Suspect files     :0
Warnings          :0
Identified viruses:2
I/O errors        :0

C:\kicomav\Release> _
```


## Author

**Kei Choi**

+ [http://twitter.com/hanul93](http://twitter.com/hanul93)
+ [http://facebook.com/hanul93](http://facebook.com/hanul93)
+ [http://github.com/hanul93](http://github.com/hanul93)