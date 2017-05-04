<img src="https://raw.githubusercontent.com/hanul93/kicomav-db/master/logo/kicomav.jpg">

# KicomAV v0.27

[![License](https://img.shields.io/badge/license-gpl2-blue.svg)](LICENSE)
![Platform](https://img.shields.io/badge/platform-windows-lightgrey.svg)
![Platform](https://img.shields.io/badge/platform-linux-lightgrey.svg)
![Platform](https://img.shields.io/badge/platform-mac-lightgrey.svg)

KicomAV is an open source (GPL v2) antivirus engine designed for detecting malware and disinfecting it. This antivirus engine is created and maintained by [Kei Choi](http://www.hanul93.com).


## Requirements

* Python 2.7


## Quick start

Three quick start options are available:

* [Download the latest release](https://github.com/hanul93/kicomav/archive/master.zip) and unzip it.
* Clone the repo: `git clone git://github.com/hanul93/kicomav.git`.
* Build KicomAV Engine & Plugins modules : `build.sh` or `build.bat build`
* You can see `Release` Directory. 
* [Download the latest signature file](https://github.com/hanul93/kicomav-db/raw/master/update/main.zip) and unzip it to `Release/plugins`.
* Change the `Release` directory and run `k2.py`.



## Usage

```
C:\kicomav\Release> python k2.py [path] [options]
```

**Example 1 :** KicomAV help Options 

```
C:\kicomav\Release> python k2.py
------------------------------------------------------------
KICOM Anti-Virus II (for WIN32) Ver 0.27 (May 4 2017)
Copyright (C) 1995-2017 Kei Choi. All rights reserved.
------------------------------------------------------------

Usage: k2.py path[s] [options]
Options:
        -f,  --files           scan files *
        -r,  --arc             scan archives
        -G,  --log=file        create log file
        -I,  --list            display all files
        -e,  --app             append to log file
        -F,  --infp=path       set infected quarantine folder
        -R,  --nor             do not recurse into folders
        -V,  --vlist           display virus list
        -p,  --prompt          prompt for action
        -d,  --dis             disinfect files
        -l,  --del             delete infected files
             --no-color        don't print with color
             --move            move infected files in quarantine folder
             --update          update
             --verbose         enabling verbose mode
             --sigtool         make files for malware signatures
        -?,  --help            this help
                               * = default option
			       
C:\kicomav\Release> _
```

**Example 2 :** Scan for current path

```
C:\kicomav\Release> python k2.py .
------------------------------------------------------------
KICOM Anti-Virus II (for WIN32) Ver 0.27 (May 4 2017)
Copyright (C) 1995-2017 Kei Choi. All rights reserved.
------------------------------------------------------------
Last updated Thu May  4 01:59:44 2017 UTC
Signature number: 1635

C:\kicomav\Relea ... 08ecba90d0cd778  infected : Trojan-Ransom.Win32.Snocry.cxu
C:\kicomav\Release\ ... 218e8a8d7eb93df1003  infected : Trojan.Win32.Agent.icgh


Results:
Folders           :4
Files             :37
Packed            :0
Infected files    :2
Suspect files     :0
Warnings          :0
Identified viruses:2
I/O errors        :0


C:\kicomav\Release> _
```

**Example 3 :** Scan for ZIP files

```
C:\kicomav\Release> python k2.py c:\temp -r -I
------------------------------------------------------------
KICOM Anti-Virus II (for WIN32) Ver 0.27 (May 4 2017)
Copyright (C) 1995-2017 Kei Choi. All rights reserved.
------------------------------------------------------------
Last updated Thu May  4 05:13:44 2017 UTC
Signature number: 1638

C:\kicomav\Release\sample\test.zip  ok
C:\kicomav\Relea ... .zip (dummy.txt)  infected : Dummy-Test-File (not a virus)


Results:
Folders           :0
Files             :2
Packed            :1
Infected files    :1
Suspect files     :0
Warnings          :0
Identified viruses:1
I/O errors        :0


C:\kicomav\Release> _
```

**Example 4 :** Display Virus list

```
C:\kicomav\Release> python k2.py c:\temp -V
------------------------------------------------------------
KICOM Anti-Virus II (for WIN32) Ver 0.27 (May 4 2017)
Copyright (C) 1995-2017 Kei Choi. All rights reserved.
------------------------------------------------------------
Last updated Thu May  4 05:13:44 2017 UTC
Signature number: 1638

Dummy-Test-File (not a virus)                      [dummy.kmd]
EICAR-Test-File (not a virus)                      [eicar.kmd]
Backdoor.Linux.Mirai.a.gen                         [emalware.kmd]
Trojan-Ransom.NSIS.MyxaH.niz                       [emalware.kmd]
Trojan-Ransom.NSIS.Onion.afvz                      [emalware.kmd]
Trojan-Ransom.Win32.Agent.aagy                     [emalware.kmd]
Trojan-Ransom.Win32.Agent.aahp                     [emalware.kmd]

...

Trojan.Win32.Inject.adnta                          [emalware.kmd]
Trojan.Win32.Inject.wnfq                           [emalware.kmd]
Trojan.Win32.Invader                               [emalware.kmd]
Trojan.Win32.KillDisk.gen                          [emalware.kmd]
Trojan.Win32.Menti.gen                             [emalware.kmd]
Worm.Script.Generic                                [emalware.kmd]
Virus.MSExcel.Laroux.Gen                           [macro.kmd]
Exploit.HWP.Generic                                [hwp.kmd]


C:\kicomav\Release> _
```

## Author

**Kei Choi**

+ [http://www.hanul93.com](http://www.hanul93.com)
+ [http://twitter.com/hanul93](http://twitter.com/hanul93)
+ [http://facebook.com/hanul93](http://facebook.com/hanul93)
+ [http://github.com/hanul93](http://github.com/hanul93)

## Supporters

![Supporters](http://www.kicomav.com/images/support.png)