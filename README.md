<img src="https://dl.dropboxusercontent.com/u/5806441/safe_image.png">


# KicomAV v0.26

KicomAV is an open source (GPL v2) antivirus engine designed for detecting malware and disinfecting it. This antivirus engine is created and maintained by [Kei Choi](http://twitter.com/hanul93).


## Requirements

* Python 2.7


## Quick start

Three quick start options are available:

* [Download the latest release](https://github.com/hanul93/kicomav/archive/master.zip) and unzip it.
* Clone the repo: `git clone git://github.com/hanul93/kicomav.git`.
* Build KicomAV Engine & Plugins modules : `build.sh` or `build.bat build`
* You can see `Release` Directory. Change the `Release` directory and run `k2.py`.



## Usage

```
C:\kicomav\Release> python k2.py [path] [options]
```

**Example 1 :** KicomAV help Options 

```
C:\kicomav\Release> python k2.py
------------------------------------------------------------
KICOM Anti-Virus II (for WIN32) Ver 0.26 (Jun 16 2016)
Copyright (C) 1995-2016 Kei Choi. All rights reserved.
------------------------------------------------------------

Usage: k2.py path[s] [options]
Options:
        -f,  --files           scan files *
        -r,  --arc             scan archives
        -I,  --list            display all files
        -V,  --vlist           display virus list
             --update          update
             --sigtool         create a malware signature
             --no-color        not print color
        -?,  --help            this help
                               * = default option

C:\kicomav\Release> _
```

**Example 2 :** Scan for current path

```
C:\kicomav\Release> python k2.py .
------------------------------------------------------------
KICOM Anti-Virus II (for WIN32) Ver 0.26 (Jun 16 2016)
Copyright (C) 1995-2016 Kei Choi. All rights reserved.
------------------------------------------------------------
Last updated Thu Jun 16 05:09:56 2016 UTC
Signature number: 10

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

**Example 3 :** Scan for ZIP files

```
C:\kicomav\Release> python k2.py c:\temp -r -I
------------------------------------------------------------
KICOM Anti-Virus II (for WIN32) Ver 0.26 (Jun 16 2016)
Copyright (C) 1995-2016 Kei Choi. All rights reserved.
------------------------------------------------------------
Last updated Thu Jun 16 05:09:56 2016 UTC
Signature number: 10

c:\temp ok
c:\temp\1.zip ok
c:\temp\1.zip (eicar.txt) infected : EICAR-Test-File (not a virus)
c:\temp\1.zip (test.zip) ok
c:\temp\1.zip (test.zip/dummy.txt) infected : Dummy-Test-File (not a virus)
c:\temp\1.zip (test.zip/eicar.txt) infected : EICAR-Test-File (not a virus)
c:\temp\CSS2013.docx ok
c:\temp\CSS2013.docx ([Content_Types].xml) ok
c:\temp\CSS2013.docx (_rels/.rels) ok
c:\temp\CSS2013.docx (word/_rels/document.xml.rels) ok
c:\temp\CSS2013.docx (word/document.xml) ok
c:\temp\CSS2013.docx (word/endnotes.xml) ok
c:\temp\CSS2013.docx (word/footnotes.xml) ok
c:\temp\CSS2013.docx (word/footer1.xml) ok
c:\temp\CSS2013.docx (word/_rels/footer1.xml.rels) ok
c:\temp\CSS2013.docx (word/_rels/header1.xml.rels) ok
c:\temp\CSS2013.docx (word/header1.xml) ok
c:\temp\CSS2013.docx (word/media/image2.jpeg) ok
c:\temp\CSS2013.docx (word/theme/theme1.xml) ok
c:\temp\CSS2013.docx (word/media/image1.png) ok
c:\temp\CSS2013.docx (word/settings.xml) ok
c:\temp\CSS2013.docx (word/styles.xml) ok
c:\temp\CSS2013.docx (customXml/itemProps1.xml) ok
c:\temp\CSS2013.docx (word/numbering.xml) ok
c:\temp\CSS2013.docx (customXml/_rels/item1.xml.rels) ok
c:\temp\CSS2013.docx (customXml/item1.xml) ok
c:\temp\CSS2013.docx (docProps/core.xml) ok
c:\temp\CSS2013.docx (word/fontTable.xml) ok
c:\temp\CSS2013.docx (word/webSettings.xml) ok
c:\temp\CSS2013.docx (word/stylesWithEffects.xml) ok
c:\temp\CSS2013.docx (docProps/app.xml) ok


Results:
Folders           :1
Files             :30
Packed            :0
Infected files    :3
Suspect files     :0
Warnings          :0
Identified viruses:2
I/O errors        :0

C:\kicomav\Release> _
```

**Example 4 :** Display Virus list

```
C:\kicomav\Release> python k2.py c:\temp -V
------------------------------------------------------------
KICOM Anti-Virus II (for WIN32) Ver 0.26 (Jun 16 2016)
Copyright (C) 1995-2016 Kei Choi. All rights reserved.
------------------------------------------------------------
Last updated Thu Jun 16 05:09:56 2016 UTC
Signature number: 10

Virus.MSExcel.Laroux.A                             [macro.kmd]
Exploit.HWP.Generic.42                             [hwp.kmd]
Exploit.HWP.Generic.43                             [hwp.kmd]
Exploit.HWP.Generic.5A                             [hwp.kmd]
Exploit.HWP.Generic.EX                             [hwp.kmd]
Dummy-Test-File (not a virus)                      [dummy.kmd]
EICAR Test                                         [eicar.kmd]
Exploit.Android.MasterKey.A                        [apk.kmd]
Exploit.OLE.CVE-2014-4114                          [base1.kmd]

C:\kicomav\Release> _
```

## Author

**Kei Choi**

+ [http://twitter.com/hanul93](http://twitter.com/hanul93)
+ [http://facebook.com/hanul93](http://facebook.com/hanul93)
+ [http://github.com/hanul93](http://github.com/hanul93)