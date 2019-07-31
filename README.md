<img src="https://raw.githubusercontent.com/hanul93/kicomav-db/master/logo/k2_full_2.png">

# KicomAV v0.32

[![License](https://img.shields.io/badge/license-gpl2-blue.svg)](LICENSE)
![Platform](https://img.shields.io/badge/platform-windows-lightgrey.svg)
![Platform](https://img.shields.io/badge/platform-linux-lightgrey.svg)
![Platform](https://img.shields.io/badge/platform-mac-lightgrey.svg)

KicomAV is an open source (GPL v2) antivirus engine designed for detecting malware and disinfecting it. This antivirus engine is created and maintained by [Kei Choi](http://www.hanul93.com).


## Requirements

* Python 2.7
* [pylzma](https://github.com/fancycode/pylzma)
* [yara](https://github.com/plusvic/yara)
* [backports.lzma](https://github.com/peterjc/backports.lzma)

## Quick start

Three quick start options are available:

* [Download the latest release](https://github.com/hanul93/kicomav/archive/master.zip) and unzip it.
* Clone the repo: `git clone git://github.com/hanul93/kicomav.git`.
* Build KicomAV Engine & Plugins modules : `build.sh build` or `build.bat build`
* You can see `Release` Directory. Change the `Release` directory and run `k2.py`.


## Usage

```
C:\kicomav\Release> python k2.py [path] [options]
```

**Example 1 :** KicomAV help Options 

```
C:\kicomav\Release> python k2.py
```

![KicomAV_Run](http://www.hanul93.com/images/kicomav/k2_run.gif)

**Example 2 :** Update for malware signatures

```
C:\kicomav\Release> python k2.py --update
```

![KicomAV_Update](http://www.hanul93.com/images/kicomav/k2_update.gif)

**Example 3 :** Scan for current path

```
C:\kicomav\Release> python k2.py . -I
```

![KicomAV_Scan](http://www.hanul93.com/images/kicomav/k2_scan.gif)

**Example 4 :** Scan for ZIP files

```
C:\kicomav\Release> python k2.py sample -r -I
```

![KicomAV_Scan_Zip](http://www.hanul93.com/images/kicomav/k2_scan_zip.gif)

**Example 5 :** Display Virus list

```
C:\kicomav\Release> python k2.py -V
```

![KicomAV_Virus_list](http://www.hanul93.com/images/kicomav/k2_vlist.gif)


## Author

**Kei Choi**

+ [http://www.hanul93.com](http://www.hanul93.com)
+ [http://twitter.com/hanul93](http://twitter.com/hanul93)
+ [http://facebook.com/hanul93](http://facebook.com/hanul93)
+ [http://github.com/hanul93](http://github.com/hanul93)

## Supporters

![Supporters](http://www.kicomav.com/images/support.png)