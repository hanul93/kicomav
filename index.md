---
layout: default
---

# About KicomAV

***


KicomAV is an open source (GPL v2) antivirus engine designed for detecting malware and disinfecting it. In fact, Since 1995, it has been written in C/C++ and it was integrated into the ViRobot engine of [HAURI](http://www.hauri.co.kr), 1998. I decided to re-create a new KicomAV. So, this is developed in Python. Anyone can participate in the development easily.

<style>.embed-container { position: relative; padding-bottom: 56.25%; height: 0; overflow: hidden; max-width: 100%; } .embed-container iframe, .embed-container object, .embed-container embed { position: absolute; top: 0; left: 0; width: 100%; height: 100%; }</style><div class='embed-container'><iframe src='https://www.youtube.com/embed/In-YnHDyDbk' frameborder='0' allowfullscreen></iframe></div>

## 1. How to use

***

### Requirements

* Python 2.7
* [pylzma](https://github.com/fancycode/pylzma)
* [yara](https://github.com/plusvic/yara)


### Quick start

* Three quick start options are available:
    * [Download the latest release](https://github.com/hanul93/kicomav/archive/master.zip) and unzip it.
    * Clone the repo: ```git clone git://github.com/hanul93/kicomav.git```.
    * Build KicomAV Engine & Plugins modules : ```build.sh build``` or ```build.bat build```
    * You can see ```Release``` Directory. Change the ```Release``` directory and run ```k2.py```.
    * You can update the latest signature. Run ```k2.py --update```.

## 2. Releases

***

### 0.28 (Sep 4, 2017)

* Improved decompression speed of compressed files
* Added resource parsing function for PE file
* Added malware scanning function using YARA rule
* Fixed product hang when extracting ZIP files with errors
* Fixed errors when scanning ZIP and HWP files with passwords

### 0.27b (May 22, 2017)

* Fixed for pylzma import error

### 0.27a (May 17, 2017)

* Enabled update option (--update)

### 0.27 (May 4, 2017)

* Redesigned an architecture of KicomAV

### 0.26 (June 16, 2016)

* Added support for decompressed BinData/BIN0001.OLE in HWP File
* Added support for decompressed OleNative in OLE File
* Added support for scanning the malware for APK(Android) files

### 0.25 (July 18, 2013)

* Added support for decompressed UPX file
* Added support for separated the attached files from PE file
* Added support for scannning the malware for Common Object File Format (COFF)

### 0.24 (July 7, 2013)

* Added support for decompressed ALZ file
* Added support for decompressed EGG file
* Added support for scanning the malware for MSWord and MSExcel files

### 0.23 (June 27, 2013)

* Added support for scanning the malware for PE file
* Added support for multi scan paths
* Added display for the signature number and the last update information
* BUGFIX : infinite loop in OLE PPS Dump

### 0.22 (June 16, 2013)

* Added support for decompressed OLE file
* Added support for scanning the exploit code for Hangul Word Processor (HWP) file

### 0.21 (June 11, 2013)

* Added support for command option for archive files
* Added support for decompressed ZIP file

### 0.20b (June 1, 2013)

* Added support for command line : k2.py

### 0.20 (May 27, 2013)

* Redesigned Plug-in architectures

### 0.10 (May 8, 2013)

* Initial release


## 3. Supporters

***

![](/images/support.png)