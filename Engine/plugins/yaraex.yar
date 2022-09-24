rule IsPeFile {
meta:
    ref = "https://github.com/godaddy/yara-rules/blob/master/example.yara"
strings:
		$mz = "MZ"

	condition:
		$mz at 0 and uint32(uint32(0x3C)) == 0x4550
}

rule Hwp_Malware1
{
meta:
	author = "Kei Choi (hanul93@gmail.com)"
	date = "2017-08-23"
	KicomAV = "Trojan.PS.Agent.yra"
strings:
        $regex1 = /<[0-9A-Fa-f]{500,}/
        $string1 = "1 bitshift add" nocase
        $string2 = "(KERNEL32.DLL)" nocase
        $string3 = "(VirtualProtect)" nocase
        $string4 = "(ExitProcess)" nocase
    condition:
        all of them
}


rule Hwp_Malware2
{
meta:
	author = "Kei Choi (hanul93@gmail.com)"
	date = "2017-08-23"
	KicomAV = "Trojan.PS.Agent.yrb"
strings:
        $regex1 = /<[0-9A-Fa-f]{500,}/
        $regex2 = "90909090"
        $string1 = "putinterval def" nocase
        $string2 = "repeat" nocase
    condition:
        $regex1 in (0..256) and $regex2 in (0x17000..filesize) and (2 of ($string1, $string2))
}


rule Hwp_Malware3
{
meta:
	author = "Kei Choi (hanul93@gmail.com)"
	date = "2017-08-23"
	KicomAV = "Trojan.PS.Agent.yrc"
    strings:
        $regex1 = /<[0-9A-Fa-f]{500,}/
        $string1 = "4 mod get xor put" nocase
        $string2 = "exec" nocase
    condition:
        all of them
}


rule WannaCry : Ransomware
{
meta:
	author = "Kei Choi"
	date = "2018-04-04"
    KicomAV = "Trojan-Ransom.Win32.Wanna.gen"
	description = "Ransomware_WannaCry Yara Rule"
	hash0 = "a4cbf2307cafc733506e465b5a686307"
	hash1 = "f4856b368dc74f04adb9c4548993f148"
	hash2 = "04e1e9bacc659ae64fc2ae3a637a2daa"
	hash3 = "b1d52d54af3002b6775258a28bb38953"
	hash4 = "77a5be0a7d0c0ded340269d2ca9b8b94"
	hash5 = "aa089f31594076f4a1a4f5c76656a9db"
	hash6 = "4dcdb23838a010aa05f81447e826e65e"
	hash7 = "0bee63f915fe72daee9360f8f168bc64"
	hash8 = "c969cab67a026fb98309b62d35d6c605"
	hash9 = "ae72a3d3b9ee295436ba281171c50538"
	hash10 = "3503df16479880fdf484ace875ff3588"
	hash11 = "d69044b6e7fb5dfa6e07b4dfa0e06d15"
	hash12 = "9f2f3a01ddfbd0ddc65083f6472aa16c"
	sample_filetype = "exe"
	yaragenerator = "https://github.com/Xen0ph0n/YaraGenerator"
strings:
	$string0 = "gcblhgnjinjinjinjilhgjgfjfe"
	$string1 = "}yxfbagcb"
	$string2 = "V22dN::t"
	$string3 = "\\WINDOWS" wide
	$string4 = "XhHpSeA"
	$string5 = "_Tidy@"
	$string6 = "qnn]YXeaaifenjisontpoplkkgfplkqmlokjhdc"
	$string7 = "kgfhdciedfba"
	$string8 = "s.wnry"
	$string9 = "Amazon"
	$string10 = "$8,4-6'96$:."
	$string11 = "mihhdcgcbgcbgcbgcbgbaxts"
	$string12 = "1exception@@UAE@XZ"
	$string13 = "OMMuss"
	$string14 = "$allocator@G@2@@std@@2IB"
	$string15 = "Qkkbal"
	$string16 = "CryptImportKey"
condition:
	16 of them and IsPeFile
}


rule APT34_Malware_Exeruner {
   meta:
      description = "Detects APT 34 malware"
      author = "Florian Roth"
      reference = "https://www.fireeye.com/blog/threat-research/2017/12/targeted-attack-in-middle-east-by-apt34.html"
      date = "2017-12-07"
      hash1 = "c75c85acf0e0092d688a605778425ba4cb2a57878925eee3dc0f4dd8d636a27a"
      KicomAV = "Trojan-Dropper.MSIL.Agent.gen"
   strings:
      $x1 = "\\obj\\Debug\\exeruner.pdb" ascii
      $x2 = "\"wscript.shell`\")`nShell0.run" wide
      $x3 = "powershell.exe -exec bypass -enc \" + ${global:$http_ag} +" wide
      $x4 = "/c powershell -exec bypass -window hidden -nologo -command " fullword wide
      $x5 = "\\UpdateTasks\\JavaUpdatesTasksHosts\\" wide
      $x6 = "schtasks /create /F /ru SYSTEM /sc minute /mo 1 /tn" wide
      $x7 = "UpdateChecker.ps1 & ping 127.0.0.1" wide
      $s8 = "exeruner.exe" fullword wide
      $s9 = "${global:$address1} = $env:ProgramData + \"\\Windows\\Microsoft\\java\";" fullword wide
      $s10 = "C:\\ProgramData\\Windows\\Microsoft\\java" fullword wide
      $s11 = "function runByVBS" fullword wide
      $s12 = "$84e31856-683b-41c0-81dd-a02d8b795026" fullword ascii
      $s13 = "${global:$dns_ag} = \"aQBmACAAKAAoAEcAZQB0AC0AVwBtAGk" wide
   condition:
      IsPeFile and filesize < 100KB and 1 of them
}

rule APT34_Malware_HTA {
   meta:
      description = "Detects APT 34 malware"
      author = "Florian Roth"
      reference = "https://www.fireeye.com/blog/threat-research/2017/12/targeted-attack-in-middle-east-by-apt34.html"
      date = "2017-12-07"
      hash1 = "f6fa94cc8efea0dbd7d4d4ca4cf85ac6da97ee5cf0c59d16a6aafccd2b9d8b9a"
      KicomAV = "Trojan.VBS.Powbow.gen"
   strings:
      $x1 = "WshShell.run \"cmd.exe /C C:\\ProgramData\\" ascii
      $x2 = ".bat&ping 127.0.0.1 -n 6 > nul&wscript  /b" ascii
      $x3 = "cmd.exe /C certutil -f  -decode C:\\ProgramData\\" ascii
      $x4 = "a.WriteLine(\"set Shell0 = CreateObject(" ascii
      $x5 = "& vbCrLf & \"Shell0.run" ascii

      $s1 = "<title>Blog.tkacprow.pl: HTA Hello World!</title>" fullword ascii
      $s2 = "<body onload=\"test()\">" fullword ascii
   condition:
      filesize < 60KB and ( 1 of ($x*) or all of ($s*) )
}

rule Trojan_JS_Malware1 {
   meta:
      hash1 = "000461e3edf7eee69ed45f0831858db2b0636f3059d31162040015d1330a0cee"
      KicomAV = "Trojan.JS.Generic"
   strings:

      $regex1 = /[0-9A-Fa-f]{500}/
      
      $hex1 = "function"
      $hex2 = "eval(eval"

   condition:
       $hex1 in (0..4096) and all of them
      
}

rule HWP_eps_exploit1 {
    meta:
        hash1 = "a68169aba0691c337241ea1049d8d848765dcfc35a9e43897c51379979b48455"
        KicomAV = "Exploit.HWP.CVE-2015-2545"
    strings:
        $regex1 = /[0-9A-Fa-f]{200}/
        $regex2 = /3.{46}D>\s+token\s+pop\s+exch\s+pop\s+exec\b/ nocase
    condition:
        $regex1 in (0..4096) and filesize < 20KB and all of them
}

rule HWP_Trojan_Agent1 {
    meta:
        hash1 = "cd6a12cc693e98e4f47d2161e9fe99d04895472d964575c749bbdd460f0fefdc"
        KicomAV = "Exploit.HWP.Agent"
    strings:
        $regex1 = /[0-9A-Fa-f]{200}/
        $regex2 = /\bcopy\s*get\s*\d{1,}\s*xor\s+put\s+ar\s*}for\b/ nocase
    condition:
        $regex1 in (0..4096) and filesize < 20KB and all of them
}



