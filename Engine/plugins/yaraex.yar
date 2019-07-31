import "pe"

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

rule Exploit_HWP_Agent_b
{
    meta:
        author = "Kei Choi"
        date = "2018-06-19"
        KicomAV = "Exploit.HWP.Agent.b"
    strings:
        $s1 = "kernel32.dll" nocase
        $s2 = /1\s+get\s+<636C6F736566696C65>\s+cvx\s+exec/
        $regex1 = /<[0-9A-Fa-f]{500,}/
    condition:
        all of them
}


rule Virus_Win32_PolyRansom_a
{
    meta:
        author = "Kei Choi"
        date = "2018-06-26"
        KicomAV = "Virus.Win32.PolyRansom.a"
    strings:
        $s1 = { b? ?? ?? 0? 00 b? ?? ?? 0? 00 81 ?? ?? ?? 0? 00 ?? ?? ?? 0? 00 }
        $s2 = { b? ?? ?? 0? 00 b? ?? ?? 0? 00 81 ?? ?? ?? 0? 00 81 ?? ?? ?? 0? 00 }
    condition:
        $s1 at pe.entry_point or $s2 at pe.entry_point
}
