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
