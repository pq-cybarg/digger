/*
    digger baseline YARA rules.
    Catches a small set of high-signal patterns. Customize/replace under
    digger/rules/yara/ for your environment.
*/

import "hash"

rule digger_mimikatz_strings
{
    meta:
        author = "digger"
        severity = "high"
        description = "Mimikatz-like strings (sekurlsa/kerberos/lsadump)"
    strings:
        $a = "sekurlsa::" ascii wide
        $b = "kerberos::" ascii wide
        $c = "lsadump::"  ascii wide
        $d = "privilege::debug" ascii wide
        $e = "gentilkiwi"  ascii wide
    condition:
        any of them
}

rule digger_cobaltstrike_default_strings
{
    meta:
        author = "digger"
        severity = "high"
        description = "Cobalt Strike default beacon strings"
    strings:
        $a = "%%IMPORT%%" ascii
        $b = "beacon.x64.dll" ascii
        $c = "beacon.dll" ascii
        $d = "ReflectiveLoader" ascii
        $e = "spawnto_x64" ascii
        $f = "%PROCESS%_%PID%" ascii
    condition:
        2 of them
}

rule digger_powerview_strings
{
    meta:
        author = "digger"
        severity = "medium"
        description = "PowerView/PowerSploit strings (PowerShell tooling)"
    strings:
        $a = "Invoke-Mimikatz" ascii wide
        $b = "PowerView" ascii wide
        $c = "Invoke-Kerberoast" ascii wide
        $d = "Invoke-PsExec" ascii wide
    condition:
        any of them
}

rule digger_reverse_shell_oneliners
{
    meta:
        author = "digger"
        severity = "high"
        description = "Common reverse shell one-liners"
    strings:
        $a = "/dev/tcp/" ascii wide
        $b = "socket.socket(socket.AF_INET" ascii wide
        $c = "pty.spawn(\"/bin/" ascii wide
        $d = "powershell -nop -w hidden -c $client = New-Object" ascii wide nocase
    condition:
        any of them
}

rule digger_credharvest_keywords
{
    meta:
        author = "digger"
        severity = "medium"
        description = "Credential-harvesting keywords inline in a binary"
    strings:
        $a = "AWS_SECRET_ACCESS_KEY" ascii wide
        $b = "OPENAI_API_KEY" ascii wide
        $c = "NPM_TOKEN" ascii wide
        $d = "GITHUB_TOKEN" ascii wide
        $e = "passw" ascii wide nocase
    condition:
        2 of them
}

rule digger_shai_hulud_markers
{
    meta:
        author = "digger"
        severity = "critical"
        description = "Shai-Hulud worm marker strings (bundle.js, workflow)"
    strings:
        $a = "shai-hulud" ascii wide nocase
        $b = "trufflehog" ascii wide nocase
        $c = "webhook.site/" ascii wide
        $d = "shai-hulud-workflow" ascii wide nocase
    condition:
        2 of them
}
