import "hash"


rule ReEvil
{
    meta:
        description = "Detects REvil ransomware based on full behavioral indicators, hashes, and PE structure"
        author = "Jayesh Choudhary"
        date = "2025-05-07"
        reference = "https://doublepulsar.com/kaseya-supply-chain-attack-delivers-mass-ransomware-event-to-us-companies-76e4ec6ec64b, https://community.sophos.com/b/security-blog/posts/active-ransomware-attack-on-kaseya-customersw, https://csirt.divd.nl/2021/07/04/Kaseya-Case-Update-2/, https://github.com/cado-security/DFIR_Resources_REvil_Kaseya/tree/main,https://github.com/Neo23x0/signature-base/blob/e360605894c12859de36f28fda95140aa330694b/yara/crime_ransom_revil.yar"

    strings:
        
        $reg = "HKEY_LOCAL_MACHINE\\SOFTWARE\\Wow6432Node\\BlackLivesMatter" ascii nocase

        
        $ps1 = "C:\\WINDOWS\\system32\\cmd.exe /c ping 127.0.0.1 -n 6258 > nul & C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe Set-MpPreference -DisableRealtimeMonitoring $true -DisableIntrusionPreventionSystem $true -DisableIOAVProtection $true -DisableScriptScanning $true -EnableControlledFolderAccess Disabled -EnableNetworkProtection AuditMode -Force -MAPSReporting Disabled -SubmitSamplesConsent NeverSend & copy /Y C:\\Windows\\System32\\certutil.exe C:\\Windows\\cert.exe & echo %RANDOM% >> C:\\Windows\\cert.exe & C:\\Windows\\cert.exe -decode c:\\kworking\\agent.crt c:\\kworking\\agent.exe & del /q /f c:\\kworking\\agent.crt C:\\Windows\\cert.exe & c:\\kworking\\agent.exe" ascii nocase

        $ps2 = "C:\\Windows\\system32\\cmd.exe /c ping 127.0.0.1 -n 5693 > nul & C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe Set-MpPreference -DisableRealtimeMonitoring $true -DisableIntrusionPreventionSystem $true -DisableIOAVProtection $true -DisableScriptScanning $true -EnableControlledFolderAccess Disabled -EnableNetworkProtection AuditMode -Force -MAPSReporting Disabled -SubmitSamplesConsent NeverSend & copy /Y C:\\Windows\\System32\\certutil.exe C:\\Windows\\cert.exe & echo %RANDOM% >> C:\\Windows\\cert.exe & C:\\Windows\\cert.exe -decode c:\\kworking\\agent.crt c:\\kworking\\agent.exe & del /q /f c:\\kworking\\agent.crt C:\\Windows\\cert.exe & c:\\kworking\\agent.exe" ascii nocase

        
        $cmd1 = "copy /Y C:\\Windows\\System32\\certutil.exe C:\\Windows\\cert.exe" ascii nocase
        $cmd2 = "C:\\Windows\\cert.exe -decode c:\\kworking\\agent.crt c:\\kworking\\agent.exe" ascii nocase
        $cmd3 = "echo %RANDOM% >> C:\\Windows\\cert.exe" ascii nocase
        $cmd4 = "del /q /f c:\\kworking\\agent.crt C:\\Windows\\cert.exe" ascii nocase
        $cmd5 = "c:\\kworking\\agent.exe" ascii nocase

        
        $file1 = "cert.exe" ascii nocase
        $file2 = "msmpeng.exe" ascii nocase
        $file3 = "agent.crt" ascii nocase
        $file4 = "agent.exe" ascii nocase
        $file5 = "mpsvc.dll" ascii nocase


        $api1 = "VirtualAlloc" ascii nocase
        $api2 = "VirtualProtect" ascii nocase
        $api3 = "LoadLibraryA" ascii nocase
        $api4 = "GetProcAddress" ascii nocase
        $api5 = "InternetOpenUrlA" ascii nocase
        $api6 = "WinExec" ascii nocase

        
        $s1 = { 0f 8c 74 ff ff ff 33 c0 5f 5e 5b 8b e5 5d c3 8b }
        $s2 = { 8d 85 68 ff ff ff 50 e8 2a fe ff ff 8d 85 68 ff }
        $s3 = { 89 4d f4 8b 4e 0c 33 4e 34 33 4e 5c 33 8e 84 }
        $s4 = { 8d 85 68 ff ff ff 50 e8 05 06 00 00 8d 85 68 ff }
        $s5 = { 8d 85 68 ff ff ff 56 57 ff 75 0c 50 e8 2f }

    condition:
        (
            
            hash.sha256(0, filesize) == "d55f983c994caa160ec63a59f6b4250fe67fb3e8c43a388aec60a4a6978e9f1e" or
            hash.sha256(0, filesize) == "0496ca57e387b10dfdac809de8a4e039f68e8d66535d5d19ec76d39f7d0a4402" or
            hash.sha256(0, filesize) == "8dd620d9aeb35960bb766458c8890ede987c33d239cf730f93fe49d90ae759dd" or
            hash.sha256(0, filesize) == "cc0cdc6a3d843e22c98170713abf1d6ae06e8b5e34ed06ac3159adafe85e3bd6" or
            hash.sha256(0, filesize) == "f864922f947a6bb7d894245b53795b54b9378c0f7633c521240488e86f60c2c5" or
            hash.sha256(0, filesize) == "559e9c0a2ef6898fabaf0a5fb10ac4a0f8d721edde4758351910200fe16b5fa7" or
            hash.sha256(0, filesize) == "ea1872b2835128e3cb49a0bc27e4727ca33c4e6eba1e80422db19b505f965bc4" or

            
            hash.md5(0, filesize) == "4f09f5d17fca62c6f59e6b68f0a0e6e9" or
            hash.md5(0, filesize) == "47f4c6f0a7464a3c338d32c07ef0f123" or
            hash.md5(0, filesize) == "b3e81ab25b4b8c4d9b5d7b301bca95cc" or
            hash.md5(0, filesize) == "d6f0f299a8f44d07b1f2762ec1d2eb4c"
        )
        or
        (
            
            3 of ($s*) or 3 of ($ps*) or 5 of ($cmd*) or 5 of ($file*) or 3 of ($api*) or $reg
        )
        
}
