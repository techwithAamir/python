/*
   Rule Set for Malware Detection
   This file contains rules for detecting various types of malware based on 
   string patterns, hexadecimal byte sequences, and specific file attributes.
*/

rule Detect_Malicious_Powershell
{
    meta:
        description = "Detects suspicious Powershell usage in scripts or executables"
        author = "YARA Example"
        date = "2024-09-22"
    strings:
        $powershell = "powershell.exe"
        $base64_cmd = "base64"
        $encoded = "-EncodedCommand"
    condition:
        $powershell and $encoded and $base64_cmd
}

rule Detect_Packed_Executable
{
    meta:
        description = "Detects executables packed with UPX or other packers"
        author = "YARA Example"
        date = "2024-09-22"
    strings:
        $upx = "UPX!"                // UPX packer signature
        $pe_start = { 4D 5A }        // MZ header (PE file format)
    condition:
        $upx or ($pe_start and filesize < 100KB)   // Small PE files can be packed
}

rule Detect_Malicious_Registry_Changes
{
    meta:
        description = "Detects modifications to suspicious Windows registry keys"
        author = "YARA Example"
        date = "2024-09-22"
    strings:
        $reg_key1 = "HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Windows\\CurrentVersion\\Run"
        $reg_key2 = "HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Run"
    condition:
        any of ($reg_key*)
}

rule Detect_Network_Connections
{
    meta:
        description = "Detects hardcoded IP addresses, commonly used in malware for C2 servers"
        author = "YARA Example"
        date = "2024-09-22"
    strings:
        $ip1 = "192.168.1.1"   // Replace with known malicious IPs
        $ip2 = "10.0.0.5"
        $ip_regex = /\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/   // Regex to match IP addresses
    condition:
        any of ($ip*)   // Matches any of the IP strings or the regex
}

rule Detect_Malicious_Javascript
{
    meta:
        description = "Detects common malicious JavaScript patterns"
        author = "YARA Example"
        date = "2024-09-22"
    strings:
        $eval = "eval("
        $unescape = "unescape("
        $document_write = "document.write("
        $base64 = "atob("   // Base64 decoding function in JS
    condition:
        any of ($eval, $unescape, $document_write, $base64)
}

rule Detect_Malicious_VBScript
{
    meta:
        description = "Detects common malicious VBScript patterns"
        author = "YARA Example"
        date = "2024-09-22"
    strings:
        $wscript_shell = "WScript.Shell"
        $create_object = "CreateObject"
        $exec = "Exec("
        $cmd = "cmd.exe"
    condition:
        $wscript_shell and $create_object and $cmd
}

rule Detect_Ransomware_Behavior
{
    meta:
        description = "Detects common ransomware behaviors such as file encryption"
        author = "YARA Example"
        date = "2024-09-22"
    strings:
        $ransom_note = "Your files have been encrypted"
        $file_extension1 = ".lock"
        $file_extension2 = ".crypt"
    condition:
        $ransom_note or any of ($file_extension*)
}

rule Detect_PE_Executable
{
    meta:
        description = "Detects the presence of PE executables within a file"
        author = "YARA Example"
        date = "2024-09-22"
    strings:
        $mz = { 4D 5A }   // PE file signature (MZ header)
        $pe = { 50 45 00 00 }   // PE signature
    condition:
        $mz at 0 and $pe at 0x3C
}

rule Detect_Malicious_Shellcode
{
    meta:
        description = "Detects suspicious shellcode patterns in binaries"
        author = "YARA Example"
        date = "2024-09-22"
    strings:
        $shellcode1 = { 31 C0 50 68 2E 65 78 65 68 63 61 6C 63 8D 1C 24 50 B8 C7 93 C2 77 FFD0 }
        $shellcode2 = { 6A 0B 58 99 52 66 68 2D 70 89 E1 52 6A 68 68 2F 2F 73 68 68 2F 62 69 6E 89 E3 52 53 89 E1 CD 80 }
    condition:
        any of them
}
