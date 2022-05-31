# Detect new code injection method in Microsoft Office CVE-2022-30190

## Author
Trellix Threat Labs - CB

## Description
A recent maldoc contained a novel way of downloading and injecting code using the msdt.exe tool to execute PowerShell and download malicious code #CVE-2022-30190
## Rule Class 
Processes

## Rule TCL
```tcl
The original rule: 
Rule {
    Process {
        Include OBJECT_NAME { -v "WINWORD.exe" }
        Include OBJECT_NAME { -v "EXCEL.exe" }
        Include OBJECT_NAME { -v "OUTLOOK.exe"}
    }
    Target {
        Match PROCESS {
            Include OBJECT_NAME { -v "msdt.exe" }
            
            Include -access "CREATE"
        }
    }
}
```

## Trigger
NA

## Tested Platforms
OS: Windows 10 1909 x64
ENS: 10.7.0

## Notes
Customers are advised to fine-tune the rule in their environment or disable the signature if there are false positives.
