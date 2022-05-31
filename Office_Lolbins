# Detects Office applications that spin up LOLbins

## Author
Trellix Threat Labs - CB

## Description
In some cases, Office docuemtns with a malicious intent can fire up a LOLbin process to execute a suspicious process.
## Rule Class 
Processes

## Rule TCL
```tcl
The original rule: 
Rule {
    Process {
        Include OBJECT_NAME { -v "WINWORD.exe" }
 
    }
    Target {
        Match PROCESS {
            Include OBJECT_NAME { -v "msdt" }
            Include OBJECT_NAME { -v "msiexec" }
            Include OBJECT_NAME { -v "mshta" }
            Include OBJECT_NAME { -v "verclsid" }
            Include OBJECT_NAME { -v "certutil" }
            
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
