# Block non-microsoft signed mpsvc.dll loading into MsMpEng.exe

## Author
McAfee

## Description
This rule blocks a non-microsoft signed mpsvc.dll loading into MsMpEng.exe process (mpsvc.dll side-loading vulnerable version of MsMpEng.exe needs to be dropped to box as pre-requisite). This behavior is observed with a few ransomware actors.

## Rule Class 
Processes

## Rule TCL
```tcl
The original rule: 
Rule {
    Process {
        Include OBJECT_NAME { -v "MsMpEng.exe" }
    }
	Target {
		Match FILE {
			Include OBJECT_NAME { 					
				-v "mpsvc.dll"
			}	
			Exclude CERT_NAME { -v "*Microsoft Corporation*" }
			Include -access "CREATE READ EXECUTE"
		}
			
	}
}
```

## Trigger
NA

## Tested Platforms
OS: Windows 10 1909 x64
ENS: 10.7.0 November'20 update

## Notes
This rule should be applied with both block and report action enabled. 
Customers are advised to fine-tune the rule in their environment or disable the signature if there are false positives.
