# Detect VSS COM Object Invocation via non-microsoft signed process loading vss_ps.dll

## Author
McAfee

## Description
This rule detects when the VSS (Volume Shadow Copy Service) COM Object DLL vss_ps.dll is called outside of normal call sequence indicating volume shadow share is about to be deleted. This is a new VSS deletion method likely to be used by ransomware actors.

## Rule Class 
Processes

## Rule TCL
```tcl
The original rule: 
Rule {
    Process {
        Include OBJECT_NAME { -v ** }
        Exclude CERT_NAME { -v "*Microsoft Corporation*" }
    }
	Target {
		Match FILE {
			Include OBJECT_NAME { 					
				-v "vss_ps.dll"
			}	
			Include CERT_NAME { -v "*Microsoft Corporation*" }
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
Customers are advised to fine-tune the rule in their environment or disable the signature if there are false positives.
