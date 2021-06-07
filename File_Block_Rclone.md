
Scenario 1 // block the execution of RCLone by calling the config
----------
Rule {
    Target {
        Match FILE {
            Include OBJECT_NAME { -v "C:\\Users\\**\\.config\\rclone*" }
            Include -access "CREATE"
        }
    }
}

Scenario 2 // block the usage of RClone and used commandline options
----------
Rule {
    Process {
        Include OBJECT_NAME { -v "powershell.exe" }
        Include OBJECT_NAME { -v "cmd.exe" }
    }
    Target {
        Match PROCESS {
            Include OBJECT_NAME { -v "rclone.exe" }
            Include PROCESS_CMD_LINE {
                -v "** pass **"
                -v "** user **"
                -v "** copy **"
                -v "** mega **"
                -v "** sync **"
                -v "** config **"
                -v "** lsd **"
                -v "** remote **"
                -v "** ls **"
            }
            Include -access "CREATE"
        }
    }
}

