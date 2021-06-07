
Scenario 1
----------
Rule {
    Target {
        Match FILE {
            Include OBJECT_NAME { -v "C:\\Users\\**\\.config\\rclone*" }
            Include -access "CREATE"
        }
    }
}

Scenario 2
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

