# # # # # # # # # # # # # # # # # # 
#   Sysmon + other winevents :P  #
# # # # # # # # # # # # # # # # # # 

$ErrorActionPreference = "Stop"

# # # # # # # # # # # # # # #
#      Admin Check          #
# # # # # # # # # # # # # # #

$isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()
).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")

if (-not $isAdmin) {
    Write-Error "Run this script as Administrator."
    exit 1
}

# # # # # # # # # # # # # # #
#   Set Audit func          #
# # # # # # # # # # # # # # #

function Set-AuditSubcategory {
    param(
        [Parameter(Mandatory=$true)][string]$Name,
        [Parameter(Mandatory=$true)][ValidateSet("enable","disable")]$Success,
        [Parameter(Mandatory=$true)][ValidateSet("enable","disable")]$Failure
    )
    cmd /c "auditpol /set /subcategory:`"$Name`" /success:$Success /failure:$Failure" | Out-Null
}

# # # # # # # # # # # # # # #
# Download + Install Sysmon #
# # # # # # # # # # # # # # #

New-Item -ItemType Directory -Path C:\Sysmon -Force | Out-Null

Invoke-WebRequest `
  -Uri "https://download.sysinternals.com/files/Sysmon.zip" `
  -OutFile "C:\Sysmon\Sysmon.zip" `
  -UseBasicParsing

Expand-Archive C:\Sysmon\Sysmon.zip C:\Sysmon -Force

Invoke-WebRequest `
  -Uri "https://raw.githubusercontent.com/SwiftOnSecurity/sysmon-config/refs/heads/master/sysmonconfig-export.xml" `
  -OutFile "C:\Sysmon\sysmonconfig.xml" `
  -UseBasicParsing

Set-Location C:\Sysmon
.\Sysmon64.exe -accepteula -i sysmonconfig.xml

# # # # # # # # # # # # # # #
# Enable Process Cmdline    #
# # # # # # # # # # # # # # #

reg add HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System\Audit `
 /v ProcessCreationIncludeCmdLine_Enabled /t REG_DWORD /d 1 /f | Out-Null

# # # # # # # # # # # # # # #
# Enable Audit Categories   #
# # # # # # # # # # # # # # #

# Success + Failure (high value failures)
Set-AuditSubcategory "Process Creation"              enable enable
Set-AuditSubcategory "File Share"                    enable enable
Set-AuditSubcategory "Detailed File Share"           enable enable
Set-AuditSubcategory "Other Logon/Logoff Events"     enable enable
Set-AuditSubcategory "Security System Extension"     enable enable

# Success only (reduce noise)
Set-AuditSubcategory "Process Termination"           enable disable
Set-AuditSubcategory "Filtering Platform Connection" enable disable
Set-AuditSubcategory "Other Object Access Events"    enable disable

# # # # # # # # # # # # # # #
#          Done             #
# # # # # # # # # # # # # # #

Write-Host "Sysmon + other stuff."


# 5140 and 5145
Enable-Audit "File Share" enable enable
Enable-Audit "Detailed File Share" enable enable

# 4648 
Enable-Audit "Other Logon/Logoff Events" enable enable

# 5156 and 5158
Enable-Audit "Filtering Platform Connection" enable disable

# 4697 b
Enable-Audit "Security System Extension" enable enable

Enable-Audit "Other Object Access Events" enable enable

Write-Host "Done Sysmon + other good stuff."
