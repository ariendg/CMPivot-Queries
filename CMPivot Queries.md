# All sorts of different CMPivot Queries to share to the community on github
```
Registry('HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion')
| where Property == 'UBR'
| summarize count() by Value
| render piechart with (legend=visible)
```
```
Registry('HKLM:\SOFTWARE\Microsoft\Windows Advanced Threat Protection\Status')
| where Property == 'Onboardingstate'
| summarize count() by Value
| render barchart
```
```
SystemBootData
| where Device == 'MyDevice'
| project SystemStartTime, BootDuration, OSStart=EventLogStart, GPDuration, UpdateDuration
| order by SystemStartTime desc
| render barchart with (kind=stacked, title='Boot times for MyDevice', ytitle='Time (ms)')
```
```
Registry('HKLM:\SOFTWARE\Microsoft\Windows Advanced Threat Protection\Status')
| where Property == 'Onboardingstate'
| join kind=fullouter Device
| join kind=fullouter OperatingSystem
| where Caption != 'Microsoft Windows Server 2012 Standard' and Caption != 'Microsoft Windows Server 2012 Datacenter' and Caption !like 'Microsoft Windows Server 2008%'
| where isnull(Value)
| project Device, Property, Value, Domain, Caption
```
```
Registry('HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Printers\PointAndPrint\NoElevationOnInstall')
| summarize count() by Value
| render piechart
```
```
Registry('HKLM:\\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Client')
| where Property == 'Enabled'
| summarize count() by Value
| render piechart

Registry('HKLM:\\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Client')
| summarize StateEnabled=countif(Property == 'Enabled') by Device
| summarize NumberOfDevices=count() by iif(StateEnabled==1,'YAY!','BOOO!')
| render piechart with (title='TLS 1.2 Status')

Registry('HKLM:\\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Client')
| where Property == 'Enabled'
| join kind=fullouter Device
| project Device, Value
| summarize count() by Value=iif(Value == '1', 'Enabled', 'Disabled')
```
```
Registry('HKLM:\SOFTWARE\Wow6432Node\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_ALLOW_USER32_EXCEPTION_HANDLER_HARDENING')
| where Property == 'iexplore.exe'
| summarize count() by Value
| render piechart
```
```
Registry('HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion')
| where Property == 'ProductName'
| summarize count() by Value
| render piechart
```
```
Registry('HKLM:\SOFTWARE\Microsoft\NET Framework Setup\NDP\v4\Full')
| where (Property == 'Release')
| summarize count() by iif(Value=='528049','.NET Framework 4.8',iif(Value=='461814','.NET Framework 4.7.2',iif(Value=='461310','.NET Framework 4.7.1',iif(Value=='460805','.NET Framework 4.7',iif(Value=='394802','.NET Framework 4.6.2',iif(Value=='379893','.NET Framework 4.5.2','Add more releases to iff'))))))
| order by iif desc
| render barchart with (title='.NET Framework Versions',xtitle='Version',ytitle='Device')
```
```
Registry('HKLM:\SOFTWARE\Microsoft\NET Framework Setup\NDP\v4\Full')
| join Device
| join OperatingSystem
| where (Property == 'Release')
| project Device, Domain, Caption, Value=iif(Value=='528049','.NET Framework 4.8',iif(Value=='461814','.NET Framework 4.7.2',iif(Value=='461310','.NET Framework 4.7.1',iif(Value=='460805','.NET Framework 4.7',iif(Value=='394802','.NET Framework 4.6.2',iif(Value=='379893','.NET Framework 4.5.2','Add more releases to iff'))))))
| order by Value asc
```
```
ComputerSystem | project Device
| join kind=leftouter Registry('HKLM:\\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Client')
| project Device, Property, Value
| summarize count() by Property, Value
```
```
Registry('HKLM:\\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Client')
| summarize NumberOfDevices=count() by Enabled=iif(Property == 'Enabled' and Value == '1', 'Enabled', 'Disabled')
| render barchart with (title='TLS 1.2 Status', xtitle='Status', ytitle='Number of Devices')
```
```
InstalledSoftware
| summarize countif( (ProductName like 'Traps%') ) by Device
| where (countif_ > 0)
| render piechart

InstalledSoftware
| where (ProductName like 'Traps%')

InstalledSoftware
| where (ProductName like 'Microsoft Office Professional%')

InstalledSoftware
| where (ProductName like 'VMware Tools%')
```
```
Device
| join kind=rightouter InstalledSoftware
| where (ProductName like 'Local Administrator%')
| summarize count() by ProductVersion
| render piechart with (title='LAPS Versions installed')
```
```
Registry('HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters') | where (Property == 'SMB1')
```
```
SMBConfig | summarize countif( (EnableSMB1Protocol == true) ) by Device | where (countif_ > 0) | summarize count() by countif_
SMBConfig | summarize countif( (EnableSMB1Protocol == false) ) by Device | where (countif_ > 0) | summarize count() by countif_

SMBConfig
| summarize Enabled=countif(EnableSMB1Protocol == true) by Device
| summarize NumberOfDevices=count() by iif(Enabled==1,'Enabled','Disabled')
| render barchart with (title='SMBv1 Status', xtitle='Status', ytitle='Number of Devices')
```
```
Registry('HKLM:\\SOFTWARE\\Microsoft\\PowerShell\\3\\PowerShellEngine')
| where (Property == 'PowerShellVersion')
| where Value != '5.1.14409.1005'

Registry('HKLM:\\SOFTWARE\\Microsoft\\PowerShell\\3\\PowerShellEngine')
| where (Property == 'PowerShellVersion')
| where Value !like '5.1%'

Registry('HKLM:\\SOFTWARE\\Microsoft\\PowerShell\\1\\PowerShellEngine')
| where (Property == 'PowerShellVersion')
```
```
Registry('HKLM:\\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest')
| where Property == 'UseLogonCredential'
| join kind=rightouter Device
| project Device, Property, Value, Domain
```
```
Registry('HKLM:\\SYSTEM\CurrentControlSet\Control\Lsa')
| where Property == 'RunAsPPL'
| join kind=fullouter Device
| join kind=fullouter OperatingSystem
| where Caption != 'Microsoft Windows Server 2012 Standard' and Caption != 'Microsoft Windows Server 2012 Datacenter' and Caption !like 'Microsoft Windows Server 2008%'
| project Device, Property, Value, Domain, Caption
```
```
Registry('HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\real-time protection')
| where Property == 'RealTimeScanDirection'
| join kind=fullouter Device
| summarize NumberOfDevices=count() by RealTimeScanDirectionComplianceState=iif(Property == 'RealTimeScanDirection' and Value == '0', 'Enabled', 'Disabled')
| render piechart

Registry('HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\real-time protection')
| where Property == 'DisableRealtimeMonitoring'
| join kind=fullouter Device
| summarize NumberOfDevices=count() by DisableRealtimeMonitoringComplianceState=iif(Property == 'DisableRealtimeMonitoring' and Value == '0', 'Enabled', 'Disabled')
```
```
Registry('HKLM:\\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest')
| where Property == 'UseLogonCredential'
| join kind=rightouter Device
| project Device, Property, Value, Domain
| where isnull(Value) | count
```
```
EPStatus
| project Device, RealTimeProtectionEnabled
| summarize count() by RealTimeProtectionEnabled
| render barchart with (title='Defender Endpoint Protection Real Time Protection Enabled')
```
```
Service
| where Name == 'Spooler'
| project name, Device, State, StartMode
Service
| where Name == 'Spooler'
| summarize count() by State
| render piechart
Service
| where (Name == 'QualysAgent')
| where (State == 'Stopped')
| join Device
| project Device, Domain, Name, StartMode, State
```
```
Service
| where (Name == 'DiagTrack')
| join kind=rightouter Device
| join kind=fullouter OperatingSystem
| where StartMode != 'Auto' or isnull(StartMode)
| where (((Caption != 'Microsoft Windows Server 2012 Standard') and (Caption != 'Microsoft Windows Server 2012 Datacenter')) and (Caption !like 'Microsoft Windows Server 2008%'))
| project Device, Domain, Caption, Name, StartMode, State
```
```
Registry('HKLM:\\\Software\Policies\Microsoft\Windows NT\Printers\PointAndPrint')
| where Property == 'RestrictDriverInstallationToAdministrators'
| join kind=rightouter Device
```
```
EventLog('System',60d)
| where EventID == 1074
```
```
CcmLog('LocationServices',1d ) | where LogText contains 'There is no AMP for site code' | project Device, LogText, DateTime
| summarize count() by Device
```
```
InstalledSoftware
| where (ProductName like 'Java%') and (ProductName like '%Update %')
| join kind=leftouter Device
| project Device, Domain, ProductName, ProductVersion
| order by ProductName asc
```
```
Registry('HKLM:\\Software\\Microsoft\\ServerManager')
| where (Property == 'DoNotOpenServerManagerAtLogon')
| join kind=rightouter Device
| where isnull(Property) or (Value == '0')
| project Device, Property, Value, Domain, UserName
```
```
QuickFixEngineering
| where HotFixID like 'KB500860%'
| join OperatingSystem
| project Device, ProductName, ProductVersion, Caption
| order by Caption asc

QuickFixEngineering
| where HotFixID like 'KB500860%'
| join kind=rightouter OperatingSystem 
| project Device, HotFixID, Version
```
```
InstalledSoftware
| where (ProductName like 'Microsoft SQL Server Management Studio%')
| join OperatingSystem
| project Device, ProductName, ProductVersion, Caption
| order by ProductVersion asc
```
```
SoftwareUpdate
| summarize count() by Title
| where Title !like 'Security Intelligence%'
| order by count_ desc
```
```
CcmLog('InventoryAgent',3d ) | where LogText contains 'log4j'
| join kind=rightouter Device
| where isnull(LogText)
| project Device, LogText, DateTime
```
```
Registry('HKLM:\SOFTWARE\Microsoft\Windows Advanced Threat Protection\Status')
| where Property == 'Onboardingstate' | project Device, Onboardingstate=Value
| join kind=fullouter Device
| join Registry('HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Group Policy\State\Machine')
| where Property == 'Distinguished-Name'
| join kind=fullouter OperatingSystem
| where Caption != 'Microsoft Windows Server 2012 Standard' and Caption != 'Microsoft Windows Server 2012 Datacenter' and Caption !like 'Microsoft Windows Server 2008%'
| where Onboardingstate == '0' or isnull(Onboardingstate)
| project Device, Onboardingstate, Domain, Caption, InstallDate, Property, OU=Value

Registry('HKLM:\\SOFTWARE\\Microsoft\\Windows Advanced Threat Protection\\Status')
| where (Property == 'Onboardingstate')
| project Device, Onboardingstate = Value
| join kind=fullouter Device
| join kind=fullouter OperatingSystem
| join WinEvent('Microsoft-Windows-SENSE/Operational',1day)
| join kind=rightouter Device
| where (((Caption != 'Microsoft Windows Server 2012 Standard') and (Caption != 'Microsoft Windows Server 2012 Datacenter')) and (Caption !like 'Microsoft Windows Server 2008%'))
| where ((Onboardingstate == '0') or isnull( Onboardingstate ))
| project Device, Onboardingstate, Domain, Caption, InstallDate, Message, DateTime
```
```
OperatingSystem
| where Caption like 'Microsoft Windows Server 2019%'
| project Device, Caption
| join kind=fullouter QuickFixEngineering
| where HotFixID == 'KB5009557'
| project Device, HotfixID
```
```
QuickFixEngineering
| where HotFixID == 'KB5009557'
| project Device, HotfixID
| join kind=rightouter OperatingSystem
| where Caption like 'Microsoft Windows Server 2019%'
| project Device, HotFixID
| summarize count() by iif(HotFixID=='KB5009557','KB5009557 is installed','Missing')
| render piechart with (title='Progress patching HTTP Protocol Stack Remote Code Execution Vulnerability CU WS2019')
```
```
Disk | where (Description == 'Local Fixed Disk')
| where Name == 'C:'
| where (FreeSpace <= 10240000000)
| join Device
| project Device, Domain, Size, FreeSpace
| order by FreeSpace asc
```
```
Service
| where (Name == 'QualysAgent')
| where (State == 'Stopped')
| join Device
| project Device, Domain, Name, StartMode, State
```
```
Service
| where (Name == 'DiagTrack')
| join kind=rightouter Device
| join kind=fullouter OperatingSystem
| where StartMode != 'Auto' or isnull(StartMode)
| where (((Caption != 'Microsoft Windows Server 2012 Standard') and (Caption != 'Microsoft Windows Server 2012 Datacenter')) and (Caption !like 'Microsoft Windows Server 2008%'))
| project Device, Domain, Caption, Name, StartMode, State
```
```
Disk | where (Description == 'Local Fixed Disk')
| where Name == 'C:'
| where (FreeSpace <= 10240000000)
| join Device
| project Device, Domain, Size, FreeSpace
| order by FreeSpace asc
```
```
Registry('HKLM:\\SYSTEM\CurrentControlSet\Control\Lsa')
| where Property == 'RunAsPPL'
| join kind=fullouter Device
| join kind=fullouter OperatingSystem
| where Caption != 'Microsoft Windows Server 2012 Standard' and Caption != 'Microsoft Windows Server 2012 Datacenter' and Caption !like 'Microsoft Windows Server 2008%'
| project Device, Value
| summarize count() by iif(Value=='1','Compliant','Non-Compliant still needs attention')
| render piechart with (title='Progress Mimikatz LSASS Protection configuration')
```
```
Registry('HKLM:\SOFTWARE\Microsoft\NET Framework Setup\NDP\v4\Full')
| join Device
| join OperatingSystem
| where (Property == 'Release')
| project Device, Domain, Caption, Value=iif(Value=='528049','.NET Framework 4.8',iif(Value=='461814','.NET Framework 4.7.2',iif(Value=='461310','.NET Framework 4.7.1',iif(Value=='460805','.NET Framework 4.7',iif(Value=='394802','.NET Framework 4.6.2',iif(Value=='379893','.NET Framework 4.5.2','Add more releases to iif'))))))
| where Value != '.NET Framework 4.8' and Value !like '.NET Framework 4.7%'
| join Service
| where Name like 'vstsagent%'
| order by Value asc
```
```
Registry('HKLM:\Software\Policies\Microsoft\SystemCertificates\AuthRoot')
| where (Property == 'DisableRootAutoUpdate')
| join kind=rightouter Device
| project Device, Domain, Key, Property, Value
```
```
WinEvent('Illumio-VEN-Services-Events/Operational',60d)
| where ID == 2002
| join Device
| join OperatingSystem
//| where Message contains 'object_limit_hard_limit_reached' 
| project Device, Domain, Caption, Message, ID, DateTime
| order by DateTime asc
```
```
File('C:\Packages\Plugins\Microsoft.Azure.Monitor.AzureMonitorWindowsAgent\1.*')
| join kind=rightouter Device
| where Manufacturer != 'Microsoft Corporation'
| join OperatingSystem
| project Device, FileName, Model, Domain, Caption
| order by FileName asc
| where isnull(FileName)
```
```
EventLog('Application',1d)
| where EventID == 7 and Source == 'AdmPwd' | take 1
| join Device
| join OperatingSystem
| join Registry('HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Group Policy\State\Machine')
| where Property == 'Distinguished-Name'
| project Device, DateTime, Message, Source, EventID, Domain, Caption, Property, OU=Value, Description
| order by Device asc
```
```
WinEvent('Microsoft-Windows-SENSE/Operational',7d)
| where ID == 5 | take 1
| join Device
| join OperatingSystem
| join Registry('HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Group Policy\State\Machine')
| where Property == 'Distinguished-Name'
| project Device, DateTime, Message, ID, Domain, Caption, Property, OU=Value, Description
| order by Device asc
```
```
ComputerSystem | project Device
| join kind=leftouter Registry('HKLM:\\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Client')
| project Device, Property, Value
| summarize count() by Property, Value
```
```
Device
| join kind=leftouter Registry('HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\*\*')
| where Property == 'Enabled' and Value == '0'
| project Device, Key, Property, Value
```
```
Device
| join kind=leftouter Registry('HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\*\*')
| where Property == 'Enabled' and Value == '0'
| project Device, Key, Property, Value
| summarize count() by Key
```
```
FileShare
| where Type == 0
| where Path startswith 'C:' and Name != 'print$'
| order by Path asc
```
```
Registry('HKLM:SOFTWARE\Microsoft\NET Framework Setup\NDP\v4\Full')
| join Device
| join OperatingSystem
| where Property == 'Version'
| project Device, Domain, Caption, Value
| order by Value asc
```
```
WinEvent('Microsoft-Windows-WindowsUpdateClient/Operational', 1h)
| take 5
| join Device
```
```
FileContent('C:\ProgramData\GuestConfig\ext_mgr_logs\gc_ext.log')
| where Content contains 'Failed to set Http version to 1.1. Error : 12009' | take 1
| join kind=rightouter Device
| join OperatingSystem
| join Registry('HKLM:\SOFTWARE\Policies\Microsoft\Cryptography\Configuration\SSL\00010002')
| project Device, Domain, OSVersion=Caption, Line, Content, CipherSuites=Value
| order by OSVersion asc
```
```
CcmLog('AppEnforce',30d ) | where LogText contains ' App enforcement completed' and LogText contains 'for App DT "VMware Tools Per-System Unattended x64"' | project Device, LogText, Date=substring(tostring(DateTime),0,9)
| summarize count() by Date
| render barchart
```
```
FileContent('C:\Windows\Temp\vmware_tools_install.log')
| where Content contains 'Windows Installer installed the product. Product Name: VMware Tools. Product Version: 12.2.5.21855600. Product Language: 1033. Manufacturer: VMware, Inc.. Installation success or error status: 0.'
```
```
Service
| where (Name like 'MSSQL%' and Name != 'MSSQL$MICROSOFT##WID') 
| where (State != 'Running')
| join Device
| project Device, Domain, Name, StartMode, State
```
```
Service
| where (StartMode == 'Auto' and State != 'Running')
| join Device
| project Device, Domain, Name, StartMode, State
| summarize count() by Name
| order by count_
```
```
File('C:\Program Files\WindowsPowerShell\Modules\Az*\*')