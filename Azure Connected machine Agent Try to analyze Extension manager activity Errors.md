FileContent('C:\ProgramData\GuestConfig\ext_mgr_logs\gc_ext.log')
| where Content contains 'Failed to set Http version to 1.1. Error : 12009' | take 1
| join kind=rightouter Device
| join OperatingSystem
| join Registry(**'HKLM:\SOFTWARE\Policies\Microsoft\Cryptography\Configuration\SSL\00010002'**)
| project Device, Domain, OSVersion=Caption, Line, Content, CipherSuites=Value
| order by OSVersion asc
```
```
FileContent('C:\ProgramData\GuestConfig\ext_mgr_logs\gc_ext.log')
| where Content contains 'Failed to set Http version to 1.1. Error : 12009' | order by Line desc | take 1
| join kind=rightouter Device
| join OperatingSystem
| join Registry(**'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\*\\*'**)
| project Device, Domain, OSVersion=Caption, Line, Content, Key, Property, Value
| order by OSVersion asc
```
```
FileContent('C:\ProgramData\GuestConfig\ext_mgr_logs\gc_ext.log')
| where Content contains 'Failed to set Http version to 1.1. Error : 12009' | order by Line desc | take 1
| join kind=rightouter Device
| join OperatingSystem
| join kind=leftouter Registry(**'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\WinHttp'**)
| project Device, Domain, OSVersion=Caption, Line, Content, Key, Property, Value
| order by OSVersion asc