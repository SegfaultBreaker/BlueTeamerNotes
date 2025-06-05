## Fileless Attacks, LOLBins, and Living-off-the-Land Detection

| Event ID | Provider                              | Description                                                   | Security Use Case                                                      |
|----------|----------------------------------------|---------------------------------------------------------------|-------------------------------------------------------------------------|
| 4688     | Microsoft-Windows-Security-Auditing    | A new process has been created                                 | Detect usage of LOLBins (e.g., `regsvr32`, `mshta`, `rundll32`)        |
| 4104     | Microsoft-Windows-PowerShell/Operational | PowerShell script block logging                               | Detect obfuscated or suspicious scripts executed in memory            |
| 4103     | Microsoft-Windows-PowerShell/Operational | PowerShell command invocation logging                         | Monitor individual PowerShell commands for suspicious usage           |
| 8003     | Microsoft-Windows-DNS-Client           | DNS query                                                    | Detect DNS tunneling or command-and-control via DNS                    |
| 7        | Microsoft-Windows-Sysmon               | Image loaded                                                 | Detect suspicious loading of LOLBin payloads or scripts               |
| 10       | Microsoft-Windows-Sysmon               | Process accessed another process                             | Identify process hollowing or injection through LOLBins               |
| 11       | Microsoft-Windows-Sysmon               | File created                                               | Detect files dropped by LOLBins or related malware                     |
| 1        | Microsoft-Windows-Sysmon               | Process creation                                           | Track usage of living-off-the-land binaries                            |
| 3002     | Microsoft-Windows-CodeIntegrity        | Code integrity check failed                                | Detect execution of unsigned or modified LOLBin code                  |
| 5007     | Microsoft-Windows-Windows Defender     | Windows Defender configuration change                     | Detect disabling of AV or tampering for fileless attack facilitation  |
| 5059     | Microsoft-Windows-WMI-Activity         | WMI consumer binding                                     | Detect persistence or execution through WMI scripting                |
| 4697     | Microsoft-Windows-Security-Auditing    | A service was installed                                   | Detect installation of suspicious services used by LOLBins          |
