## Windows Network Connections and Firewall Events

| Event ID | Provider                              | Description                                                    | Security Use Case                                                    |
|----------|----------------------------------------|----------------------------------------------------------------|--------------------------------------------------------------------|
| 5156     | Microsoft-Windows-Security-Auditing    | The Windows Filtering Platform permitted a connection        | Monitor allowed inbound/outbound connections                      |
| 5157     | Microsoft-Windows-Security-Auditing    | The Windows Filtering Platform blocked a connection          | Detect blocked malicious connection attempts                      |
| 5031     | Microsoft-Windows-Windows Firewall With Advanced Security | The Windows Firewall service was stopped                  | Detect firewall service stoppage (potential tampering)           |
| 5032     | Microsoft-Windows-Windows Firewall With Advanced Security | The Windows Firewall service was started                  | Confirm firewall service startup                                  |
| 4946     | Microsoft-Windows-Security-Auditing    | A change has been made to Windows Firewall exception list     | Detect changes allowing exceptions (potential backdoors)         |
| 4947     | Microsoft-Windows-Security-Auditing    | A change has been made to Windows Firewall settings           | Monitor firewall configuration changes                           |
| 1102     | Microsoft-Windows-Eventlog             | The audit log was cleared                                     | Detect log clearing to hide network activities                   |
