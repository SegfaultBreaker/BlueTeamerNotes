## USB, Device, and Peripheral Activity Monitoring

| Event ID | Provider                              | Description                                                   | Security Use Case                                                      |
|----------|----------------------------------------|---------------------------------------------------------------|-------------------------------------------------------------------------|
| 1006     | Microsoft-Windows-DriverFrameworks-UserMode | Device connected                                          | Detect USB device insertion                                           |
| 1007     | Microsoft-Windows-DriverFrameworks-UserMode | Device disconnected                                       | Detect USB device removal                                            |
| 2003     | Microsoft-Windows-Partition/Diagnostic   | Disk volume mounted                                       | Identify removable media mounting                                   |
| 6416     | Microsoft-Windows-Security-Auditing      | Device connected                                          | Track new device connection for audit                               |
| 4663     | Microsoft-Windows-Security-Auditing      | File object accessed                                      | Detect file access on removable devices                             |
| 4656     | Microsoft-Windows-Security-Auditing      | Handle to an object requested                            | Monitor operations on files stored on external devices             |
| 4660     | Microsoft-Windows-Security-Auditing      | File deleted                                            | Detect deletion on removable media                                 |
| 4664     | Microsoft-Windows-Security-Auditing      | Object operation attempted                               | Detect write attempts to USB or external drives                    |
| 4697     | Microsoft-Windows-Security-Auditing      | A service was installed                                 | Detect services related to device management or unauthorized tools |
| 1102     | Microsoft-Windows-Eventlog                 | Security log cleared                                    | Identify potential cover-up post device use                        |
| 7045     | Microsoft-Windows-Service Control Manager  | New service installed                                  | Detect device-related malicious service installations             |
