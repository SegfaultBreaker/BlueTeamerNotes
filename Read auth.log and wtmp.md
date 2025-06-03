# Reading a auth.log file from unix systems

What is the auth.log file ? 

The auth.log file is mainly utilized to record events related to authentication processes. Each time a user tries to log in, switch accounts, or carry out an action that requires authentication, a corresponding log entry is created. 
This includes operations involving the SSH daemon (sshd), the use of sudo, and cron jobs that require authentication.

What it looks like ? 

![image](https://github.com/user-attachments/assets/1b9e74e2-02b4-4a64-8378-4b11e5341246)

| **Field**       | **Value**            | **Description**                                                                 |
|-----------------|----------------------|---------------------------------------------------------------------------------|
| **Date**        | Apr 12               | The day and month when the log entry was recorded.                             |
| **Time**        | 14:47:19             | The exact time the event occurred (in 24-hour format).                          |
| **Hostname**    | ip-192-168-10-45     | The hostname or internal IP address of the server where the log was generated. |
| **Service**     | sshd[4127]           | The SSH daemon (sshd) handling the authentication attempt, with its process ID. (PID) of the service when the event was logged.|
| **Event Type**  | Failed password      | Indicates an unsuccessful attempt to authenticate due to a wrong password.     |
| **User Status** | invalid user guest   | The username `adl` was attempted, but it is not a valid user on the system.  |
| **Source IP**   | from 102.45.76.32    | The IP address from which the login request originated.                        |
| **Source Port** | port 55874           | The source port used by the remote client during the attempt.                  |
| **Protocol**    | ssh2                 | The SSH protocol version (SSH-2) used during the connection attempt.           |






# Reading a wtpmp file from unix systems

What is the wtpmp file ? 

The wtmp file serves as a system log that records all login and logout activities. This file is in binary format and is usually found at /var/log/wtmp. To view its contents, you can use the last command, which displays a historical record of user sessions, including logins, logouts, system restarts, and changes in runlevel.

Information Contained in wtmp
Because wtmp is a binary file, it cannot be read like plain text logs such as auth.log. However, tools like last interpret and present the data in a human-readable format, including:

- Username: Identifies the user who logged in or out.
- Terminal: Specifies the terminal (TTY) used for the session. Remote sessions often indicate SSH or Telnet details.
- IP Address or Hostname: For remote sessions, this shows the originating IP address or hostname.
- Login Time: The date and time when the session began.
- Logout Time: When the session ended or the user logged out.
- Session Duration: The total length of the session.

Below is a sample output of the last command:

SegfaultBreaker pts/0 10.1.1.1 Sat April 9 09:25 - 10:25 (01:00).

The user Segfaulbreaker was logged in for 1h. 


## Important

It is important to understand that problems may arise when using standard tools like last or utmpdump if the CPU architecture of the forensic investigator’s machine differs from that of the system where the wtmp file was originally created. To address this issue, use a tool called utmp.py (https://gist.github.com/4n6ist/99241df331bb06f393be935f82f036a5).

## reading utmp.py inputs

![image](https://github.com/user-attachments/assets/ba18a964-8e5e-4590-9b9c-aba70142505e)

Took from the website : https://www.kazamiya.net/en/bulk_extractor-rec/utmp

| Field      | Description                                                                                           |
|------------|-------------------------------------------------------------------------------------------------------|
| **Type**   | Specifies the type of record, such as user login, logout, system boot, or shutdown event.            |
| **PID**    | The Process ID associated with the event.                                                             |
| **Line**   | The terminal line where the session occurred. `tty` refers to a physical terminal (e.g., local console), while `pts` refers to a pseudo-terminal used for remote or virtual sessions (e.g., SSH). |
| **ID**     | A short identifier linked to the terminal line.                                                       |
| **User**   | The username involved in the event.                                                                   |
| **Host**   | The hostname or IP address from which the user accessed the system, if applicable.                   |
| **Exit**   | The exit status of the session or process.                                                            |
| **Session**| The session identifier.                                                                               |
| **sec**    | The event timestamp in seconds (based on your system's timezone, not the source system's).           |
| **usec**   | The microsecond part of the timestamp related to the login/logout event.                              |
| **Addr**   | Additional address info, such as an IP address for remote connections.                                |


# Usefull information that can be retrieved with those tools.

## Auth.log 

Information such as multiple connection that were made from a single source in a short time frime (could indicate a bruteforce login attempt): 
![{C331FAC4-33CF-452F-A8EF-E02ABD5C3FEC}](https://github.com/user-attachments/assets/f5e50f10-43a8-4de4-a35c-d2c94450719f)

Tracking login / logout for sensitive users timestemp and SSH session id:
![image](https://github.com/user-attachments/assets/c7e8d30c-fcd8-40e5-a7d9-787f3ddc17bd)

Persistance attemps like : 
- useradd - Indicates a user has been added to the system.
- usermod - Indicates the modifcation of user permissions or groups.
- groupadd - Indicates the creation of a new user group. 

Or other command like curl, get... (all commands that can be used for "remotely" downloading files.

## wtmp

"USER"  "3120"  "pts/0"  "ts/1"  "john"  "203.0.113.45"  "0"  "0"  "2024/05/28 10:14:22"  "312456"  "203.0.113.45"

| Field             | Value             | Description                                               |
|------------------|-------------------|-----------------------------------------------------------|
| **Type**         | `"USER"`          | Type of event (user login)                                |
| **PID**          | `"3120"`          | Process ID of the session                                 |
| **Line**         | `"pts/0"`         | Terminal line used (pseudo-terminal)                      |
| **ID**           | `"ts/1"`          | Line ID (used for internal session tracking)              |
| **User**         | `"john"`          | Username who logged in                                    |
| **Host**         | `"203.0.113.45"`  | Remote IP address of the user                             |
| **Exit Code**    | `"0"`             | Exit status (0 = successful)                              |
| **Session**      | `"0"`             | Session ID (can vary depending on the system)             |
| **Login Time**   | `"2024/05/28 10:14:22"` | Timestamp of login                               |
| **Microseconds** | `"312456"`        | Microsecond part of the login timestamp                   |
| **Addr**         | `"203.0.113.45"`  | Redundant IP field (used in some UTMP/WTMP tools)         |











