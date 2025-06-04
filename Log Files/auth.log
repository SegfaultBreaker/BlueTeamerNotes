Reading a auth.log file from unix systems
What is the auth.log file ?

The auth.log file is mainly utilized to record events related to authentication processes. Each time a user tries to log in, switch accounts, or carry out an action that requires authentication, a corresponding log entry is created. This includes operations involving the SSH daemon (sshd), the use of sudo, and cron jobs that require authentication.

What it looks like ?

image

Field	Value	Description
Date	Apr 12	The day and month when the log entry was recorded.
Time	14:47:19	The exact time the event occurred (in 24-hour format).
Hostname	ip-192-168-10-45	The hostname or internal IP address of the server where the log was generated.
Service	sshd[4127]	The SSH daemon (sshd) handling the authentication attempt, with its process ID. (PID) of the service when the event was logged.
Event Type	Failed password	Indicates an unsuccessful attempt to authenticate due to a wrong password.
User Status	invalid user guest	The username adl was attempted, but it is not a valid user on the system.
Source IP	from 102.45.76.32	The IP address from which the login request originated.
Source Port	port 55874	The source port used by the remote client during the attempt.
Protocol	ssh2	The SSH protocol version (SSH-2) used during the connection attempt.
