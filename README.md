# ADAccessChecker
Go-based web server for checking access based on LDAP group membership

## Purpose
This service is to allow something like a Raspi-based RFID reader to check access to a machine by way of group membership in an LDAP server, like Active Diretory. The idea is that a dangerous machine, like a lathe or mill, has its access controlled by some mechanism that requires the person to scan his or her RFID tag to turn on. The RFID system, whether it be an Arduino or Raspi or some other system, performs an HTTP call to this service with a JSON payload: the tag number and the group to check (this would have to be known by the machine ahead of time). 

The service then looks up the tag in the LDAP server, gets the user name, then checks whether the person is in the group that was sent in the JSON payload. If the user *is* in the group, the response will be OK. If not, it will return FAIL and an explanation. There is a third field, data, which is a dictionary of key-value pairs for future use.
