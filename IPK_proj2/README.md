# IPK - Port scanner
Jednoduchý TCP a UDP port scanner.

#### Popis
UDP scan funguje na principu zasílání paketu na daný port.
Zpět buď přijde ICMP zpráva port unreachable - port uzavřený, nebo je port považován za otevřený.

TCP scan provádí tzv. nekompletní hanshake. Posílá SYN pakety. Zpět buď přijde SYN-ACK paket (port je otevřený),
RST paket (port je uzavřený), nebo nepřijde nic (port je považován za filtrovaný).

#### Rozšíření / Omezení
U UDP scannu je implementována i IPv6 varianta. U TCP pouze IPv4.
 
#### Spuštění
```
./ipk-scan {-i <interface>} --pu <port-ranges> --pt <port-ranges> [<domain-name> | <IP-address>]
```
* -i jméno rozhraní, pokud není vyplněno, zvolí se první neloopbackové aktivní rozhraní
* -t | --pt, skenované tcp porty
* -u | --pu, skenované udp porty
* domain-name | ip address - doménové jméno, nebo IP adresa skenovaného stroje,
 u doménového jména je přednostně vybraná IPv4 adresa
 
Skenované porty mohou být ve tvaru: 1-65535; 10,11,12; 1-20,100,105-108


#### Příklad Spuštění
```
./ipk-scan -i wlp3s0 -t 80-82 -u 80-82 www.google.cz

PROT	PORT	STATUS
udp	80	opened
udp	81	opened
udp	82	opened

tcp	80	opened
tcp	81	filtred
tcp	82	filtred
```
#### Návratové kódy
* 0 - vše proběhlo úspěšně
* 1 - ARG_ERR, chybný argument
* 2 - NO_INTERFACE_ERR, nenalezeno rozhraní
* 3 - TARGET_ERR, nepřeložitelné doménové jménom nebo špatný formát IP adresy
* 4 - INTERN_ERR, interní chyba

#### Seznam odevzdaných souborů
* ipk-scan.cpp - hlavní tělo programu, spouští oba scannery a zpracování argumentů
* scan_setting.cpp, scan_setting.h - třída pro zpracování argumentů
* udp_scanner.cpp, udp_scanner.cpp - UDP scanner
* tcp_scanner.cpp, tcp_scanner.cpp - TCP scanner
* scan_exit.cpp, scan_exit.h - funce pro ukončení scanneru