# 1. Tomando como base de trabajo el SSH pruebe sus diversas utilidades:

## a) Abra un shell remoto sobre SSH y analice el proceso que se realiza. Configure su fichero ssh_known_hosts para dar soporte a la clave pública del servidor

```bash
lsi@debian:~$ ssh -v lsi@10.11.48.69
```

Conexión verbose
ssh msg kexinit -> intercambian una estructura de datos. El servidor y el cliente se intercambian estructuras. Algunos campos:

 - Server host key algorithm  -> Algoritmos asimetricos, se usan para autenticar al servidor. Cuando alguien se conecta se establece una clave de sesion pero a mayores se autentica que el servidor es quien dice ser. (fingerprinting). El servidor te pasa su clave publica. Lo logico es verificar que el hash de la clave da el fingerpring.
   - Como servidor, cojo mi publica y la cifro con mi privada, se la paso a quien se esta conectando. Pilla mi publica y al descifrar sale la publica, confirmas que la unica persona que ha podido cifrarlo es el servidor. Se autentica. (clave publica privada)
 - Kex algorithm -> Secuencia de preferencia de algoritmos para que la conexion establezca la clave de sesion (asimetricos)
 - Encryption algorithm client to server -> simetricos para cifrar con la clave de sesion
 - Encryption algorithm server to client -> simetricos 

la info sale del ssh_config y el sshd_config

Tipos de algoritmos:

- De clave privada o simétricos -> algoritmos con una sola clave. Para cifrar, se cifra con el algoritmo y la clave y se descrifra igual. Mas rapido, paqueteria, paginas web, etc. En ambos lados ha de estar la clave
- De clave publica/privada o asimétricos -> cada entidad tiene una clave publica y una privada (rsa por ejemplo)

Rsa -> basado en exponenciación
Otros son de curva elíptica -> mas rapidos y mas seguros

```bash
# /etc/ssh/ssh_known_hosts
root@debian:/etc/ssh# ls
moduli      ssh_config.d  sshd_config.d     ssh_host_dsa_key.pub  ssh_host_ecdsa_key.pub  ssh_host_ed25519_key.pub  ssh_host_rsa_key.pub
ssh_config  sshd_config   ssh_host_dsa_key  ssh_host_ecdsa_key    ssh_host_ed25519_key    ssh_host_rsa_key          ssh_known_hosts
# claves publicas y privadas para distintos algoritmos del proceso de autenticación o establecimiento de la clave de sesion (del servidor) 
# Se añaden al known hosts de $HOME/.ssh/

# creamos el ssh_known_hosts. Fichero de claves publicas de servidores. Global para todo mi sistema
# intercambiamos las publicas. que son, para que son? min 30
lsi@debian:~$ touch /etc/ssh/ssh_known_hosts
# Se puede hacer "casero" copiando los archivos, o ejecutar el siguiente archivo:
lsi@debian:~$ ssh-keyscan 10.11.48.70 >> /etc/ssh/ssh_known_hosts 
```

## ?? - b. Haga una copia remota de un fichero utilizando un algoritmo de cifrado determinado. Analice el proceso que se realiza.

Comando scp. copy seguro. Abre una conexión ssh para copiar ficheros de un lado al otro.

```bash
lsi@debian:~$ scp *.txt lsi@10.11.48.70:/home/lsi
# copia todos los txt de ese directorio a /home/lsi de la maquina especificada. Autentica, abre conexión ssh, cifra el flujo y pasa los fichero txt

lsi@debian:~$ scp -c aes128-ctr archivo lsi@10.11.48.70:/home/lsi
lsi@debian:~$ scp -c aes128-ctr lsi@10.11.48.70:/home/lsi/archivo carpeta_destino 
```

## c. Configure su cliente y servidor para permitir conexiones basadas en un esquema de autenticación de usuario de clave pública.

Toda la clave de sesión y ya existe un tubo con la paquetería cifrada. Ahora vamos a cambiar la autenticación, en vez de usuario y password, clave y publica.
Cuando me conecte, no pedirá password.

En el $HOME/.ssh/ se pueden meter ficheros de claves publicas y privadas. Estas claves publicas y privadas son de cada usuario. Se le asignan publica y privada AL USUARIO LSI. Frase de paso en blanco. Le aplica una función hash que da una huella digital que se utiliza para cifrar dentro de este fichero, la clave privada. La clave privada, si te la roban -> fin. Si le metes una fase de paso, al conectarte te pedirá la frase de paso, meterla sería lo correcto, si no, cuidado con los permisos de la privada.

**En lugar de user y pass. Cojo mi publica y la cifro con mi privada, envio ese paquete cifrado, tu en tu authorized keys, descifras el paquete y si lo que sale es la publica, yo soy el unico que ha podido cifrarlo -> autenticado**

```bash
lsi@debian:~$ ssh-keygen -t rsa # tambien los otros algoritmos? 
# se genera una clave privada y una publica. Nosotros utilizamos rsa. 
lsi@debian:~$ ssh-copy-id -i $HOME/.ssh/id_rsa.pub lsi@10.11.48.70
# Se las pasamos a nuestro compañero 
# Ahora no nos pedira la password 
```

## d. Mediante túneles SSH securice algún servicio no seguro. 

```bash
lsi@debian:~$ ssh -L 10080:10.11.48.70:80 lsi@10.11.48.70
# En la maquina en la que ejecuto esto, redireciono el puerto 10080 de mi localhost al 80 de mi compañero a traves de una conexión ssh.

lsi@debian:~$ wget localhost:10080 # Devuelve el 80 de la máquina de mi compañero, normalmente es no seguro, pero ahora lo mete por el tunel ssh seguro

# Esto redirecciona el localhost, si quisiera que redireccionara mi ip, se pone al prinicipio :
lsi@debian:~$ ssh -L 10.11.48.69:10080:10.11.48.70:80 lsi@10.11.48.70
```
nfs, samba -> montado de ficheros en red. (ssh fs)

# 2. Tomando como base de trabajo el servidor Apache2

## a. Configure una Autoridad Certificadora en su equipo.

Se monta una autoridad certificadora. 2 ficheros -> publica y privada. **Certifican con firma digital certificados digitales.** 

```bash
root@debian:/usr/lib/ssl/misc$  ./CA.pl -newca
Country Name (2 letter code) [AU]: ES
State or Province Name (full name) [Some-State]: A-Coruna
Locality Name (eg, city) []: A-Coruna
Organization Name (eg, company) [Internet Widgits Pty Ltd]:LSI_UDC
Organizational Unit Name (eg, section) []: 
Common Name (e.g. server FQDN or YOUR name) []: web
Email Address []:
.
.
.
```

## b. Cree su propio certificado para ser firmado por la Autoridad Certificadora. Bueno, y fírmelo.

Creamos un certificado digital para el servidor web de mi compañero de practicas, para montar https en apache. Tiene una serie de certificados y una clave publica, que se utiliza en el servidor web. Luego hay otro fichero con la privada.

Se firma digitalmente este certificado. Le aplico un hash, y eso me da la huella digital del contenido del certificado, esa huella la cifro con la privada. **La firma digital siempre es con la privada de la AC, esa huella se la pego al certificado.** 



```bash
root@debian:/usr/lib/ssl/misc$ ./CA.pl -newreq-nodes
Country Name (2 letter code) [AU]: ES
State or Province Name (full name) [Some-State]: A-Coruna
Locality Name (eg, city) []: A-Coruna
Organization Name (eg, company) [Internet Widgits Pty Ltd]:LSI_UDC
Organizational Unit Name (eg, section) []: 
Common Name (e.g. server FQDN or YOUR name) []: web
Email Address []:
.
.
.

```

## c. Configure su Apache para que únicamente proporcione acceso a un determinado directorio del árbol web bajo la condición del uso de SSL. 

Una vez creado el certificado, se le envía al servidor web junto a la publica de la CA

newcert.pem , newkey.pem, cacert.pem

```bash
root@debian:/home/lsi$ scp ./* lsi@10.11.48.70:/home/lsi/certs
```

#### El servidor: 

Activa ssl en apache con:

```bash
root@debian:/etc/apache2$ a2enmod ssl
root@debian:/etc/apache2$ systemctl restart apache2
```

Se modifica `/etc/apache2/sites-available/default-ssl.conf`

```bash
root@debian:~$ cat /etc/apache2/sites-available/default-ssl.conf

<IfModule mod_ssl.c>
	<VirtualHost _default_:443>
		ServerAdmin webmaster@localhost
		DocumentRoot /var/www/html
		# Available loglevels: trace8, ..., trace1, debug, info, notice, warn,
		# error, crit, alert, emerg.
		# It is also possible to configure the loglevel for particular
		# modules, e.g.
		#LogLevel info ssl:warn

		ErrorLog ${APACHE_LOG_DIR}/error.log
		CustomLog ${APACHE_LOG_DIR}/access.log combined
		
		# For most configuration files from conf-available/, which are
		# enabled or disabled at a global level, it is possible to
		# include a line for only one particular virtual host. For example the
		# following line enables the CGI configuration for this host only
		# after it has been globally disabled with "a2disconf".
		#Include conf-available/serve-cgi-bin.conf

		#   SSL Engine Switch:
		#   Enable/Disable SSL for this virtual host.
		SSLEngine on
		
		#   A self-signed (snakeoil) certificate can be created by installing
		#   the ssl-cert package. See
		#   /usr/share/doc/apache2/README.Debian.gz for more info.
		#   If both key and certificate are stored in the same file, only the
		#   SSLCertificateFile directive is needed.
		SSLCertificateFile	/etc/ssl/certs/newcert.pem
		SSLCertificateKeyFile /etc/ssl/private/newkey.pem

.
.
.
.
.
.
	</VirtualHost>
</IfModule>

# vim: syntax=apache ts=4 sw=4 sts=4 sr noet
```

En el cliente:

Se introduce cacert.pem en `/usr/local/share/ca-certificates/` 

```bash
root@debian:~$ update-ca-certificates
```

Para comprobarlo, desde la máquina cliente:

```bash
root@debian:/home/lsi$ cat /etc/hosts
127.0.0.1	localhost
127.0.1.1	debian
10.11.48.70	web

# The following lines are desirable for IPv6 capable hosts
::1     localhost ip6-localhost ip6-loopback
ff02::1 ip6-allnodes
ff02::2 ip6-allrouters

root@debian:~$ lynx https://web
```

Https, generas una clave de sesion, la cifras con mi publica, me la envías y ya tienes la clave simetrica. A mayores se autentica el servidor. Cifro mi publica con la privada, te la envio, la descifras con la publica, y si es tu publica sabes que el servidor está autenticado. **La publica va en un certificado digital**

Una tercera persona que se quiere conectar al servidor, se engancha al 443. Le envía el certificado digital firmado, el navegador verifica la firma digital: **descifra con la publica de la AC** y descifro la firma, obtengo la huella digital que cifró la AC. Cojo el certificado, le hago un hash y obtengo su huella digital, comparas las dos, y si son la misma verificas el servidor.

Habitualmente en las maquinas hay repositorios de claves publicas de ACs, a veces están en los navegadores.

Genero una clave de sesion en el navegador, se cifra con la publica del certificado se la envio al servidor, el servidor pilla la clave de sesion y con la clave en ambos lados se cifra todos los paquetes de http.

# 3. Tomando como base de trabajo el openVPN deberá configurar una VPN entre dos equipos virtuales del laboratorio que garanticen la confidencialidad entre sus comunicaciones.

Desde el servidor: 

```bash
root@debian:/home/lsi$ apt install openvpn
root@debian:/home/lsi$ lsmod | grep tun
root@debian:/home/lsi$ modprobe tun
root@debian:/home/lsi$ echo tun >> /etc/modules
root@debian:/home/lsi$ cd /etc/openvpn
root@debian:/etc/openvpn$ openvpn --genkey --secret vpn_key.key

# El archivo tunel.conf deberia quedar tal que así:
root@debian:/etc/openvpn$ cat tunel.conf 
local 10.11.48.69 # mi ip
remote 10.11.48.70 # ip compa
dev tun1 # interface de red asociado a mi extremo de la vpn
port 5555 # puerto
comp-lzo # metodo de compresión. La vpn antes de cifrar la comprime
user nobody # servidor con permisos del usuario nobody
ping 15 # cada 15 segundos le manda un ping al otro extremo de la vpn para ver si está ahi
ifconfig 172.160.0.1 172.160.0.2 # yo el 0.1
secret /etc/openvpn/vpn_key.key # path de la clave con la que se va a cifrar y descifrar toda la paqueteria. (algoritmo de clave privada/simetrico)
```

Le paso la `vpn_key.key` a mi compañero y hace exactamente lo mismo intercambiando las ip

Para probar:

```bash
# en el cliente, sin rebotar se podria probar haciendo: 
root@debian:/home/lsi$ openvpn --config /etc/openvpn/tunel.conf 

root@debian:/home/lsi$ ifconfig -a
root@debian:/home/lsi$ ping 172.160.0.2
```

# 6. En este punto, cada máquina virtual será servidor y cliente de diversos servicios (NTP, syslog, ssh, web, etc.). Configure un “firewall stateful” de máquina adecuado a la situación actual de su máquina

iptables [-t table] COMANDO CADENA condición acción [opciones]
comando: -A
condicion: -p tcp --dport 23
accion: -j DROP
opciones: --ctstate...

```bash
#!/bin/sh
#borrado de reglas y cadenas
/sbin/iptables -F
/sbin/iptables -X
/sbin/iptables -Z
/sbin/ip6tables -F
/sbin/ip6tables -X
/sbin/ip6tables -Z


echo "Reglas ESTABLISHED y RELATED"
##Cualquier paquete de una conexión establecida previamente con un NEW, se acepta.
/sbin/iptables -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
/sbin/iptables -A OUTPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT

/sbin/ip6tables -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
/sbin/ip6tables -A OUTPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT

echo "Trafico localhost"
##Aceptar trafico localhost, interface lo
/sbin/iptables -A INPUT -i lo -j ACCEPT
/sbin/iptables -A OUTPUT -o lo -j ACCEPT

/sbin/ip6tables -A INPUT -i lo -j ACCEPT
/sbin/ip6tables -A OUTPUT -o lo -j ACCEPT

echo "Trafico con el compañero por ssh"
##Conexión con los compañeros.
/sbin/iptables -A INPUT -s 10.11.48.70,10.11.48.71 -d 10.11.48.69 -p tcp --dport 22 -m conntrack --ctstate NEW -j ACCEPT
/sbin/iptables -A OUTPUT -s 10.11.48.69 -d 10.11.48.70,10.11.48.71 -p tcp --dport 22 -m conntrack --ctstate NEW -j ACCEPT


echo "Trafico con el compañero por ipv6"
## Compañeros v6
# conexiones por IPv6
/sbin/iptables -A INPUT -p ipv6 -m conntrack -s 10.11.48.70,10.11.48.71 -d 10.11.48.69 --ctstate NEW -j ACCEPT
/sbin/iptables -A OUTPUT -p ipv6 -m conntrack -s 10.11.48.69 -d 10.11.48.70,10.11.48.71 --ctstate NEW -j ACCEPT
# icmp
/sbin/ip6tables -A INPUT -p icmpv6 -s 2002:a0b:3046::1,2002:a0b:3047::1 -d 2002:a0b:3045::1  -m conntrack --ctstate NEW -j ACCEPT
/sbin/ip6tables -A OUTPUT -p icmpv6 -s 2002:a0b:3045::1 -d 2002:a0b:3046::1,2002:a0b:3047::1 -m conntrack --ctstate NEW -j ACCEPT
# ssh
/sbin/ip6tables -A INPUT -p tcp --dport 22 -s 2002:a0b:3046::1,2002:a0b:3047::1 -d 2002:a0b:3045::1 -m conntrack --ctstate NEW -j ACCEPT
/sbin/ip6tables -A OUTPUT -p tcp --dport 22 -s 2002:a0b:3045::1 -d 2002:a0b:3046::1,2002:a0b:3047::1 -m conntrack --ctstate NEW -j ACCEPT



echo "cliente ntp"
##NTP
/sbin/iptables -A OUTPUT -s 10.11.48.69 -d 10.11.48.70 -p udp --sport 123 -m conntrack --ctstate NEW -j ACCEPT

echo "servidor syslog"
##RSYSLOG
/sbin/iptables -A INPUT -s 10.11.48.70 -d 10.11.48.69 -p tcp --dport 514 -m conntrack --ctstate NEW -j ACCEPT

echo "conexión eduroam"
##EDUROAM
/sbin/iptables -A INPUT -s 10.20.32.0/21 -d 10.11.48.69 -p tcp --dport 22 -m conntrack --ctstate NEW -j ACCEPT

echo "conexion vpn"
##VPN udc
/sbin/iptables -A INPUT -s 10.30.8.0/21 -d 10.11.48.69 -p tcp --dport 22 -m conntrack --ctstate NEW -j ACCEPT

echo "conexión ICMP"
##ICMP
/sbin/iptables -A INPUT -s 10.11.48.70,10.11.48.71 -d 10.11.48.69 -p icmp -m conntrack --ctstate NEW -j ACCEPT
/sbin/iptables -A OUTPUT -s 10.11.48.69 -d 10.11.48.70,10.11.48.71 -p icmp -m conntrack --ctstate NEW -j ACCEPT

echo "conexión DNS"
#DNS
/sbin/iptables -A OUTPUT -s 10.11.48.69 -d 10.8.12.49,10.8.12.47,10.8.12.50 -p tcp --dport 53 -m conntrack --ctstate NEW -j ACCEPT
/sbin/iptables -A OUTPUT -s 10.11.48.69 -d 10.8.12.49,10.8.12.47,10.8.12.50 -p udp --dport 53 -m conntrack --ctstate NEW -j ACCEPT

echo "Acceso a los repositorios"
#Acceso a los repositorios
/sbin/iptables -A OUTPUT -s 10.11.48.69 -d deb.debian.org -m conntrack --ctstate NEW -j ACCEPT
/sbin/iptables -A OUTPUT -s 10.11.48.69 -d security.debian.org -m conntrack --ctstate NEW -j ACCEPT

##HTTP
echo "http compa"
/sbin/iptables -A INPUT -s 10.11.48.70,10.11.48.71 -d 10.11.48.69 -p tcp --dport 80 -m conntrack --ctstate NEW -j ACCEPT
/sbin/iptables -A OUTPUT -p tcp --dport 80 -m conntrack --ctstate NEW -j ACCEPT

##HTTPS
echo "https compa"
/sbin/iptables -A INPUT -s 10.11.48.70,10.11.48.71 -d 10.11.48.69 -p tcp --dport 443 -m conntrack --ctstate NEW -j ACCEPT
/sbin/iptables -A OUTPUT -p tcp --dport 443 -m conntrack --ctstate NEW -j ACCEPT

##TUNEL VPN
echo "tunel vpn"
/sbin/iptables -A INPUT -s 10.11.48.70 -d 10.11.48.69 -p udp --dport 5555 -m conntrack --ctstate NEW -j ACCEPT
/sbin/iptables -A OUTPUT -s 10.11.48.69 -d 10.11.48.70 -p udp --sport 5555 -m conntrack --ctstate NEW -j ACCEPT
/sbin/iptables -A INPUT -s 172.160.0.2 -d 172.160.0.1 -m conntrack --ctstate NEW -j ACCEPT
/sbin/iptables -A OUTPUT -s 172.160.0.1 -d 172.160.0.2 -m conntrack --ctstate NEW -j ACCEPT


echo "politicas por defecto"
##POLITICAS POR DEFECTO - DROP
/sbin/iptables -P INPUT DROP
/sbin/iptables -P OUTPUT DROP

/sbin/ip6tables -P INPUT DROP
/sbin/ip6tables -P OUTPUT DROP


echo 'Nuevas reglas establecidas. Pulsa enter para detener el firewall'
SALIR=0
read SALIR
echo "Restableciendo reglas por defecto en:"
echo "5"
sleep 1
echo "4"
sleep 1
echo "3"
sleep 1
echo "2"
sleep 1
echo "1"
sleep 1
echo "restableciendo..."

/sbin/iptables -P INPUT ACCEPT
/sbin/iptables -P OUTPUT ACCEPT

/sbin/ip6tables -P INPUT ACCEPT
/sbin/ip6tables -P OUTPUT ACCEPT

/sbin/iptables -F # Borradas reglas
/sbin/iptables -X # Borradas cadenas
/sbin/iptables -Z # Borradas tablas

/sbin/ip6tables -F
/sbin/ip6tables -X
/sbin/ip6tables -Z
```

iptables se centra en capa 3-4. 

### Cadenas  (Agrupaciones de reglas que se van a ejecutarse en ciertos momentos)

- INPUT
- OUTPUT
- FORWARD
- PREROUTING (acciones antes de que se decida el routing)
- POSTROUTING (acciones despues del routing antes de mandar el paquete)

### Tablas

- mangle (las 5 cadenas)
- NAT -> prerouting, output y postrouting
- filter -> tabla por defecto (para poner otra tabla -t tabla)
- Otra: raw...

firewall con control de estado:

NEW -> se abre una nueva conexión
ESTABLISHED -> handshake hecho
RELATED-> paquetes relacionados. No tienen por que ser conexiones que se generan de otra conexion. Por ejemplo ftp pasivo (Protocolo de transferencia de archivos. Una vez se establece la conexion, la transferencia va por otro puerto. Conexion related.). error ICMP de una conexion establecida es RELATED.

# 7. Instale el SIEM splunk en su máquina. Sobre dicha plataforma haga los siguientes puntos.: 

http://10.11.48.69:8000

## a. Genere una query que visualice los logs internos del splunk 

```sql
index= _internal
```

## b. Cargué el fichero /var/log/apache2/access.log y el journald del sistema y visualícelos.

```sql
host="debian" source="/var/log/syslog" date_month="december" date_mday=4

host="debian" source="/var/log/apache2/access.*"
```

## c. Obtenga las IPs de los equipos que se han conectado a su servidor web (pruebe a generar algún tipo de gráfico de visualización), así como las IPs que se han conectado un determinado día de un determinado mes.

```sql
host="debian" source="/var/log/apache2/access.*" | top clientip

source="/var/log/apache2/access.log" date_month="december" date_mday="8" | table clientip
source="/var/log/apache2/access.log" date_month="december" date_mday="8" | top clientip
```

## d. Trate de obtener el país y región origen de las IPs que se han conectado a su servidor web y si posible sus coordenadas geográficas. 

```sql
source="/var/log/apache2/access.log" | iplocation clientip | table clientip City Country Region lat lon
```

## e. Obtenga los hosts origen, sources y sourcestypes. 

```sql

```

## f. ¿cómo podría hacer que splunk haga de servidor de log de su cliente?

monitor > tcp/udp > activo tcp 514, ip de las maquinas de los clientes



Defensa

defensa (segun nino en la grabacion de la practica que pasó roi):
1. **Borrame $HOME/.ssh/known_host** -> NO PUEDE APARECER fingerprinting. Que has hecho, que hay en cada archivo y para que se utiliza.
2. **No sale contraseña**. Entra directo? OK. Que has hecho? Cree la publica privada usuario lsi, le paso las publicas y las mete en el authorizedkeys. Cuando me quiero autenticar en lugar de usuario y password, cifro mi publica con la privada, se lo envio, descifra con la publica del authorized_keys, es la publica? si
3. **copiame un fichero de forma segura** -> scp
4. **securizame el puerto 80 por un tunel ssh** -> ssh -L 10080:ip:80 lsi@ip
5. **Enseñame la configuracion del site ssl** (default-ssl.conf), que has metido en cada sitio.
    Certificado con la clave publica que te pasa la AC, firmado digitalmente por la AC
    Aqui va la privada
    El certificado de la AC donde lo metes -> lo meti en este directorio -> update-ca-certificates
6. **Ping al otro lado de la VPN** -> ping 172.160.0.2
7. **Conectate a tu splunk -**> hazme un par de queries
   del mes, grafiquito
9. **Abreme el script del firewall de control de estado**. Salva. Ejecuta. Fin.
