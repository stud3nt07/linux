# Linux-patch

## Introducción
Una ruta práctica y organizada para convertirte en administrador/a de Linux. He condensado y reestructurado el documento para que sea más claro: quité el plan inicial extenso por etapas y dejé un resumen de temas por bloque + el Plan de 6 meses (calendario semanal) detallado, proyectos para el portfolio y checklist final.

---

## Temas por bloque (resumen rápido)
- Fundamentos: shell, permisos, procesos, systemd, edición y scripting.
- Administración base: usuarios, paquetes, discos, LVM, RAID, backups.
- Redes y servicios: IP, routing, nftables, SSH hardening, DNS, web/TLS.
- Automatización y contenedores: Ansible, Docker/Podman, CI/CD, scanning.
- Virtualización y orquestación: KVM/QEMU, Proxmox, Kubernetes (k3s/minikube).
- Observabilidad y seguridad: Prometheus/Grafana, Loki, Lynis, CIS, AppArmor/SELinux.

---

## Plan de 6 meses (Calendario semanal)
Este plan está diseñado para completarse en 24 semanas (aprox. 6 meses) con una dedicación recomendada de 8–12 h/semana. Cada semana tiene objetivos, tareas prácticas y entregables claros para tu portafolio.

Resumen por meses:
- Mes 1 (Semanas 1–4): Fundamentos y Shell.
- Mes 2 (Semanas 5–8): Administración del sistema y almacenamiento.
- Mes 3 (Semanas 9–12): Redes y servicios esenciales.
- Mes 4 (Semanas 13–16): Automatización y contenedores.
- Mes 5 (Semanas 17–20): Virtualización y Kubernetes básico.
- Mes 6 (Semanas 21–24): Observabilidad, seguridad y proyecto final.

Semana 1 — Introducción y entorno (8–10 h)
- Objetivo: Preparar entorno de laboratorio y dominar comandos básicos.
- Tareas: Instalar Ubuntu Server en VM; instalar Git, Neovim, tmux; configurar SSH keys.
- Entregable: README del laboratorio con pasos y acceso SSH (captura).

Ejercicios Prácticos:
1. Crear una VM con Ubuntu Server 22.04 LTS (4GB RAM, 20GB disco, 2 vCPUs).
2. Ejecutar `sudo apt update && sudo apt upgrade -y` para actualizar el sistema.
3. Instalar herramientas básicas: `sudo apt install -y git neovim tmux curl wget htop tree`
4. Generar par de claves SSH: `ssh-keygen -t ed25519 -C "tu-email@example.com" -f ~/.ssh/id_ed25519` (reemplaza "tu-email@example.com" con tu email real)
5. Copiar la clave pública al servidor: `ssh-copy-id -i ~/.ssh/id_ed25519.pub usuario@ip-servidor` (reemplaza "usuario" y "ip-servidor" con tus valores reales)
6. Probar conexión SSH sin contraseña: `ssh -i ~/.ssh/id_ed25519 usuario@ip-servidor`
7. Crear archivo `/home/usuario/LAB_README.md` documentando: IP del servidor, usuario, comandos de conexión.
8. Practicar navegación: `cd`, `ls -lah`, `pwd`, `mkdir lab-week1`, `touch test.txt`
9. Explorar el sistema: `df -h` (espacio en disco), `free -h` (memoria), `uname -a` (kernel)
10. Tomar captura de pantalla de conexión SSH exitosa y guardarla en el LAB_README.md.

Semana 2 — Shell y scripting básico (8–12 h)
- Objetivo: Dominar bash/zsh, redirecciones y scripts simples.
- Tareas: Escribir 3 scripts (listar/backups/limpieza); practicar pipes y expresiones regulares.
- Entregable: 3 scripts en repo con README y ejemplos.

Ejercicios Prácticos:
1. Crear directorio de trabajo: `mkdir -p ~/scripts/week2 && cd ~/scripts/week2`
2. Script 1 - `list_files.sh`: Listar archivos de un directorio con tamaño y fecha, ordenados por tamaño.
   ```bash
   #!/bin/bash
   # Uso: ./list_files.sh /ruta/directorio
   ls -lhS "$1" | awk '{print $5, $9}' | sort -hr
   ```
3. Script 2 - `backup_home.sh`: Crear backup comprimido de directorio home con fecha.
   ```bash
   #!/bin/bash
   FECHA=$(date +%Y%m%d_%H%M%S)
   tar -czf "/tmp/backup_home_${FECHA}.tar.gz" "$HOME" && echo "Backup creado: /tmp/backup_home_${FECHA}.tar.gz"
   ```
4. Script 3 - `cleanup_logs.sh`: Eliminar logs antiguos (más de 7 días) en /tmp.
   ```bash
   #!/bin/bash
   find /tmp -name "*.log" -type f -mtime +7 -exec rm -f {} \;
   echo "Logs antiguos eliminados"
   ```
5. Hacer los scripts ejecutables: `chmod +x *.sh`
6. Practicar pipes: Contar cuántas veces aparece "error" en /var/log/syslog: `grep -i "error" /var/log/syslog | wc -l`
7. Usar redirecciones: `ls -l /etc > /tmp/etc_listing.txt 2>&1`
8. Expresiones regulares: Encontrar IPs en un archivo: `grep -E '\b([0-9]{1,3}\.){3}[0-9]{1,3}\b' /var/log/syslog`
9. Pipeline complejo: `ps aux | grep -v grep | sort -k3 -r | head -5` (top 5 procesos por CPU)
10. Crear repositorio Git: `git init`, agregar scripts, commit inicial con mensaje descriptivo.

Semana 3 — Permisos, archivos y edición (8–10 h)
- Objetivo: Entender permisos, enlaces y atributos extendidos; usar vim/neovim.
- Tareas: Practicar `chmod`, `chown`, `getfacl`; crear cheatsheet.
- Entregable: Cheatsheet y ejercicios resueltos.

Ejercicios Prácticos:
1. Crear estructura de prueba: `mkdir -p ~/permisos-lab/{dir1,dir2,dir3} && cd ~/permisos-lab`
2. Crear archivos de prueba: `touch file{1..5}.txt`
3. Ver permisos actuales: `ls -l` (formato: -rwxrwxrwx)
4. Cambiar permisos con notación octal: `chmod 644 file1.txt` (rw-r--r--)
5. Cambiar permisos con notación simbólica: `chmod u+x,g-w,o-r file2.txt`
6. Aplicar permisos recursivamente: `chmod -R 755 dir1/`
7. Cambiar propietario: `sudo chown usuario:grupo file3.txt`
8. Crear enlace simbólico: `ln -s /var/log/syslog ~/permisos-lab/syslog_link`
9. Crear enlace duro: `ln file1.txt file1_hardlink.txt`
10. ACLs: Instalar si es necesario: `sudo apt install -y acl`
11. Dar permisos especiales con ACL: `setfacl -m u:www-data:rw file4.txt`
12. Ver ACLs: `getfacl file4.txt`
13. Probar setuid: `sudo chmod u+s /usr/bin/passwd` (ya debería tenerlo)
14. Ver atributos extendidos: `lsattr file5.txt`
15. Hacer archivo inmutable: `sudo chattr +i file5.txt`, intentar borrarlo (fallará), remover: `sudo chattr -i file5.txt`
16. Práctica en vim/neovim: Crear archivo `cheatsheet.md` con: `:help`, movimientos (hjkl), edición (i,a,o), guardar (`:w`), salir (`:q`)
17. Documentar en `cheatsheet.md`: tabla de permisos octales (0-7), diferencias entre enlaces duros/simbólicos, ejemplos de ACLs.

Semana 4 — Procesos y systemd (8–12 h)
- Objetivo: Gestión de procesos y servicios con systemd.
- Tareas: Crear una unit systemd para un script; usar `journalctl`; manejo de jobs.
- Entregable: Unit file y README explicando timers/services.

Ejercicios Prácticos:
1. Ver procesos en ejecución: `ps aux`, `ps -ef`, `top`, `htop`
2. Encontrar proceso específico: `ps aux | grep nginx`
3. Ver árbol de procesos: `pstree -p`
4. Enviar señales: Iniciar proceso largo `sleep 300 &`, obtener PID, enviar `kill -SIGTERM <PID>`
5. Manejo de jobs: `sleep 500 &` (background), `jobs` (listar), `fg %1` (foreground), Ctrl+Z (suspender), `bg %1` (reanudar en background)
6. Crear script de prueba en `/usr/local/bin/hello-service.sh`:
   ```bash
   #!/bin/bash
   while true; do
     echo "Hello from systemd service - $(date)"
     sleep 30
   done
   ```
7. Hacer ejecutable: `sudo chmod +x /usr/local/bin/hello-service.sh`
8. Crear unit file `/etc/systemd/system/hello.service`:
   ```
   [Unit]
   Description=Hello World Service
   After=network.target
   
   [Service]
   Type=simple
   ExecStart=/usr/local/bin/hello-service.sh
   Restart=on-failure
   
   [Install]
   WantedBy=multi-user.target
   ```
9. Recargar systemd: `sudo systemctl daemon-reload`
10. Iniciar servicio: `sudo systemctl start hello.service`
11. Ver estado: `sudo systemctl status hello.service`
12. Habilitar inicio automático: `sudo systemctl enable hello.service`
13. Ver logs: `sudo journalctl -u hello.service -f`
14. Crear timer: `/etc/systemd/system/hello.timer`:
    ```
    [Unit]
    Description=Run Hello Service every 5 minutes
    
    [Timer]
    OnBootSec=1min
    OnUnitActiveSec=5min
    
    [Install]
    WantedBy=timers.target
    ```
15. Activar timer: `sudo systemctl start hello.timer && sudo systemctl enable hello.timer`
16. Listar timers: `systemctl list-timers`
17. Documentar en README: ciclo de vida de servicios, diferencia entre Type=simple/forking/oneshot.

Semana 5 — Gestión de usuarios y paquetes (8–12 h)
- Objetivo: Usuarios, sudo y gestión de paquetes.
- Tareas: Crear usuarios, configurar sudoers, probar apt/dnf.
- Entregable: Documento de políticas de usuarios.

Ejercicios Prácticos:
1. Crear usuario nuevo: `sudo useradd -m -s /bin/bash developer`
2. Establecer contraseña: `sudo passwd developer`
3. Crear usuario con configuración completa: `sudo useradd -m -s /bin/bash -G sudo,docker -c "Admin User" admin1`
4. Ver información de usuario: `id developer`, `getent passwd developer`
5. Modificar usuario existente: `sudo usermod -aG docker developer`
6. Crear grupo personalizado: `sudo groupadd devops`
7. Agregar usuario a grupo: `sudo usermod -aG devops developer`
8. Ver grupos de usuario: `groups developer`
9. Configurar sudo sin contraseña para grupo: Editar `sudo visudo`, agregar: `%devops ALL=(ALL) NOPASSWD: /usr/bin/systemctl`
10. Probar sudo: `su - developer`, luego `sudo systemctl status nginx`
11. Gestión de paquetes APT (Ubuntu/Debian):
    - Actualizar índice: `sudo apt update`
    - Buscar paquete: `apt search nginx`
    - Ver información: `apt show nginx`
    - Instalar: `sudo apt install -y nginx`
    - Listar instalados: `apt list --installed | grep nginx`
    - Remover: `sudo apt remove nginx`
    - Purge completo: `sudo apt purge nginx && sudo apt autoremove`
12. Ver logs de apt: `cat /var/log/apt/history.log`
13. Crear archivo `/home/usuario/politicas_usuarios.md` documentando:
    - Convenciones de nombres de usuario (ej: nombre.apellido)
    - Grupos estándar (sudo, devops, www-data)
    - Política de contraseñas (longitud, expiración)
    - Procedimientos de alta/baja de usuarios
14. Listar usuarios del sistema: `cat /etc/passwd | grep -v nologin | tail -10`
15. Ver últimos logins: `lastlog`, `last -10`

Semana 6 — Discos, LVM y backup básico (8–12 h)
- Objetivo: Particionamiento, LVM y estrategia de backups.
- Tareas: Crear volumen LVM, snapshot; script de backup y restore.
- Entregable: Script de backup probado y guía de recuperación.

Ejercicios Prácticos:
1. Ver discos disponibles: `lsblk`, `sudo fdisk -l`
2. Crear archivo para simular disco: `sudo dd if=/dev/zero of=/tmp/disk1.img bs=1M count=1024` (1GB)
3. Crear otro disco virtual: `sudo dd if=/dev/zero of=/tmp/disk2.img bs=1M count=1024`
4. Asociar como loop device: `sudo losetup -fP /tmp/disk1.img`, `sudo losetup -a` (ver loop0)
5. Instalar LVM si no está: `sudo apt install -y lvm2`
6. Crear Physical Volume: `sudo pvcreate /dev/loop0`
7. Crear Volume Group: `sudo vgcreate vg_data /dev/loop0`
8. Ver VG: `sudo vgdisplay vg_data`
9. Crear Logical Volume: `sudo lvcreate -L 500M -n lv_datos vg_data`
10. Ver LV: `sudo lvdisplay /dev/vg_data/lv_datos`
11. Formatear LV: `sudo mkfs.ext4 /dev/vg_data/lv_datos`
12. Montar: `sudo mkdir -p /mnt/datos && sudo mount /dev/vg_data/lv_datos /mnt/datos`
13. Crear datos de prueba: `sudo touch /mnt/datos/archivo{1..5}.txt`
14. Crear snapshot: `sudo lvcreate -L 100M -s -n lv_datos_snap /dev/vg_data/lv_datos`
15. Modificar datos originales: `sudo rm /mnt/datos/archivo1.txt`
16. Montar snapshot: `sudo mkdir -p /mnt/snap && sudo mount /dev/vg_data/lv_datos_snap /mnt/snap`
17. Verificar datos en snapshot: `ls /mnt/snap` (archivo1.txt debe existir)
18. Script de backup `/usr/local/bin/backup.sh`:
    ```bash
    #!/bin/bash
    BACKUP_DIR="/backup"
    DATE=$(date +%Y%m%d_%H%M%S)
    SOURCE="/mnt/datos"
    DEST="$BACKUP_DIR/backup_$DATE.tar.gz"
    
    mkdir -p "$BACKUP_DIR"
    tar -czf "$DEST" "$SOURCE" && echo "Backup exitoso: $DEST"
    find "$BACKUP_DIR" -name "backup_*.tar.gz" -mtime +7 -delete
    ```
19. Hacer ejecutable y probar: `sudo chmod +x /usr/local/bin/backup.sh && sudo /usr/local/bin/backup.sh`
20. Crear guía de recuperación en `recovery_guide.md`: pasos para restaurar desde tar.gz, recuperar desde snapshot LVM.

Semana 7 — Logs y rotación (8–10 h)
- Objetivo: journalctl y logrotate.
- Tareas: Configurar logrotate; pruebas de compresión/retención.
- Entregable: Configs y pruebas documentadas.

Ejercicios Prácticos:
1. Ver logs del sistema: `sudo journalctl`
2. Logs en tiempo real: `sudo journalctl -f`
3. Logs de un servicio específico: `sudo journalctl -u nginx.service`
4. Logs desde arranque actual: `sudo journalctl -b`
5. Logs del último arranque: `sudo journalctl -b -1`
6. Filtrar por prioridad: `sudo journalctl -p err` (solo errores)
7. Logs de las últimas 2 horas: `sudo journalctl --since "2 hours ago"`
8. Logs con formato JSON: `sudo journalctl -o json-pretty -n 5`
9. Ver espacio usado por journals: `sudo journalctl --disk-usage`
10. Limpiar journals antiguos: `sudo journalctl --vacuum-time=7d`
11. Crear aplicación de prueba que genere logs: `/usr/local/bin/log-generator.sh`:
    ```bash
    #!/bin/bash
    LOGFILE="/var/log/myapp/app.log"
    sudo mkdir -p /var/log/myapp
    for i in {1..100}; do
      echo "$(date) - Log entry $i - Sample application message" | sudo tee -a "$LOGFILE"
    done
    ```
12. Ejecutar generador: `sudo bash /usr/local/bin/log-generator.sh`
13. Crear configuración logrotate `/etc/logrotate.d/myapp`:
    ```
    /var/log/myapp/*.log {
        daily
        rotate 7
        compress
        delaycompress
        missingok
        notifempty
        create 0644 root root
        postrotate
            systemctl reload myapp > /dev/null 2>&1 || true
        endscript
    }
    ```
14. Probar configuración: `sudo logrotate -d /etc/logrotate.d/myapp` (dry-run)
15. Forzar rotación: `sudo logrotate -f /etc/logrotate.d/myapp`
16. Verificar archivos rotados: `ls -lh /var/log/myapp/`
17. Ver logs comprimidos: `zcat /var/log/myapp/app.log.1.gz | head`
18. Documentar en `logs_config.md`: estrategia de retención (7 días), ubicación de logs por servicio, comandos útiles de journalctl.

Semana 8 — RAID y mdadm (8–12 h)
- Objetivo: Configurar RAID 1 con `mdadm` y test de fallo de disco.
- Tareas: Crear RAID, simular fallo y recuperación.
- Entregable: Diagrama y pasos de recuperación.

Ejercicios Prácticos:
1. Instalar mdadm: `sudo apt install -y mdadm`
2. Crear 2 archivos para simular discos: 
   ```bash
   sudo dd if=/dev/zero of=/tmp/raid_disk1.img bs=1M count=1024
   sudo dd if=/dev/zero of=/tmp/raid_disk2.img bs=1M count=1024
   ```
3. Asociar como loop devices:
   ```bash
   sudo losetup /dev/loop1 /tmp/raid_disk1.img
   sudo losetup /dev/loop2 /tmp/raid_disk2.img
   sudo losetup -a
   ```
4. Crear RAID 1: `sudo mdadm --create /dev/md0 --level=1 --raid-devices=2 /dev/loop1 /dev/loop2`
5. Confirmar creación: `y` cuando pregunte
6. Ver estado del RAID: `cat /proc/mdstat`
7. Ver detalles: `sudo mdadm --detail /dev/md0`
8. Formatear RAID: `sudo mkfs.ext4 /dev/md0`
9. Montar RAID: `sudo mkdir -p /mnt/raid1 && sudo mount /dev/md0 /mnt/raid1`
10. Crear datos de prueba: `sudo dd if=/dev/urandom of=/mnt/raid1/testfile.dat bs=1M count=100`
11. Verificar checksum: `md5sum /mnt/raid1/testfile.dat > /tmp/checksum_original.txt`
12. Simular fallo de disco: `sudo mdadm --manage /dev/md0 --fail /dev/loop1`
13. Ver estado degradado: `cat /proc/mdstat`
14. Remover disco fallido: `sudo mdadm --manage /dev/md0 --remove /dev/loop1`
15. Verificar datos intactos: `md5sum /mnt/raid1/testfile.dat` (comparar con checksum original)
16. Crear nuevo disco de reemplazo:
    ```bash
    sudo dd if=/dev/zero of=/tmp/raid_disk3.img bs=1M count=1024
    sudo losetup /dev/loop3 /tmp/raid_disk3.img
    ```
17. Agregar disco al RAID: `sudo mdadm --manage /dev/md0 --add /dev/loop3`
18. Ver reconstrucción: `watch cat /proc/mdstat` (Ctrl+C para salir)
19. Guardar configuración: `sudo mdadm --detail --scan | sudo tee -a /etc/mdadm/mdadm.conf`
20. Crear diagrama en `raid_recovery.md`: topología RAID 1, procedimiento de recuperación paso a paso, tiempo estimado de rebuild.

Semana 9 — Redes básicas (8–12 h)
- Objetivo: IP, netmask, routing y `iproute2`.
- Tareas: Configurar IPs estáticas, rutas; usar `ss`, `ip`.
- Entregable: Lab con topología y comandos.

Ejercicios Prácticos:
1. Ver interfaces de red: `ip addr show`, `ip link show`
2. Ver tabla de rutas: `ip route show`
3. Ver estadísticas de interfaces: `ip -s link show`
4. Ver conexiones activas: `ss -tuln` (TCP/UDP listening), `ss -tupn` (con procesos)
5. Ver sockets específicos: `ss -t -a` (TCP all), `ss state established` (conexiones establecidas)
6. Configurar IP estática temporal: `sudo ip addr add 192.168.100.10/24 dev eth0`
7. Agregar ruta: `sudo ip route add 10.0.0.0/8 via 192.168.100.1`
8. Eliminar ruta: `sudo ip route del 10.0.0.0/8`
9. Configuración persistente en Ubuntu (netplan): Editar `/etc/netplan/01-netcfg.yaml`:
   ```yaml
   network:
     version: 2
     ethernets:
       eth0:
         dhcp4: no
         addresses:
           - 192.168.100.10/24
         gateway4: 192.168.100.1
         nameservers:
           addresses: [8.8.8.8, 8.8.4.4]
   ```
10. Aplicar configuración: `sudo netplan apply`
11. Probar conectividad: `ping -c 4 8.8.8.8`
12. Traceroute: `traceroute google.com` o `mtr google.com`
13. Ver estadísticas de red: `netstat -i`, `ip -s -s link show eth0`
14. Analizar tráfico con tcpdump: `sudo tcpdump -i eth0 -n -c 10`
15. Capturar solo ICMP: `sudo tcpdump -i eth0 icmp -c 5`
16. Ver DNS queries: `sudo tcpdump -i eth0 port 53 -n`
17. Diagnosticar con nmap: `sudo apt install -y nmap`, `nmap -sn 192.168.100.0/24` (host discovery)
18. Escanear puertos: `nmap -p 22,80,443 192.168.100.1`
19. Crear diagrama de topología en `network_lab.md`: interfaces, IPs, gateway, rutas, tabla de comandos útiles.
20. Documentar diferencias entre `ifconfig` (deprecated) y `ip` (moderno).

Semana 10 — Firewalls y nftables (8–12 h)
- Objetivo: Aprender `nftables` y reglas stateful.
- Tareas: Escribir reglas básicas y probar tráfico.
- Entregable: Reglas y explicación.

Ejercicios Prácticos:
1. Instalar nftables: `sudo apt install -y nftables`
2. Ver configuración actual: `sudo nft list ruleset`
3. Crear tabla: `sudo nft add table inet filter`
4. Crear cadena de input: `sudo nft add chain inet filter input { type filter hook input priority 0 \; policy drop \; }`
5. Permitir tráfico establecido: `sudo nft add rule inet filter input ct state established,related accept`
6. Permitir loopback: `sudo nft add rule inet filter input iif lo accept`
7. Permitir SSH: `sudo nft add rule inet filter input tcp dport 22 accept`
8. Permitir HTTP/HTTPS: `sudo nft add rule inet filter input tcp dport { 80, 443 } accept`
9. Permitir ICMP (ping): `sudo nft add rule inet filter input icmp type echo-request accept`
10. Crear cadena de output: `sudo nft add chain inet filter output { type filter hook output priority 0 \; policy accept \; }`
11. Crear cadena de forward: `sudo nft add chain inet filter forward { type filter hook forward priority 0 \; policy drop \; }`
12. Guardar reglas: `sudo nft list ruleset > /etc/nftables.conf`
13. Habilitar servicio: `sudo systemctl enable nftables.service`
14. Probar desde otra máquina: `ssh usuario@ip-servidor`, `curl http://ip-servidor`
15. Ver estadísticas: `sudo nft list ruleset -a` (con handles)
16. Ver contadores: `sudo nft add rule inet filter input counter` (agregar contador a regla)
17. Bloquear IP específica: `sudo nft add rule inet filter input ip saddr 1.2.3.4 drop`
18. Rate limiting para SSH: `sudo nft add rule inet filter input tcp dport 22 ct state new limit rate 3/minute accept`
19. Crear archivo `/etc/nftables/firewall.nft` con reglas organizadas:
    ```
    table inet filter {
      chain input {
        type filter hook input priority 0; policy drop;
        ct state established,related accept
        iif lo accept
        tcp dport 22 ct state new limit rate 3/minute accept
        tcp dport { 80, 443 } accept
        icmp type echo-request accept
      }
    }
    ```
20. Documentar en `firewall_rules.md`: filosofía default-deny, reglas stateful vs stateless, ejemplos de troubleshooting.

Semana 11 — SSH hardening y bastion (8–10 h)
- Objetivo: Harden SSH; claves ed25519; bastion host.
- Tareas: Configurar `sshd_config` seguro; deshabilitar auth por contraseña.
- Entregable: Config y guía de acceso seguro.

Ejercicios Prácticos:
1. Backup configuración SSH actual: `sudo cp /etc/ssh/sshd_config /etc/ssh/sshd_config.backup`
2. Generar claves ed25519 (más seguras): `ssh-keygen -t ed25519 -C "admin@server" -f ~/.ssh/id_ed25519_admin`
3. Copiar clave al servidor: `ssh-copy-id -i ~/.ssh/id_ed25519_admin.pub usuario@servidor`
4. Editar `/etc/ssh/sshd_config` con hardening:
   ```
   Port 2222
   PermitRootLogin no
   PasswordAuthentication no
   PubkeyAuthentication yes
   AuthorizedKeysFile .ssh/authorized_keys
   ChallengeResponseAuthentication no
   UsePAM yes
   X11Forwarding no
   MaxAuthTries 3
   MaxSessions 2
   ClientAliveInterval 300
   ClientAliveCountMax 2
   AllowUsers usuario admin
   Protocol 2
   ```
5. Validar configuración: `sudo sshd -t`
6. Reiniciar SSH: `sudo systemctl restart sshd`
7. Probar acceso con nueva clave: `ssh -i ~/.ssh/id_ed25519_admin -p 2222 usuario@servidor`
8. Configurar SSH sin contraseña en `~/.ssh/config`:
   ```
   Host servidor-prod
     HostName 192.168.100.10
     Port 2222
     User admin
     IdentityFile ~/.ssh/id_ed25519_admin
     ServerAliveInterval 60
   ```
9. Probar acceso simplificado: `ssh servidor-prod`
10. Implementar 2FA (opcional): `sudo apt install -y libpam-google-authenticator`, `google-authenticator`
11. Configurar bastion host: En servidor bastion, editar `/etc/ssh/sshd_config`:
    ```
    AllowUsers bastion-user
    PermitTunnel yes
    GatewayPorts no
    ```
12. Configurar ProxyJump en cliente: Agregar a `~/.ssh/config`:
    ```
    Host servidor-interno
      HostName 10.0.1.50
      User admin
      ProxyJump bastion-user@bastion.example.com
      IdentityFile ~/.ssh/id_ed25519_admin
    ```
13. Probar acceso via bastion: `ssh servidor-interno`
14. Ver logs de autenticación: `sudo journalctl -u ssh -f`
15. Configurar fail2ban para SSH: `sudo apt install -y fail2ban`
16. Editar `/etc/fail2ban/jail.local`:
    ```
    [sshd]
    enabled = true
    port = 2222
    logpath = /var/log/auth.log
    maxretry = 3
    bantime = 3600
    ```
17. Reiniciar fail2ban: `sudo systemctl restart fail2ban`
18. Ver IPs baneadas: `sudo fail2ban-client status sshd`
19. Documentar en `ssh_hardening.md`: mejores prácticas, configuración de bastion, procedimiento de recuperación si se pierde acceso.
20. Crear checklist de seguridad SSH con todas las configuraciones aplicadas.

Semana 12 — Servidor web y TLS (8–12 h)
- Objetivo: Desplegar Nginx con TLS automático (Certbot).
- Tareas: Configurar Nginx; obtener certificado; forzar HTTPS.
- Entregable: Playbook o pasos manuales + captura.

Ejercicios Prácticos:
1. Instalar Nginx: `sudo apt install -y nginx`
2. Verificar instalación: `sudo systemctl status nginx`, `curl http://localhost`
3. Crear directorio para sitio: `sudo mkdir -p /var/www/miapp/html`
4. Crear página de prueba: `echo '<h1>Mi Aplicación Web</h1>' | sudo tee /var/www/miapp/html/index.html`
5. Configurar virtual host `/etc/nginx/sites-available/miapp`:
   ```nginx
   server {
       listen 80;
       server_name miapp.local;
       root /var/www/miapp/html;
       index index.html;
       
       location / {
           try_files $uri $uri/ =404;
       }
       
       access_log /var/log/nginx/miapp_access.log;
       error_log /var/log/nginx/miapp_error.log;
   }
   ```
6. Habilitar sitio: `sudo ln -s /etc/nginx/sites-available/miapp /etc/nginx/sites-enabled/`
7. Probar configuración: `sudo nginx -t`
8. Recargar Nginx: `sudo systemctl reload nginx`
9. Probar acceso: `curl -H "Host: miapp.local" http://localhost`
10. Instalar Certbot: `sudo apt install -y certbot python3-certbot-nginx`
11. Obtener certificado (usar dominio real o trabajar con certificado autofirmado para laboratorio local - ver paso 18)
12. Verificar renovación automática: `sudo certbot renew --dry-run`
13. Ver certificados instalados: `sudo certbot certificates`
14. Configurar renovación automática: `sudo systemctl status certbot.timer`
15. Editar config para forzar HTTPS: `/etc/nginx/sites-available/miapp`:
    ```nginx
    server {
        listen 80;
        server_name miapp.local;
        return 301 https://$server_name$request_uri;
    }
    
    server {
        listen 443 ssl http2;
        server_name miapp.local;
        root /var/www/miapp/html;
        
        ssl_certificate /etc/ssl/certs/miapp.crt;
        ssl_certificate_key /etc/ssl/private/miapp.key;
        ssl_protocols TLSv1.2 TLSv1.3;
        ssl_ciphers HIGH:!aNULL:!MD5;
        ssl_prefer_server_ciphers on;
        
        add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;
        
        location / {
            try_files $uri $uri/ =404;
        }
    }
    ```
16. Recargar Nginx: `sudo nginx -t && sudo systemctl reload nginx`
17. Probar HTTPS: `curl -k https://localhost` (con certificado autofirmado para testing)
18. Generar certificado autofirmado para pruebas locales:
    ```bash
    sudo openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
      -keyout /etc/ssl/private/miapp.key \
      -out /etc/ssl/certs/miapp.crt \
      -subj "/CN=miapp.local"
    ```
19. Ver logs de Nginx: `sudo tail -f /var/log/nginx/miapp_access.log`
20. Documentar en `nginx_setup.md`: configuración completa, proceso de renovación SSL, optimizaciones de performance (gzip, caching), headers de seguridad.

Semana 13 — Introducción a Ansible (8–12 h)
- Objetivo: Provisionamiento reproducible con Ansible.
- Tareas: Playbook para Nginx, usuarios y firewall básico.
- Entregable: Playbook en repo y README.

Ejercicios Prácticos:
1. Instalar Ansible: `sudo apt install -y ansible`
2. Verificar instalación: `ansible --version`
3. Crear estructura de proyecto: `mkdir -p ~/ansible-lab/{inventories,playbooks,roles}`
4. Crear inventario `~/ansible-lab/inventories/hosts.ini`:
   ```ini
   [webservers]
   web1 ansible_host=192.168.100.10 ansible_user=admin
   
   [dbservers]
   db1 ansible_host=192.168.100.11 ansible_user=admin
   
   [all:vars]
   ansible_python_interpreter=/usr/bin/python3
   ```
5. Probar conectividad: `ansible -i inventories/hosts.ini all -m ping`
6. Ejecutar comando ad-hoc: `ansible -i inventories/hosts.ini webservers -m shell -a "uptime"`
7. Crear playbook `~/ansible-lab/playbooks/webserver_setup.yml`:
   ```yaml
   ---
   - name: Configurar servidor web
     hosts: webservers
     become: yes
     tasks:
       - name: Actualizar cache de apt
         apt:
           update_cache: yes
           cache_valid_time: 3600
       
       - name: Instalar Nginx
         apt:
           name: nginx
           state: present
       
       - name: Iniciar y habilitar Nginx
         systemd:
           name: nginx
           state: started
           enabled: yes
       
       - name: Crear usuario deploy
         user:
           name: deploy
           shell: /bin/bash
           groups: www-data
           state: present
       
       - name: Copiar página HTML
         copy:
           content: |
             <html>
             <head><title>Deployed by Ansible</title></head>
             <body><h1>This server was configured with Ansible!</h1></body>
             </html>
           dest: /var/www/html/index.html
           owner: www-data
           group: www-data
           mode: '0644'
       
       - name: Configurar firewall (UFW)
         ufw:
           rule: allow
           port: "{{ item }}"
           proto: tcp
         loop:
           - '22'
           - '80'
           - '443'
       
       - name: Habilitar UFW
         ufw:
           state: enabled
   ```
8. Validar sintaxis: `ansible-playbook --syntax-check playbooks/webserver_setup.yml`
9. Ejecutar en modo dry-run: `ansible-playbook -i inventories/hosts.ini playbooks/webserver_setup.yml --check`
10. Ejecutar playbook: `ansible-playbook -i inventories/hosts.ini playbooks/webserver_setup.yml`
11. Verificar idempotencia: Ejecutar de nuevo y verificar que no haga cambios
12. Crear role: `ansible-galaxy init roles/nginx`
13. Mover tareas a role: Editar `roles/nginx/tasks/main.yml` con las tareas de Nginx
14. Usar role en playbook: `playbooks/webserver_with_role.yml`:
    ```yaml
    ---
    - name: Configurar servidor web con roles
      hosts: webservers
      become: yes
      roles:
        - nginx
    ```
15. Crear playbook con variables: `playbooks/nginx_with_vars.yml`:
    ```yaml
    ---
    - name: Nginx con variables
      hosts: webservers
      become: yes
      vars:
        server_name: miapp.local
        document_root: /var/www/miapp
      tasks:
        - name: Crear document root
          file:
            path: "{{ document_root }}"
            state: directory
            owner: www-data
            group: www-data
    ```
16. Usar templates: Crear `roles/nginx/templates/nginx.conf.j2` con configuración parametrizada
17. Crear playbook con handlers: Definir handler para reload nginx cuando cambie configuración
18. Ver facts del servidor: `ansible -i inventories/hosts.ini webservers -m setup`
19. Filtrar facts: `ansible -i inventories/hosts.ini webservers -m setup -a "filter=ansible_distribution*"`
20. Documentar en `ansible_guide.md`: conceptos de inventario, playbooks, roles, idempotencia, mejores prácticas.

Semana 14 — Docker/Podman y builds (8–12 h)
- Objetivo: Crear imágenes reproducibles y multistage.
- Tareas: Dockerfile optimizado; probar `docker build` y `podman`.
- Entregable: Dockerfile + instrucciones.

Ejercicios Prácticos:
1. Instalar Docker: 
   ```bash
   sudo apt update
   sudo apt install -y ca-certificates curl gnupg
   sudo install -m 0755 -d /etc/apt/keyrings
   curl -fsSL https://download.docker.com/linux/ubuntu/gpg | sudo gpg --dearmor -o /etc/apt/keyrings/docker.gpg
   echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/ubuntu $(lsb_release -cs) stable" | sudo tee /etc/apt/sources.list.d/docker.list
   sudo apt update
   sudo apt install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin
   ```
2. Agregar usuario a grupo docker: `sudo usermod -aG docker $USER` (logout/login)
3. Verificar instalación: `docker --version`, `docker run hello-world`
4. Crear proyecto simple: `mkdir -p ~/docker-lab/app1 && cd ~/docker-lab/app1`
5. Crear aplicación Python `app.py`:
   ```python
   from flask import Flask
   app = Flask(__name__)
   
   @app.route('/')
   def hello():
       return '<h1>Hello from Docker!</h1>'
   
   if __name__ == '__main__':
       app.run(host='0.0.0.0', port=5000)
   ```
6. Crear `requirements.txt`: `echo "flask==2.3.0" > requirements.txt`
7. Crear Dockerfile básico:
   ```dockerfile
   FROM python:3.11-slim
   WORKDIR /app
   COPY requirements.txt .
   RUN pip install --no-cache-dir -r requirements.txt
   COPY app.py .
   EXPOSE 5000
   CMD ["python", "app.py"]
   ```
8. Construir imagen: `docker build -t myapp:v1 .`
9. Ver imágenes: `docker images`
10. Ejecutar contenedor: `docker run -d -p 5000:5000 --name myapp-container myapp:v1`
11. Probar aplicación: `curl http://localhost:5000`
12. Ver contenedores: `docker ps`, `docker ps -a`
13. Ver logs: `docker logs myapp-container`
14. Entrar al contenedor: `docker exec -it myapp-container /bin/bash`
15. Crear Dockerfile multistage (optimizado):
    ```dockerfile
    # Stage 1: Build
    FROM python:3.11-slim AS builder
    WORKDIR /app
    COPY requirements.txt .
    RUN pip install --user --no-cache-dir -r requirements.txt
    
    # Stage 2: Runtime
    FROM python:3.11-slim
    WORKDIR /app
    COPY --from=builder /root/.local /root/.local
    COPY app.py .
    ENV PATH=/root/.local/bin:$PATH
    EXPOSE 5000
    USER nobody
    CMD ["python", "app.py"]
    ```
16. Reconstruir con multistage: `docker build -t myapp:v2 .`
17. Comparar tamaños: `docker images | grep myapp`
18. Crear `.dockerignore`:
    ```
    __pycache__
    *.pyc
    .git
    .env
    ```
19. Limpiar contenedores: `docker stop myapp-container && docker rm myapp-container`
20. Instalar Podman: `sudo apt install -y podman`
21. Construir con Podman: `podman build -t myapp:podman .`
22. Ejecutar con Podman: `podman run -d -p 5001:5000 --name myapp-podman myapp:podman`
23. Ver diferencias rootless: `podman ps --all`
24. Crear docker-compose.yml:
    ```yaml
    version: '3.8'
    services:
      web:
        build: .
        ports:
          - "5000:5000"
        environment:
          - FLASK_ENV=development
        volumes:
          - ./app.py:/app/app.py
    ```
25. Ejecutar con compose: `docker compose up -d`
26. Ver logs: `docker compose logs -f`
27. Documentar en `docker_guide.md`: mejores prácticas, diferencias Docker/Podman, optimización de capas, seguridad de imágenes.

Semana 15 — Scanning y hardening de imágenes (8–10 h)
- Objetivo: Escanear imágenes con Trivy/Grype y reducir vulnerabilidades.
- Tareas: Ejecutar scans; aplicar fixes.
- Entregable: Informe de scan y cambios.

Ejercicios Prácticos:
1. Instalar Trivy:
   ```bash
   sudo apt-get install wget apt-transport-https gnupg lsb-release
   # Descargar e importar clave GPG (verificar origen desde https://aquasecurity.github.io/trivy-repo/)
   wget -qO - https://aquasecurity.github.io/trivy-repo/deb/public.key | gpg --dearmor | sudo tee /usr/share/keyrings/trivy.gpg > /dev/null
   echo "deb [signed-by=/usr/share/keyrings/trivy.gpg] https://aquasecurity.github.io/trivy-repo/deb $(lsb_release -sc) main" | sudo tee -a /etc/apt/sources.list.d/trivy.list
   sudo apt-get update
   sudo apt-get install trivy
   ```
2. Escanear imagen existente: `trivy image myapp:v2`
3. Ver solo vulnerabilidades críticas: `trivy image --severity CRITICAL,HIGH myapp:v2`
4. Generar reporte JSON: `trivy image -f json -o scan_report.json myapp:v2`
5. Escanear imagen base: `trivy image python:3.11-slim`
6. Escanear con imagen Alpine (más segura): Crear Dockerfile con Alpine:
   ```dockerfile
   FROM python:3.11-alpine
   WORKDIR /app
   RUN apk add --no-cache gcc musl-dev linux-headers
   COPY requirements.txt .
   RUN pip install --no-cache-dir -r requirements.txt
   COPY app.py .
   EXPOSE 5000
   USER nobody
   CMD ["python", "app.py"]
   ```
7. Construir imagen Alpine: `docker build -t myapp:alpine -f Dockerfile.alpine .`
8. Comparar scans: `trivy image myapp:alpine`
9. Instalar Grype (alternativa a Trivy):
   ```bash
   # ADVERTENCIA: Revisa el script antes de ejecutar o descarga el binario manualmente desde GitHub releases
   curl -sSfL https://raw.githubusercontent.com/anchore/grype/main/install.sh | sh -s -- -b /usr/local/bin
   # Alternativa más segura: descargar release desde https://github.com/anchore/grype/releases
   ```
10. Escanear con Grype: `grype myapp:v2`
11. Escanear con diferentes formatos: `grype myapp:v2 -o json`, `grype myapp:v2 -o table`
12. Implementar mejoras de seguridad en Dockerfile:
    ```dockerfile
    FROM python:3.11-alpine AS builder
    WORKDIR /app
    RUN apk add --no-cache gcc musl-dev linux-headers
    COPY requirements.txt .
    RUN pip install --user --no-cache-dir -r requirements.txt
    
    FROM python:3.11-alpine
    WORKDIR /app
    
    # Crear usuario no-root
    RUN addgroup -g 1001 appgroup && \
        adduser -D -u 1001 -G appgroup appuser
    
    # Copiar solo lo necesario
    COPY --from=builder --chown=appuser:appgroup /root/.local /home/appuser/.local
    COPY --chown=appuser:appgroup app.py .
    
    # No root
    USER appuser
    
    # Variables de entorno
    ENV PATH=/home/appuser/.local/bin:$PATH
    
    EXPOSE 5000
    
    # Health check
    HEALTHCHECK --interval=30s --timeout=3s \
      CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:5000')"
    
    CMD ["python", "app.py"]
    ```
13. Construir imagen hardened: `docker build -t myapp:hardened -f Dockerfile.hardened .`
14. Escanear imagen mejorada: `trivy image myapp:hardened`
15. Comparar resultados: Crear tabla con vulnerabilidades encontradas antes/después
16. Escanear filesystem: `trivy fs .` (escanea código y dependencias)
17. Ignorar vulnerabilidades específicas: Crear `.trivyignore`:
    ```
    # CVE-2023-12345 - False positive
    CVE-2023-12345
    ```
18. Escanear con políticas: `trivy image --severity CRITICAL --exit-code 1 myapp:hardened` (falla si hay críticas)
19. Integrar en CI: Crear script `scan.sh`:
    ```bash
    #!/bin/bash
    IMAGE=$1
    trivy image --severity CRITICAL,HIGH --exit-code 1 "$IMAGE"
    if [ $? -eq 0 ]; then
      echo "✓ Scan passed - no critical vulnerabilities"
    else
      echo "✗ Scan failed - critical vulnerabilities found"
      exit 1
    fi
    ```
20. Documentar en `security_scanning.md`: proceso de scanning, interpretación de CVEs, estrategias de mitigación, imágenes base recomendadas.

Semana 16 — CI/CD básico (8–12 h)
- Objetivo: Integrar build y test en GitHub Actions.
- Tareas: Workflow que construya imagen y corra linters.
- Entregable: Archivo de workflow y doc.

Ejercicios Prácticos:
1. Crear repositorio en GitHub: `gh repo create myapp-cicd --public` (o via web)
2. Clonar repositorio: `git clone https://github.com/usuario/myapp-cicd.git && cd myapp-cicd`
3. Copiar archivos del proyecto Docker: `cp -r ~/docker-lab/app1/* .`
4. Crear estructura de CI: `mkdir -p .github/workflows`
5. Crear workflow básico `.github/workflows/ci.yml`:
   ```yaml
   name: CI Pipeline
   
   on:
     push:
       branches: [main]
     pull_request:
       branches: [main]
   
   jobs:
     lint:
       runs-on: ubuntu-latest
       steps:
         - uses: actions/checkout@v3
         
         - name: Set up Python
           uses: actions/setup-python@v4
           with:
             python-version: '3.11'
         
         - name: Install dependencies
           run: |
             pip install flake8 pylint
             pip install -r requirements.txt
         
         - name: Lint with flake8
           run: |
             flake8 . --count --select=E9,F63,F7,F82 --show-source --statistics
             flake8 . --count --exit-zero --max-complexity=10 --max-line-length=127 --statistics
         
         - name: Lint with pylint
           run: pylint app.py || true
     
     build:
       runs-on: ubuntu-latest
       needs: lint
       steps:
         - uses: actions/checkout@v3
         
         - name: Set up Docker Buildx
           uses: docker/setup-buildx-action@v2
         
         - name: Build Docker image
           run: docker build -t myapp:${{ github.sha }} .
         
         - name: Run Trivy vulnerability scanner
           uses: aquasecurity/trivy-action@master
           with:
             image-ref: 'myapp:${{ github.sha }}'
             format: 'table'
             exit-code: '1'
             severity: 'CRITICAL,HIGH'
     
     test:
       runs-on: ubuntu-latest
       needs: build
       steps:
         - uses: actions/checkout@v3
         
         - name: Build and run container
           run: |
             docker build -t myapp:test .
             docker run -d -p 5000:5000 --name test-container myapp:test
             sleep 5
         
         - name: Test application
           run: |
             curl -f http://localhost:5000 || exit 1
             echo "Application is responding correctly"
         
         - name: Stop container
           if: always()
           run: docker stop test-container && docker rm test-container
   ```
6. Crear archivo de configuración flake8 `.flake8`:
   ```ini
   [flake8]
   max-line-length = 120
   exclude = .git,__pycache__,.venv
   ignore = E203,W503
   ```
7. Crear tests básicos `test_app.py`:
   ```python
   import pytest
   from app import app
   
   @pytest.fixture
   def client():
       app.config['TESTING'] = True
       with app.test_client() as client:
           yield client
   
   def test_home_page(client):
       response = client.get('/')
       assert response.status_code == 200
       assert b'Hello from Docker!' in response.data
   ```
8. Actualizar requirements.txt: `echo "pytest==7.4.0" >> requirements.txt`
9. Agregar job de tests al workflow:
   ```yaml
   pytest:
     runs-on: ubuntu-latest
     steps:
       - uses: actions/checkout@v3
       - uses: actions/setup-python@v4
         with:
           python-version: '3.11'
       - name: Install dependencies
         run: pip install -r requirements.txt
       - name: Run pytest
         run: pytest -v test_app.py
   ```
10. Commit y push: 
    ```bash
    git add .
    git commit -m "Add CI/CD pipeline with GitHub Actions"
    git push origin main
    ```
11. Ver ejecución en GitHub: Ir a Actions tab en GitHub
12. Crear workflow para Docker Hub (opcional): `.github/workflows/docker-publish.yml`:
    ```yaml
    name: Publish Docker Image
    
    on:
      push:
        tags:
          - 'v*'
    
    jobs:
      push:
        runs-on: ubuntu-latest
        steps:
          - uses: actions/checkout@v3
          
          - name: Log in to Docker Hub
            uses: docker/login-action@v2
            with:
              username: ${{ secrets.DOCKER_USERNAME }}
              password: ${{ secrets.DOCKER_PASSWORD }}
          
          - name: Extract metadata
            id: meta
            uses: docker/metadata-action@v4
            with:
              images: TU_USUARIO/myapp  # Reemplaza TU_USUARIO con tu usuario de Docker Hub
          
          - name: Build and push
            uses: docker/build-push-action@v4
            with:
              context: .
              push: true
              tags: ${{ steps.meta.outputs.tags }}
              labels: ${{ steps.meta.outputs.labels }}
    ```
13. Crear badge en README.md:
    ```markdown
    ![CI Pipeline](https://github.com/usuario/myapp-cicd/workflows/CI%20Pipeline/badge.svg)
    ```
14. Crear pre-commit hook local: `.git/hooks/pre-commit`:
    ```bash
    #!/bin/bash
    echo "Running linters..."
    flake8 . || exit 1
    echo "✓ Linting passed"
    ```
15. Hacer ejecutable: `chmod +x .git/hooks/pre-commit`
16. Probar workflow localmente con act: `act -l` (requiere Docker)
17. Ver logs de workflow: `gh run list`, `gh run view <run-id>`
18. Crear workflow de despliegue staging: Agregar job que despliega a servidor de pruebas
19. Documentar en `ci_cd_guide.md`: anatomía del workflow, secretos en GitHub, estrategias de deployment, mejores prácticas CI/CD.
20. Crear diagrama de flujo: código → lint → build → test → scan → deploy.

Semana 17 — KVM/QEMU y virtualización (8–12 h)
- Objetivo: Herramientas básicas de virtualización.
- Tareas: Crear VM con `virt-install`; snapshots y restore.
- Entregable: Guía y pruebas.

Ejercicios Prácticos:
1. Verificar soporte de virtualización: `egrep -c '(vmx|svm)' /proc/cpuinfo` (debe ser >0)
2. Instalar KVM y herramientas:
   ```bash
   sudo apt install -y qemu-kvm libvirt-daemon-system libvirt-clients bridge-utils virt-manager virtinst
   ```
3. Verificar instalación: `sudo systemctl status libvirtd`
4. Agregar usuario a grupos: `sudo usermod -aG libvirt,kvm $USER` (logout/login)
5. Verificar que KVM funciona: `kvm-ok`
6. Ver redes disponibles: `virsh net-list --all`
7. Iniciar red por defecto: `virsh net-start default`, `virsh net-autostart default`
8. Descargar imagen de Ubuntu: `wget https://cloud-images.ubuntu.com/jammy/current/jammy-server-cloudimg-amd64.img`
9. Crear disco para VM: `qemu-img create -f qcow2 -F qcow2 -b jammy-server-cloudimg-amd64.img vm1-disk.qcow2 20G`
10. Crear cloud-init config: `cloud-init-config.yml`:
    ```yaml
    #cloud-config
    users:
      - name: admin
        sudo: ALL=(ALL) NOPASSWD:ALL
        groups: sudo
        shell: /bin/bash
        ssh_authorized_keys:
          - TU_CLAVE_PUBLICA_AQUI  # Pega aquí el contenido de ~/.ssh/id_ed25519.pub
    ```
11. Generar ISO de cloud-init: 
    ```bash
    cloud-localds seed.img cloud-init-config.yml
    ```
12. Crear VM con virt-install:
    ```bash
    virt-install \
      --name vm1 \
      --memory 2048 \
      --vcpus 2 \
      --disk path=vm1-disk.qcow2,format=qcow2 \
      --disk path=seed.img,device=cdrom \
      --os-variant ubuntu22.04 \
      --network network=default \
      --graphics none \
      --console pty,target_type=serial \
      --import
    ```
13. Listar VMs: `virsh list --all`
14. Ver información de VM: `virsh dominfo vm1`
15. Obtener IP de VM: `virsh domifaddr vm1`
16. Conectar por SSH: `ssh admin@<ip-vm>`
17. Apagar VM: `virsh shutdown vm1`
18. Forzar apagado: `virsh destroy vm1` (si no responde)
19. Iniciar VM: `virsh start vm1`
20. Crear snapshot: `virsh snapshot-create-as vm1 snapshot1 "Snapshot inicial"`
21. Listar snapshots: `virsh snapshot-list vm1`
22. Ver info de snapshot: `virsh snapshot-info vm1 snapshot1`
23. Hacer cambios en VM: Conectar por SSH, crear archivos, instalar paquetes
24. Revertir a snapshot: `virsh snapshot-revert vm1 snapshot1`
25. Verificar que cambios se revirtieron: Conectar y verificar que archivos no existen
26. Clonar VM: `virt-clone --original vm1 --name vm2 --auto-clone`
27. Ver almacenamiento: `virsh pool-list`, `virsh vol-list default`
28. Exportar definición de VM: `virsh dumpxml vm1 > vm1-definition.xml`
29. Eliminar VM: `virsh undefine vm1 --remove-all-storage`
30. Recrear desde definición: `virsh define vm1-definition.xml`
31. Documentar en `kvm_guide.md`: arquitectura KVM/QEMU, diferencias entre shutdown/destroy, gestión de snapshots, mejores prácticas de storage.

Semana 18 — Kubernetes básico (k3s/minikube) (8–12 h)
- Objetivo: Desplegar cluster ligero y publicar una app.
- Tareas: Instalar k3s/minikube; desplegar app; Ingress TLS.
- Entregable: Manifiestos YAML y README.

Ejercicios Prácticos:
1. Instalar k3s (ligero para laboratorio):
   ```bash
   curl -sfL https://get.k3s.io | sh -
   sudo chmod 644 /etc/rancher/k3s/k3s.yaml
   ```
2. Configurar kubectl: `mkdir -p ~/.kube && sudo cp /etc/rancher/k3s/k3s.yaml ~/.kube/config && sudo chown $USER ~/.kube/config`
3. Verificar cluster: `kubectl cluster-info`, `kubectl get nodes`
4. Ver componentes del sistema: `kubectl get pods -n kube-system`
5. Crear namespace: `kubectl create namespace demo`
6. Crear deployment `deployment.yaml`:
   ```yaml
   apiVersion: apps/v1
   kind: Deployment
   metadata:
     name: webapp
     namespace: demo
   spec:
     replicas: 3
     selector:
       matchLabels:
         app: webapp
     template:
       metadata:
         labels:
           app: webapp
       spec:
         containers:
         - name: nginx
           image: nginx:1.25-alpine
           ports:
           - containerPort: 80
           resources:
             requests:
               memory: "64Mi"
               cpu: "100m"
             limits:
               memory: "128Mi"
               cpu: "200m"
   ```
7. Aplicar deployment: `kubectl apply -f deployment.yaml`
8. Ver deployments: `kubectl get deployments -n demo`
9. Ver pods: `kubectl get pods -n demo -o wide`
10. Ver logs de un pod: `kubectl logs -n demo <pod-name>`
11. Ejecutar comando en pod: `kubectl exec -n demo <pod-name> -- ls /usr/share/nginx/html`
12. Crear Service `service.yaml`:
    ```yaml
    apiVersion: v1
    kind: Service
    metadata:
      name: webapp-service
      namespace: demo
    spec:
      selector:
        app: webapp
      ports:
      - protocol: TCP
        port: 80
        targetPort: 80
      type: ClusterIP
    ```
13. Aplicar service: `kubectl apply -f service.yaml`
14. Ver services: `kubectl get svc -n demo`
15. Probar servicio internamente: `kubectl run test-pod --rm -i --tty --image=busybox -n demo -- wget -qO- webapp-service`
16. Crear Ingress `ingress.yaml`:
    ```yaml
    apiVersion: networking.k8s.io/v1
    kind: Ingress
    metadata:
      name: webapp-ingress
      namespace: demo
      annotations:
        cert-manager.io/cluster-issuer: "letsencrypt-staging"
    spec:
      rules:
      - host: webapp.local
        http:
          paths:
          - path: /
            pathType: Prefix
            backend:
              service:
                name: webapp-service
                port:
                  number: 80
    ```
17. Aplicar ingress: `kubectl apply -f ingress.yaml`
18. Ver ingress: `kubectl get ingress -n demo`
19. Probar desde host: `curl -H "Host: webapp.local" http://localhost`
20. Escalar deployment: `kubectl scale deployment webapp --replicas=5 -n demo`
21. Ver proceso de escalado: `kubectl get pods -n demo -w`
22. Actualizar imagen: `kubectl set image deployment/webapp nginx=nginx:1.26-alpine -n demo`
23. Ver rollout: `kubectl rollout status deployment/webapp -n demo`
24. Ver historial: `kubectl rollout history deployment/webapp -n demo`
25. Rollback: `kubectl rollout undo deployment/webapp -n demo`
26. Crear ConfigMap: `kubectl create configmap webapp-config --from-literal=ENV=production -n demo`
27. Ver ConfigMap: `kubectl get configmap webapp-config -n demo -o yaml`
28. Crear Secret: `kubectl create secret generic webapp-secret --from-literal=api-key=supersecret123 -n demo`
29. Ver secret (base64): `kubectl get secret webapp-secret -n demo -o yaml`
30. Limpiar recursos: `kubectl delete namespace demo`
31. Documentar en `k8s_guide.md`: conceptos básicos (pod, deployment, service, ingress), comandos esenciales kubectl, troubleshooting común.

Semana 19 — Persistencia y backups en K8s (velero) (8–12 h)
- Objetivo: PVs y backups con Velero.
- Tareas: Crear PV; probar backup/restore.
- Entregable: Procedimiento y pruebas.

Ejercicios Prácticos:
1. Crear namespace para pruebas: `kubectl create namespace storage-demo`
2. Ver storage classes disponibles: `kubectl get storageclass`
3. Crear PersistentVolume `pv.yaml`:
   ```yaml
   apiVersion: v1
   kind: PersistentVolume
   metadata:
     name: test-pv
   spec:
     capacity:
       storage: 1Gi
     accessModes:
       - ReadWriteOnce
     hostPath:
       path: /tmp/k8s-data
     storageClassName: local-storage
   ```
4. Aplicar PV: `kubectl apply -f pv.yaml`
5. Crear PersistentVolumeClaim `pvc.yaml`:
   ```yaml
   apiVersion: v1
   kind: PersistentVolumeClaim
   metadata:
     name: test-pvc
     namespace: storage-demo
   spec:
     accessModes:
       - ReadWriteOnce
     resources:
       requests:
         storage: 500Mi
     storageClassName: local-storage
   ```
6. Aplicar PVC: `kubectl apply -f pvc.yaml`
7. Ver estado: `kubectl get pv`, `kubectl get pvc -n storage-demo`
8. Crear pod con volumen montado `pod-with-storage.yaml`:
   ```yaml
   apiVersion: v1
   kind: Pod
   metadata:
     name: test-pod
     namespace: storage-demo
   spec:
     containers:
     - name: app
       image: nginx:alpine
       volumeMounts:
       - name: data
         mountPath: /data
     volumes:
     - name: data
       persistentVolumeClaim:
         claimName: test-pvc
   ```
9. Aplicar pod: `kubectl apply -f pod-with-storage.yaml`
10. Crear datos: `kubectl exec -n storage-demo test-pod -- sh -c "echo 'Hello from persistent storage' > /data/test.txt"`
11. Verificar datos: `kubectl exec -n storage-demo test-pod -- cat /data/test.txt`
12. Eliminar pod: `kubectl delete pod test-pod -n storage-demo`
13. Recrear pod y verificar persistencia: `kubectl apply -f pod-with-storage.yaml`, luego `kubectl exec -n storage-demo test-pod -- cat /data/test.txt`
14. Instalar Velero CLI:
    ```bash
    wget https://github.com/vmware-tanzu/velero/releases/download/v1.12.0/velero-v1.12.0-linux-amd64.tar.gz
    tar -xvf velero-v1.12.0-linux-amd64.tar.gz
    sudo mv velero-v1.12.0-linux-amd64/velero /usr/local/bin/
    velero version --client-only
    ```
15. Instalar Velero en cluster (modo local/MinIO):
    ```bash
    kubectl create namespace velero
    velero install \
      --provider aws \
      --plugins velero/velero-plugin-for-aws:v1.8.0 \
      --bucket velero \
      --secret-file ./credentials-velero \
      --use-volume-snapshots=false \
      --backup-location-config region=minio,s3ForcePathStyle="true",s3Url=http://minio.velero.svc:9000
    ```
16. Verificar instalación: `kubectl get pods -n velero`
17. Crear backup del namespace: `velero backup create storage-backup --include-namespaces storage-demo`
18. Ver backups: `velero backup get`
19. Ver detalles del backup: `velero backup describe storage-backup --details`
20. Ver logs del backup: `velero backup logs storage-backup`
21. Simular desastre: `kubectl delete namespace storage-demo`
22. Verificar que namespace no existe: `kubectl get namespace storage-demo`
23. Restaurar desde backup: `velero restore create --from-backup storage-backup`
24. Ver proceso de restore: `velero restore get`
25. Verificar restauración: `kubectl get pods -n storage-demo`, `kubectl exec -n storage-demo test-pod -- cat /data/test.txt`
26. Crear backup schedule (automático): `velero schedule create daily-backup --schedule="0 2 * * *" --include-namespaces storage-demo`
27. Ver schedules: `velero schedule get`
28. Backup de cluster completo: `velero backup create full-cluster-backup`
29. Exportar backup para migración: `velero backup download storage-backup -o storage-backup.tar.gz`
30. Documentar en `k8s_persistence_guide.md`: tipos de volúmenes, access modes, estrategia de backups, procedimiento de DR (Disaster Recovery).

Semana 20 — Observabilidad básica (Prometheus + Grafana) (8–12 h)
- Objetivo: Instrumentar y visualizar métricas.
- Tareas: Desplegar Prometheus y Grafana; crear dashboard.
- Entregable: Dashboard y alertas.

Ejercicios Prácticos:
1. Crear namespace: `kubectl create namespace monitoring`
2. Agregar repositorio Helm: `helm repo add prometheus-community https://prometheus-community.github.io/helm-charts`
3. Actualizar repos: `helm repo update`
4. Instalar kube-prometheus-stack:
   ```bash
   helm install prometheus prometheus-community/kube-prometheus-stack \
     --namespace monitoring \
     --set prometheus.prometheusSpec.retention=7d \
     --set grafana.adminPassword=admin123
   ```
5. Ver recursos creados: `kubectl get all -n monitoring`
6. Verificar pods running: `kubectl get pods -n monitoring -w`
7. Port-forward Prometheus: `kubectl port-forward -n monitoring svc/prometheus-kube-prometheus-prometheus 9090:9090` (en otra terminal)
8. Acceder a Prometheus: Navegador en `http://localhost:9090`
9. Probar queries en Prometheus:
   - `up` (servicios activos)
   - `node_cpu_seconds_total` (uso de CPU)
   - `container_memory_usage_bytes` (memoria de contenedores)
10. Port-forward Grafana: `kubectl port-forward -n monitoring svc/prometheus-grafana 3000:80`
11. Acceder a Grafana: Navegador en `http://localhost:3000` (user: admin, pass: admin123)
12. Explorar dashboards pre-configurados: Kubernetes / Compute Resources / Namespace
13. Crear dashboard personalizado: + → Create → Dashboard → Add visualization
14. Agregar panel con query: `rate(container_cpu_usage_seconds_total[5m])`
15. Crear aplicación instrumentada `metrics-app.py`:
    ```python
    from flask import Flask
    from prometheus_client import Counter, Histogram, generate_latest
    import time
    
    app = Flask(__name__)
    
    REQUEST_COUNT = Counter('app_requests_total', 'Total requests')
    REQUEST_LATENCY = Histogram('app_request_latency_seconds', 'Request latency')
    
    @app.route('/')
    def home():
        REQUEST_COUNT.inc()
        return 'Hello from instrumented app!'
    
    @app.route('/slow')
    @REQUEST_LATENCY.time()
    def slow():
        time.sleep(0.5)
        return 'Slow endpoint'
    
    @app.route('/metrics')
    def metrics():
        return generate_latest()
    
    if __name__ == '__main__':
        app.run(host='0.0.0.0', port=5000)
    ```
16. Crear ServiceMonitor para la app `servicemonitor.yaml`:
    ```yaml
    apiVersion: monitoring.coreos.com/v1
    kind: ServiceMonitor
    metadata:
      name: webapp-monitor
      namespace: demo
      labels:
        release: prometheus
    spec:
      selector:
        matchLabels:
          app: webapp
      endpoints:
      - port: metrics
        interval: 30s
    ```
17. Aplicar: `kubectl apply -f servicemonitor.yaml`
18. Verificar targets en Prometheus: Status → Targets
19. Crear alerta `alert-rules.yaml`:
    ```yaml
    apiVersion: monitoring.coreos.com/v1
    kind: PrometheusRule
    metadata:
      name: webapp-alerts
      namespace: monitoring
    spec:
      groups:
      - name: webapp
        interval: 30s
        rules:
        - alert: HighRequestLatency
          expr: histogram_quantile(0.95, rate(app_request_latency_seconds_bucket[5m])) > 1
          for: 5m
          labels:
            severity: warning
          annotations:
            summary: "High request latency detected"
            description: "95th percentile latency is above 1s"
    ```
20. Aplicar alertas: `kubectl apply -f alert-rules.yaml`
21. Ver alertas en Prometheus: Alerts tab
22. Configurar Alertmanager: Editar ConfigMap para enviar notificaciones (email, Slack)
23. Ver métricas custom: Query `app_requests_total` en Prometheus
24. Crear dashboard de aplicación en Grafana: Panel con requests/sec, latencia p50/p95/p99
25. Exportar dashboard: Settings → JSON Model → Copiar JSON
26. Simular carga: `while true; do curl http://webapp-service/slow; sleep 1; done`
27. Ver métricas en tiempo real en Grafana
28. Configurar retención de datos: Editar prometheus.prometheusSpec.retention
29. Ver uso de almacenamiento: `kubectl exec -n monitoring prometheus-prometheus-kube-prometheus-prometheus-0 -- df -h /prometheus`
30. Documentar en `observability_guide.md`: arquitectura de Prometheus, PromQL básico, creación de dashboards, estrategia de alertas, mejores prácticas de instrumentación.

Semana 21 — Logging centralizado (Loki/Fluentd) (8–10 h)
- Objetivo: Centralizar logs y consultas.
- Tareas: Desplegar Loki + promtail; indexar logs.
- Entregable: Consultas y ejemplos.

Ejercicios Prácticos:
1. Agregar repositorio Grafana Loki: `helm repo add grafana https://grafana.github.io/helm-charts`
2. Actualizar repos: `helm repo update`
3. Instalar Loki stack:
   ```bash
   helm install loki grafana/loki-stack \
     --namespace monitoring \
     --set grafana.enabled=false \
     --set promtail.enabled=true \
     --set loki.persistence.enabled=true \
     --set loki.persistence.size=10Gi
   ```
4. Verificar instalación: `kubectl get pods -n monitoring | grep loki`
5. Ver configuración de Promtail: `kubectl get configmap loki-promtail -n monitoring -o yaml`
6. Crear aplicación que genera logs `logging-app.py`:
   ```python
   import logging
   import time
   from flask import Flask
   
   app = Flask(__name__)
   logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
   
   @app.route('/')
   def home():
       app.logger.info('Home page accessed')
       return 'Logging App'
   
   @app.route('/error')
   def error():
       app.logger.error('Error endpoint accessed - simulating error')
       return 'Error logged', 500
   
   @app.route('/warn')
   def warn():
       app.logger.warning('Warning endpoint accessed')
       return 'Warning logged'
   
   if __name__ == '__main__':
       app.run(host='0.0.0.0', port=5000)
   ```
7. Desplegar aplicación en K8s con labels específicos para Loki
8. Port-forward Grafana (si no está ya): `kubectl port-forward -n monitoring svc/prometheus-grafana 3000:80`
9. Agregar Loki como datasource en Grafana: Configuration → Data Sources → Add Loki
10. URL de Loki: `http://loki:3100`
11. Probar conexión: Save & Test
12. Crear consulta LogQL básica en Grafana Explore:
    - `{namespace="demo"}` (todos los logs del namespace demo)
    - `{app="webapp"}` (logs de app específica)
    - `{namespace="demo"} |= "error"` (logs que contienen "error")
13. Consultas avanzadas LogQL:
    - `{namespace="demo"} | json | level="error"` (parsear JSON y filtrar)
    - `rate({namespace="demo"}[5m])` (tasa de logs)
    - `{namespace="demo"} |~ "error|fail"` (regex)
14. Crear dashboard de logs en Grafana: Panel tipo "Logs" con query de Loki
15. Generar tráfico y logs: 
    ```bash
    for i in {1..100}; do 
      curl http://webapp-service/
      curl http://webapp-service/error
      sleep 1
    done
    ```
16. Ver logs en tiempo real: Grafana Explore → Loki → Live tail
17. Agregar filtros por label: `{namespace="demo", pod=~"webapp-.*"}`
18. Extraer campos de logs: `{namespace="demo"} | regexp "(?P<method>\\w+) (?P<path>\\S+)"`
19. Crear alerta basada en logs: Crear alert rule que se dispare si tasa de errores > umbral
20. Configurar retención de Loki: Editar valores de Helm `loki.config.table_manager.retention_period`
21. Ver uso de almacenamiento: `kubectl exec -n monitoring loki-0 -- df -h /data`
22. Exportar logs: Usar LogCLI para extraer logs: 
    ```bash
    kubectl port-forward -n monitoring svc/loki 3100:3100
    logcli query '{namespace="demo"}' --limit=100 --from=1h
    ```
23. Instalar LogCLI: 
    ```bash
    wget https://github.com/grafana/loki/releases/download/v2.9.0/logcli-linux-amd64.zip
    unzip logcli-linux-amd64.zip
    chmod +x logcli-linux-amd64
    sudo mv logcli-linux-amd64 /usr/local/bin/logcli
    ```
24. Configurar LogCLI: `export LOKI_ADDR=http://localhost:3100`
25. Query con LogCLI: `logcli query '{namespace="monitoring"}' --since=3h --limit=50`
26. Crear dashboard combinado: Métricas (Prometheus) + Logs (Loki) en mismo dashboard
27. Correlacionar métricas y logs: Link desde alerta de Prometheus a logs de Loki
28. Documentar en `centralized_logging.md`: arquitectura Loki, LogQL syntax, diferencias con ELK stack, estrategias de retención, troubleshooting común.

Semana 22 — Seguridad y hardening (CIS, AppArmor/SELinux) (8–12 h)
- Objetivo: Aplicar hardening y ejecutar auditoría.
- Tareas: Correr lynis; aplicar recomendaciones; habilitar AppArmor/SELinux.
- Entregable: Informe y acciones tomadas.

Ejercicios Prácticos:
1. Instalar Lynis: 
   ```bash
   sudo apt install -y lynis
   ```
2. Ejecutar auditoría completa: `sudo lynis audit system`
3. Ver reporte: `sudo cat /var/log/lynis.log`
4. Ver score: Buscar "Hardening index" en output
5. Guardar baseline: `sudo lynis audit system > lynis_baseline.txt`
6. Revisar sugerencias críticas: Filtrar por "Suggestion" y "Warning"
7. Implementar mejoras básicas:
   - Deshabilitar servicios innecesarios: `sudo systemctl disable cups`
   - Configurar límites: Editar `/etc/security/limits.conf`
   - Hardening de kernel: Editar `/etc/sysctl.conf`
8. Configurar parámetros de kernel en `/etc/sysctl.conf`:
   ```
   # IP Forwarding
   net.ipv4.ip_forward = 0
   
   # SYN flood protection
   net.ipv4.tcp_syncookies = 1
   
   # Ignore ICMP redirects
   net.ipv4.conf.all.accept_redirects = 0
   net.ipv6.conf.all.accept_redirects = 0
   
   # Disable source routing
   net.ipv4.conf.all.accept_source_route = 0
   
   # Log martian packets
   net.ipv4.conf.all.log_martians = 1
   
   # Ignore ICMP ping
   net.ipv4.icmp_echo_ignore_all = 0
   
   # Increase system file descriptor limit
   fs.file-max = 65535
   ```
9. Aplicar cambios: `sudo sysctl -p`
10. Verificar AppArmor activo: `sudo aa-status`
11. Ver perfiles AppArmor: `ls /etc/apparmor.d/`
12. Crear perfil AppArmor personalizado para nginx:
    ```bash
    sudo aa-genprof /usr/sbin/nginx
    ```
13. Ejecutar nginx y generar tráfico para aprender comportamiento
14. Poner perfil en modo enforce: `sudo aa-enforce /usr/sbin/nginx`
15. Ver logs de AppArmor: `sudo grep apparmor /var/log/syslog`
16. Auditar con violations: `sudo aa-logprof`
17. Instalar herramientas CIS: 
    ```bash
    git clone https://github.com/dev-sec/cis-docker-benchmark.git
    cd cis-docker-benchmark
    ```
18. Ejecutar CIS Docker benchmark: `sudo sh cis-docker-benchmark.sh`
19. Revisar fallos y aplicar correcciones:
    - Crear usuario no-root en Dockerfiles
    - Habilitar user namespaces
    - Configurar resource limits
20. Aplicar CIS para K8s: Usar kube-bench:
    ```bash
    kubectl apply -f https://raw.githubusercontent.com/aquasecurity/kube-bench/main/job.yaml
    kubectl logs job/kube-bench
    ```
21. Configurar RBAC en K8s: Crear roles limitados para usuarios
22. Crear Role limitado `readonly-role.yaml`:
    ```yaml
    apiVersion: rbac.authorization.k8s.io/v1
    kind: Role
    metadata:
      namespace: demo
      name: pod-reader
    rules:
    - apiGroups: [""]
      resources: ["pods", "pods/log"]
      verbs: ["get", "list", "watch"]
    ```
23. Crear RoleBinding: Asignar role a usuario específico
24. Probar acceso limitado: Intentar crear pod con usuario limitado (debe fallar)
25. Implementar Network Policies en K8s `network-policy.yaml`:
    ```yaml
    apiVersion: networking.k8s.io/v1
    kind: NetworkPolicy
    metadata:
      name: deny-all
      namespace: demo
    spec:
      podSelector: {}
      policyTypes:
      - Ingress
      - Egress
    ```
26. Crear policy específica permitiendo solo tráfico necesario
27. Probar conectividad: Verificar que pods aislados no pueden comunicarse
28. Configurar Pod Security Standards: Habilitar pod-security en namespace
29. Crear PodSecurityPolicy restringida (deprecated, usar Pod Security Admission)
30. Escanear configuraciones con kubesec: 
    ```bash
    docker run -i kubesec/kubesec:latest scan /dev/stdin < deployment.yaml
    ```
31. Ejecutar segunda auditoría con Lynis: `sudo lynis audit system`
32. Comparar scores: baseline vs post-hardening
33. Documentar en `security_report.md`: Score inicial/final, vulnerabilidades encontradas, remediaciones aplicadas, recomendaciones pendientes, plan de mantenimiento.

Semana 23 — Proyecto final: Integración (8–15 h)
- Objetivo: Integrar lo aprendido en un proyecto demostrable.
- Tareas: Desplegar app multi-tier con CI, monitorización y backups; documentar.
- Entregable: Repo del proyecto, README y video corto (opcional).

Ejercicios Prácticos - Proyecto: "Sistema de Blog Multi-Tier"

Componentes:
- Frontend: Nginx sirviendo static files
- Backend: API REST (Python/Flask o Node.js)
- Base de datos: PostgreSQL
- Cache: Redis
- CI/CD: GitHub Actions
- Monitoreo: Prometheus + Grafana
- Logging: Loki
- Backups: Velero

1. Planificación y arquitectura:
   - Crear diagrama de arquitectura en `docs/architecture.md`
   - Definir requisitos funcionales y no funcionales
   - Listar tecnologías y justificación

2. Setup del repositorio:
   ```bash
   mkdir -p blog-platform/{frontend,backend,database,k8s,ansible,docs}
   cd blog-platform
   git init
   ```

3. Desarrollo Backend API (`backend/app.py`):
   ```python
   from flask import Flask, jsonify, request
   from prometheus_flask_exporter import PrometheusMetrics
   import redis
   import psycopg2
   
   app = Flask(__name__)
   metrics = PrometheusMetrics(app)
   
   # Conexiones
   cache = redis.Redis(host='redis', port=6379)
   
   @app.route('/health')
   def health():
       return jsonify({"status": "healthy"})
   
   @app.route('/api/posts')
   def get_posts():
       # Implementar lógica de posts
       return jsonify({"posts": []})
   
   if __name__ == '__main__':
       app.run(host='0.0.0.0', port=5000)
   ```

4. Dockerfile Backend multi-stage:
   ```dockerfile
   FROM python:3.11-alpine AS builder
   WORKDIR /app
   COPY requirements.txt .
   RUN pip install --user --no-cache-dir -r requirements.txt
   
   FROM python:3.11-alpine
   RUN addgroup -g 1001 appgroup && adduser -D -u 1001 -G appgroup appuser
   WORKDIR /app
   COPY --from=builder --chown=appuser:appgroup /root/.local /home/appuser/.local
   COPY --chown=appuser:appgroup . .
   USER appuser
   ENV PATH=/home/appuser/.local/bin:$PATH
   EXPOSE 5000
   CMD ["python", "app.py"]
   ```

5. Manifiestos Kubernetes (`k8s/backend-deployment.yaml`):
   - Deployment para backend con 3 replicas
   - Service ClusterIP
   - ConfigMap para variables de entorno
   - Secret para credenciales DB
   - HPA (HorizontalPodAutoscaler)

6. Deployment PostgreSQL con PVC:
   ```yaml
   apiVersion: apps/v1
   kind: StatefulSet
   metadata:
     name: postgres
   spec:
     serviceName: postgres
     replicas: 1
     template:
       spec:
         containers:
         - name: postgres
           image: postgres:15-alpine
           env:
           - name: POSTGRES_DB
             value: blogdb
           volumeMounts:
           - name: postgres-data
             mountPath: /var/lib/postgresql/data
     volumeClaimTemplates:
     - metadata:
         name: postgres-data
       spec:
         accessModes: ["ReadWriteOnce"]
         resources:
           requests:
             storage: 5Gi
   ```

7. Configurar Ingress con TLS:
   - Crear certificado con cert-manager
   - Configurar rutas: / → frontend, /api → backend
   - Habilitar rate limiting

8. Pipeline CI/CD (`.github/workflows/deploy.yml`):
   ```yaml
   name: Deploy Pipeline
   on:
     push:
       branches: [main]
   
   jobs:
     test:
       runs-on: ubuntu-latest
       steps:
         - uses: actions/checkout@v3
         - name: Run tests
           run: |
             cd backend
             pip install -r requirements.txt
             pytest tests/
     
     build-and-scan:
       needs: test
       runs-on: ubuntu-latest
       steps:
         - uses: actions/checkout@v3
         - name: Build images
           run: |
             docker build -t blog-backend:${{ github.sha }} backend/
             docker build -t blog-frontend:${{ github.sha }} frontend/
         - name: Scan with Trivy
           run: |
             trivy image --severity CRITICAL,HIGH --exit-code 1 blog-backend:${{ github.sha }}
     
     deploy:
       needs: build-and-scan
       runs-on: ubuntu-latest
       steps:
         - name: Deploy to K8s
           run: |
             kubectl apply -f k8s/
             kubectl rollout status deployment/backend
   ```

9. Configurar Prometheus ServiceMonitor para backend

10. Crear dashboards Grafana:
    - Dashboard de aplicación: requests/sec, latencia, errores
    - Dashboard de infraestructura: CPU, memoria, disco por pod
    - Dashboard de base de datos: conexiones, queries/sec

11. Configurar alertas:
    - API response time > 500ms
    - Error rate > 1%
    - Database connections > 80%
    - Pod restart count > 3

12. Implementar backup strategy:
    - Velero schedule para namespace completo
    - Backup de base de datos con pg_dump (cronjob K8s)
    - Retention policy: 7 días

13. Crear playbook Ansible para provisioning:
    ```yaml
    # ansible/site.yml
    - hosts: k8s_master
      roles:
        - k8s-cluster
        - monitoring
        - backup
    ```

14. Documentación completa en README.md:
    - Prerequisitos
    - Instrucciones de instalación
    - Arquitectura (con diagramas)
    - Comandos útiles
    - Troubleshooting
    - Procedimientos de backup/restore

15. Crear script de deployment automatizado `deploy.sh`:
    ```bash
    #!/bin/bash
    set -e
    
    echo "🚀 Deploying Blog Platform..."
    
    # Create namespace
    kubectl create namespace blog --dry-run=client -o yaml | kubectl apply -f -
    
    # Apply configurations
    kubectl apply -f k8s/
    
    # Wait for rollout
    kubectl rollout status deployment/backend -n blog
    kubectl rollout status deployment/frontend -n blog
    
    echo "✅ Deployment complete!"
    ```

16. Testing end-to-end:
    - Crear tests de integración
    - Smoke tests post-deployment
    - Load testing con hey o k6

17. Implementar observabilidad distribuida:
    - Tracing con Jaeger (opcional)
    - Correlación de logs y traces

18. Security hardening:
    - Network policies entre componentes
    - RBAC roles específicos
    - Secrets encryption at rest
    - Image scanning en CI

19. Documentar DR (Disaster Recovery):
    - RTO/RPO definidos
    - Procedimiento de restore
    - Runbook de incidentes

20. Crear video demo (5-10 min):
    - Arquitectura overview
    - Demo de la aplicación
    - Mostrar monitoring/alerting
    - Simular fallo y recovery
    - Explicar CI/CD pipeline

21. Preparar presentación del proyecto:
    - Slides con arquitectura
    - Decisiones técnicas y trade-offs
    - Métricas y KPIs
    - Lecciones aprendidas

22. Subir a GitHub con README profesional, badges de CI, y documentación completa

23. Opcional: Desplegar en cloud (DigitalOcean, Linode, o AWS free tier) para demo público

Semana 24 — Pulir portfolio y búsqueda de empleo (8–10 h)
- Objetivo: Preparar CV, GitHub y materiales para entrevistas.
- Tareas: Escribir READMEs; añadir logs de aprendizaje; preparar pruebas técnicas.
- Entregable: Portfolio público con 2–3 proyectos listos.

Ejercicios Prácticos:

1. Organizar repositorio de portfolio personal:
   ```bash
   mkdir -p ~/portfolio/{projects,certifications,learning-logs,interview-prep}
   cd ~/portfolio
   git init
   ```

2. Crear README principal profesional (`README.md`):
   ```markdown
   # 👨‍💻 [Tu Nombre] - Linux System Administrator & DevOps Engineer
   
   ## 🎯 Sobre mí
   [Breve introducción - 2-3 líneas]
   
   ## 🛠️ Skills Técnicas
   - **Linux**: Ubuntu/Debian, RHEL, systemd, bash scripting
   - **Containerización**: Docker, Podman, image optimization
   - **Orquestación**: Kubernetes, Helm, k3s
   - **Automatización**: Ansible, Terraform, CI/CD (GitHub Actions)
   - **Monitoreo**: Prometheus, Grafana, Loki
   - **Seguridad**: nftables, SSH hardening, AppArmor, Lynis
   - **Virtualización**: KVM/QEMU, libvirt
   - **Storage**: LVM, RAID, backups con Velero
   
   ## 📂 Proyectos Destacados
   ### 1. [Blog Platform Multi-Tier](./projects/blog-platform)
   Sistema completo con CI/CD, monitoreo y backups
   - Stack: Kubernetes, PostgreSQL, Redis, Prometheus
   - [Demo](link) | [Código](link)
   
   ### 2. [Infrastructure as Code Lab](./projects/iac-lab)
   Automatización de infraestructura con Ansible y Terraform
   - [Código](link)
   
   ### 3. [Security Hardening Framework](./projects/security-hardening)
   Scripts y playbooks para hardening de servidores Linux
   - [Código](link)
   
   ## 📜 Certificaciones
   - [Lista de certificaciones si tienes]
   
   ## 📫 Contacto
   - Email: tu@email.com
   - LinkedIn: [perfil]
   - Blog: [si tienes]
   ```

3. Mejorar READMEs de proyectos individuales con:
   - Badges (build status, license)
   - Screenshots/GIFs
   - Prerequisitos claros
   - Quick start guide
   - Troubleshooting section
   - Contributing guidelines

4. Crear learning log (`learning-logs/6-month-journey.md`):
   - Semana por semana qué aprendiste
   - Desafíos enfrentados y soluciones
   - Recursos útiles encontrados
   - Reflexiones y próximos pasos

5. Preparar CV técnico:
   - Formato limpio (LaTeX con moderncv o markdown)
   - Secciones: Experiencia, Skills, Proyectos, Educación
   - Cuantificar logros: "Reduje tiempo de deploy en 50%"
   - Incluir links a GitHub/LinkedIn
   - 1-2 páginas máximo

6. Optimizar perfil de GitHub:
   - Foto profesional
   - Bio concisa con keywords
   - Pinear 3-4 mejores proyectos
   - Contribuciones consistentes (green squares)
   - README de perfil con estadísticas

7. Crear perfil de LinkedIn completo:
   - Headline optimizado: "Linux SysAdmin | DevOps | Kubernetes"
   - Resumen con keywords relevantes
   - Experiencia detallada (aunque sea labs/proyectos)
   - Skills endorsements
   - Publicar artículos sobre aprendizajes

8. Preparar casos de estudio de proyectos:
   - Problema/Challenge
   - Solución implementada
   - Tecnologías utilizadas
   - Resultados y métricas
   - Lecciones aprendidas

9. Crear repositorio de ejercicios de entrevistas (`interview-prep/`):
   ```bash
   mkdir -p interview-prep/{bash-exercises,k8s-scenarios,troubleshooting,system-design}
   ```

10. Practicar preguntas técnicas comunes:
    - "Explica el proceso de boot de Linux"
    - "¿Cómo debugueas un pod que no arranca?"
    - "Diferencias entre Docker y Podman"
    - "¿Cómo optimizas una imagen Docker?"
    - "Explica cómo funciona Prometheus"

11. Crear cheat sheets personalizadas:
    - Comandos kubectl esenciales
    - Comandos systemctl/journalctl
    - Troubleshooting workflows
    - Ansible playbook patterns

12. Preparar escenarios prácticos resueltos:
    - Troubleshooting: "Pod en CrashLoopBackOff"
    - Security: "Hardening de servidor SSH"
    - Performance: "Optimización de consultas DB"
    - Automation: "Deployment con zero-downtime"

13. Documentar tu stack de herramientas favoritas:
    - Editor: vim/neovim con plugins
    - Terminal: tmux setup
    - Scripts de productividad
    - Aliases útiles

14. Crear presentación personal (slides):
    - Quién soy
    - Mis proyectos principales
    - Stack técnico
    - Qué busco en siguiente rol

15. Preparar demos rápidas (5 min cada una):
    - Demo 1: Deployment en K8s con GitOps
    - Demo 2: Monitoreo con Grafana
    - Demo 3: Automatización con Ansible

16. Lista de empresas objetivo:
    - Investigar tech stack de cada una
    - Personalizar CV por empresa
    - Preparar preguntas para entrevistas

17. Networking y comunidad:
    - Unirse a grupos: DevOps ES, r/devops, r/linuxadmin
    - Asistir a meetups locales o virtuales
    - Contribuir a proyectos open source (issues, docs)
    - Publicar artículos en Medium/Dev.to

18. Crear blog técnico (opcional pero recomendado):
    - Usar GitHub Pages o Hugo
    - 3-5 artículos sobre proyectos realizados
    - SEO básico con keywords técnicas

19. Preparar referencias y recomendaciones:
    - Pedir recomendaciones en LinkedIn
    - Mantener contactos de compañeros/mentores

20. Practicar entrevistas técnicas:
    - Mock interviews con amigos/comunidad
    - Plataformas: Pramp, interviewing.io
    - Practicar explicar decisiones técnicas

21. Crear video de presentación personal (LinkedIn/portfolio):
    - 1-2 minutos
    - Introducción + stack + proyecto destacado
    - Profesional pero auténtico

22. Configurar alertas de empleo:
    - LinkedIn Jobs
    - Indeed, InfoJobs
    - Twitter con keywords
    - Mailing lists de tech communities

23. Preparar respuestas a preguntas comportamentales:
    - "Cuéntame sobre un desafío técnico que resolviste"
    - "¿Cómo priorizas tareas?"
    - "Describe un momento de aprendizaje de un error"

24. Checklist final antes de aplicar:
    - [ ] GitHub profile optimizado con proyectos pineados
    - [ ] LinkedIn completo con recommendations
    - [ ] CV actualizado (ATS-friendly)
    - [ ] Portfolio website/README profesional
    - [ ] 3 proyectos demostrables listos
    - [ ] Cheat sheets y notes organizadas
    - [ ] Practice interviews realizadas
    - [ ] Networking activo en comunidades

25. Aplicar estratégicamente:
    - Calidad > Cantidad en aplicaciones
    - Personalizar cada aplicación
    - Follow up educado después de 1 semana
    - Mantener spreadsheet de aplicaciones

26. Post-interview routine:
    - Enviar thank you email
    - Documentar preguntas que te hicieron
    - Actualizar prep material con nuevos learnings
    - Mantener momentum con más aplicaciones

¡Éxito en tu búsqueda de empleo! 🚀

---

## Proyectos recomendados para el portfolio
1. Servidor web seguro: Nginx + Certbot + nftables + Ansible + CI.
2. Backup & Recovery: Script + systemd timer + documentación y pruebas.
3. Kubernetes App: App multi-service con Helm, Prometheus/Grafana.

---

## Empleabilidad y ritmo
- Consistencia > Intensidad: 1 h diaria es mejor que sesiones largas ocasionales.
- Proyectos > Certificaciones: crea evidencia práctica.
- Comunidad: participa en foros y meetups.

---

## Checklist rápida (al finalizar 6 meses)
- [ ] 5+ scripts documentados y automatizados.
- [ ] Playbooks Ansible reutilizables.
- [ ] Pipeline CI que construye/escanea imágenes.
- [ ] Cluster k3s/minikube con ingress y monitoring.
- [ ] Backup y recovery documentado (VMs y K8s).
- [ ] Configs de hardening y resultado de auditoría.
- [ ] Portfolio público con 3 proyectos demostrables.

---

## Recursos y lecturas recomendadas
- The Linux Command Line — William Shotts.
- DigitalOcean Community Tutorials.
- OverTheWire (Bandit) para práctica shell.
- Trivy/Grype, Prometheus/Grafana docs, Kubernetes docs.

---

## Notas finales

Este documento ha sido actualizado con ejercicios prácticos y accionables para cada una de las 24 semanas del plan de aprendizaje. Cada ejercicio incluye:
- Comandos específicos y ejecutables
- Nombres de archivos y rutas concretas
- Escenarios prácticos realizables en laboratorio
- Scripts y configuraciones de ejemplo
- Procedimientos paso a paso

**Consejos para aprovechar al máximo este plan:**
- No te saltes ejercicios, cada uno construye sobre el anterior
- Documenta todos tus aprendizajes en tu repositorio personal
- Adapta el ritmo a tu disponibilidad, pero mantén la consistencia
- Únete a comunidades para resolver dudas y compartir experiencias
- Celebra cada hito completado

**Próximos pasos:**
1. Configura tu entorno de laboratorio (Semana 1)
2. Crea un repositorio GitHub para documentar tu progreso
3. Establece un horario regular de estudio (ej: 1-2h diarias)
4. Conecta con otros estudiantes en comunidades de Linux/DevOps

¡Mucho éxito en tu camino para convertirte en administrador/a de Linux! 🚀
