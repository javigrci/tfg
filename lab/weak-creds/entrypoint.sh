#!/bin/sh
# Arranca vsftpd en segundo plano y sshd en primer plano (proceso principal
# del contenedor). Si sshd muere, el contenedor muere.
set -e

# vsftpd necesita este directorio para el "secure chroot" de usuarios sin shell.
mkdir -p /var/run/vsftpd/empty

vsftpd /etc/vsftpd/vsftpd.conf &

exec /usr/sbin/sshd -D -e
