# AuditFlow lab — servicios de red con credenciales débiles (SSH + FTP).
#
# Objetivo de descubrimiento de servicios (Nmap -sV identifica OpenSSH y vsftpd
# con versión) y de las plantillas default-logins de Nuclei. El ataque de
# credenciales real (hydra) es la spec 011; esta imagen solo deja el objetivo
# listo. Credenciales triviales A PROPÓSITO: root:root / admin:admin / test:test.
FROM alpine:3.20

RUN set -eux \
 && apk add --no-cache openssh openssh-sftp-server vsftpd \
 && ssh-keygen -A \
 && adduser -D admin \
 && adduser -D test \
 && echo 'root:root'   | chpasswd \
 && echo 'admin:admin' | chpasswd \
 && echo 'test:test'   | chpasswd \
 && sed -i 's/^#\?PermitRootLogin.*/PermitRootLogin yes/' /etc/ssh/sshd_config \
 && sed -i 's/^#\?PasswordAuthentication.*/PasswordAuthentication yes/' /etc/ssh/sshd_config \
 && printf '%s\n' \
      'anonymous_enable=NO' \
      'local_enable=YES' \
      'write_enable=NO' \
      'seccomp_sandbox=NO' \
      'pasv_enable=YES' \
      'pasv_min_port=30000' \
      'pasv_max_port=30009' \
      'listen=YES' \
      'listen_ipv6=NO' \
      'background=NO' \
    > /etc/vsftpd/vsftpd.conf

COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

EXPOSE 21 22
ENTRYPOINT ["/entrypoint.sh"]
