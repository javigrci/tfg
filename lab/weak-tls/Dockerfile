# AuditFlow lab — HTTPS con configuración TLS deliberadamente débil (spec 011a, RF-036).
#
# Objetivo reproducible para testssl.sh: protocolos obsoletos (TLS 1.0 / 1.1), cifrados
# débiles (RC4 / 3DES), certificado autofirmado. NUNCA se despliega con la app.
FROM nginx:1.27-alpine

RUN apk add --no-cache openssl && \
    mkdir -p /etc/nginx/certs && \
    openssl req -x509 -nodes -newkey rsa:2048 -days 365 \
        -keyout /etc/nginx/certs/self.key \
        -out /etc/nginx/certs/self.crt \
        -subj "/CN=weak-tls.lab/O=AuditFlow Lab/C=ES"

COPY nginx.conf /etc/nginx/conf.d/default.conf
RUN echo '<!doctype html><title>weak-tls lab</title><h1>AuditFlow lab — weak TLS target</h1>' \
    > /usr/share/nginx/html/index.html

EXPOSE 443
