#!/bin/bash
set -euo pipefail
source /usr/local/lib/ts-up.sh

: "${NODE_NAME:?}" "${TAILNET:?}" "${TAILSCALE_AUTHKEY:?}" "${ES_HOSTS_MAP:?}" "${ES_URLS:?}" \
  "${KIBANA_SYSTEM_PASSWORD:?}" "${KIBANA_ENC_KEY:?}" "${KIBANA_HEAP_MB:?}"

KBN_HOME=/opt/kibana
CONF="${KBN_HOME}/config"
FQDN="${NODE_NAME}.${TAILNET}"

ts_up "$FQDN" "${CONF}/certs" kibana

# Userspace Tailscale can't carry Kibana's outbound traffic, so resolve the ES
# FQDNs to their apple/container network IPs. TLS still verifies the LE cert.
IFS=',' read -ra pairs <<< "$ES_HOSTS_MAP"
for p in "${pairs[@]}"; do
  ip="${p%%=*}"
  host="${p#*=}"
  tmp="$(mktemp)"
  grep -v -F " ${host}" /etc/hosts > "$tmp" || true
  echo "${ip} ${host}" >> "$tmp"
  cat "$tmp" > /etc/hosts
  rm -f "$tmp"
done

cat > "${CONF}/kibana.yml" <<YML
server.name: "${NODE_NAME}"
server.host: "0.0.0.0"
server.port: 5601
server.publicBaseUrl: "https://${FQDN}:5601"
server.ssl.enabled: true
server.ssl.certificate: ${CONF}/certs/http.crt
server.ssl.key: ${CONF}/certs/http.key

elasticsearch.hosts: [${ES_URLS}]
elasticsearch.username: "kibana_svc"
elasticsearch.password: "${KIBANA_SYSTEM_PASSWORD}"

xpack.encryptedSavedObjects.encryptionKey: "${KIBANA_ENC_KEY}"
xpack.security.encryptionKey: "${KIBANA_ENC_KEY}"
xpack.reporting.encryptionKey: "${KIBANA_ENC_KEY}"
YML
chown -R kibana:kibana "$CONF"

unset TAILSCALE_AUTHKEY KIBANA_SYSTEM_PASSWORD KIBANA_ENC_KEY
exec runuser -u kibana -- env NODE_OPTIONS="--max-old-space-size=${KIBANA_HEAP_MB}" "${KBN_HOME}/bin/kibana"
