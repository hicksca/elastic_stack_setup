# Sourced by start-es.sh and start-kibana.sh.
# ts_up <fqdn> <cert-dir> <owner>
#
# Joins the tailnet and writes the Let's Encrypt cert/key for <fqdn> into
# <cert-dir>/http.crt and <cert-dir>/http.key. /var/lib/tailscale is a host
# mount, so the node identity and cert cache survive container rebuilds.
ts_up() {
  local fqdn="$1" certdir="$2" owner="$3"
  mkdir -p /var/lib/tailscale "$certdir"

  # Userspace networking forwards inbound tailnet connections to localhost,
  # which is all ES and Kibana need. Logs go to a file to keep stdout readable.
  tailscaled --tun=userspace-networking --statedir=/var/lib/tailscale \
    >>/var/log/tailscaled.log 2>&1 &

  for _ in $(seq 1 30); do
    [ -S /var/run/tailscale/tailscaled.sock ] && break
    sleep 1
  done

  tailscale up --authkey="${TAILSCALE_AUTHKEY}" --hostname="${NODE_NAME}" \
    --accept-dns=false --timeout=60s

  local actual
  actual="$(tailscale status --json | jq -r '.Self.DNSName' | sed 's/\.$//')"
  if [ "$actual" != "$fqdn" ]; then
    echo "FATAL: tailnet named this node ${actual}, expected ${fqdn}." >&2
    echo "A stale machine called ${NODE_NAME} likely exists in the admin console, or --tailnet is wrong." >&2
    exit 1
  fi

  # tailscale cert blocks for as long as tailscaled's ACME flow does, with no
  # timeout of its own. Bound it so a stalled attempt gets retried from scratch.
  local ok=0
  for attempt in 1 2 3; do
    if timeout 180 tailscale cert --cert-file "$certdir/http.crt" --key-file "$certdir/http.key" "$fqdn"; then
      ok=1
      break
    fi
    echo "tailscale cert attempt ${attempt} for ${fqdn} failed or timed out, retrying" >&2
    sleep 10
  done
  if [ "$ok" -ne 1 ]; then
    echo "FATAL: tailscale cert failed for ${fqdn}, see /var/log/tailscaled.log" >&2
    exit 1
  fi

  chown -R "${owner}:${owner}" "$certdir"
  chmod 0600 "$certdir/http.key"
}
