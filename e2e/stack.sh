#!/usr/bin/env bash
# The end-to-end stack: Clerk built from this checkout, with administrators
# signed in through a mock OpenID Connect provider and authorized by a Bouncer
# stub. Nothing here reaches the internet or needs real credentials.
#
#   e2e/stack.sh up     build Clerk, start all three containers, wait until healthy
#   e2e/stack.sh logs   print every container's logs
#   e2e/stack.sh down   remove the containers and their data
#
# Every container shares the host network. The upstream issuer URL has to be
# the same for the browser, which is sent to it to sign in, and for Clerk,
# which discovers it and checks it against the ID token's iss claim. That also
# means ports 8080-8082 must be free, and Docker Desktop needs host networking
# enabled.
set -euo pipefail

e2e_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repo_root="$(dirname "$e2e_dir")"

oauth=clerk-e2e-oauth
bouncer=clerk-e2e-bouncer
clerk=clerk-e2e
containers=("$oauth" "$bouncer" "$clerk")

# The fixed admin identity: issued by the mock provider (stubs/oauth.json) and
# granted the admin role by the Bouncer stub.
admin_sub=e2e-admin
bouncer_key=bncr_e2e

logs() {
  for c in "${containers[@]}"; do
    echo "===== $c ====="
    docker logs "$c" 2>&1 || true
  done
}

down() {
  # -v also removes Clerk's anonymous /data and /keys volumes, so the next run
  # starts from an empty database.
  docker rm -fv "${containers[@]}" >/dev/null 2>&1 || true
}

wait_for() {
  local name=$1 url=$2
  for _ in $(seq 1 60); do
    if curl -fsS "$url" >/dev/null 2>&1; then
      echo "$name is ready"
      return 0
    fi
    sleep 2
  done
  echo "$name did not become ready at $url" >&2
  logs >&2
  exit 1
}

up() {
  down
  docker build -t clerk:e2e "$repo_root"

  docker run -d --name "$oauth" --network host \
    -e SERVER_PORT=8081 \
    -e JSON_CONFIG_PATH=/stub/oauth.json \
    -v "$e2e_dir/stubs:/stub:ro" \
    ghcr.io/navikt/mock-oauth2-server:6.0.2 >/dev/null

  docker run -d --name "$bouncer" --network host \
    -e PORT=8082 \
    -e BOUNCER_API_KEY="$bouncer_key" \
    -e BOUNCER_ADMIN_SUB="$admin_sub" \
    -v "$e2e_dir/stubs:/stub:ro" \
    node:22-alpine node /stub/bouncer.mjs >/dev/null

  # Clerk discovers the provider at startup and refuses to start without it.
  wait_for "mock provider" http://localhost:8081/isalive
  wait_for "bouncer stub" http://localhost:8082/health

  docker run -d --name "$clerk" --network host \
    -e ISSUER=http://localhost:8080 \
    -e GOOGLE_CLIENT_ID=clerk-e2e \
    -e GOOGLE_CLIENT_SECRET=clerk-e2e-secret \
    -e GOOGLE_ISSUER=http://localhost:8081/google \
    -e BOUNCER_URL=http://localhost:8082 \
    -e BOUNCER_API_KEY="$bouncer_key" \
    clerk:e2e >/dev/null

  wait_for clerk http://localhost:8080/health
}

case "${1:-}" in
  up) up ;;
  down) down ;;
  logs) logs ;;
  *)
    echo "usage: $0 up|down|logs" >&2
    exit 2
    ;;
esac
