#!/usr/bin/env bash
# Zero-downtime blue-green deploy (trial-update: "don't crash the site").
#
#   scripts/deploy-bluegreen.sh            # deploy the inactive color + switch
#   scripts/deploy-bluegreen.sh --status   # show active color + container health
#
# Contract:
#   1. The ACTIVE color keeps serving traffic the entire time.
#   2. The new (inactive) color is built + booted BESIDE it.
#   3. Health gates: /health on engine+firewall and /api on proxy must pass
#      before any traffic switches. A failed deploy leaves the old color
#      untouched — the site never goes down.
#   4. Switch = rewrite edge.conf + `nginx -s reload` (graceful — in-flight
#      requests finish on the old color).
#   5. Only after the switch does the old color stop.
set -euo pipefail
cd "$(dirname "$0")/.."

EDGE_PORT=8090
ACTIVE_FILE=.deploy-active
APP=deploy/bluegreen/app.yml
EDGE=deploy/bluegreen/edge.yml
ENV_FILE=deploy/bluegreen/app.env

other() { [ "$1" = blue ] && echo green || echo blue; }

active_color() { cat "$ACTIVE_FILE" 2>/dev/null || echo blue; }

health() { # color → 0 when all three services answer
  local c=$1 ok=0
  docker exec "dlf-$c-engine" python -c "import urllib.request;urllib.request.urlopen('http://localhost:8011/health',timeout=3)" >/dev/null 2>&1 && ok=$((ok+1))
  docker exec "dlf-$c-firewall" python -c "import urllib.request;urllib.request.urlopen('http://localhost:8020/health',timeout=3)" >/dev/null 2>&1 && ok=$((ok+1))
  docker exec "dlf-$c-proxy" node -e "fetch('http://localhost:4001/api/alerts/status',{signal:AbortSignal.timeout(3000)}).then(r=>process.exit(r.ok?0:1)).catch(()=>process.exit(1))" >/dev/null 2>&1 && ok=$((ok+1))
  [ "$ok" -eq 3 ]
}

write_edge_conf() { # color
  sed -e "s/dlf-blue-proxy/dlf-$1-proxy/g" \
      -e "s/dlf-blue-firewall/dlf-$1-firewall/g" \
      -e "s/color=blue/color=$1/" \
      -e "s|# Active color: blue|# Active color: $1|" \
      deploy/bluegreen/edge.conf.tmpl > deploy/bluegreen/edge.conf
}

if [ "${1:-}" = "--status" ]; then
  a=$(active_color); echo "active color : $a"
  for c in blue green; do
    if health "$c"; then s=healthy; else s="down/absent"; fi
    echo "  $c: $s"
  done
  curl -sf "http://localhost:$EDGE_PORT/edge-health" || echo "(edge not running)"
  exit 0
fi

# Shared edge network — created once, used by both colors and the edge.
docker network inspect dlf-edge >/dev/null 2>&1 || docker network create dlf-edge

A=$(active_color); T=$(other "$A")
echo "▸ active=$A  deploying=$T"

# Optional per-host env (LLM keys etc.) — an empty file is created so the
# compose env_file reference always resolves.
touch "$ENV_FILE"

echo "▸ building + starting $T (old color keeps serving)…"
COLOR=$T ENV_FILE=app.env docker compose -p "dlf-$T" -f "$APP" up -d --build

echo "▸ health gate on $T…"
for i in $(seq 1 40); do
  if health "$T"; then echo "  $T healthy ✓"; break; fi
  if [ "$i" -eq 40 ]; then
    echo "  ✗ $T failed its health gate — ABORTING. $A still serving; site untouched."
    docker compose -p "dlf-$T" -f "$APP" down >/dev/null 2>&1 || true
    exit 1
  fi
  sleep 5
done

echo "▸ switching edge traffic: $A → $T (graceful nginx reload)…"
write_edge_conf "$T"
docker compose -f "$EDGE" up -d
docker exec dlf-edge nginx -s reload
sleep 3
curl -sf "http://localhost:$EDGE_PORT/edge-health"

echo ""
echo "▸ draining + stopping old color $A…"
docker compose -p "dlf-$A" -f "$APP" down >/dev/null 2>&1 || true

echo "$T" > "$ACTIVE_FILE"
echo "✓ DEPLOYED — $T is live, zero downtime. (was $A)"
