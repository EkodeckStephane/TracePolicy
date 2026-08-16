#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
EXT="$ROOT/.external"
REPO="$EXT/wazuh-docker"
mkdir -p "$EXT"
if [ ! -d "$REPO/.git" ]; then
  git clone --depth 1 --branch v4.14.7 https://github.com/wazuh/wazuh-docker.git "$REPO"
else
  git -C "$REPO" fetch --tags
  git -C "$REPO" checkout v4.14.7
fi
cd "$REPO/single-node"
# Official v4.14.7 single-node procedure.
docker compose -f generate-indexer-certs.yml run --rm generator
docker compose up -d
echo "Waiting for Wazuh manager / analysisd ..."
for i in $(seq 1 120); do
  CID="$(docker compose ps -q wazuh.manager 2>/dev/null || true)"
  if [ -n "$CID" ]; then
    STATUS="$(docker exec "$CID" /var/ossec/bin/wazuh-control status 2>/dev/null || true)"
    if echo "$STATUS" | grep -q "wazuh-analysisd is running"; then
      echo "WAZUH_MANAGER_ID=$CID"
      echo "$CID" > "$ROOT/results/logs/wazuh_manager_container_v2.txt"
      exit 0
    fi
  fi
  sleep 5
done
docker compose ps
docker compose logs --tail=200 wazuh.manager || true
echo "Wazuh analysisd did not become ready." >&2
exit 3
