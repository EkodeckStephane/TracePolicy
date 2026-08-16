$ErrorActionPreference = "Stop"
$Root = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
$Ext = Join-Path $Root ".external"
$Repo = Join-Path $Ext "wazuh-docker"
New-Item -ItemType Directory -Force -Path $Ext | Out-Null
if (-not (Test-Path (Join-Path $Repo ".git"))) {
    git clone --depth 1 --branch v4.14.7 https://github.com/wazuh/wazuh-docker.git $Repo
} else {
    git -C $Repo fetch --tags
    git -C $Repo checkout v4.14.7
}
Push-Location (Join-Path $Repo "single-node")
try {
    docker compose -f generate-indexer-certs.yml run --rm generator
    docker compose up -d
    for ($i=0; $i -lt 120; $i++) {
        $cid = (docker compose ps -q wazuh.manager 2>$null)
        if ($cid) {
            $status = (docker exec $cid /var/ossec/bin/wazuh-control status 2>$null | Out-String)
            if ($status -match "wazuh-analysisd is running") {
                New-Item -ItemType Directory -Force -Path (Join-Path $Root "results/logs") | Out-Null
                Set-Content -Path (Join-Path $Root "results/logs/wazuh_manager_container_v2.txt") -Value $cid
                Write-Host "WAZUH_MANAGER_ID=$cid"
                exit 0
            }
        }
        Start-Sleep -Seconds 5
    }
    docker compose ps
    docker compose logs --tail=200 wazuh.manager
    throw "Wazuh analysisd did not become ready."
} finally {
    Pop-Location
}
