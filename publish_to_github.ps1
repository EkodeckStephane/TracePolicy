$ErrorActionPreference = 'Stop'
$repo = 'https://github.com/EkodeckStephane/TracePolicy.git'
$source = Split-Path -Parent $MyInvocation.MyCommand.Path
$tmp = Join-Path $env:TEMP ('TracePolicy-publish-' + [guid]::NewGuid().ToString())
Write-Host "Cloning $repo"
git clone $repo $tmp
Get-ChildItem -Force -LiteralPath $tmp | Where-Object { $_.Name -ne '.git' } | Remove-Item -Recurse -Force
Get-ChildItem -Force -LiteralPath $source | Where-Object { $_.Name -ne '.git' } | ForEach-Object {
    Copy-Item -LiteralPath $_.FullName -Destination $tmp -Recurse -Force
}
Set-Location $tmp
git add -A
if (-not (git diff --cached --quiet)) {
    git commit -m 'Publish complete TracePolicy reproducibility materials'
    git push origin main
} else {
    Write-Host 'No differences to publish.'
}
Write-Host 'Publication complete: https://github.com/EkodeckStephane/TracePolicy'
