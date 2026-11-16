# Downloads the pinned wireguard-nt 1.1 archive, checks both digests, and
# copies the amd64 DLL plus the license beside the test binaries.
# A mismatch stops the job. Nothing here is built from source.

$ErrorActionPreference = "Stop"
$archiveUrl = "https://download.wireguard.com/wireguard-nt/wireguard-nt-1.1.zip"
$archiveSha = "dceb30a9bc4be48cce0f74160fc88a585a2c2627366e8f846fc6658f9038dace"
$dllSha = "b1b85e072c45d81358be29d94c599dc76652f912be8c0f0a41e2d5d89a6461d3"
$root = if ($env:RUNNER_TEMP) { $env:RUNNER_TEMP } else { $env:TEMP }
$zip = Join-Path $root "wireguard-nt-1.1.zip"
Invoke-WebRequest -Uri $archiveUrl -OutFile $zip
$archiveHash = (Get-FileHash -Algorithm SHA256 $zip).Hash.ToLower()
if ($archiveHash -ne $archiveSha) {
    throw "wireguard-nt archive digest mismatch: $archiveHash"
}
$extract = Join-Path $root "wireguard-nt-extract"
if (Test-Path $extract) { Remove-Item -Recurse -Force $extract }
Expand-Archive -Path $zip -DestinationPath $extract
$dll = Join-Path $extract "wireguard-nt/bin/amd64/wireguard.dll"
$dllHash = (Get-FileHash -Algorithm SHA256 $dll).Hash.ToLower()
if ($dllHash -ne $dllSha) {
    throw "wireguard.dll digest mismatch: $dllHash"
}
$license = Join-Path $extract "wireguard-nt/LICENSE.txt"
foreach ($dest in @("target/debug", "target/debug/deps")) {
    New-Item -ItemType Directory -Force -Path $dest | Out-Null
    Copy-Item $dll (Join-Path $dest "wireguard.dll") -Force
    Set-Content -Path (Join-Path $dest "wireguard.dll.sha256") -Value $dllSha -NoNewline
    Copy-Item $license (Join-Path $dest "LICENSE.txt") -Force
}
Write-Output "wireguard-nt archive $archiveSha"
Write-Output "wireguard.dll $dllSha"
