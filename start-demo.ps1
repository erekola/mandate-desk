[CmdletBinding()]
param(
    [ValidateRange(1024,65535)][int]$Port = 4327,
    [string]$Data = '.local-demo',
    [switch]$ValidateOnly
)
$ErrorActionPreference = 'Stop'
$mandateRoot = [System.IO.Path]::GetFullPath($PSScriptRoot)
$mandateNode = (Get-Command node -CommandType Application -ErrorAction Stop | Select-Object -First 1).Source
$mandateMajor = & $mandateNode -p 'process.versions.node.split(".")[0]'
if ($LASTEXITCODE -ne 0 -or [int]$mandateMajor -lt 24) { throw 'Node.js 24 or later is required.' }
foreach ($mandateFile in @('src/server.mjs','src/mcp.mjs','public/index.html','public/copy.json')) {
    if (-not (Test-Path -LiteralPath (Join-Path $mandateRoot $mandateFile) -PathType Leaf)) { throw ('Missing package file: ' + $mandateFile) }
}
$mandateData = [System.IO.Path]::GetFullPath((Join-Path $mandateRoot $Data))
if (-not $mandateData.StartsWith($mandateRoot + [System.IO.Path]::DirectorySeparatorChar, [StringComparison]::OrdinalIgnoreCase)) { throw 'Demo storage must be inside this package.' }
if ($mandateData -eq (Join-Path $mandateRoot 'data')) { throw 'Use a separate demo data directory.' }
# The application's bounded-path check rejects linked paths before any write.
$mandateStoreUri = ([System.Uri]::new((Join-Path $mandateRoot 'src/store.mjs'))).AbsoluteUri
& $mandateNode --input-type=module -e 'const {boundedPath}=await import(process.argv[1]); boundedPath(process.argv[2]);' $mandateStoreUri $mandateData
if ($LASTEXITCODE -ne 0) { throw 'Demo data path validation failed.' }
foreach ($mandateFile in @('src/server.mjs','src/mcp.mjs')) {
    & $mandateNode --check (Join-Path $mandateRoot $mandateFile)
    if ($LASTEXITCODE -ne 0) { throw ('Syntax check failed: ' + $mandateFile) }
}
if ($ValidateOnly) { Write-Output 'PASS: Node runtime, package files, syntax and isolated data path verified.'; return }
$mandateUrl = 'http://127.0.0.1:' + $Port
$mandateHealth = $null
try { $mandateHealth = Invoke-RestMethod -Uri ($mandateUrl + '/api/health') -TimeoutSec 2 } catch { }
if ($mandateHealth) {
    if ($mandateHealth.app -ne 'mandate-desk' -or $mandateHealth.root -ne $mandateRoot -or $mandateHealth.dataDirectory -ne $mandateData) { throw 'This port belongs to another app or demo instance. Existing servers were preserved.' }
    Write-Output ('Mandate Desk is ready: ' + $mandateUrl)
    Write-Output ('Data: ' + $mandateData)
    return
}
$mandateProbe = [System.Net.Sockets.TcpListener]::new([System.Net.IPAddress]::Loopback,$Port)
try { $mandateProbe.Start() } catch { throw 'The loopback port is occupied. Existing servers were preserved.' } finally { $mandateProbe.Stop() }
New-Item -ItemType Directory -Path $mandateData -Force | Out-Null
$mandateStamp = [DateTime]::UtcNow.ToString('yyyyMMdd-HHmmss') + '-' + [Guid]::NewGuid().ToString('N')
$mandateArguments = '"' + (Join-Path $mandateRoot 'src/server.mjs') + '" --port ' + $Port + ' --data "' + $mandateData + '"'
$mandateProcess = Start-Process -FilePath $mandateNode -ArgumentList $mandateArguments -WorkingDirectory $mandateRoot -WindowStyle Hidden -RedirectStandardOutput (Join-Path $mandateData ($mandateStamp + '.log')) -RedirectStandardError (Join-Path $mandateData ($mandateStamp + '.error.log')) -PassThru
$mandateReady = $false
for ($mandateAttempt=0; $mandateAttempt -lt 30; $mandateAttempt++) {
    Start-Sleep -Milliseconds 200
    try {
        $mandateHealth = Invoke-RestMethod -Uri ($mandateUrl + '/api/health') -TimeoutSec 2
        if ($mandateHealth.app -eq 'mandate-desk' -and $mandateHealth.pid -eq $mandateProcess.Id -and $mandateHealth.root -eq $mandateRoot -and $mandateHealth.dataDirectory -eq $mandateData) { $mandateReady=$true; break }
    } catch { }
    if ($mandateProcess.HasExited) { break }
}
if (-not $mandateReady) { throw 'The new demo did not become ready. Inspect the new error log in its data directory. No other application was stopped.' }
Write-Output ('Mandate Desk is ready: ' + $mandateUrl)
Write-Output ('Data: ' + $mandateData)
Write-Output 'Simulation uses synthetic MDT. Sepolia preparation is separate and cannot sign or broadcast.'
