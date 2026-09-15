# Starts the Mandate Desk live signer for one owner-approved Sepolia run.
# The Brickken sandbox API key is read from the clipboard after Enter and is
# passed to the signer on standard input, never as an argument, environment
# variable or file. The two test keystores are unlocked inside the signer
# process. Stop the signer with Ctrl+C when the run is finished.
#
# The launcher holds the key only between the clipboard read and the write to
# the signer's standard input. It drops its own copies right after that write,
# also when the write fails, before it waits for the signer to exit.
# Clearing a managed string variable does not wipe the bytes cryptographically;
# it releases the reference so the launcher keeps no live copy for the run.
param(
    [Parameter(Mandatory = $true)][string]$ApprovalSha256,
    [Parameter(Mandatory = $true)][string]$WalletDirectory,
    [string]$Data = '.local-demo'
)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$root = Split-Path -Parent $PSScriptRoot
if ($ApprovalSha256 -cnotmatch '^[a-f0-9]{64}$') { throw 'The approval hash must be 64 lowercase hexadecimal characters.' }
if ($Data -notmatch '^[A-Za-z0-9._-]+$') { throw 'The data directory must be a simple folder name inside the repository.' }
$approvalRelative = $Data + '/live/run-approval-' + $ApprovalSha256.Substring(0, 16) + '.json'
if (-not (Test-Path -LiteralPath (Join-Path $root $approvalRelative) -PathType Leaf)) {
    throw 'The run approval file was not found. Prepare the live plan in the owner workspace first.'
}
if (-not (Test-Path -LiteralPath $WalletDirectory -PathType Container)) { throw 'The wallet directory was not found.' }
$node = (Get-Command node -CommandType Application | Select-Object -First 1).Source
$signer = Join-Path $root 'tools\live-signer.mjs'

# Quotes one argument for the Windows command line without changing its bytes.
# Backslashes before an inner quote are doubled and the quote is escaped; a run of
# backslashes at the end is doubled too, so the closing quote stays a closing quote.
function Format-Argument([string]$value) {
    if ($value -notmatch '[\s"]') { return $value }
    $escaped = $value -replace '(\\*)"', '$1$1\"'
    $escaped = $escaped -replace '(\\+)$', '$1$1'
    return '"' + $escaped + '"'
}

Write-Host 'Mandate Desk live signer'
Write-Host ('Run approval: ' + $ApprovalSha256)
Write-Host 'Copy the Brickken sandbox API key to the clipboard. Do not paste it into this window.'
# Hidden input also protects an accidental paste into the Enter prompt.
$null = Read-Host 'Press Enter when the key is on the clipboard' -AsSecureString
$key = Get-Clipboard -Raw
if ([string]::IsNullOrWhiteSpace($key)) { throw 'The clipboard is empty.' }
$key = $key.Trim()
if ($key.Length -gt 4096 -or $key -match '[^\x21-\x7e]') { $key = $null; throw 'The clipboard does not contain a valid API key.' }
$payload = ConvertTo-Json -InputObject @{ apiKey = $key } -Compress
$key = $null
# The key is not left on the clipboard for other programs or a later paste.
try { Set-Clipboard -Value ' ' ; Write-Host 'The clipboard was cleared.' }
catch { Write-Host 'The clipboard could not be cleared. Copy something else over the key now.' }
Write-Host 'Unlocking the two test keystores. This takes a few seconds.'

# The signer is started as a child process with only its standard input
# redirected, so its output stays on this console. The payload is written once
# and the launcher's references are released in the same step, on success and
# on failure alike, before the signer serves any request.
$startInfo = [System.Diagnostics.ProcessStartInfo]::new()
$startInfo.FileName = $node
$startInfo.UseShellExecute = $false
$startInfo.RedirectStandardInput = $true
$arguments = @($signer, '--approval', $approvalRelative, '--approval-sha256', $ApprovalSha256, '--wallet-dir', $WalletDirectory, '--data', $Data)
$startInfo.Arguments = ($arguments | ForEach-Object { Format-Argument $_ }) -join ' '
$process = $null
try {
    $process = [System.Diagnostics.Process]::Start($startInfo)
    $process.StandardInput.Write($payload)
    $process.StandardInput.Close()
}
finally {
    $payload = $null
    $key = $null
    [System.GC]::Collect()
}
if ($null -eq $process) { throw 'The signer process could not be started.' }
$process.WaitForExit()
exit $process.ExitCode
