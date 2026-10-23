#Requires -Version 7.2
[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
foreach ($scriptName in @('Grant-PlaybookAccess.ps1', 'Deploy-SentinelUsbIsolation.ps1', 'Simulate-UsbTestEvent.ps1')) {
    $tokens = $null
    $parseErrors = $null
    [System.Management.Automation.Language.Parser]::ParseFile(
        (Join-Path $PSScriptRoot $scriptName),
        [ref] $tokens,
        [ref] $parseErrors
    ) | Out-Null
    if ($parseErrors.Count -gt 0) {
        throw ($parseErrors | ForEach-Object { $_.ToString() } | Out-String)
    }
    Write-Output "$scriptName PowerShell syntax: PASS"
}
& python -B -m unittest discover -s $PSScriptRoot -p test_package.py -v
if ($LASTEXITCODE -ne 0) { throw "Offline tests failed with exit code $LASTEXITCODE." }
