#Requires -Version 7.2
<#
.SYNOPSIS
    Self-service simulation and end-to-end verification script for the Sentinel
    USB VID_03EB -> MDE Full Isolation Playbook.

.DESCRIPTION
    Why a script is needed:
    1. `DeviceEvents` in Microsoft Sentinel / Log Analytics is a built-in system
       table and cannot be written to via the Custom Logs Ingestion API.
    2. Azure VMs do not have physical USB controllers, and MDE's kernel sensor
       only emits `PnpDeviceConnected` when a physical USB bus PDO enumerates or
       when Defender XDR raw `DeviceEvents` streaming is enabled.
    3. This script provides a safe, repeatable way to test the entire detection
       and isolation pipeline on demand:
       - Optionally registers a real `USB\VID_03EB&PID_2404` PnP device node on
         an Azure Windows VM via `az vm run-command invoke` (SetupAPI).
       - Auto-discovers (or accepts) an onboarded MDE machine ID (`MDEDeviceId`).
       - Temporarily injects a 1-row `SimulatedUsbEvent` (`PnpDeviceConnected`)
         into the Sentinel Analytics Rule KQL query (`union DeviceEvents, SimulatedUsbEvent`).
       - Polls for the newly created Sentinel Incident, automated Logic App run,
         MDE Action Center status (`Isolate` / `Full`), and Sentinel Incident
         comments.
       - Always restores the clean production `DeviceEvents` KQL query in a
         `finally` block so synthetic data never remains in the rule.
       - Optionally submits an `unisolate` request in MDE (`-UnisolateAfterTest`)
         once isolation is verified.

.EXAMPLE
    # Run an end-to-end simulated USB isolation test in your environment:
    .\Simulate-UsbTestEvent.ps1 `
        -SubscriptionId "<SUBSCRIPTION-ID>" `
        -ResourceGroupName "<RESOURCE-GROUP-NAME>" `
        -WorkspaceName "<SENTINEL-WORKSPACE-NAME>" `
        -LogicAppName "isolate-usb-03eb-dod" `
        -RuleId "05e12e72-b5b5-4350-afd8-fa3a3f54864c" `
        -MdeDeviceName "<MDE-HOSTNAME>" `
        -UnisolateAfterTest

.EXAMPLE
    # Also register the PnP devnode inside the guest VM via Run Command:
    .\Simulate-UsbTestEvent.ps1 `
        -SubscriptionId "<SUBSCRIPTION-ID>" `
        -ResourceGroupName "<RESOURCE-GROUP-NAME>" `
        -WorkspaceName "<SENTINEL-WORKSPACE-NAME>" `
        -LogicAppName "isolate-usb-03eb-dod" `
        -MdeDeviceName "<MDE-HOSTNAME>" `
        -VmResourceGroup "<VM-RESOURCE-GROUP>" `
        -VmName "<VM-NAME>" `
        -RegisterGuestPnpDevice
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [guid] $SubscriptionId,

    [Parameter(Mandatory)]
    [ValidateNotNullOrEmpty()]
    [string] $ResourceGroupName,

    [Parameter(Mandatory)]
    [ValidateNotNullOrEmpty()]
    [string] $WorkspaceName,

    [Parameter(Mandatory)]
    [ValidateNotNullOrEmpty()]
    [string] $LogicAppName,

    [Parameter()]
    [ValidateNotNullOrEmpty()]
    [string] $RuleId = '05e12e72-b5b5-4350-afd8-fa3a3f54864c',

    [Parameter()]
    [ValidateSet('Commercial', 'GCC', 'GCCHigh', 'DoD')]
    [string] $CloudEnvironment = 'Commercial',

    [Parameter()]
    [ValidatePattern('^[a-fA-F0-9]{40}$')]
    [string] $MdeDeviceId,

    [Parameter()]
    [string] $MdeDeviceName,

    [Parameter()]
    [string] $VmResourceGroup,

    [Parameter()]
    [string] $VmName,

    [Parameter()]
    [switch] $RegisterGuestPnpDevice,

    [Parameter()]
    [switch] $UnisolateAfterTest,

    [Parameter()]
    [int] $TimeoutMinutes = 8
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$cloudMap = @{
    Commercial = @{
        ArmEndpoint = 'https://management.azure.com'
        MdeEndpoint = 'https://api.securitycenter.microsoft.com'
    }
    GCC = @{
        ArmEndpoint = 'https://management.azure.com'
        MdeEndpoint = 'https://api-gcc.securitycenter.microsoft.us'
    }
    GCCHigh = @{
        ArmEndpoint = 'https://management.usgovcloudapi.net'
        MdeEndpoint = 'https://api-gov.securitycenter.microsoft.us'
    }
    DoD = @{
        ArmEndpoint = 'https://management.usgovcloudapi.net'
        MdeEndpoint = 'https://api-gov.securitycenter.microsoft.us'
    }
}

$armEndpoint = $cloudMap[$CloudEnvironment].ArmEndpoint
$mdeEndpoint = $cloudMap[$CloudEnvironment].MdeEndpoint
$subId       = $SubscriptionId.ToString()

az account set --subscription $subId
Write-Host "=== 1. Resolving Target MDE Endpoint ($CloudEnvironment) ===" -ForegroundColor Cyan
$mdeToken = az account get-access-token --resource $mdeEndpoint --query accessToken -o tsv 2>$null
if (-not $mdeToken -and $CloudEnvironment -eq 'GCC') {
    Write-Warning "Falling back to https://api.securitycenter.microsoft.com for commercial-backed tenant..."
    $mdeEndpoint = 'https://api.securitycenter.microsoft.com'
    $mdeToken = az account get-access-token --resource $mdeEndpoint --query accessToken -o tsv
}
$mdeHeaders = @{ Authorization = "Bearer $mdeToken"; 'Content-Type' = 'application/json' }

if (-not $MdeDeviceId) {
    $machines = (Invoke-RestMethod -Method GET -Uri "$mdeEndpoint/api/machines" -Headers $mdeHeaders).value
    $onboarded = @($machines | Where-Object { $_.onboardingStatus -eq 'Onboarded' })
    if ($onboarded.Count -eq 0) {
        throw "No Onboarded machines found in MDE ($mdeEndpoint)."
    }
    if ($MdeDeviceName) {
        $match = @($onboarded | Where-Object { $_.computerDnsName -ieq $MdeDeviceName })
        if ($match.Count -eq 0) {
            throw "No onboarded MDE machine matched computerDnsName '$MdeDeviceName'."
        }
        $targetMachine = $match[0]
    } else {
        $targetMachine = $onboarded | Sort-Object lastSeen -Descending | Select-Object -First 1
    }
    $MdeDeviceId   = $targetMachine.id
    $MdeDeviceName = $targetMachine.computerDnsName
} elseif (-not $MdeDeviceName) {
    $targetMachine = Invoke-RestMethod -Method GET -Uri "$mdeEndpoint/api/machines/$MdeDeviceId" -Headers $mdeHeaders
    $MdeDeviceName = $targetMachine.computerDnsName
}

Write-Host "Target MDE Machine : $MdeDeviceName" -ForegroundColor Green
Write-Host "Target MDEDeviceId : $MdeDeviceId" -ForegroundColor Green

# Check for any pending/in-progress machine actions before starting
$pendingActions = (Invoke-RestMethod -Method GET -Uri "$mdeEndpoint/api/machineactions?`$filter=machineId eq '$MdeDeviceId'" -Headers $mdeHeaders).value |
    Where-Object { $_.status -in @('Pending', 'InProgress') }
if ($pendingActions) {
    Write-Warning "Machine $MdeDeviceName currently has pending/in-progress MDE action(s): $(($pendingActions | ForEach-Object { "$($_.type):$($_.status) ($($_.id))" }) -join ', ')"
}

if ($RegisterGuestPnpDevice) {
    if (-not $VmResourceGroup -or -not $VmName) {
        throw "When using -RegisterGuestPnpDevice, provide both -VmResourceGroup and -VmName."
    }
    Write-Host "`n=== 2. Registering Simulated USB\VID_03EB&PID_2404 PnP Device on VM $VmName ===" -ForegroundColor Cyan
    $vmScript = @'
$code = @"
using System;
using System.Runtime.InteropServices;
public class PnpSim {
    [DllImport("setupapi.dll", SetLastError = true, CharSet = CharSet.Auto)]
    public static extern IntPtr SetupDiCreateDeviceInfoList(ref Guid ClassGuid, IntPtr hwndParent);
    [DllImport("setupapi.dll", SetLastError = true, CharSet = CharSet.Auto)]
    public static extern bool SetupDiCreateDeviceInfo(IntPtr DeviceInfoSet, string DeviceName, ref Guid ClassGuid, string DeviceDescription, IntPtr hwndParent, uint CreationFlags, out SP_DEVINFO_DATA DeviceInfoData);
    [DllImport("setupapi.dll", SetLastError = true, CharSet = CharSet.Auto)]
    public static extern bool SetupDiSetDeviceRegistryProperty(IntPtr DeviceInfoSet, ref SP_DEVINFO_DATA DeviceInfoData, uint Property, byte[] PropertyBuffer, uint PropertyBufferSize);
    [DllImport("setupapi.dll", SetLastError = true, CharSet = CharSet.Auto)]
    public static extern bool SetupDiCallClassInstaller(uint InstallFunction, IntPtr DeviceInfoSet, ref SP_DEVINFO_DATA DeviceInfoData);
    [DllImport("setupapi.dll", SetLastError = true)]
    public static extern bool SetupDiDestroyDeviceInfoList(IntPtr DeviceInfoSet);
    [StructLayout(LayoutKind.Sequential)]
    public struct SP_DEVINFO_DATA {
        public uint cbSize;
        public Guid ClassGuid;
        public uint DevInst;
        public IntPtr Reserved;
    }
    public static string RegisterUsb() {
        Guid usbClass = new Guid("36fc9e60-c465-11cf-8056-444553540000");
        IntPtr set = SetupDiCreateDeviceInfoList(ref usbClass, IntPtr.Zero);
        SP_DEVINFO_DATA data = new SP_DEVINFO_DATA();
        data.cbSize = (uint)Marshal.SizeOf(data);
        SetupDiCreateDeviceInfo(set, "USB\\VID_03EB&PID_2404\\SIM03EB01", ref usbClass, "Atmel USB Rubber Ducky Simulator (VID_03EB)", IntPtr.Zero, 0, out data);
        string hwId = "USB\\VID_03EB&PID_2404\0\0";
        byte[] bytes = System.Text.Encoding.Unicode.GetBytes(hwId);
        SetupDiSetDeviceRegistryProperty(set, ref data, 1, bytes, (uint)bytes.Length);
        SetupDiCallClassInstaller(0x19, set, ref data);
        SetupDiDestroyDeviceInfoList(set);
        return "Registered USB\\VID_03EB&PID_2404";
    }
}
"@
Add-Type -TypeDefinition $code
[PnpSim]::RegisterUsb()
Get-PnpDevice | Where-Object { $_.InstanceId -like '*VID_03EB*' } | Select-Object Status, Class, FriendlyName, InstanceId | Format-List
'@
    $tempScript = Join-Path ([System.IO.Path]::GetTempPath()) "sim-usb-$([guid]::NewGuid().ToString('N')).ps1"
    Set-Content -Path $tempScript -Value $vmScript -Encoding UTF8
    try {
        $vmOut = az vm run-command invoke --resource-group $VmResourceGroup --name $VmName --command-id RunPowerShellScript --scripts "@$tempScript" --query "value[0].message" -o tsv
        Write-Host $vmOut
    } finally {
        Remove-Item $tempScript -Force -ErrorAction SilentlyContinue
    }
}

$wsResourceId     = "/subscriptions/$subId/resourceGroups/$ResourceGroupName/providers/Microsoft.OperationalInsights/workspaces/$WorkspaceName"
$ruleUrl          = "${armEndpoint}${wsResourceId}/providers/Microsoft.SecurityInsights/alertRules/${RuleId}?api-version=2023-02-01"
$incidentsBaseUrl = "${armEndpoint}${wsResourceId}/providers/Microsoft.SecurityInsights/incidents?api-version=2024-03-01"
$runsUrl          = "${armEndpoint}/subscriptions/$subId/resourceGroups/$ResourceGroupName/providers/Microsoft.Logic/workflows/$LogicAppName/runs?api-version=2016-06-01"

Write-Host "`n=== 3. Snapshotting Analytics Rule & Injecting Simulated USB\VID_03EB Event ===" -ForegroundColor Cyan
$originalRule = az rest --method GET --url $ruleUrl | ConvertFrom-Json
$cleanProductionQuery = @"
DeviceEvents
| where ActionType == "PnpDeviceConnected"
| where coalesce(ingestion_time(), TimeGenerated) > ago(5m)
| extend UsbFields = parse_json(AdditionalFields)
| extend USBDeviceId = tostring(UsbFields.DeviceId),
         USBDescription = tostring(UsbFields.DeviceDescription),
         USBClassId = tostring(UsbFields.ClassId),
         USBClassName = tostring(UsbFields.ClassName)
| where USBDeviceId startswith @"USB\VID_03EB"
| where isnotempty(DeviceId)
| summarize arg_max(TimeGenerated, *) by DeviceId
| extend MDEDeviceId = DeviceId, DetectionSignature = "USB-VID-03EB-v1"
| project TimeGenerated, DeviceName, MDEDeviceId, USBDeviceId,
          USBDescription, USBClassId, USBClassName, DetectionSignature
"@

$simulatedQuery = @"
let SimulatedUsbEvent = print
    TimeGenerated = now() - 1m,
    ActionType = "PnpDeviceConnected",
    DeviceId = "$MdeDeviceId",
    DeviceName = "$MdeDeviceName",
    AdditionalFields = dynamic({
        "DeviceId": "USB\\VID_03EB&PID_2404\\9E2E01E9",
        "DeviceDescription": "Atmel USB Rubber Ducky Simulator (VID_03EB)",
        "ClassId": "{36fc9e60-c465-11cf-8056-444553540000}",
        "ClassName": "USB"
    });
union DeviceEvents, SimulatedUsbEvent
| where ActionType == "PnpDeviceConnected"
| extend UsbFields = parse_json(AdditionalFields)
| extend USBDeviceId = tostring(UsbFields.DeviceId),
         USBDescription = tostring(UsbFields.DeviceDescription),
         USBClassId = tostring(UsbFields.ClassId),
         USBClassName = tostring(UsbFields.ClassName)
| where USBDeviceId startswith @"USB\VID_03EB"
| where isnotempty(DeviceId)
| summarize arg_max(TimeGenerated, *) by DeviceId
| extend MDEDeviceId = DeviceId, DetectionSignature = "USB-VID-03EB-v1"
| project TimeGenerated, DeviceName, MDEDeviceId, USBDeviceId,
          USBDescription, USBClassId, USBClassName, DetectionSignature
"@

$existingRuns = @((az rest --method GET --url $runsUrl | ConvertFrom-Json).value)
$latestRunBefore = if ($existingRuns.Count -gt 0) { $existingRuns[0].name } else { "" }

try {
    $patchRule = $originalRule | ConvertTo-Json -Depth 15 | ConvertFrom-Json
    $patchRule.properties.PSObject.Properties.Remove('lastModifiedUtc')
    $patchRule.properties.query = $simulatedQuery
    $patchRule.properties.enabled = $true
    $patchRule | ConvertTo-Json -Depth 15 -Compress | az rest --method PUT --url $ruleUrl --headers "Content-Type=application/json" --body "@-" | Out-Null
    Write-Host "Injected simulated PnpDeviceConnected row into rule '$($originalRule.properties.displayName)'." -ForegroundColor Yellow

    Write-Host "`n=== 4. Waiting for Sentinel Incident & Logic App Playbook Execution ===" -ForegroundColor Cyan
    $deadline = (Get-Date).AddMinutes($TimeoutMinutes)
    $triggeredRun = $null
    while ((Get-Date) -lt $deadline) {
        Start-Sleep -Seconds 15
        $currentRuns = @((az rest --method GET --url $runsUrl | ConvertFrom-Json).value)
        if ($currentRuns.Count -gt 0 -and $currentRuns[0].name -ne $latestRunBefore) {
            $triggeredRun = $currentRuns[0]
            Write-Host "Playbook Run Detected: $($triggeredRun.name) | Status: $($triggeredRun.properties.status)" -ForegroundColor Green
            while ($triggeredRun.properties.status -in @('Running', 'Waiting')) {
                Start-Sleep -Seconds 10
                $triggeredRun = az rest --method GET --url "${armEndpoint}/subscriptions/$subId/resourceGroups/$ResourceGroupName/providers/Microsoft.Logic/workflows/$LogicAppName/runs/$($triggeredRun.name)?api-version=2016-06-01" | ConvertFrom-Json
                Write-Host "  Polling Run $($triggeredRun.name) -> $($triggeredRun.properties.status)..."
            }
            break
        }
        Write-Host "  Waiting for 5-minute Scheduled Analytics Rule evaluation..."
    }
} finally {
    Write-Host "`n=== 5. Restoring Clean Production KQL Query on Analytics Rule ===" -ForegroundColor Cyan
    $restoreRule = az rest --method GET --url $ruleUrl | ConvertFrom-Json
    $restoreRule.properties.PSObject.Properties.Remove('lastModifiedUtc')
    $restoreRule.properties.query = $cleanProductionQuery
    $restoreRule | ConvertTo-Json -Depth 15 -Compress | az rest --method PUT --url $ruleUrl --headers "Content-Type=application/json" --body "@-" | Out-Null
    Write-Host "Restored clean production DeviceEvents KQL query." -ForegroundColor Green
}

if (-not $triggeredRun) {
    throw "Timed out waiting for a new Logic App run within $TimeoutMinutes minutes."
}

Write-Host "`n=== 6. Verifying MDE Action Center & Sentinel Incident Results ===" -ForegroundColor Cyan
Write-Host "Logic App Run Name   : $($triggeredRun.name)"
Write-Host "Logic App Run Status : $($triggeredRun.properties.status)" -ForegroundColor $(if ($triggeredRun.properties.status -eq 'Succeeded') { 'Green' } else { 'Red' })

$mdeActions = (Invoke-RestMethod -Method GET -Uri "$mdeEndpoint/api/machineactions?`$filter=machineId eq '$MdeDeviceId'" -Headers $mdeHeaders).value |
    Sort-Object creationDateTimeUtc -Descending | Select-Object -First 3
foreach ($act in $mdeActions) {
    Write-Host "MDE Action           : $($act.id) | Type=$($act.type) | Scope=$($act.scope) | Status=$($act.status) | Created=$($act.creationDateTimeUtc)"
}

$incidents = (az rest --method GET --url $incidentsBaseUrl | ConvertFrom-Json).value |
    Sort-Object { $_.properties.createdTimeUtc } -Descending | Select-Object -First 1
if ($incidents) {
    Write-Host "Latest Incident      : #$($incidents.properties.incidentNumber) - $($incidents.properties.title) ($($incidents.name))"
    $commentsUrl = "${armEndpoint}$($incidents.id)/comments?api-version=2024-03-01"
    $comments = (az rest --method GET --url $commentsUrl | ConvertFrom-Json).value
    foreach ($c in $comments) {
        Write-Host "Incident Comment     : $($c.properties.message)" -ForegroundColor Green
    }
}

if ($UnisolateAfterTest) {
    Write-Host "`n=== 7. Releasing Test Endpoint from MDE Isolation (-UnisolateAfterTest) ===" -ForegroundColor Cyan
    $unisolateBody = @{ Comment = "Unisolating test machine after Simulate-UsbTestEvent.ps1 verification" } | ConvertTo-Json -Compress
    $unisolateResp = Invoke-RestMethod -Method POST -Uri "$mdeEndpoint/api/machines/$MdeDeviceId/unisolate" -Headers $mdeHeaders -Body $unisolateBody
    Write-Host "Submitted MDE Unisolate Action: $($unisolateResp.id) (Status: $($unisolateResp.status))" -ForegroundColor Yellow
}
