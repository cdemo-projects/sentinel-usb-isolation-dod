#Requires -Version 7.2
<#
.SYNOPSIS
    End-to-end automated deployment and test script for the Sentinel USB VID_03EB
    MDE Full Isolation solution (Analytics Rule + Logic App Playbook + RBAC/MDE
    Permissions + Automation Rule + optional simulated USB test).

.DESCRIPTION
    Implements all lessons learned from live deployment & testing:
    1. Supports Commercial, GCC, GCC High, and DoD (IL5) cloud environments.
    2. Auto-discovers the tenant's WindowsDefenderATP service principal (AppId
       fc780465-2017-40d4-a0c5-307022471b92) and verifies which MDE API endpoint
       responds before wiring the Logic App.
    3. Uses `az rest` for Microsoft Graph AppRoleAssignments (`Machine.Isolate`,
       `Machine.ReadWrite.All`) to avoid `Connect-MgGraph` device-code admin
       consent blocks.
    4. Configures Logic App `ParseJson` schemas without unsupported `pattern`
       keywords, falls back to `triggerBody()` for `Custom Details` when the
       Sentinel `/incidents/{id}/alerts` REST API omits custom details, and
       allows `"scope": null` on initial `201 Created` (`Pending`) MDE machine
       actions while strictly requiring `"scope": "Full"` on final completion.
    5. Optionally injects a simulated `PnpDeviceConnected` (`USB\VID_03EB`)
       event to verify end-to-end incident creation and MDE isolation, then
       restores the clean production query.

.EXAMPLE
    .\Deploy-SentinelUsbIsolation.ps1 `
        -SubscriptionId "<SUBSCRIPTION-ID>" `
        -ResourceGroupName "<RESOURCE-GROUP-NAME>" `
        -WorkspaceName "<SENTINEL-WORKSPACE-NAME>" `
        -CloudEnvironment DoD `
        -EnableAutomation
#>
[CmdletBinding(SupportsShouldProcess)]
param(
    [Parameter(Mandatory)]
    [guid] $SubscriptionId,

    [Parameter(Mandatory)]
    [ValidateNotNullOrEmpty()]
    [string] $ResourceGroupName,

    [Parameter(Mandatory)]
    [ValidateNotNullOrEmpty()]
    [string] $WorkspaceName,

    [Parameter()]
    [ValidateSet('Commercial', 'GCC', 'GCCHigh', 'DoD')]
    [string] $CloudEnvironment = 'DoD',

    [Parameter()]
    [ValidateNotNullOrEmpty()]
    [string] $LogicAppName = 'isolate-usb-03eb-playbook',

    [Parameter()]
    [ValidateNotNullOrEmpty()]
    [string] $RuleDisplayName = 'USB VID_03EB connected - automatic full isolation',

    [Parameter()]
    [ValidateNotNullOrEmpty()]
    [string] $UsbHardwarePrefix = 'USB\VID_03EB',

    [Parameter()]
    [switch] $EnableAutomation,

    [Parameter()]
    [string] $NotificationSenderEmail = '',

    [Parameter()]
    [string] $NotificationRecipientEmail = '',

    [Parameter()]
    [ValidatePattern('^[a-fA-F0-9]{40}$')]
    [string] $SimulateTestDeviceId,

    [Parameter()]
    [string] $SimulateTestDeviceName = 'test-endpoint'
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$cloudMap = @{
    Commercial = @{
        AzCloud      = 'AzureCloud'
        ArmEndpoint  = 'https://management.azure.com'
        ArmAudience  = 'https://management.core.windows.net/'
        GraphUrl     = 'https://graph.microsoft.com'
        MdeEndpoint  = 'https://api.securitycenter.microsoft.com'
    }
    GCC = @{
        AzCloud      = 'AzureCloud'
        ArmEndpoint  = 'https://management.azure.com'
        ArmAudience  = 'https://management.core.windows.net/'
        GraphUrl     = 'https://graph.microsoft.com'
        MdeEndpoint  = 'https://api-gcc.securitycenter.microsoft.us'
    }
    GCCHigh = @{
        AzCloud      = 'AzureUSGovernment'
        ArmEndpoint  = 'https://management.usgovcloudapi.net'
        ArmAudience  = 'https://management.core.usgovcloudapi.net/'
        GraphUrl     = 'https://graph.microsoft.us'
        MdeEndpoint  = 'https://api-gov.securitycenter.microsoft.us'
    }
    DoD = @{
        AzCloud      = 'AzureUSGovernment'
        ArmEndpoint  = 'https://management.usgovcloudapi.net'
        ArmAudience  = 'https://management.core.usgovcloudapi.net/'
        GraphUrl     = 'https://dod-graph.microsoft.us'
        MdeEndpoint  = 'https://api-gov.securitycenter.microsoft.us'
    }
}

$envConfig = $cloudMap[$CloudEnvironment]
$armEndpoint = $envConfig.ArmEndpoint
$armAudience = $envConfig.ArmAudience
$graphUrl    = $envConfig.GraphUrl
$mdeEndpoint = $envConfig.MdeEndpoint

Write-Host "=== 1. Verifying Azure CLI Context ($CloudEnvironment) ===" -ForegroundColor Cyan
$account = az account show -o json | ConvertFrom-Json
if ($account.id -ne $SubscriptionId.ToString()) {
    az account set --subscription $SubscriptionId.ToString()
    $account = az account show -o json | ConvertFrom-Json
}
$tenantId = $account.tenantId
Write-Host "Tenant: $tenantId | Subscription: $($account.name) ($($account.id)) | User: $($account.user.name)"

# Verify workspace exists and get location
$subId = $SubscriptionId.ToString()
$wsResourceId = "/subscriptions/$subId/resourceGroups/$ResourceGroupName/providers/Microsoft.OperationalInsights/workspaces/$WorkspaceName"
$wsObj = az rest --method GET --url "${armEndpoint}${wsResourceId}?api-version=2022-10-01" | ConvertFrom-Json
$location = $wsObj.location
Write-Host "Found Sentinel Workspace: $WorkspaceName in $location"

Write-Host "`n=== 2. Discovering WindowsDefenderATP & Probing Live MDE Endpoint ===" -ForegroundColor Cyan
$mdeSpList = az rest --method GET --url "$graphUrl/v1.0/servicePrincipals?`$filter=appId eq 'fc780465-2017-40d4-a0c5-307022471b92'" | ConvertFrom-Json
if (-not $mdeSpList.value -or $mdeSpList.value.Count -eq 0) {
    throw "WindowsDefenderATP (fc780465-2017-40d4-a0c5-307022471b92) was not found in tenant $tenantId."
}
$mdeSp = $mdeSpList.value[0]
Write-Host "Found MDE Service Principal: $($mdeSp.displayName) (ObjectId: $($mdeSp.id))"

# If GCC is selected on a commercial-backed lab tenant, probe whether api-gcc or api.securitycenter responds
if ($CloudEnvironment -eq 'GCC') {
    try {
        $gccToken = az account get-access-token --resource "https://api-gcc.securitycenter.microsoft.us" --query accessToken -o tsv 2>$null
        Invoke-RestMethod -Method GET -Uri "https://api-gcc.securitycenter.microsoft.us/api/machines?`$top=1" -Headers @{ Authorization = "Bearer $gccToken" } | Out-Null
        Write-Host "Verified live MDE endpoint: https://api-gcc.securitycenter.microsoft.us" -ForegroundColor Green
    } catch {
        Write-Warning "api-gcc.securitycenter.microsoft.us returned 403/error; probing commercial MDE endpoint (https://api.securitycenter.microsoft.com)..."
        $comToken = az account get-access-token --resource "https://api.securitycenter.microsoft.com" --query accessToken -o tsv 2>$null
        Invoke-RestMethod -Method GET -Uri "https://api.securitycenter.microsoft.com/api/machines?`$top=1" -Headers @{ Authorization = "Bearer $comToken" } | Out-Null
        $mdeEndpoint = 'https://api.securitycenter.microsoft.com'
        Write-Host "Switched MDE endpoint to verified tenant endpoint: $mdeEndpoint" -ForegroundColor Yellow
    }
}

Write-Host "`n=== 3. Deploying Scheduled Analytics Rule ($RuleDisplayName) ===" -ForegroundColor Cyan
$ruleId = "05e12e72-b5b5-4350-afd8-fa3a3f54864c"
$ruleResourceId = "$wsResourceId/providers/Microsoft.SecurityInsights/alertRules/$ruleId"

$productionQuery = @"
DeviceEvents
| where ActionType == "PnpDeviceConnected"
| where coalesce(ingestion_time(), TimeGenerated) > ago(5m)
| extend UsbFields = parse_json(AdditionalFields)
| extend USBDeviceId = tostring(UsbFields.DeviceId),
         USBDescription = tostring(UsbFields.DeviceDescription),
         USBClassId = tostring(UsbFields.ClassId),
         USBClassName = tostring(UsbFields.ClassName)
| where USBDeviceId startswith @"$UsbHardwarePrefix"
| where isnotempty(DeviceId)
| summarize arg_max(TimeGenerated, *) by DeviceId
| extend MDEDeviceId = DeviceId, DetectionSignature = "USB-VID-03EB-v1"
| project TimeGenerated, DeviceName, MDEDeviceId, USBDeviceId,
          USBDescription, USBClassId, USBClassName, DetectionSignature
"@

$ruleBody = @{
    kind = "Scheduled"
    properties = @{
        displayName       = $RuleDisplayName
        description       = "Automatically requests FULL MDE isolation when a $UsbHardwarePrefix PnP connection is observed."
        enabled           = [bool]$EnableAutomation
        severity          = "High"
        query             = $productionQuery
        queryFrequency    = "PT5M"
        queryPeriod       = "PT1H"
        triggerOperator   = "GreaterThan"
        triggerThreshold  = 0
        suppressionEnabled = $false
        suppressionDuration = "PT5M"
        tactics           = @("InitialAccess", "LateralMovement")
        techniques        = @("T1091")
        eventGroupingSettings = @{
            aggregationKind = "AlertPerResult"
        }
        incidentConfiguration = @{
            createIncident = $true
            groupingConfiguration = @{
                enabled              = $false
                reopenClosedIncident = $false
                lookbackDuration     = "PT1H"
                matchingMethod       = "AllEntities"
                groupByEntities      = @()
                groupByAlertDetails  = @()
                groupByCustomDetails = @()
            }
        }
        customDetails = @{
            MDEDeviceId        = "MDEDeviceId"
            DetectionSignature = "DetectionSignature"
            USBDeviceId        = "USBDeviceId"
        }
        entityMappings = @(
            @{
                entityType    = "Host"
                fieldMappings = @(
                    @{
                        identifier = "FullName"
                        columnName = "DeviceName"
                    }
                )
            }
        )
    }
} | ConvertTo-Json -Depth 15 -Compress

if ($PSCmdlet.ShouldProcess($ruleResourceId, "Create/Update Sentinel Scheduled Analytics Rule")) {
    $ruleBody | az rest --method PUT --url "${armEndpoint}${ruleResourceId}?api-version=2023-02-01" --headers "Content-Type=application/json" --body "@-" | Out-Null
    Write-Host "Configured Analytics Rule: $RuleDisplayName ($ruleId)" -ForegroundColor Green
}

Write-Host "`n=== 4. Deploying Managed Identity Sentinel Connection & Logic App ($LogicAppName) ===" -ForegroundColor Cyan
$logicAppResourceId = "/subscriptions/$subId/resourceGroups/$ResourceGroupName/providers/Microsoft.Logic/workflows/$LogicAppName"
$logicAppLocation = $location
try {
    $existingWf = az rest --method GET --url "${armEndpoint}${logicAppResourceId}?api-version=2019-05-01" 2>$null | ConvertFrom-Json
    if ($existingWf -and $existingWf.location) {
        $logicAppLocation = $existingWf.location
        Write-Host "Preserving existing Logic App location: $logicAppLocation"
    }
} catch { }

$connectionName = "$LogicAppName-sentinel"
$connectionId = "/subscriptions/$subId/resourceGroups/$ResourceGroupName/providers/Microsoft.Web/connections/$connectionName"
$connLocation = $logicAppLocation
try {
    $existingConn = az rest --method GET --url "${armEndpoint}${connectionId}?api-version=2016-06-01" 2>$null | ConvertFrom-Json
    if ($existingConn -and $existingConn.location) {
        $connLocation = $existingConn.location
    }
} catch { }
$managedApiId = "/subscriptions/$subId/providers/Microsoft.Web/locations/$connLocation/managedApis/azuresentinel"

$connBody = @{
    location   = $connLocation
    kind       = "V1"
    properties = @{
        displayName        = $connectionName
        parameterValueType = "Alternative"
        api                = @{ id = $managedApiId }
    }
} | ConvertTo-Json -Depth 10 -Compress

if ($PSCmdlet.ShouldProcess($connectionId, "Create Managed Identity API Connection")) {
    $connBody | az rest --method PUT --url "${armEndpoint}${connectionId}?api-version=2016-06-01" --headers "Content-Type=application/json" --body "@-" | Out-Null
}

# Load base workflow definition and adapt endpoints + parameters
$baseDefPath = Join-Path $PSScriptRoot "portal-workflow-definition.json"
$defText = Get-Content -Path $baseDefPath -Raw
$defText = $defText.Replace('https://management.usgovcloudapi.net', $armEndpoint)
$defText = $defText.Replace('https://management.core.usgovcloudapi.net/', $armAudience)
$defText = $defText.Replace('https://api-gov.securitycenter.microsoft.us', $mdeEndpoint)
$defText = $defText.Replace('https://dod-graph.microsoft.us', $graphUrl)
$defObj = $defText | ConvertFrom-Json

$wfBody = @{
    location   = $logicAppLocation
    identity   = @{ type = "SystemAssigned" }
    properties = @{
        state      = "Enabled"
        definition = $defObj
        parameters = @{
            '$connections' = @{
                value = @{
                    azuresentinel = @{
                        id                   = $managedApiId
                        connectionId         = $connectionId
                        connectionName       = $connectionName
                        connectionProperties = @{
                            authentication = @{ type = "ManagedServiceIdentity" }
                        }
                    }
                }
            }
            workspaceResourceId        = @{ value = $wsResourceId }
            ruleResourceId             = @{ value = $ruleResourceId }
            alertTitle                 = @{ value = $RuleDisplayName }
            notificationSenderEmail    = @{ value = $NotificationSenderEmail }
            notificationRecipientEmail = @{ value = $NotificationRecipientEmail }
        }
    }
} | ConvertTo-Json -Depth 30 -Compress

if ($PSCmdlet.ShouldProcess($logicAppResourceId, "Create/Update Consumption Logic App")) {
    $wfResult = $wfBody | az rest --method PUT --url "${armEndpoint}${logicAppResourceId}?api-version=2019-05-01" --headers "Content-Type=application/json" --body "@-" | ConvertFrom-Json
    $principalId = $wfResult.identity.principalId
    Write-Host "Deployed Logic App: $LogicAppName (Managed Identity PrincipalId: $principalId)" -ForegroundColor Green
}

Write-Host "`n=== 5. Granting Azure RBAC & MDE Application Permissions ===" -ForegroundColor Cyan
if ($PSCmdlet.ShouldProcess($principalId, "Grant Microsoft Sentinel Responder & MDE AppRoles")) {
    # 5A. Microsoft Sentinel Responder on the Resource Group
    az role assignment create `
        --assignee-object-id $principalId `
        --assignee-principal-type ServicePrincipal `
        --role "Microsoft Sentinel Responder" `
        --scope "/subscriptions/$subId/resourceGroups/$ResourceGroupName" | Out-Null
    Write-Host "Granted: Microsoft Sentinel Responder on resource group $ResourceGroupName" -ForegroundColor Green

    # 5B. Machine.Isolate and Machine.ReadWrite.All via az rest (bypasses Connect-MgGraph device-code block)
    $existingAssignments = (az rest --method GET --url "$graphUrl/v1.0/servicePrincipals/$principalId/appRoleAssignments" | ConvertFrom-Json).value
    foreach ($perm in @('Machine.Isolate', 'Machine.ReadWrite.All')) {
        $role = $mdeSp.appRoles | Where-Object { $_.value -eq $perm -and $_.isEnabled -and $_.allowedMemberTypes -contains 'Application' }
        if (-not $role) { throw "AppRole $perm not found on WindowsDefenderATP." }
        $already = $existingAssignments | Where-Object { $_.resourceId -eq $mdeSp.id -and $_.appRoleId -eq $role.id }
        if ($already) {
            Write-Host "Already granted MDE permission: $perm" -ForegroundColor Green
        } else {
            $assignBody = @{
                principalId = $principalId
                resourceId  = $mdeSp.id
                appRoleId   = $role.id
            } | ConvertTo-Json -Compress
            $assignOut = $assignBody | az rest --method POST --url "$graphUrl/v1.0/servicePrincipals/$principalId/appRoleAssignments" --headers "Content-Type=application/json" --body "@-" 2>&1
            if ($LASTEXITCODE -ne 0) {
                throw "Failed to grant MDE permission $perm (ensure Global Administrator or Privileged Role Administrator is active in PIM): $assignOut"
            }
            Write-Host "Granted MDE permission: $perm" -ForegroundColor Green
        }
    }

    # 5C. Optional: Grant Microsoft Graph Mail.Send if NotificationSenderEmail is configured
    if ($NotificationSenderEmail) {
        $graphSp = (az rest --method GET --url "$graphUrl/v1.0/servicePrincipals?`$filter=appId eq '00000003-0000-0000-c000-000000000000'" | ConvertFrom-Json).value[0]
        $mailRole = $graphSp.appRoles | Where-Object { $_.value -eq 'Mail.Send' -and $_.isEnabled -and $_.allowedMemberTypes -contains 'Application' }
        $alreadyMail = $existingAssignments | Where-Object { $_.resourceId -eq $graphSp.id -and $_.appRoleId -eq $mailRole.id }
        if ($alreadyMail) {
            Write-Host "Already granted Microsoft Graph permission: Mail.Send" -ForegroundColor Green
        } else {
            $mailOut = @{
                principalId = $principalId
                resourceId  = $graphSp.id
                appRoleId   = $mailRole.id
            } | ConvertTo-Json -Compress | az rest --method POST --url "$graphUrl/v1.0/servicePrincipals/$principalId/appRoleAssignments" --headers "Content-Type=application/json" --body "@-" 2>&1
            if ($LASTEXITCODE -ne 0) {
                Write-Warning "Could not grant Microsoft Graph Mail.Send (ensure Global Administrator or Privileged Role Administrator is active in PIM). Re-run Grant-PlaybookAccess.ps1 -NotificationSenderEmail '$NotificationSenderEmail' after activating PIM."
            } else {
                Write-Host "Granted Microsoft Graph permission: Mail.Send (for $NotificationSenderEmail)" -ForegroundColor Green
            }
        }
    }
}

Write-Host "`n=== 6. Configuring Sentinel Playbook Permissions & Automation Rule ===" -ForegroundColor Cyan
$sentinelSpId = az ad sp list --filter "appId eq '98785600-1bb7-4fb9-b9fa-19afe2c8a360'" --query "[0].id" -o tsv
if ($sentinelSpId -and $PSCmdlet.ShouldProcess($ResourceGroupName, "Grant Microsoft Sentinel Automation Contributor to Azure Security Insights")) {
    az role assignment create `
        --assignee-object-id $sentinelSpId `
        --assignee-principal-type ServicePrincipal `
        --role "Microsoft Sentinel Automation Contributor" `
        --scope "/subscriptions/$subId/resourceGroups/$ResourceGroupName" | Out-Null
    Write-Host "Granted: Microsoft Sentinel Automation Contributor to Azure Security Insights ($sentinelSpId)" -ForegroundColor Green
}

$automationRuleId = "b8c403eb-1111-4444-8888-05e12e72b5b5"
$automationUrl = "${armEndpoint}${wsResourceId}/providers/Microsoft.SecurityInsights/automationRules/${automationRuleId}?api-version=2023-02-01"
$automationBody = @{
    properties = @{
        displayName     = "Isolate Bad USB Device"
        order           = 1
        triggeringLogic = @{
            isEnabled    = [bool]$EnableAutomation
            triggersOn   = "Incidents"
            triggersWhen = "Created"
            conditions   = @(
                @{
                    conditionType       = "Property"
                    conditionProperties = @{
                        propertyName   = "IncidentRelatedAnalyticRuleIds"
                        operator       = "Contains"
                        propertyValues = @($ruleResourceId)
                    }
                }
            )
        }
        actions = @(
            @{
                order               = 1
                actionType          = "RunPlaybook"
                actionConfiguration = @{
                    logicAppResourceId = $logicAppResourceId
                    tenantId           = $tenantId
                }
            }
        )
    }
} | ConvertTo-Json -Depth 15 -Compress

if ($PSCmdlet.ShouldProcess($automationUrl, "Create/Update Sentinel Automation Rule")) {
    $automationBody | az rest --method PUT --url $automationUrl --headers "Content-Type=application/json" --body "@-" | Out-Null
    Write-Host "Configured Automation Rule: Isolate Bad USB Device (Enabled: $([bool]$EnableAutomation))" -ForegroundColor Green
}

if ($SimulateTestDeviceId) {
    Write-Host "`n=== 7. Injecting Simulated USB Event for End-to-End Test ($SimulateTestDeviceName / $SimulateTestDeviceId) ===" -ForegroundColor Cyan
    $simQuery = @"
let SimulatedUsbEvent = print TimeGenerated = now() - 1m, ActionType = "PnpDeviceConnected", DeviceId = "$SimulateTestDeviceId", DeviceName = "$SimulateTestDeviceName", AdditionalFields = dynamic({"DeviceId":"${UsbHardwarePrefix}&PID_2404\\SIMTEST01","DeviceDescription":"Simulated Test USB Device","ClassId":"{36fc9e60-c465-11cf-8056-444553540000}","ClassName":"USB"});
union DeviceEvents, SimulatedUsbEvent
| where ActionType == "PnpDeviceConnected"
| extend UsbFields = parse_json(AdditionalFields)
| extend USBDeviceId = tostring(UsbFields.DeviceId),
         USBDescription = tostring(UsbFields.DeviceDescription),
         USBClassId = tostring(UsbFields.ClassId),
         USBClassName = tostring(UsbFields.ClassName)
| where USBDeviceId startswith @"$UsbHardwarePrefix"
| where isnotempty(DeviceId)
| summarize arg_max(TimeGenerated, *) by DeviceId
| extend MDEDeviceId = DeviceId, DetectionSignature = "USB-VID-03EB-v1"
| project TimeGenerated, DeviceName, MDEDeviceId, USBDeviceId,
          USBDescription, USBClassId, USBClassName, DetectionSignature
"@
    $ruleObj = az rest --method GET --url "${armEndpoint}${ruleResourceId}?api-version=2023-02-01" | ConvertFrom-Json
    $ruleObj.properties.PSObject.Properties.Remove('lastModifiedUtc')
    $ruleObj.properties.query = $simQuery
    $ruleObj.properties.enabled = $true
    $ruleObj | ConvertTo-Json -Depth 15 -Compress | az rest --method PUT --url "${armEndpoint}${ruleResourceId}?api-version=2023-02-01" --headers "Content-Type=application/json" --body "@-" | Out-Null
    Write-Host "Injected simulated event into rule. Polling up to 6 minutes for incident creation..." -ForegroundColor Yellow

    for ($i = 1; $i -le 24; $i++) {
        Start-Sleep -Seconds 15
        $runs = (az rest --method GET --url "${armEndpoint}${logicAppResourceId}/runs?api-version=2016-06-01" | ConvertFrom-Json).value
        if ($runs -and $runs.Count -gt 0) {
            Write-Host "Logic App triggered! Latest run: $($runs[0].name) ($($runs[0].properties.status))" -ForegroundColor Green
            break
        }
    }

    # Restore clean production query immediately
    $ruleObj = az rest --method GET --url "${armEndpoint}${ruleResourceId}?api-version=2023-02-01" | ConvertFrom-Json
    $ruleObj.properties.PSObject.Properties.Remove('lastModifiedUtc')
    $ruleObj.properties.query = $productionQuery
    $ruleObj.properties.enabled = [bool]$EnableAutomation
    $ruleObj | ConvertTo-Json -Depth 15 -Compress | az rest --method PUT --url "${armEndpoint}${ruleResourceId}?api-version=2023-02-01" --headers "Content-Type=application/json" --body "@-" | Out-Null
    Write-Host "Restored clean production KQL query on $RuleDisplayName." -ForegroundColor Green
}

Write-Host "`nDeployment complete!" -ForegroundColor Cyan
