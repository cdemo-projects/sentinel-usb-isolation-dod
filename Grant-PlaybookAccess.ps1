#Requires -Version 7.2
#Requires -Modules Az.Accounts, Az.Resources, Microsoft.Graph.Authentication, Microsoft.Graph.Applications

[CmdletBinding(SupportsShouldProcess)]
param(
    [Parameter(Mandatory)]
    [guid] $TenantId,

    [Parameter(Mandatory)]
    [ValidatePattern('^/subscriptions/[0-9a-fA-F-]{36}/resourceGroups/[^/]+/providers/Microsoft\.Logic/workflows/[^/]+$')]
    [string] $LogicAppResourceId,

    [Parameter(Mandatory)]
    [ValidatePattern('^/subscriptions/[0-9a-fA-F-]{36}/resourceGroups/[^/]+/providers/Microsoft\.OperationalInsights/workspaces/[^/]+$')]
    [string] $WorkspaceResourceId,

    [Parameter(Mandatory)]
    [guid] $MdeResourceServicePrincipalId,

    [Parameter()]
    [switch] $GrantGraphMailSend
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
Disable-AzContextAutosave -Scope Process | Out-Null

$subscriptionId = $LogicAppResourceId.Split('/')[2]
$workspaceSubscriptionId = $WorkspaceResourceId.Split('/')[2]
$playbookResourceGroup = $LogicAppResourceId.Split('/')[4]
if ($subscriptionId -ne $workspaceSubscriptionId -or
    $playbookResourceGroup -ne $WorkspaceResourceId.Split('/')[4]) {
    throw 'This package requires the Logic App and existing workspace in the same subscription and resource group.'
}

Connect-AzAccount -Environment AzureUSGovernment -Tenant $TenantId.ToString() `
    -Subscription $subscriptionId -Scope Process | Out-Null
$context = Get-AzContext
if ($context.Environment.Name -ne 'AzureUSGovernment' -or $context.Tenant.Id -ne $TenantId.ToString()) {
    throw 'Expected the specified tenant in AzureUSGovernment.'
}
$response = Invoke-AzRestMethod -Method GET -Path "${LogicAppResourceId}?api-version=2019-05-01"
if ($response.StatusCode -ne 200) { throw "Logic App lookup failed: HTTP $($response.StatusCode)." }
$workflow = $response.Content | ConvertFrom-Json -AsHashtable
if ($workflow.identity.type -ne 'SystemAssigned' -or
    -not $workflow.identity.principalId -or
    $workflow.identity.tenantId -ne $TenantId.ToString()) {
    throw 'Expected a system-assigned managed identity in the specified tenant.'
}
$principalId = [string] $workflow.identity.principalId

Connect-MgGraph -Environment USGovDoD -TenantId $TenantId.ToString() -ContextScope Process `
    -Scopes 'Application.Read.All', 'AppRoleAssignment.ReadWrite.All' -NoWelcome
$graphContext = Get-MgContext
if ($graphContext.Environment -ne 'USGovDoD' -or $graphContext.TenantId -ne $TenantId.ToString()) {
    throw 'Expected Microsoft Graph USGovDoD in the specified tenant.'
}
$identity = Get-MgServicePrincipal -ServicePrincipalId $principalId -Property Id,ServicePrincipalType
if ($identity.ServicePrincipalType -ne 'ManagedIdentity') {
    throw 'The Logic App principal is not a managed identity.'
}
$mde = Get-MgServicePrincipal -ServicePrincipalId $MdeResourceServicePrincipalId.ToString() `
    -Property Id,DisplayName,ServicePrincipalNames,AppRoles
$audiences = @($mde.ServicePrincipalNames | ForEach-Object { $_.TrimEnd('/') })
if ($audiences -notcontains 'https://api-gov.securitycenter.microsoft.us') {
    throw 'The specified API service principal does not advertise the documented government MDE audience. Stop and verify tenant API registration with Microsoft; do not substitute a commercial audience.'
}
$assignments = @(Get-MgServicePrincipalAppRoleAssignment -ServicePrincipalId $principalId -All)
foreach ($permission in @('Machine.Isolate', 'Machine.ReadWrite.All')) {
    $roles = @($mde.AppRoles | Where-Object {
        $_.Value -eq $permission -and $_.IsEnabled -and $_.AllowedMemberTypes -contains 'Application'
    })
    if ($roles.Count -ne 1) { throw "Expected exactly one enabled application role: $permission." }
    $existing = @($assignments | Where-Object {
        $_.ResourceId -eq $mde.Id -and $_.AppRoleId -eq $roles[0].Id
    })
    if ($existing.Count -eq 0 -and $PSCmdlet.ShouldProcess($principalId, "Grant MDE $permission")) {
        New-MgServicePrincipalAppRoleAssignment -ServicePrincipalId $principalId -BodyParameter @{
            principalId = $principalId
            resourceId = $mde.Id
            appRoleId = $roles[0].Id
        } | Out-Null
        $verified = @(Get-MgServicePrincipalAppRoleAssignment -ServicePrincipalId $principalId -All |
            Where-Object { $_.ResourceId -eq $mde.Id -and $_.AppRoleId -eq $roles[0].Id })
        if ($verified.Count -ne 1) { throw "Grant not verified: $permission. Allow propagation and rerun." }
        Write-Output "Verified MDE application permission: $permission."
    }
    elseif ($existing.Count -gt 0) {
        Write-Output "MDE application permission already exists: $permission."
    }
}

if ($GrantGraphMailSend) {
    $graphSp = @(Get-MgServicePrincipal -Filter "appId eq '00000003-0000-0000-c000-000000000000'" -Property Id,AppRoles)[0]
    $mailRoles = @($graphSp.AppRoles | Where-Object {
        $_.Value -eq 'Mail.Send' -and $_.IsEnabled -and $_.AllowedMemberTypes -contains 'Application'
    })
    if ($mailRoles.Count -ne 1) { throw 'Expected exactly one enabled Microsoft Graph application role: Mail.Send.' }
    $existingMail = @($assignments | Where-Object {
        $_.ResourceId -eq $graphSp.Id -and $_.AppRoleId -eq $mailRoles[0].Id
    })
    if ($existingMail.Count -eq 0 -and $PSCmdlet.ShouldProcess($principalId, 'Grant Microsoft Graph Mail.Send')) {
        New-MgServicePrincipalAppRoleAssignment -ServicePrincipalId $principalId -BodyParameter @{
            principalId = $principalId
            resourceId  = $graphSp.Id
            appRoleId   = $mailRoles[0].Id
        } | Out-Null
        Write-Output 'Verified Microsoft Graph application permission: Mail.Send.'
    }
    elseif ($existingMail.Count -gt 0) {
        Write-Output 'Microsoft Graph application permission already exists: Mail.Send.'
    }
}

$existingRbac = @(Get-AzRoleAssignment -ObjectId $principalId -Scope $WorkspaceResourceId |
    Where-Object { $_.Scope -eq $WorkspaceResourceId -and $_.RoleDefinitionName -eq 'Microsoft Sentinel Responder' })
if ($existingRbac.Count -eq 0 -and
    $PSCmdlet.ShouldProcess($WorkspaceResourceId, "Grant Microsoft Sentinel Responder to $principalId")) {
    New-AzRoleAssignment -ObjectId $principalId -RoleDefinitionName 'Microsoft Sentinel Responder' `
        -Scope $WorkspaceResourceId | Out-Null
    $verifiedRbac = @(Get-AzRoleAssignment -ObjectId $principalId -Scope $WorkspaceResourceId |
        Where-Object { $_.Scope -eq $WorkspaceResourceId -and $_.RoleDefinitionName -eq 'Microsoft Sentinel Responder' })
    if ($verifiedRbac.Count -eq 0) { throw 'Sentinel Responder grant not verified. Allow propagation and rerun.' }
    Write-Output 'Verified Microsoft Sentinel Responder at the workspace.'
}
elseif ($existingRbac.Count -gt 0) {
    Write-Output 'Microsoft Sentinel Responder is already assigned at the workspace.'
}
Write-Output 'Separate required step: in Sentinel > Automation > Manage playbook permissions, grant Sentinel permission to run playbooks in the playbook resource group. Do not enable detection until the pilot succeeds.'
