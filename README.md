# Sentinel USB-Triggered MDE Full Isolation (`USB\VID_03EB`)

Automated Microsoft Sentinel detection and Consumption Logic App playbook that isolates an onboarded Microsoft Defender for Endpoint (MDE) machine (`IsolationType: Full`) when a matching USB PnP device (`USB\VID_03EB*`) is connected (`DeviceEvents | where ActionType == "PnpDeviceConnected"`).

---

## 1. Upfront Prerequisites & Every Required Role

Before starting, verify **who has which role**. A common deployment blocker is assuming that `Azure Owner` or `Security Administrator` alone can complete every step—**assigning MDE API application permissions to a Managed Identity requires an active Entra ID role (`Privileged Role Administrator` or `Global Administrator`)**.

### A. Human Roles Required to Deploy & Configure (One-Time Setup)

| Step / Action | Minimum Azure RBAC Role (Scope: Resource Group / Workspace) | Minimum Entra ID Role (Directory Scope) | Important Notes (PIM / Separation of Duties) |
| --- | --- | --- | --- |
| **1. Create Analytics Rule & Automation Rule** | `Microsoft Sentinel Contributor` | *None* | Scoped to the Log Analytics workspace resource group. |
| **2. Create Logic App & Managed Identity Connection** | `Logic App Contributor` + `Contributor` | *None* | Scoped to the resource group hosting the playbook. |
| **3. Assign Azure RBAC (`Microsoft Sentinel Responder` & `Automation Contributor`)** | `Role Based Access Control Administrator` or `User Access Administrator` (or `Owner`) | *None* | `Contributor` cannot assign Azure RBAC roles. |
| **4. Grant MDE API App Roles (`Machine.Isolate`, `Machine.ReadWrite.All`) & Optional Graph `Mail.Send` to Logic App Managed Identity** | *None (Azure RBAC does not apply here)* | **`Privileged Role Administrator`** or **`Global Administrator`** | **Must be actively elevated in PIM.** `Security Administrator` and `Azure Owner` **cannot** grant AppRoles on `WindowsDefenderATP` or `Microsoft Graph`. |
| **5. (Optional) Scope Graph `Mail.Send` to a Single Shared Mailbox** | *None* | **`Exchange Administrator`** *(or `Global Administrator`)* | Optional: runs `New-ApplicationAccessPolicy` in Exchange Online PowerShell so the Logic App can only send mail as the designated SOC mailbox (or sign in with a mailbox via the **Office 365 Outlook** connector in Designer instead). |
| **6. Verify Defender XDR `DeviceEvents` Connector** | `Microsoft Sentinel Contributor` | `Security Administrator` or `Global Administrator` | Required in Defender XDR / Sentinel to enable raw `DeviceEvents` streaming. |

### B. Service Identity Roles Created & Used at Runtime (Zero Secrets / Managed Identity Only)

| Runtime Identity | Role / Permission | Type | Scope / Target Resource | Why It Is Needed |
| --- | --- | --- | --- | --- |
| **Logic App System-Assigned Managed Identity** | `Microsoft Sentinel Responder` | Azure RBAC Role | Sentinel Workspace (or Resource Group) | Reads the incident/alerts via ARM and writes status comments to the Sentinel incident. |
| **Logic App System-Assigned Managed Identity** | `Machine.Isolate` | Entra App Role (Application) | `WindowsDefenderATP` (`fc780465-2017-40d4-a0c5-307022471b92`) | Submits `POST /api/machines/{id}/isolate` (`Full` isolation). |
| **Logic App System-Assigned Managed Identity** | `Machine.ReadWrite.All` | Entra App Role (Application) | `WindowsDefenderATP` (`fc780465-2017-40d4-a0c5-307022471b92`) | Required by MDE APIs for `GET /api/machines/{id}` and `GET /api/machineactions` status polling/duplicate guard. |
| **Logic App System-Assigned Managed Identity** *(When Built-in Email Enabled)* | `Mail.Send` | Entra App Role (Application) | `Microsoft Graph` (`00000003-0000-0000-c000-000000000000`) | Sends isolation success and failure alert emails via `POST /v1.0/users/{sender}/sendMail` without user tokens. *(Not needed if using the Office 365 Outlook connector in Designer).* |
| **`Azure Security Insights`** *(First-Party Sentinel Service Principal)* | `Microsoft Sentinel Automation Contributor` | Azure RBAC Role | Playbook Resource Group | Allows Sentinel Automation Rules to trigger the Logic App when an incident is created. |

### C. Required Data Connector & Environment Endpoints

1. **Defender XDR Raw `DeviceEvents` Streaming**: In **Microsoft Sentinel > Data connectors > Microsoft Defender XDR**, ensure **Connect events -> `DeviceEvents`** is checked (not just *Incidents & Alerts*). Without raw `DeviceEvents` collection enabled, the `DeviceEvents` table in Log Analytics will have `0` rows even when MDE Advanced Hunting shows live USB events.
2. **Cloud Endpoint Reference** (if switching between Commercial, GCC, GCC High, and DoD):

| Cloud Environment | ARM Endpoint | ARM Audience | Microsoft Graph Endpoint | MDE API Endpoint & Audience |
| --- | --- | --- | --- | --- |
| **DoD (IL5)** *(Template Default)* | `https://management.usgovcloudapi.net` | `https://management.core.usgovcloudapi.net/` | `https://dod-graph.microsoft.us` | `https://api-gov.securitycenter.microsoft.us` |
| **GCC High (IL4)** | `https://management.usgovcloudapi.net` | `https://management.core.usgovcloudapi.net/` | `https://graph.microsoft.us` | `https://api-gov.securitycenter.microsoft.us` |
| **GCC (Moderate)** | `https://management.azure.com` | `https://management.core.windows.net/` | `https://graph.microsoft.com` | `https://api-gcc.securitycenter.microsoft.us` *(or `.com` on commercial-backed tenants)* |
| **Commercial** | `https://management.azure.com` | `https://management.core.windows.net/` | `https://graph.microsoft.com` | `https://api.securitycenter.microsoft.com` |

---

## 2. Choose Your Deployment Path (3 Customer Options)

Customers often have different change-control preferences. Pick the option that best fits your environment:

| Option | Best For | How It Works | Guide / File |
| --- | --- | --- | --- |
| **Option A: Paste ARM JSON in Azure Portal** *(Fastest — ~5 mins)* | Customers who **do not want to run CLI/Bicep scripts**, but **will paste JSON in the Azure Portal** | Paste [azuredeploy.json](./azuredeploy.json) into **Azure Portal > Deploy a custom template**. Deploys the Analytics Rule, Logic App, Managed Identity, API Connection, and Automation Rule in **one click**. | [Jump to Option A below](#option-a-paste-arm-template-json-in-azure-portal-fastest--no-cli-deployment) |
| **Option B: Manual Portal Copy-Paste** *(Zero ARM)* | Customers whose policy **prohibits ARM templates**, and who prefer creating the rule & Logic App in the UI and pasting KQL + Workflow JSON | Follow the consolidated 4-phase portal checklist and paste [detection.kql](./detection.kql) and [portal-workflow-definition.json](./portal-workflow-definition.json). | [Open CUSTOMER-PORTAL-SETUP.md](./CUSTOMER-PORTAL-SETUP.md) / [PDF Guide](./CUSTOMER-PORTAL-SETUP.pdf) |
| **Option C: 1-Command PowerShell Automation** | Engineers who want **one script** to deploy everything, grant RBAC + MDE AppRoles, and optionally run a live simulation test | Run [Deploy-SentinelUsbIsolation.ps1](./Deploy-SentinelUsbIsolation.ps1) from Cloud Shell or PowerShell 7. | [Jump to Option C below](#option-c-one-command-powershell-deployment-deploy-sentinelusbisolationps1) |

---

### Option A: Paste ARM Template JSON in Azure Portal (Fastest — No CLI Deployment)

If the customer is willing to deploy the ARM template through the Azure Portal UI (no Bicep/CLI deployment commands required), this consolidates steps 1, 2, 3, 5, and 8 of the manual guide into a **single portal form**:

1. **Deploy the Template in Portal**:
   - In the Azure Portal, search for **Deploy a custom template** -> click **Build your own template in the editor**.
   - Paste the entire contents of [azuredeploy.json](./azuredeploy.json) and click **Save**.
   - Select your **Subscription**, your existing Sentinel **Resource group**, and fill in:
     - **Workspace Name**: `<your-existing-sentinel-workspace-name>`
     - **Logic App Name**: `isolate-usb-03eb-dod` (or your preferred name)
     - **Notification Sender Email** *(Optional)*: `<soc-alerts@yourdomain.gov>` (shared/service mailbox UPN for Managed Identity Graph `sendMail`, or leave blank)
     - **Notification Recipient Email** *(Optional)*: `<soc-team@yourdomain.gov>` (recipient email for isolation success/failure alerts, or leave blank)
     - **Enable Detection And Automation**: leave `false` for initial testing, or set `true` if ready to go live.
   - Click **Review + create** -> **Create**.
   - Once complete, open the deployment's **Outputs** tab and copy `managedIdentityPrincipalId`.
2. **Grant Permissions (Cloud Shell PowerShell)**:
   - Open Azure Cloud Shell (PowerShell) as a user with active `Privileged Role Administrator` / `Global Administrator` + Resource Group `Owner`/`RBAC Administrator` and paste:
   ```powershell
   $subId       = "<SUBSCRIPTION-ID>"
   $rgName      = "<RESOURCE-GROUP-NAME>"
   $principalId = "<PASTE-managedIdentityPrincipalId-FROM-OUTPUTS>"
   $graphUrl    = "https://dod-graph.microsoft.us" # Use https://graph.microsoft.us (GCC High) or https://graph.microsoft.com (GCC/Commercial)

   # 1. Grant Sentinel Responder to Logic App Managed Identity
   az role assignment create --assignee-object-id $principalId --assignee-principal-type ServicePrincipal `
       --role "Microsoft Sentinel Responder" --scope "/subscriptions/$subId/resourceGroups/$rgName"

   # 2. Grant Sentinel Automation Contributor to Azure Security Insights
   $sentinelSpId = az ad sp list --filter "appId eq '98785600-1bb7-4fb9-b9fa-19afe2c8a360'" --query "[0].id" -o tsv
   az role assignment create --assignee-object-id $sentinelSpId --assignee-principal-type ServicePrincipal `
       --role "Microsoft Sentinel Automation Contributor" --scope "/subscriptions/$subId/resourceGroups/$rgName"

   # 3. Grant MDE Machine.Isolate and Machine.ReadWrite.All to Logic App Managed Identity
   $mdeSp = (az rest --method GET --url "$graphUrl/v1.0/servicePrincipals?`$filter=appId eq 'fc780465-2017-40d4-a0c5-307022471b92'" | ConvertFrom-Json).value[0]
   foreach ($perm in @('Machine.Isolate', 'Machine.ReadWrite.All')) {
       $roleId = ($mdeSp.appRoles | Where-Object { $_.value -eq $perm -and $_.isEnabled }).id
       @{ principalId = $principalId; resourceId = $mdeSp.id; appRoleId = $roleId } | ConvertTo-Json -Compress |
           az rest --method POST --url "$graphUrl/v1.0/servicePrincipals/$principalId/appRoleAssignments" --headers "Content-Type=application/json" --body "@-"
   }

   # 4. (If using built-in Managed Identity Graph Email) Grant Microsoft Graph Mail.Send
   $graphSp = (az rest --method GET --url "$graphUrl/v1.0/servicePrincipals?`$filter=appId eq '00000003-0000-0000-c000-000000000000'" | ConvertFrom-Json).value[0]
   $mailRoleId = ($graphSp.appRoles | Where-Object { $_.value -eq 'Mail.Send' -and $_.isEnabled }).id
   @{ principalId = $principalId; resourceId = $graphSp.id; appRoleId = $mailRoleId } | ConvertTo-Json -Compress |
       az rest --method POST --url "$graphUrl/v1.0/servicePrincipals/$principalId/appRoleAssignments" --headers "Content-Type=application/json" --body "@-"
   ```
3. **Verify API Connection**:
   - Open the Logic App -> **Development Tools > API connections** -> click the Sentinel connection -> **Edit API connection** -> **Save** to ensure the Managed Identity connection is authorized.

---

### Option B: Manual Portal Setup Without ARM (Paste KQL + Workflow JSON)

If the customer does not want to use **Deploy a custom template**, follow the streamlined 4-phase guide in [CUSTOMER-PORTAL-SETUP.md](./CUSTOMER-PORTAL-SETUP.md), where you simply paste [detection.kql](./detection.kql) into the Analytics Rule and paste [portal-workflow-definition.json](./portal-workflow-definition.json) into the Logic App's **Code view**.

---

### Option C: One-Command PowerShell Deployment ([Deploy-SentinelUsbIsolation.ps1](./Deploy-SentinelUsbIsolation.ps1))

If the customer allows running a single PowerShell script from Azure Cloud Shell or a workstation, [Deploy-SentinelUsbIsolation.ps1](./Deploy-SentinelUsbIsolation.ps1) automates **every** step (Analytics Rule, Logic App, Managed Identity Connection, Azure RBAC, MDE AppRole grants via `az rest`, and Automation Rule) and automatically adapts endpoints for `Commercial`, `GCC`, `GCCHigh`, or `DoD`:

```powershell
.\Deploy-SentinelUsbIsolation.ps1 `
    -SubscriptionId "<SUBSCRIPTION-ID>" `
    -ResourceGroupName "<RESOURCE-GROUP-NAME>" `
    -WorkspaceName "<SENTINEL-WORKSPACE-NAME>" `
    -CloudEnvironment DoD `
    -EnableAutomation
```

---

## Behavior & Architecture

```text
DeviceEvents: PnpDeviceConnected + USB\VID_03EB prefix
  -> scheduled analytics rule, every 5 minutes
  -> one alert per endpoint result, a new ungrouped incident
  -> incident-created automation rule, scoped to this analytics rule
  -> Logic App validates incident, alert details and onboarded MDE endpoint
  -> checks isolation/release action history for pending or duplicate requests
  -> requests FULL isolation and polls the returned MDE action
  -> records confirmed success, refusal, duplicate/pending state, or failure
```

**The match is a USB vendor-ID prefix, not evidence of maliciousness.** All matching
onboarded devices visible to the API identity are in scope, including servers. Get
customer approval of that policy and identify critical-device exclusions before
activation. This package does not classify USB devices as malicious or implement
device-control blocking.

The query preserves the supplied prefix test and distinguishes:

- `MDEDeviceId`: endpoint `DeviceEvents.DeviceId`, used for the isolation API.
- `USBDeviceId`: `AdditionalFields.DeviceId`, used only as USB event evidence.

It parses additional fields once and summarizes to the latest matching event per
endpoint per run. It uses a 5-minute ingestion window within a 1-hour event-time
lookback. If ingestion time is unavailable it uses `TimeGenerated`; those records
do not receive delayed-ingestion protection. Events older than the lookback and
periods missed during rule outages require manual hunting. This is scheduled
detection, not instantaneous USB prevention.

## Files & Project Outline

```text
sentinel-usb-isolation-dod/
├── detection.kql                    # Scheduled KQL query (PnpDeviceConnected + USB\VID_03EB -> MDEDeviceId)
├── azuredeploy.json                 # Full ARM template (Logic App + Sentinel Connection + Analytics Rule + Automation Rule)
├── azuredeploy.parameters.json      # ARM parameters file (safe defaults: detection/automation disabled)
├── portal-workflow-definition.json  # Standalone Logic App workflow definition for Azure Portal Code View
├── Deploy-SentinelUsbIsolation.ps1  # End-to-end automated deployment & permissions script (Commercial/GCC/GCCHigh/DoD)
├── Simulate-UsbTestEvent.ps1        # Self-service simulation & end-to-end isolation test script
├── Grant-PlaybookAccess.ps1         # DoD/Gov-specific RBAC & MDE AppRole helper (with -WhatIf)
├── CUSTOMER-PORTAL-SETUP.md         # Step-by-step no-ARM portal walkthrough + DoD IL5 Monday Call Runbook
├── test_package.py                  # Offline unit test suite (19 contract, expression, and schema checks)
└── Test-Package.ps1                 # Test runner validating PowerShell syntax and Python unit tests
```

- [azuredeploy.json](./azuredeploy.json): Logic App Consumption, managed-identity
  Sentinel connection/access policy, scheduled rule, and automation rule.
- [azuredeploy.parameters.json](./azuredeploy.parameters.json): editable deployment
  parameters; detection and automation disabled by default.
- [portal-workflow-definition.json](./portal-workflow-definition.json): standalone
  Logic App workflow definition for portal copy/paste deployment.
- [detection.kql](./detection.kql): readable copy of the exact embedded query.
- [Deploy-SentinelUsbIsolation.ps1](./Deploy-SentinelUsbIsolation.ps1): one-command
  deployment script supporting `Commercial`, `GCC`, `GCCHigh`, and `DoD` using `az rest`.
- [Simulate-UsbTestEvent.ps1](./Simulate-UsbTestEvent.ps1): self-service script to
  generate/simulate a `USB\VID_03EB` event on demand, trigger the Sentinel incident
  and Logic App playbook, verify MDE isolation, and restore the clean production KQL.
- [Grant-PlaybookAccess.ps1](./Grant-PlaybookAccess.ps1): explicit government-only
  permissions helper with `-WhatIf`.
- [test_package.py](./test_package.py): offline contract/expression/fixture tests.
- [Test-Package.ps1](./Test-Package.ps1): runs tests and PowerShell syntax checks.

## DoD / IL5 deployment gates

**Government URLs do not make a solution IL5-authorized.** The customer must verify
the selected subscription, region, Sentinel workspace, Logic Apps Consumption,
managed Sentinel connector, managed identity, API versions, logging and all data
flows are available and approved within its authorization boundary. If Consumption
or the connector is not approved/available, stop: this template is not a substitute
for a separately designed Logic Apps Standard/private-network solution.

Runtime service endpoints are intentionally fixed:

| Purpose | Endpoint |
| --- | --- |
| Azure Resource Manager | `https://management.usgovcloudapi.net` |
| ARM managed-identity audience | `https://management.core.usgovcloudapi.net/` |
| MDE API and audience | `https://api-gov.securitycenter.microsoft.us` |
| Administrator Entra sign-in | `https://login.microsoftonline.us` |
| Administrator Microsoft Graph | Microsoft Graph PowerShell `USGovDoD` environment |

Microsoft's current MDE government documentation lists `api-gov.securitycenter.microsoft.us`
for **both GCC High and DoD**. Do not substitute an assumed `api-dod` hostname.
Confirm the resource audience against the API service principal in the customer
tenant before enabling. The helper refuses a resource principal that does not
advertise this audience; resolve differences with Microsoft rather than bypassing
the check.

The workflow uses HTTP actions directly against the government MDE API, not an MDE
connector that might default to a commercial endpoint. The Sentinel managed
connector is resolved in the selected deployment location.

**Full isolation does not allow third-party forensic network exceptions.** If the
customer still requires the forensic connectivity discussed earlier, do not enable
this full-isolation workflow; agree on a selective-isolation design instead.
Validate the endpoint's MDE management/release path on proxy and VPN networks.

## Permissions

The Logic App has a system-assigned identity. No secrets or user refresh tokens are
stored in the template.

| Principal | Permission | Scope / reason |
| --- | --- | --- |
| Logic App identity | Microsoft Sentinel Responder | Existing workspace; incident/alert reads and incident comments |
| Logic App identity | MDE `Machine.Isolate` application role | Submit isolation |
| Logic App identity | MDE `Machine.ReadWrite.All` application role | MDE documents this role for machine reads and action-history/status APIs |
| Microsoft Sentinel service identity | Microsoft Sentinel Automation Contributor | Playbook resource group, granted using Sentinel's Manage playbook permissions |

The MDE read/write role is broad. Review it explicitly; Sentinel workspace RBAC does
not restrict the identity's MDE API access to only hosts in that workspace. A
separate identity and dedicated, approved resource group are recommended.

The grant helper needs PowerShell 7.2+ and the modules listed by its `#Requires`.
An authorized administrator must have Azure role-assignment rights at the workspace
and appropriate Entra application-role grant privileges (for example activated PRA
or Global Administrator). Azure Owner alone does not grant Entra API permissions.
Conversely an Entra administrator role does not grant Azure RBAC assignment rights.

## Deploy in stages

These commands are instructions for an authorized customer administrator. They
have not been executed against a tenant. Deploy into the **existing workspace's
resource group and subscription**. The template does not create a workspace.

1. Validate [detection.kql](./detection.kql) in Sentinel Logs. Confirm benign matching
   devices, the endpoint IDs, ingestion delay, and the intended response policy.
2. Confirm the DoD authorization gates above, the region, network/recovery procedure,
   and MDE full-isolation support for all in-scope endpoint OS/agent versions.
3. Edit `workspaceName` in the parameter file. Leave activation false.
4. Select the government cloud, sign in, select the approved subscription, validate,
   preview, then deploy:

   ```powershell
   az cloud set --name AzureUSGovernment
   az login --tenant <tenant-id>
   az account set --subscription <subscription-id>
   az account show --query "{tenant:tenantId,subscription:id,cloud:environmentName}"

   az deployment group validate --resource-group <existing-workspace-rg> `
     --template-file .\azuredeploy.json --parameters '@azuredeploy.parameters.json'
   az deployment group what-if --resource-group <existing-workspace-rg> `
     --template-file .\azuredeploy.json --parameters '@azuredeploy.parameters.json'
   az deployment group create --name usb-isolation-dod `
     --resource-group <existing-workspace-rg> `
     --template-file .\azuredeploy.json --parameters '@azuredeploy.parameters.json'
   ```

   CLI cloud/account selection changes the administrator's local CLI context.
   Explicitly inspect it before every deployment; do not use an unrelated active
   session. Override `location=<approved-region>` if the resource group's metadata
   location is not the approved deployment region.

5. Record the deployment outputs. Obtain the **object ID of the MDE API enterprise
   application** in the DoD tenant, not its application/client ID and not the
   playbook identity object ID. Review the helper with `-WhatIf`, then grant:

   ```powershell
   .\Grant-PlaybookAccess.ps1 -TenantId <tenant-id> `
     -LogicAppResourceId '<deployment-output-logicAppResourceId>' `
     -WorkspaceResourceId '<deployment-output-workspaceResourceId>' `
     -MdeResourceServicePrincipalId <mde-api-enterprise-app-object-id> -WhatIf
   # Rerun without -WhatIf only after reviewing the proposed grants.
   ```

   The helper signs in and reads even under `-WhatIf`, but does not create grants.
   Newly created identities/permissions may need time to propagate; failures are
   surfaced, not silently ignored.

6. In Sentinel **Automation > Manage playbook permissions**, grant Sentinel
   permission to run playbooks in the playbook resource group. This is separate
   from granting the playbook its own permissions.
7. Verify the Sentinel API connection is connected using the system-assigned
   identity. Run the test/pilot checklist below.
8. Once approved, redeploy with activation true:

   ```powershell
   az deployment group create --name usb-isolation-dod `
     --resource-group <existing-workspace-rg> `
     --template-file .\azuredeploy.json --parameters '@azuredeploy.parameters.json' `
     --parameters enableDetectionAndAutomation=true
   ```

   Keep the parameter file aligned with the approved state: a later deployment
   using false disables both rules. Once enabled, matching detections invoke full
   isolation automatically, without an approval step.

**Disabled detection is not dry-run mode.** The Logic App itself is enabled so that
it can be tested manually. A manual run on a valid incident can isolate a real
device even while the analytics and automation rules are disabled.

## Failure handling and operating limits

- The workflow trusts only incidents under the configured workspace and verifies
  the analytics rule association through ARM, not a hostname from an arbitrary
  trigger. It requires exactly one matching alert and exactly one 40-character
  MDE endpoint ID plus the fixed detection signature. Missing/malformed/aggregated
  details fail closed. It does not isolate every host entity in an incident.
- Custom details are parsed as JSON, never cleaned by removing escape characters.
  The package accepts ARM additional-data keys `Custom Details` or `CustomDetails`.
  Validate the actual DoD incident-alert representation in the pilot; unexpected
  payloads fail before an isolation request.
- Workflow runs are serialized. Before POST, action history is checked for pending
  isolation/release actions and for the exact incident/device request comment.
  A replay of the same incident is not automatically resubmitted, even after
  release or a failed request, while that action remains in MDE history.
- This is **not** a cross-system lock or an exactly-once guarantee. Another product,
  playbook or analyst can act between the history check and POST. MDE history
  retention also bounds replay protection. A separate new matching incident may
  submit a new request; coordinate response automation to avoid re-isolation.
- Already-isolated machines are not inferred from an undocumented machine-state
  field. MDE may reject a new incident's isolation request; that failure is recorded
  for analyst review, not reported as successful containment.
- Incomplete/paginated action history is refused, not silently truncated.
- POST isolation has **no automatic retries**. A timeout may mean MDE accepted the
  request. Check Action center before resubmitting.
- Polling is bounded to 15 iterations with a 20-second delay and a six-minute loop
  limit. Success requires MDE action status `Succeeded`, type `Isolate`, scope
  `Full`, and the expected endpoint ID. Pending/offline devices are not called
  successfully isolated. Pending actions may execute after the playbook stops.
- Existing/duplicate/pending requests produce an explanatory comment without
  claiming confirmed full isolation. Other errors cause failed runs and attempt
  an incident comment. If ARM/authentication is unavailable, the comment can fail
  too: configure Azure Monitor failure alerts and a SOC owner before activation.
- MDE rate limits still apply (isolation: 100/minute, 1,500/hour). Serial processing
  with status polling is deliberately conservative but can build a backlog. This
  starter package is not a high-volume containment service. Sentinel per-result
  alert limits can aggregate large result sets; the single-ID guard rejects those
  aggregates rather than choosing an arbitrary endpoint.
- No release action is implemented. Disable both rules to stop new automated
  responses, inspect/cancel any queued runs and pending MDE actions, and release
  endpoints separately when authorized. Disabling rules does not undo isolation.
  Do not assume MDE isolation persists indefinitely; follow product behavior and
  the customer's incident procedures.

## Required pilot and logging

Use approved noncritical test endpoints. Do not test live automatic isolation on a
production domain controller, hypervisor, critical server or remote-only endpoint.

1. With Python available, install the local test dependency using
   `python -m pip install -r .\requirements-dev.txt`, then run `.\Test-Package.ps1`.
2. Run ARM validate/what-if in the actual customer subscription. Confirm selected
   API versions, connector availability, managed identity token audiences and grants.
3. For a controlled pilot, enable the analytics rule only in Sentinel while leaving
   its automation rule disabled. Generate an approved matching USB event, confirm
   exactly one endpoint ID in the resulting alert, and manually run the playbook
   on the incident. **This is a live isolation test.**
4. Verify that MDE reports Full isolation Succeeded and an incident comment appears.
   Check actual endpoint network containment, continued MDE telemetry/response, and
   that an unrelated endpoint is untouched.
5. Resubmit that incident and confirm no duplicate POST. Exercise missing/invalid
   IDs, wrong rules/workspaces, multi-device aggregate alerts, offline devices,
   MDE 403/429/timeouts, a pending isolation/release, and comment-write failures.
6. Manually release the approved test endpoint; verify connectivity, VPN/proxy
   reconnect and reboot behavior. Confirm no other rule re-isolates it.
7. Enable workflow diagnostic settings to the approved government Log Analytics
   destination and alert on failed runs/backlog. Run history, incident comments,
   API action comments and diagnostics contain device/incident identifiers: apply
   approved access controls and retention. Optional email notifications are sent via
   Microsoft Graph `sendMail` (`https://dod-graph.microsoft.us` in DoD IL5) only when
   both `notificationSenderEmail` and `notificationRecipientEmail` are configured; if
   email delivery fails after MDE Full Isolation succeeds, `Record_email_warning` logs
   a warning comment on the Sentinel incident without failing the containment run.
8. Return to a known disabled baseline if any pilot check fails. Activate both
   rules only after customer authorization and operational ownership are recorded.

## Self-Service Simulation & Lessons Learned from Live Deployment

### How to Simulate Data & Trigger Isolation on Demand (`Simulate-UsbTestEvent.ps1`)

Because `DeviceEvents` is a built-in system table in Microsoft Sentinel / Log Analytics (cannot be written via the Custom Logs Ingestion API) and Azure VMs lack physical USB controllers, use [Simulate-UsbTestEvent.ps1](./Simulate-UsbTestEvent.ps1) whenever you want to create test data and verify the full pipeline end-to-end:

```powershell
# Trigger a simulated USB\VID_03EB event against an onboarded MDE VM, verify full isolation,
# automatically restore the clean production KQL query, and optionally unisolate afterward:
.\Simulate-UsbTestEvent.ps1 `
    -SubscriptionId "<SUBSCRIPTION-ID>" `
    -ResourceGroupName "<RESOURCE-GROUP-NAME>" `
    -WorkspaceName "<SENTINEL-WORKSPACE-NAME>" `
    -LogicAppName "isolate-usb-03eb-dod" `
    -RuleId "05e12e72-b5b5-4350-afd8-fa3a3f54864c" `
    -MdeDeviceName "<MDE-HOSTNAME>" `
    -UnisolateAfterTest
```

To also register the simulated `USB\VID_03EB&PID_2404` PnP device inside the guest Windows VM via `SetupAPI` (`az vm run-command invoke`), add `-RegisterGuestPnpDevice -VmResourceGroup "<vm-rg>" -VmName "<vm-name>"`.

### Key Lessons Learned Incorporated into This Package

1. **Logic Apps `ParseJson` Rejects `"pattern"` at Runtime (`ActionSchemaNotSupported`)**:
   - Azure ARM template validation accepts `"pattern"` in `ParseJson` schemas at deploy time, but the Logic Apps runtime fails with `ActionSchemaNotSupported` when executing the action.
   - **Fix applied**: Replaced `"pattern"` in `Parse_custom_details` and `Validate_submitted_action` with `"minLength"` and `"maxLength"`, and added a unit test (`test_no_parse_json_uses_unsupported_pattern_keywords`) to prevent regressions.
2. **MDE `POST /api/machines/{id}/isolate` Returns `"scope": null` While `"status": "Pending"`**:
   - The immediate `201 Created` response from MDE's isolate endpoint has `"status": "Pending"` and `"scope": null`; MDE only populates `"scope": "Full"` after the action completes on the polling endpoint (`GET /api/machineactions/{id}`).
   - **Fix applied**: `Validate_submitted_action` allows `"scope": ["string", "null"]` on initial submission, while `Verify_completion` strictly enforces `equals(body('Poll_action')?['scope'], 'Full')` before recording success.
3. **Sentinel `POST /incidents/{id}/alerts` Omits `Custom Details` on Fresh Scheduled Alerts**:
   - Calling the ARM `POST /incidents/{id}/alerts` endpoint immediately after incident creation can omit `Custom Details` from `properties.additionalData`, whereas the Sentinel incident creation webhook (`triggerBody()`) embeds `Custom Details` inside `triggerBody()?['object']?['properties']?['alerts']?[0]?['properties']?['additionalData']?['Custom Details']`.
   - **Fix applied**: `Parse_custom_details` now coalesces both `body('One_alert')` and `triggerBody()` so `MDEDeviceId` and `DetectionSignature` are reliably extracted.
4. **Use `az rest` Instead of `Connect-MgGraph` in Cloud Shell to Avoid Device-Code Admin Consent Blocks**:
   - In Azure Cloud Shell, `Connect-MgGraph` uses device-code flow, which suppresses interactive admin consent prompts (`Need admin approval for Microsoft Graph Command Line Tools`).
   - **Fix applied**: [Deploy-SentinelUsbIsolation.ps1](./Deploy-SentinelUsbIsolation.ps1) and [CUSTOMER-PORTAL-SETUP.md](./CUSTOMER-PORTAL-SETUP.md) provide an `az rest` workflow that auto-discovers `WindowsDefenderATP` (`appId eq 'fc780465-2017-40d4-a0c5-307022471b92'`) and assigns `Machine.Isolate` and `Machine.ReadWrite.All` directly.
5. **Verify MDE API Endpoint & Defender XDR Raw `DeviceEvents` Connector**:
   - Commercial-backed demo/lab tenants return `403 Forbidden` on `api-gcc.securitycenter.microsoft.us` and require `api.securitycenter.microsoft.com`.
   - Ensure the **Microsoft Defender XDR** connector in Microsoft Sentinel has raw **`DeviceEvents`** table collection enabled (not only Incidents & Alerts), otherwise `DeviceEvents` in Log Analytics will have 0 rows even when MDE Advanced Hunting shows live events.

## Validation status

Local validation completed: **19 offline tests passed**, all PowerShell scripts passed syntax validation, and both the embedded
and standalone portal workflows passed Microsoft's published Logic Apps definition
schema. The ARM envelope also passed its published schema
with resource bodies excluded. Full provider-schema resolution was interrupted by
a remote schema connection reset, so no full ARM provider-schema validation is
claimed. Run ARM validate/what-if in the customer subscription before deployment.

Offline tests validate JSON/schema contracts, expression syntax/references,
query parity, target parsing and failure/completion guards. They do **not**
execute KQL, emulate the Logic Apps service, validate IL5 authorization, prove
connector/API availability in DoD, or replace the live isolation/release pilot.

## Microsoft references

- [Government MDE API endpoints](https://learn.microsoft.com/en-us/defender-endpoint/gov#api)
- [Isolation API](https://learn.microsoft.com/en-us/defender-endpoint/api/isolate-machine)
- [Machine actions and status](https://learn.microsoft.com/en-us/defender-endpoint/api/machineaction)
- [Get machine action permissions](https://learn.microsoft.com/en-us/defender-endpoint/api/get-machineaction-object)
- [Sentinel incident triggers](https://learn.microsoft.com/en-us/azure/sentinel/automation/playbook-triggers-actions)
- [Incident list-alerts REST API](https://learn.microsoft.com/en-us/rest/api/securityinsights/incidents/list-alerts?view=rest-securityinsights-2024-03-01)
- [Automation rule template schema](https://learn.microsoft.com/en-us/azure/templates/microsoft.securityinsights/2024-03-01/automationrules)
- [MDE isolation connectivity considerations](https://learn.microsoft.com/en-us/defender-endpoint/respond-machine-alerts#isolate-devices-from-the-network)
