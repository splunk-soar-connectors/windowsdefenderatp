# Microsoft Defender for Endpoint

Publisher: Splunk <br>
Connector Version: 4.0.5 <br>
Product Vendor: Microsoft <br>
Product Name: Microsoft Defender for Endpoint <br>
Minimum Product Version: 6.2.2

This app integrates with Microsoft Defender for Endpoint to execute various containment, corrective, generic, and investigative actions

## Defender for Endpoint Instance Minimum Version Compatibility

- With this major version 2.0.0 of the Microsoft Defender for Endpoint app on Splunk SOAR, we declare support
  for (on and above) the cloud 'November-December 2019' GA release for the Defender for Endpoint instances. This app
  has been tested and certified on the mentioned GA release of the Defender for Endpoint and its APIs.

## Playbook Backward Compatibility

- The existing action parameters have been modified in the actions given below. Hence, it is
  requested to the end-user to please update their existing playbooks by re-inserting | modifying
  | deleting the corresponding action blocks, or by providing appropriate values to these action
  parameters to ensure the correct functioning of the playbooks created on the earlier versions of
  the app.

  - List Devices - The 'IP' option has been removed from the value list of the [input_type]
    action parameter in the app version 3.0.0 because there is no specific API currently
    available to support the filtering of devices based on the IP in the Defender for Endpoint.
  - List Devices - The new [query] parameter has been added to support the additional OData V4
    filters.

## Port Information

The app uses HTTP/ HTTPS protocol for communicating with the Defender for Endpoint server. Below are the
default ports used by Splunk SOAR.

|         Service Name | Transport Protocol | Port |
|----------------------|--------------------|------|
|         http | tcp | 80 |
|         https | tcp | 443 |

## Pagination Not Supported

- Based on the base URL link ( [Microsoft Defender for Endpoint API
  Documentation](https://docs.microsoft.com/en-us/windows/security/threat-protection/microsoft-defender-atp/exposed-apis-list)
  ), the pagination is not supported by the Defender for Endpoint APIs. Hence, this app does not implement
  the pagination for the below-mentioned actions.

  - List Devices
  - List Alerts
  - List Sessions
  - List Indicators
  - Get Installed Software
  - Get Discovered Vulnerabilities
  - Get File Devices
  - Get User Devices
  - Get Domain Devices
  - Get Missing KBs
  - Run Query

## Explanation of Asset Configuration Parameters

- Tenant ID - It is the Directory ID of the Microsoft Azure Active Directory on the Microsoft
  Azure portal.
- Client ID - It is the Application ID of an application configured in the Microsoft Azure Active
  Directory.
- Client Secret - It is the secret string used by the application to prove its identity when
  requesting a token. It can be generated for the configured application on the Microsoft Azure
  Active Directory.
- Environment - Cloud services are provided by Azure and used to connect with Public, Government
  Community Cloud (GCC) or GCC High Azure cloud services.
- Non Interactive Auth - It is used to determine the authentication method. If it is checked then
  non interactive auth will be used otherwise interactive auth will be used. Whenever this
  checkbox is toggled then the test connectivity action must be run again.

## Explanation of Asset Configuration Parameters for On Poll

- Max Alerts for Polling - During each polling cycle, the specified number of alerts is retrieved for scheduled or interval polling (Default: 1000). Each alert is ingested as a container. This parameter determines the maximum number of alerts that can be fetched in a single poll cycle.
- Start Time - This parameter is used to filter alerts based on their last updated time. If no value is provided, the default behavior is a week.<br>
  **Note: The start time filters alerts based on their lastUpdateTime property.**
- Filter - Allows additional filtering to be applied to alert properties (such as severity or status). This is useful for targeting specific types of alerts during polling.

## Explanation of On Poll Behavior

- Start Time Parameter - The `start_time` parameter directly correlates with the lastUpdateTime property of the alerts, ensuring that only alerts updated after this time are included in the ingestion process.
- Max Alerts Parameter - The `max_alerts_per_poll` setting works only with scheduled or interval polling, controlling how many alerts are ingested per cycle. For instance, if this value is set to 100, the system will ingest up to 100 distinct alerts, applying the provided filters and start time.
- Example - If you configure the maximum alerts parameter to 100, the on_poll function will retrieve up to 100 alerts, considering any filter and start time provided. The filtering ensures only relevant alerts based on the time and other criteria are ingested during the polling process.

## Configure and set up permissions of the app created on the Microsoft Azure portal

<div style="margin-left: 2em">

#### Create the app

1. Navigate to <https://portal.azure.com> .
1. Log in with a user that has permission to create an app in the Azure Active Directory (AAD).
1. Select the 'Azure Active Directory'.
1. Select the 'App registrations' menu from the left-side panel.
1. Select the 'New Registration' option at the top of the page.
1. In the registration form, choose a name for your application and then click 'Register'.

#### Add permissions

7. Select the 'API Permissions' menu from the left-side panel.
1. Click on 'Add a permission'.
1. Under the 'Select an API' section, select 'APIs my organization uses'.
1. Search for 'WindowsDefenderATP' keyword in the search box and click on the displayed option for
   it.
1. Provide the following Delegated and Application permissions to the app.
   - **Application Permissions**

     - AdvancedQuery.Read.All
     - Alert.ReadWrite.All
     - File.Read.All
     - Ip.Read.All
     - Machine.CollectForensics
     - Machine.Isolate
     - Machine.LiveResponse
     - Machine.Offboard
     - Machine.Read.All
     - Machine.ReadWrite.All
     - Machine.RestrictExecution
     - Machine.Scan
     - Machine.StopAndQuarantine
     - Score.Read.All
     - Software.Read.All
     - Ti.ReadWrite.All
     - Url.Read.All
     - User.Read.All
     - Vulnerability.Read.All

   - **Delegated Permissions**

     - AdvancedQuery.Read
     - Alert.ReadWrite
     - File.Read.All
     - Ip.Read.All
     - Machine.Isolate
     - Machine.LiveResponse
     - Machine.Offboard
     - Machine.Read
     - Machine.ReadWrite
     - Machine.RestrictExecution
     - Machine.Scan
     - Machine.StopAndQuarantine
     - Score.Read
     - Software.Read
     - Ti.ReadWrite
     - Url.Read.All
     - User.Read.All
     - Vulnerability.Read
1. 'Grant Admin Consent' for it.
1. Again click on 'Add a permission'.
1. Under the 'Select an API' section, select 'Microsoft APIs'.
1. Click on the 'Microsoft Graph' option.
1. Provide the following Delegated permission to the app.
   - **Delegated Permission**

     - offline_access

#### Create a client secret

17. Select the 'Certificates & secrets' menu from the left-side panel.
01. Select 'New client secret' button to open a pop-up window.
01. Provide the description, select an appropriate option for deciding the client secret expiration
    time, and click on the 'Add' button.
01. Click 'Copy to clipboard' to copy the generated secret value and paste it in a safe place. You
    will need it to configure the asset and will not be able to retrieve it later.

#### Copy your application id and tenant id

21. Select the 'Overview' menu from the left-side panel.
01. Copy the **Application (client) ID** and **Directory (tenant) ID** . You will need these to
    configure the SOAR asset.

## Configure the Microsoft Defender for Endpoint SOAR app's asset

When creating an asset for the app,

- Check the checkbox if you want to use Non Interactive authentication mechanism otherwise
  Interactive auth mechanism will be used.

- Provide the client ID of the app created during the previous step of app creation in the 'Client
  ID' field.

- Provide the client secret of the app created during the previous step of app creation in the
  'Client Secret' field.

- Provide the tenant ID of the app created during the previous step of Azure app creation in the
  'Tenant ID' field. For getting the value of tenant ID, navigate to the 'Azure Active Directory'
  on the Microsoft Azure portal; click on the 'App registrations' menu from the left-side panel;
  click on the earlier created app. The value displayed in the 'Directory (tenant) ID' is the
  required tenant ID.

- Save the asset with the above values.

- After saving the asset, a new uneditable field will appear in the 'Asset Settings' tab of the
  configured asset for the Defender for Endpoint app on SOAR. Copy the URL mentioned in the 'POST incoming for
  Microsoft Defender for Endpoint to this location' field. Add a suffix '/result' to the URL copied in the
  previous step. The resulting URL looks like the one mentioned below.

  ```
              https://<soar_host>/rest/handler/microsoftdefenderforendpoint_<appid>/<asset_name>/result
  ```

- Add the URL created in the earlier step into the 'Redirect URIs' section of the 'Authentication'
  menu for the registered app that was created in the previous steps on the Microsoft Azure
  portal. For the 'Redirect URIs' section, follow the below steps.

  1. Below steps are required only in case of Interactive auth (i.e. If checkbox is unchecked)
  1. Navigate to the 'Azure Active Directory' on the Microsoft Azure portal.
  1. Click on the 'App registrations' menu from the left-side panel.
  1. Click on the earlier created app. You can search for the app by name or client ID.
  1. Navigate to the 'Authentication' menu of the app on the left-side panel.
  1. Click on the 'Add a platform' button and select 'Web' from the displayed options.
  1. Enter the URL created in the earlier section in the 'Redirect URIs' text-box.
  1. Select the 'ID tokens' checkbox and click 'Save'.
  1. This will display the 'Redirect URIs' under the 'Web' section displayed on the page.

## Interactive Method to run Test Connectivity

- After setting up the asset and user, click the 'TEST CONNECTIVITY' button. A pop-up window will
  be displayed with appropriate test connectivity logs. It will also display a specific URL on
  that pop-up window.
- Open this URL in a separate browser tab. This new tab will redirect to the Microsoft login page
  to complete the login process to grant the permissions to the app.
- Log in using the same Microsoft account that was used to configure the Microsoft Defender for Endpoint
  workflow and the application on the Microsoft Azure Portal. After logging in, review the
  requested permissions listed and click on the 'Accept' button.
- This will display a successful message of 'Code received. Please close this window, the action
  will continue to get new token.' on the browser tab.
- Finally, close the browser tab and come back to the 'Test Connectivity' browser tab. The pop-up
  window should display a 'Test Connectivity Passed' message.

## Non Interactive Method to run Test Connectivity

- Here make sure that the 'Non Interactive Auth' checkbox is checked in asset configuration.
- Click on the 'TEST CONNECTIVITY' button, it should run the test connectivity action without any
  user interaction.

## Explanation of Test Connectivity Workflow for Interactive auth and Non Interactive auth

- This app uses (version 1.0) OAUTH 2.0 authorization code workflow APIs for generating the
  [access_token] and [refresh_token] pairs if the authentication method is interactive else
  [access_token] if authentication method is non interactive is used for all the API calls to
  the Defender for Endpoint instance.

- Interactive authentication mechanism is a user-context based workflow and the permissions of the
  user also matter along with the API permissions set to define the scope and permissions of the
  generated tokens. For more information visit the link mentioned here for the [OAUTH 2.0 AUTH
  CODE](https://docs.microsoft.com/en-gb/azure/active-directory/azuread-dev/v1-protocols-oauth-code)
  .

- Non Interactive authentication mechanism is a user-context based workflow and the permissions of
  the user also matter along with the API permissions set to define the scope and permissions of
  the generated token. For more information visit the link mentioned here for the [OAUTH 2.0
  CLIENT
  CREDENTIALS](https://docs.microsoft.com/en-gb/azure/active-directory/azuread-dev/v1-oauth2-client-creds-grant-flow)
  .

- The step-by-step process for the entire authentication mechanism is explained below.

  - The first step is to get an application created in a specific tenant on the Microsoft Azure
    Active Directory. Generate the [client_secret] for the configured application. The
    detailed steps have been mentioned in the earlier section.

  - Configure the Microsoft Defender for Endpoint app's asset with appropriate values for [tenant_id],
    [client_id], and [client_secret] configuration parameters.

  - Run the test connectivity action for Interactive method.

    - Internally, the connectivity creates a URL for hitting the /authorize endpoint for the
      generation of the authorization code and displays it on the connectivity pop-up window.
      The user is requested to hit this URL in a browser new tab and complete the
      authorization request successfully resulting in the generation of an authorization code.
    - The authorization code generated in the above step is used by the connectivity to make
      the next API call to generate the [access_token] and [refresh_token] pair. The
      generated authorization code, [access_token], and [refresh_token] are stored in the
      state file of the app on the Splunk SOAR server.
    - The authorization code can be used only once to generate the pair of [access_token]
      and [refresh_token]. If the [access_token] expires, then the [refresh_token] is
      used internally automatically by the application to re-generate the [access_token] by
      making the corresponding API call. This entire autonomous workflow will seamlessly work
      until the [refresh_token] does not get expired. Once the [refresh_token] expires,
      the user will have to run the test connectivity action once again to generate the
      authorization code followed by the generation of an entirely fresh pair of
      [access_token] and [refresh_token]. The default expiration time for the
      [access_token] is 1 hour and that of the [refresh_token] is 90 days. For more
      details visit [AD Configurable Token
      Lifetimes](https://docs.microsoft.com/en-us/azure/active-directory/develop/active-directory-configurable-token-lifetimes)
    - The successful run of the Test Connectivity ensures that a valid pair of
      [access_token] and [refresh_token] has been generated and stored in the app's state
      file. These tokens will be used in all the actions' execution flow to authorize their
      API calls to the Defender for Endpoint instance.

  - Run the test connectivity action for Non Interactive method.

    - Internally, the application authenticates to Azure AD token issuance endpoint and
      requests an [access_token] then it will generate the [access_token].
    - The [access_token] generated in the above step is used by the test connectivity to
      make the next API call to verify the [access_token]. The generated [access_token] is
      stored in the state file of the app on the Splunk SOAR server.
    - If the [access_token] expires, then application will automatically re-generate the
      [access_token] by making the corresponding API call.
    - The successful run of the Test Connectivity ensures that a valid [access_token] has
      been generated and stored in the app's state file. This token will be used in all the
      actions execution flow to authorize their API calls to the Defender for Endpoint instance.

## State file permissions

Please check the permissions for the state file as mentioned below.

#### State file path

- For Non-NRI instance: /opt/phantom/local_data/app_states/\<appid>/\<asset_id>\_state.json
- For NRI instance:
  /\<PHANTOM_HOME_DIRECTORY>/local_data/app_states/\<appid>/\<asset_id>\_state.json

#### State file permissions

- File rights: rw-rw-r-- (664) (The Splunk SOAR user should have read and write access for the
  state file)
- File owner: Appropriate Splunk SOAR user

## Notes

- \<appid> - The app ID will be available in the Redirect URI which gets populated in the field
  'POST incoming for Microsoft Defender for Endpoint to this location' when the Defender for Endpoint Splunk SOAR app
  asset is configured e.g.
  https://\<splunk_soar_host>/rest/handler/microsoftdefenderforendpoint\_\<appid>/\<asset_name>/result
- \<asset_id> - The asset ID will be available on the created asset's Splunk SOAR web URL e.g.
  https://\<splunk_soar_host>/apps/\<app_number>/asset/\<asset_id>/

## get file (live response) action workflow

- There can be four different cases based on the provided parameters:

  - Case 1:

    - Only event_id is provided - In this case, the rest of the parameters will be ignored and
      the action will try to get the file based on the provided **event_id** . The action can
      get the file only if the status received from the **get_status** action for the given
      event_id is **Succeeded** (How the event_id is generated is mentioned in the next Case).

  - Case 2:

    - No event_id is provided and other parameters are provided - In this case, **device_id,
      file_path and comment** all the three parameters are required. If the timeout is not
      provided, the default timeout value is considered as 300 seconds. In the given timeout,
      the action will try to get the file and if action takes longer time than the given
      timeout, it will provide an **event_id** and **file_status** . The event_id can be used
      in the **get_status** action to receive the status and once the status is **Succeeded**
      , the same event_id can be used in this action to get the file into the vault (Case 1).

  - Case 3:

    - Both event_id and other parameters are provided - In this case, the event_id will get
      the higher priority and the action will try to get the file based on the **event_id**
      (Case 1). If the action fails to get the file using event_id, it will look into other
      parameters and it will work in the same way as mentioned in Case 2.

  - Case 4:

    - No parameters are provided - In this case the action will fail, because either
      **event_id** or **Other parameters (file_path, device_id, and comment)** are required in
      order to get the file.

## run script (live response) action workflow

- There can be four different cases based on the provided parameters:

  - Case 1:

    - Only event_id is provided - In this case, the rest of the parameters will be ignored and
      the action will try to get the script output based on the provided **event_id** . The
      action can get the script output if the status received from the **get_status** action
      for the given event_id is **Succeeded** (How the event_id is generated is mentioned in
      the next Case.)

  - Case 2:

    - No event_id provided and other parameters are provided - In this case, **device_id,
      script_name and comment** all the three parameters are required. If the timeout is not
      provided, the default timeout value is considered as 300 seconds. In the given timeout,
      the action will try to execute the script and provide the output and if the action takes
      longer time than the given timeout, it will provide an **event_id** and
      **script_status** . The event_id can be used in the **get_status** action to receive the
      status and once the status is **Succeeded** , the same event_id can be used in this
      action to get the script output (Case 1).

  - Case 3:

    - Both event_id and other parameters are provided - In this case the event_id will get the
      higher priority and the action will try to get the script output based on the
      **event_id** (Case 1). If the action fails to get the script output using event_id, it
      will look into other parameters and it will work in the same way as mentioned in Case 2.

  - Case 4:

    - No parameters are provided - In this case the action will fail, because either
      **event_id** or **Other parameters (script_name, device_id, and comment)** are required
      in order to get the script output.

#### The app is configured and ready to be used now.

### Configuration variables

This table lists the configuration variables required to operate Microsoft Defender for Endpoint. These variables are specified when configuring a Microsoft Defender for Endpoint asset in Splunk SOAR.

VARIABLE | REQUIRED | TYPE | DESCRIPTION
-------- | -------- | ---- | -----------
**tenant_id** | required | string | Tenant ID |
**client_id** | required | string | Client ID |
**client_secret** | required | password | Client Secret |
**non_interactive** | optional | boolean | Non Interactive Auth |
**max_alerts_per_poll** | optional | numeric | Maximum Alerts for scheduled/interval polling for each cycle |
**start_time** | optional | string | Start time for schedule/interval/manual poll (Use ISO 8601 UTC format: 2024-09-04T16:26:58Z) |
**environment** | required | string | Azure environment to connect |

### Supported Actions

[test connectivity](#action-test-connectivity) - Validate the asset configuration for connectivity using the supplied configuration <br>
[on poll](#action-on-poll) - Callback action for the on_poll ingest functionality for Defender for Endpoint <br>
[quarantine device](#action-quarantine-device) - Quarantine the device <br>
[unquarantine device](#action-unquarantine-device) - Unquarantine the device <br>
[get status](#action-get-status) - Get status of the event on a machine <br>
[scan device](#action-scan-device) - Scan a device for virus <br>
[quarantine file](#action-quarantine-file) - Quarantine a file <br>
[get active users](#action-get-active-users) - Get active users on a device <br>
[list devices](#action-list-devices) - List of recently seen devices <br>
[list alerts](#action-list-alerts) - List all alerts of a given type <br>
[list sessions](#action-list-sessions) - List all logged in users on a machine <br>
[list software](#action-list-software) - Retrieve the organization's software inventory <br>
[list software versions](#action-list-software-versions) - Retrieve a list of organization's software version distribution <br>
[list software devices](#action-list-software-devices) - Retrieve a list of devices that have a specific software installed <br>
[list software vulnerabilities](#action-list-software-vulnerabilities) - Retrieve vulnerabilities associated with a specific software <br>
[list device vulnerabilities](#action-list-device-vulnerabilities) - Retrieve vulnerabilities affecting devices or software in organization <br>
[list vulnerabilities](#action-list-vulnerabilities) - Retrieve a list of vulnerabilities based on filters <br>
[get alert](#action-get-alert) - Retrieve specific Alert by its ID <br>
[get alert user](#action-get-alert-user) - Retrieve user for specific Alert from its ID <br>
[get alert files](#action-get-alert-files) - Retrieve files for specific Alert from its ID <br>
[get alert ips](#action-get-alert-ips) - Retrieve IP addresses for a specific Alert from its ID <br>
[get alert domains](#action-get-alert-domains) - Retrieve domains for a specific Alert from its ID <br>
[create alert](#action-create-alert) - Create a new alert in Defender for Endpoint <br>
[update alert](#action-update-alert) - Update properties of existing Alert <br>
[domain prevalence](#action-domain-prevalence) - Return statistics for the specified domain <br>
[ip prevalence](#action-ip-prevalence) - Return statistics for the specified IP <br>
[file prevalence](#action-file-prevalence) - Return statistics for the specified file <br>
[get file info](#action-get-file-info) - Retrieve a File information by identifier SHA1, or SHA256 <br>
[get file devices](#action-get-file-devices) - Retrieve a collection of devices related to a given file hash (SHA1) <br>
[get user devices](#action-get-user-devices) - Retrieve a collection of devices related to a given user ID <br>
[get installed software](#action-get-installed-software) - Retrieve a collection of installed software related to a given device ID <br>
[restrict app execution](#action-restrict-app-execution) - Restrict execution of all applications on the device except a predefined set <br>
[list indicators](#action-list-indicators) - Retrieve a collection of all active Indicators <br>
[collect investigation package](#action-collect-investigation-package) - Collect an investigation package from a device by its device ID <br>
[get investigation uri](#action-get-investigation-uri) - Retrieve a URI for downloading an investigation package by its action ID <br>
[get device details](#action-get-device-details) - Retrieve details for multiple devices by their device IDs <br>
[get affected devices](#action-get-affected-devices) - Retrieve a list of devices affected by a vulnerability using CVE IDs <br>
[get indicator](#action-get-indicator) - Retrieve an Indicator entity by its ID <br>
[submit indicator](#action-submit-indicator) - Submit or Update new Indicator entity <br>
[update indicator](#action-update-indicator) - Update an existing Indicator entity <br>
[update indicator batch](#action-update-indicator-batch) - Update or create a batch of Indicator entities <br>
[get file alerts](#action-get-file-alerts) - Retrieve alerts related to a specific file hash <br>
[get device alerts](#action-get-device-alerts) - Retrieve all alerts related to a specific device <br>
[get user alerts](#action-get-user-alerts) - Retrieve alerts related to a specific user <br>
[get domain alerts](#action-get-domain-alerts) - Retrieve alerts related to a specific domain address <br>
[delete indicator](#action-delete-indicator) - Delete an Indicator entity by ID <br>
[run query](#action-run-query) - An advanced search query <br>
[get domain devices](#action-get-domain-devices) - Retrieve a collection of devices that have communicated to or from a given domain address <br>
[update device tag](#action-update-device-tag) - Add or remove a tag from a given device (Maximum: 200 characters) <br>
[get discovered vulnerabilities](#action-get-discovered-vulnerabilities) - Retrieve a collection of discovered vulnerabilities related to a given device ID <br>
[remove app restriction](#action-remove-app-restriction) - Enable execution of any application on the device <br>
[get exposure score](#action-get-exposure-score) - Retrieve the organizational exposure score <br>
[get secure score](#action-get-secure-score) - Retrieve your Microsoft Secure Score for devices <br>
[get file](#action-get-file) - Download a file from a device using live response <br>
[put file](#action-put-file) - Put a file from the library to a device using live response <br>
[cancel live response](#action-cancel-live-response) - Cancel a live response action <br>
[run script](#action-run-script) - Run a script from the library on a device using live response <br>
[get missing kbs](#action-get-missing-kbs) - Retrieve missing KBs (security updates) by given device ID

## action: 'test connectivity'

Validate the asset configuration for connectivity using the supplied configuration

Type: **test** <br>
Read only: **True**

#### Action Parameters

No parameters are required for this action

#### Action Output

No Output

## action: 'on poll'

Callback action for the on_poll ingest functionality for Defender for Endpoint

Type: **ingest** <br>
Read only: **True**

#### Action Parameters

PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**start_time** | optional | The start time to filter alerts by their last updated time. If not provided, defaults to the last 7 days | numeric | |
**end_time** | optional | Parameter ignored in this app | numeric | |
**container_count** | optional | The number of alerts to ingest in each poll. Default is 1000 | numeric | |
**artifact_count** | optional | Parameter ignored in this app | numeric | |
**container_id** | optional | Parameter ignored in this app | numeric | |

#### Action Output

No Output

## action: 'quarantine device'

Quarantine the device

Type: **contain** <br>
Read only: **False**

This action can take a while to complete execution. The action retries at an interval of 5 seconds within a specified <b>timeout</b> to check if event execution is complete. If not, the action would return the latest status of the event along with the event ID.<br>The <b>get status</b> action can be used to fetch the latest status of the event with the event ID.<br>For parameter <i>type</i>, <b>&quotFull&quot</b> will completely quarantine the device while <b>&quotSelective&quot</b> will allow Skype and Outlook to be accessed.<br>The maximum timeout period for a status check is 10 minutes.

#### Action Parameters

PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**device_id** | required | ID of the device to quarantine | string | `defender atp device id` |
**type** | required | Type of quarantine (Default: Full) | string | |
**comment** | required | Comment for quarantine | string | |
**timeout** | optional | Timeout in seconds (Default: 30) | numeric | |

#### Action Output

DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string | | success failed |
action_result.parameter.comment | string | | selective quarantine |
action_result.parameter.device_id | string | `defender atp device id` | 7af22c8a3f92ec0c9c49b80aee3379bf9bfa0768 |
action_result.parameter.timeout | numeric | | 130 |
action_result.parameter.type | string | | Full |
action_result.data.\*.@odata.context | string | `url` | https://api.securitycenter.windows.com/api/$metadata#MachineActions/$entity |
action_result.data.\*.cancellationComment | string | | |
action_result.data.\*.cancellationDateTimeUtc | string | | |
action_result.data.\*.cancellationRequestor | string | | |
action_result.data.\*.computerDnsName | string | | win10atp2 |
action_result.data.\*.creationDateTimeUtc | string | | 2019-05-03T08:50:05.8076226Z |
action_result.data.\*.error | string | | None |
action_result.data.\*.errorHResult | numeric | | 0 |
action_result.data.\*.externalId | string | | |
action_result.data.\*.id | string | `defender atp event id` | 6925706d-3a7e-4596-b2d7-321fca9cd965 |
action_result.data.\*.lastUpdateDateTimeUtc | string | | 2019-05-03T08:50:05.8076226Z |
action_result.data.\*.machineId | string | `defender atp device id` | 349838747f77ec74e43ab7ca70773a41f7bfb6f2 |
action_result.data.\*.relatedFileInfo | string | | |
action_result.data.\*.requestSource | string | | PublicApi |
action_result.data.\*.requestor | string | `email` | testuser@example.com |
action_result.data.\*.requestorComment | string | | Selective test |
action_result.data.\*.scope | string | | Full |
action_result.data.\*.status | string | | Succeeded |
action_result.data.\*.title | string | | |
action_result.data.\*.troubleshootInfo | string | | |
action_result.data.\*.type | string | | Isolate |
action_result.summary.event_id | string | `defender atp event id` | 6925706d-3a7e-4596-b2d7-321fca9cd965 |
action_result.summary.quarantine_status | string | | Pending |
action_result.message | string | | Event id: 6925706d-3a7e-4596-b2d7-321fca9cd965, Quarantine status: Pending |
summary.total_objects | numeric | | 1 |
summary.total_objects_successful | numeric | | 1 |

## action: 'unquarantine device'

Unquarantine the device

Type: **correct** <br>
Read only: **False**

This action can take a while to complete execution. The action retries at an interval of 5 seconds within a specified <b>timeout</b> to check if event execution is complete. If not, the action would return the latest status of the event along with the event ID.<br>The <b>get status</b> action can be used to fetch the latest status of the event with the event ID.<br>The maximum timeout period for a status check is 10 minutes.

#### Action Parameters

PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**device_id** | required | ID of the device to unquarantine | string | `defender atp device id` |
**comment** | required | Comment for unquarantine | string | |
**timeout** | optional | Timeout in seconds (Default: 30) | numeric | |

#### Action Output

DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string | | success failed |
action_result.parameter.comment | string | | unquarantine the device |
action_result.parameter.device_id | string | `defender atp device id` | 349838747f77ec74e43ab7ca70773a41f7bfb6f2 |
action_result.parameter.timeout | numeric | | 30 |
action_result.data.\*.@odata.context | string | `url` | https://api.securitycenter.windows.com/api/$metadata#MachineActions/$entity |
action_result.data.\*.cancellationComment | string | | |
action_result.data.\*.cancellationDateTimeUtc | string | | |
action_result.data.\*.cancellationRequestor | string | | |
action_result.data.\*.computerDnsName | string | | win10atp2 |
action_result.data.\*.creationDateTimeUtc | string | | 2019-05-03T08:52:22.7708738Z |
action_result.data.\*.error | string | | None |
action_result.data.\*.errorHResult | numeric | | 0 |
action_result.data.\*.externalId | string | | |
action_result.data.\*.id | string | `defender atp event id` | cb15e6e0-1d53-4762-9c37-f14d412ece9e |
action_result.data.\*.lastUpdateDateTimeUtc | string | | 2019-05-03T08:52:22.7708738Z |
action_result.data.\*.machineId | string | `defender atp device id` | 349838747f77ec74e43ab7ca70773a41f7bfb6f2 |
action_result.data.\*.relatedFileInfo | string | | |
action_result.data.\*.requestSource | string | | PublicApi |
action_result.data.\*.requestor | string | `email` | testuser@example.com |
action_result.data.\*.requestorComment | string | | isolation test |
action_result.data.\*.scope | string | | |
action_result.data.\*.status | string | | Pending |
action_result.data.\*.title | string | | |
action_result.data.\*.troubleshootInfo | string | | |
action_result.data.\*.type | string | | Unisolate |
action_result.summary.event_id | string | `defender atp event id` | cb15e6e0-1d53-4762-9c37-f14d412ece9e |
action_result.summary.unquarantine_status | string | | Pending |
action_result.message | string | | Event id: cb15e6e0-1d53-4762-9c37-f14d412ece9e, Unquarantine status: Pending |
summary.total_objects | numeric | | 1 |
summary.total_objects_successful | numeric | | 1 |

## action: 'get status'

Get status of the event on a machine

Type: **investigate** <br>
Read only: **True**

#### Action Parameters

PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**event_id** | required | ID of the event | string | `defender atp event id` |

#### Action Output

DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string | | success failed |
action_result.parameter.event_id | string | `defender atp event id` | f4ddc97a-6f4e-471c-9be5-45e0d6d64ab8 |
action_result.data.\*.@odata.context | string | `url` | https://api.securitycenter.windows.com/api/$metadata#MachineActions/$entity |
action_result.data.\*.cancellationComment | string | | |
action_result.data.\*.cancellationDateTimeUtc | string | | |
action_result.data.\*.cancellationRequestor | string | | |
action_result.data.\*.commands.\*.command.params.\*.key | string | | Path |
action_result.data.\*.commands.\*.command.params.\*.value | string | | C:\\share\\1.eml |
action_result.data.\*.commands.\*.command.type | string | | GetFile |
action_result.data.\*.commands.\*.commandStatus | string | | Created |
action_result.data.\*.commands.\*.endTime | string | | |
action_result.data.\*.commands.\*.index | numeric | | |
action_result.data.\*.commands.\*.startTime | string | | |
action_result.data.\*.computerDnsName | string | | win10atp2 |
action_result.data.\*.creationDateTimeUtc | string | | 2019-05-03T09:01:19.3478911Z |
action_result.data.\*.error | string | | None |
action_result.data.\*.errorHResult | numeric | | 0 |
action_result.data.\*.externalId | string | | |
action_result.data.\*.fileInstances | string | | |
action_result.data.\*.id | string | `defender atp event id` | f4ddc97a-6f4e-471c-9be5-45e0d6d64ab8 |
action_result.data.\*.lastUpdateDateTimeUtc | string | | 2019-05-03T09:01:27.6955788Z |
action_result.data.\*.machineId | string | `defender atp device id` | ae2e5bda4bb22ec9c321680079d03e5e4cdff400 |
action_result.data.\*.relatedFileInfo | string | | |
action_result.data.\*.relatedFileInfo.fileIdentifier | string | `sha1` | 2dba4c14a5e97312f9edf617e1c8b0cc0d387fd8 |
action_result.data.\*.relatedFileInfo.fileIdentifierType | string | | Sha1 |
action_result.data.\*.requestSource | string | | PublicApi |
action_result.data.\*.requestor | string | `email` | test.user@example.onmicrosoft.com |
action_result.data.\*.requestorComment | string | | test |
action_result.data.\*.scope | string | | |
action_result.data.\*.sha1 | string | `sha1` | 11ffeabbe42159e1365aa82463d8690c845ce7b7 |
action_result.data.\*.status | string | | Succeeded |
action_result.data.\*.title | string | | |
action_result.data.\*.troubleshootInfo | string | | |
action_result.data.\*.type | string | | RunAntiVirusScan |
action_result.summary.event_status | string | | Succeeded |
action_result.message | string | | Event status: Succeeded |
summary.total_objects | numeric | | 1 |
summary.total_objects_successful | numeric | | 1 |

## action: 'scan device'

Scan a device for virus

Type: **investigate** <br>
Read only: **True**

This action can take a while to complete execution. The action retries at an interval of 5 seconds within a specified <b>timeout</b> to check if event execution is complete. If not, the action would return the latest status of the event along with the event ID.<br>The <b>get status</b> action can be used to fetch the latest status of the event with the event ID.<br>The maximum timeout period for a status check is 1 hour.

#### Action Parameters

PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**device_id** | required | ID of the device to scan | string | `defender atp device id` |
**scan_type** | required | Type of scan | string | |
**comment** | required | Comment for scan | string | |
**timeout** | optional | Timeout in seconds (Default: 30) | numeric | |

#### Action Output

DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string | | success failed |
action_result.parameter.comment | string | | Scanning from Test |
action_result.parameter.device_id | string | `defender atp device id` | a3627cbcad1e9ca2dd94eed63e3f9260e2aa7e8e |
action_result.parameter.scan_type | string | | Quick |
action_result.parameter.timeout | numeric | | 30 |
action_result.data.\*.@odata.context | string | `url` | https://api.securitycenter.windows.com/api/$metadata#MachineActions/$entity |
action_result.data.\*.cancellationComment | string | | |
action_result.data.\*.cancellationDateTimeUtc | string | | |
action_result.data.\*.cancellationRequestor | string | | |
action_result.data.\*.computerDnsName | string | | win10atp2 |
action_result.data.\*.creationDateTimeUtc | string | | 2018-07-12T11:35:30.8573959Z |
action_result.data.\*.error | string | | None |
action_result.data.\*.errorHResult | numeric | | 0 |
action_result.data.\*.externalId | string | | |
action_result.data.\*.id | string | `defender atp event id` | 34a0905e-316b-46eb-994d-c7d0e8ac2efb |
action_result.data.\*.lastUpdateDateTimeUtc | string | | 2018-07-12T11:35:30.8573959Z |
action_result.data.\*.machineId | string | `defender atp device id` | a3627cbcad1e9ca2dd94eed63e3f9260e2aa7e8e |
action_result.data.\*.relatedFileInfo | string | | |
action_result.data.\*.requestSource | string | | PublicApi |
action_result.data.\*.requestor | string | `email` | testuser@example.com |
action_result.data.\*.requestorComment | string | | From Test |
action_result.data.\*.scope | string | | Quick |
action_result.data.\*.status | string | | InProgress |
action_result.data.\*.title | string | | |
action_result.data.\*.troubleshootInfo | string | | |
action_result.data.\*.type | string | | RunAntiVirusScan |
action_result.summary.event_id | string | `defender atp event id` | 34a0905e-316b-46eb-994d-c7d0e8ac2efb |
action_result.summary.scan_status | string | | InProgress |
action_result.message | string | | Event id: 34a0905e-316b-46eb-994d-c7d0e8ac2efb, Scan status: InProgress |
summary.total_objects | numeric | | 1 |
summary.total_objects_successful | numeric | | 1 |

## action: 'quarantine file'

Quarantine a file

Type: **contain** <br>
Read only: **False**

This action can take a while to complete execution. The action retries at an interval of 5 seconds within a specified <b>timeout</b> to check if event execution is complete. If not, the action would return the latest status of the event along with the event ID.<br>The <b>get status</b> action can be used to fetch the latest status of the event with the event ID.<br>The maximum timeout period for a status check is 10 minutes.

#### Action Parameters

PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**device_id** | required | ID of the device | string | `defender atp device id` |
**file_hash** | required | Identifier of the file | string | `sha1` |
**comment** | required | Comment for quarantine | string | |
**timeout** | optional | Timeout in seconds (Default: 30) | numeric | |

#### Action Output

DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string | | success failed |
action_result.parameter.comment | string | | Test comment for file quarantine |
action_result.parameter.device_id | string | `defender atp device id` | ae2e5bda4bb22ec9c321680079d03e5e4cdff400 |
action_result.parameter.file_hash | string | `sha1` | 2dba4c14a5e97312f9edf617e1c8b0cc0d387fd8 |
action_result.parameter.timeout | numeric | | 125 |
action_result.data.\*.@odata.context | string | `url` | https://api.securitycenter.windows.com/api/$metadata#MachineActions/$entity |
action_result.data.\*.cancellationComment | string | | |
action_result.data.\*.cancellationDateTimeUtc | string | | |
action_result.data.\*.cancellationRequestor | string | | |
action_result.data.\*.computerDnsName | string | | win10atp2 |
action_result.data.\*.creationDateTimeUtc | string | | 2019-05-03T06:00:00.2740597Z |
action_result.data.\*.error | string | | None |
action_result.data.\*.errorHResult | numeric | | 0 |
action_result.data.\*.externalId | string | | |
action_result.data.\*.fileId | string | `sha1` | e1049556edc2b28ef25b2932c722e4dc927e9d04 |
action_result.data.\*.fileInstances.\*.filePath | string | `file path` | |
action_result.data.\*.fileInstances.\*.status | string | | |
action_result.data.\*.id | string | `defender atp event id` | 76e82ecd-54b8-400d-83be-a05d582b3546 |
action_result.data.\*.lastUpdateDateTimeUtc | string | | 2019-05-03T06:00:00.2740597Z |
action_result.data.\*.machineId | string | `defender atp device id` | ae2e5bda4bb22ec9c321680079d03e5e4cdff400 |
action_result.data.\*.relatedFileInfo.fileIdentifier | string | `sha1` | 2dba4c14a5e97312f9edf617e1c8b0cc0d387fd8 |
action_result.data.\*.relatedFileInfo.fileIdentifierType | string | | Sha1 |
action_result.data.\*.requestSource | string | | PublicApi |
action_result.data.\*.requestor | string | `email` | testuser@example.com |
action_result.data.\*.requestorComment | string | | file quarantine |
action_result.data.\*.scope | string | | |
action_result.data.\*.sha1 | string | `sha1` | e1049556edc2b28ef25b2932c722e4dc927e9d04 |
action_result.data.\*.status | string | | Pending |
action_result.data.\*.title | string | | |
action_result.data.\*.troubleshootInfo | string | | |
action_result.data.\*.type | string | | StopAndQuarantineFile |
action_result.summary.event_id | string | `defender atp event id` | 76e82ecd-54b8-400d-83be-a05d582b3546 |
action_result.summary.quarantine_status | string | | InProgress |
action_result.message | string | | Event id: 76e82ecd-54b8-400d-83be-a05d582b3546, Quarantine status: Pending |
summary.total_objects | numeric | | 1 |
summary.total_objects_successful | numeric | | 1 |

## action: 'get active users'

Get active users on a device

Type: **investigate** <br>
Read only: **True**

Based on the link (<a href="https://learn.microsoft.com/en-us/defender-endpoint/api/get-machine-log-on-users" target="_blank">Get Active Users API Documentation</a>).

#### Action Parameters

PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**device_id** | required | ID of the device | string | `defender atp device id` |

#### Action Output

DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string | | success failed |
action_result.parameter.device_id | string | `defender atp device id` | |
action_result.data.\*.id | string | `defender atp user id` | |
action_result.data.\*.accountName | string | | |
action_result.data.\*.accountDomain | string | | |
action_result.data.\*.firstSeen | string | | |
action_result.data.\*.lastSeen | string | | |
action_result.data.\*.logonTypes | string | | |
action_result.data.\*.isDomainAdmin | boolean | | |
action_result.data.\*.isOnlyNetworkUser | boolean | | |
action_result.summary.total_results | numeric | | |
action_result.summary.action_taken | string | | Retrieved Active Users |
action_result.message | string | | |
summary.total_objects | numeric | | |
summary.total_objects_successful | numeric | | |

## action: 'list devices'

List of recently seen devices

Type: **investigate** <br>
Read only: **True**

Based on the link (<a href="https://docs.microsoft.com/en-us/windows/security/threat-protection/microsoft-defender-atp/get-machines" target="_blank">List Machines API Documentation</a>), the user can get devices last seen in the past 30 days; the maximum page size is 10,000; rate limitations for this action are 100 calls per minute and 1500 calls per hour. If the user does not specify the limit value, it will fetch 100 devices by default.

#### Action Parameters

PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**input_type** | required | Type of input (Default: All) | string | |
**input** | optional | Input filter of type Domain, File hash or All | string | `sha1` `sha256` `md5` `domain` |
**query** | optional | Additional OData V4 filters to apply | string | |
**limit** | optional | Maximum number of devices to return (Maximum: 10,000) | numeric | |

#### Action Output

DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string | | success failed |
action_result.parameter.input | string | `sha1` `sha256` `md5` `domain` | filehash |
action_result.parameter.input_type | string | | All |
action_result.parameter.limit | numeric | | 100 |
action_result.parameter.query | string | | $filter=riskScore+eq+'High' |
action_result.data.\*.aadDeviceId | string | | |
action_result.data.\*.agentVersion | string | | 10.5850.17763.404 |
action_result.data.\*.computerDnsName | string | `domain` | desktop-ph2a1ro |
action_result.data.\*.defenderAvStatus | string | | NotSupported |
action_result.data.\*.deviceValue | string | | Normal |
action_result.data.\*.exposureLevel | string | | Medium |
action_result.data.\*.firstSeen | string | | 2019-04-16T00:27:12.2677222Z |
action_result.data.\*.groupName | string | | |
action_result.data.\*.healthStatus | string | | Active |
action_result.data.\*.id | string | `defender atp device id` | ae2e5bda4bb22ec9c321680079d03e5e4cdff400 |
action_result.data.\*.ipAddresses.\*.ipAddress | string | | 10.0.2.15 |
action_result.data.\*.ipAddresses.\*.macAddress | string | | 002248242A86 |
action_result.data.\*.ipAddresses.\*.operationalStatus | string | | Up |
action_result.data.\*.ipAddresses.\*.type | string | | Ethernet |
action_result.data.\*.isAadJoined | boolean | | True False |
action_result.data.\*.lastExternalIpAddress | string | `ip` | 204.107.141.240 |
action_result.data.\*.lastIpAddress | string | `ip` | 10.1.66.140 |
action_result.data.\*.lastSeen | string | | 2019-05-03T05:23:45.9643247Z |
action_result.data.\*.machineTags | string | | Test Tag -21 |
action_result.data.\*.managedBy | string | | |
action_result.data.\*.managedByStatus | string | | |
action_result.data.\*.onboardingStatus | string | | Onboarded |
action_result.data.\*.osArchitecture | string | | 64-bit |
action_result.data.\*.osBuild | numeric | | 17763 |
action_result.data.\*.osPlatform | string | | Windows10 |
action_result.data.\*.osProcessor | string | | x64 |
action_result.data.\*.osVersion | string | | |
action_result.data.\*.rbacGroupId | numeric | | 0 |
action_result.data.\*.rbacGroupName | string | | GROUP1 |
action_result.data.\*.riskScore | string | | None |
action_result.data.\*.systemProductName | string | | |
action_result.data.\*.version | string | | 1809 |
action_result.data.\*.vmMetadata | string | | |
action_result.data.\*.vmMetadata.cloudProvider | string | | Azure |
action_result.data.\*.vmMetadata.resourceId | string | | |
action_result.data.\*.vmMetadata.subscriptionId | string | | 1b922e46-8595-4749-997a-1205e714cd91 |
action_result.data.\*.vmMetadata.vmId | string | | 79980585-d655-43f7-80d9-5b9d34b2e30d |
action_result.summary.total_devices | numeric | | 2 |
action_result.message | string | | Total devices: 2 |
summary.total_objects | numeric | | 1 |
summary.total_objects_successful | numeric | | 1 |

## action: 'list alerts'

List all alerts of a given type

Type: **investigate** <br>
Read only: **True**

Based on the link (<a href="https://docs.microsoft.com/en-us/windows/security/threat-protection/microsoft-defender-atp/get-alerts" target="_blank">List Alerts API Documentation</a>), the user can get alerts last updated in the past 30 days; the maximum page size is 10,000; rate limitations for this action are 100 calls per minute and 1500 calls per hour. If the user does not specify the limit value, it will fetch 100 alerts by default.

#### Action Parameters

PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**input_type** | optional | Type of input (Default: All) | string | |
**input** | optional | Input filter of type Domain, File Hash, and IP | string | `domain` `sha1` `sha256` `md5` `ip` |
**limit** | optional | Maximum number of alerts to return (Maximum: 10,000) | numeric | |

#### Action Output

DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string | | success failed |
action_result.parameter.input | string | `domain` `sha1` `sha256` `md5` `ip` | 1b3b40fbc889fd4c645cc12c85d0805ac36ba254 fda7:e6ee:2e09:0:19f9:12ea:c80d:cf5b google.com |
action_result.parameter.input_type | string | | All |
action_result.parameter.limit | numeric | | 100 |
action_result.data.\*.aadTenantId | string | | 7810-b62a-4fc0-bbbb-20165d183d7f |
action_result.data.\*.alertCreationTime | string | | 2019-05-03T01:20:51.8699882Z |
action_result.data.\*.assignedTo | string | `email` | testuser@example.com |
action_result.data.\*.category | string | | General |
action_result.data.\*.classification | string | | |
action_result.data.\*.comments.\*.comment | string | | test |
action_result.data.\*.comments.\*.createdBy | string | `email` | test@example.onmicrosoft.com |
action_result.data.\*.comments.\*.createdTime | string | | 2019-05-01T13:21:37.869889Z |
action_result.data.\*.computerDnsName | string | | win10atp1 |
action_result.data.\*.description | string | | Malware and unwanted software are undesirable applications that perform annoying, disruptive, or harmful actions on affected machines. Some of these undesirable applications can replicate and spread from one machine to another. Others can able to receive commands from remote attackers and perform activities associated with cyber attacks. This detection might indicate that Windows Defender has stopped the malware from delivering its payload. However, it is prudent to check the machine for signs of infection. |
action_result.data.\*.detectionSource | string | | WindowsDefenderAv |
action_result.data.\*.detectorId | string | | 5c6b7d86-c91f-4f8c-8aec-9d2086f46527 |
action_result.data.\*.determination | string | | |
action_result.data.\*.evidence.\*.aadUserId | string | | |
action_result.data.\*.evidence.\*.accountName | string | | |
action_result.data.\*.evidence.\*.detectionStatus | string | | |
action_result.data.\*.evidence.\*.domainName | string | | |
action_result.data.\*.evidence.\*.entityType | string | | Url |
action_result.data.\*.evidence.\*.evidenceCreationTime | string | | 2022-06-10T06:26:09.5133333Z |
action_result.data.\*.evidence.\*.fileName | string | | |
action_result.data.\*.evidence.\*.filePath | string | | |
action_result.data.\*.evidence.\*.ipAddress | string | | |
action_result.data.\*.evidence.\*.parentProcessCreationTime | string | | |
action_result.data.\*.evidence.\*.parentProcessFileName | string | | |
action_result.data.\*.evidence.\*.parentProcessFilePath | string | | |
action_result.data.\*.evidence.\*.parentProcessId | string | | |
action_result.data.\*.evidence.\*.processCommandLine | string | | |
action_result.data.\*.evidence.\*.processCreationTime | string | | |
action_result.data.\*.evidence.\*.processId | string | | |
action_result.data.\*.evidence.\*.registryHive | string | | |
action_result.data.\*.evidence.\*.registryKey | string | | |
action_result.data.\*.evidence.\*.registryValue | string | | |
action_result.data.\*.evidence.\*.registryValueName | string | | |
action_result.data.\*.evidence.\*.registryValueType | string | | |
action_result.data.\*.evidence.\*.sha1 | string | | |
action_result.data.\*.evidence.\*.sha256 | string | | |
action_result.data.\*.evidence.\*.url | string | | google.com |
action_result.data.\*.evidence.\*.userPrincipalName | string | | |
action_result.data.\*.evidence.\*.userSid | string | | |
action_result.data.\*.firstEventTime | string | | 2019-05-02T23:03:43.2077683Z |
action_result.data.\*.id | string | `defender atp alert id` | 636924432519012302_1685044642 |
action_result.data.\*.incidentId | numeric | | 11 |
action_result.data.\*.investigationId | numeric | | 10 |
action_result.data.\*.investigationState | string | | Benign |
action_result.data.\*.lastEventTime | string | | 2019-05-02T23:03:43.2077683Z |
action_result.data.\*.lastUpdateTime | string | | 2019-05-03T01:29:51.9233333Z |
action_result.data.\*.loggedOnUsers.\*.accountName | string | | Test |
action_result.data.\*.loggedOnUsers.\*.domainName | string | | WINATPC1 |
action_result.data.\*.machineId | string | `defender atp device id` | ae2e5bda4bb22ec9c321680079d03e5e4cdff400 |
action_result.data.\*.rbacGroupName | string | | UnassignedGroup |
action_result.data.\*.recommendedAction | string | | Collect artifacts and determine scope Review the machine timeline for suspicious activities that may have occurred before and after the time of the alert, and record additional related artifacts (files, IPs/URLs) Look for the presence of relevant artifacts on other systems. Identify commonalities and differences between potentially compromised systems. Submit relevant files for deep analysis and review resulting in detailed behavioral information. Submit undetected files to the MMPC malware portal Initiate containment & mitigation Contact the user to verify intent and initiate local remediation actions as needed. Update AV signatures and run a full scan. The scan might reveal and remove previously-undetected malware components. Ensure that the machine has the latest security updates. In particular, ensure that you have installed the latest software, web browser, and Operating System versions. If credential theft is suspected, reset all relevant users' passwords. Block communication with relevant URLs or IPs at the organization's perimeter. |
action_result.data.\*.relatedUser | string | | |
action_result.data.\*.relatedUser.domainName | string | | WINATPC1 |
action_result.data.\*.relatedUser.userName | string | | Test |
action_result.data.\*.resolvedTime | string | | 2019-05-03T01:29:51.7614303Z |
action_result.data.\*.severity | string | | Informational |
action_result.data.\*.status | string | | Resolved |
action_result.data.\*.threatFamilyName | string | | Fuery |
action_result.data.\*.threatName | string | | |
action_result.data.\*.title | string | | Windows Defender AV detected 'Fuery' malware |
action_result.summary.total_alerts | numeric | | 12 |
action_result.message | string | | Total alerts: 12 |
summary.total_objects | numeric | | 1 |
summary.total_objects_successful | numeric | | 1 |

## action: 'list sessions'

List all logged in users on a machine

Type: **investigate** <br>
Read only: **True**

Based on the link (<a href="https://docs.microsoft.com/en-us/windows/security/threat-protection/microsoft-defender-atp/get-machine-log-on-users" target="_blank">List Sessions API Documentation</a>), the user can query on machines last seen in the past 30 days; rate limitations for this action are 100 calls per minute and 1500 calls per hour.

#### Action Parameters

PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**device_id** | required | ID of the device | string | `defender atp device id` |

#### Action Output

DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string | | success failed |
action_result.parameter.device_id | string | `defender atp device id` | 7af22c8a3f92ec0c9c49b80aee3379bf9bfa0768 |
action_result.data.\*.accountDomain | string | `domain` | win10atp1 |
action_result.data.\*.accountDomainName | string | `domain` | desktop-gq5jf56 |
action_result.data.\*.accountName | string | | example |
action_result.data.\*.accountSid | string | | |
action_result.data.\*.firstSeen | string | | 2018-07-06T00:00:00Z |
action_result.data.\*.id | string | | desktop-gq5jf56\\example |
action_result.data.\*.isDomainAdmin | boolean | | True False |
action_result.data.\*.isOnlyNetworkUser | string | | |
action_result.data.\*.lastSeen | string | | 2018-07-06T00:00:00Z |
action_result.data.\*.leastPrevalentMachineId | string | `sha1` | |
action_result.data.\*.logOnMachinesCount | numeric | | 1 |
action_result.data.\*.logonTypes | string | | Network, RemoteInteractive |
action_result.data.\*.mostPrevalentMachineId | string | `sha1` | |
action_result.summary.total_sessions | numeric | | 1 |
action_result.message | string | | Total sessions: 1 |
summary.total_objects | numeric | | 1 |
summary.total_objects_successful | numeric | | 1 |

## action: 'list software'

Retrieve the organization's software inventory

Type: **investigate** <br>
Read only: **True**

Based on the link (<a href="https://learn.microsoft.com/en-us/defender-endpoint/api/get-software" target="_blank">Get Software API Documentation</a>).

#### Action Parameters

PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**id** | optional | ID of the software | string | `defender atp software id` |
**name** | optional | Name of the software | string | |
**vendor** | optional | Vendor of the software | string | |
**limit** | optional | Maximum number of results to return | numeric | |
**offset** | optional | Number of results to offset | numeric | |

#### Action Output

DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string | | success failed |
action_result.parameter.id | string | `defender atp software id` | |
action_result.parameter.name | string | | |
action_result.parameter.vendor | string | | |
action_result.parameter.limit | numeric | | |
action_result.parameter.offset | numeric | | |
action_result.data.\*.id | string | `defender atp software id` | |
action_result.data.\*.name | string | | |
action_result.data.\*.vendor | string | | |
action_result.data.\*.weaknesses | numeric | | |
action_result.data.\*.publicExploit | numeric | | |
action_result.data.\*.activeAlert | numeric | | |
action_result.data.\*.exposedMachines | numeric | | |
action_result.data.\*.installedMachines | numeric | | |
action_result.data.\*.impactScore | numeric | | |
action_result.data.\*.isNormalized | numeric | | |
action_result.data.\*.category | string | | |
action_result.summary.total_software | numeric | | |
action_result.message | string | | |
summary.total_objects | numeric | | |
summary.total_objects_successful | numeric | | |

## action: 'list software versions'

Retrieve a list of organization's software version distribution

Type: **investigate** <br>
Read only: **True**

Based on the link (<a href="https://learn.microsoft.com/en-us/defender-endpoint/api/get-software-ver-distribution" target="_blank">Get Software Distribution API Documentation</a>).

#### Action Parameters

PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**id** | required | ID of the software | string | `defender atp software id` |

#### Action Output

DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string | | success failed |
action_result.parameter.id | string | `defender atp software id` | |
action_result.data.\*.version | string | | |
action_result.data.\*.installations | numeric | | |
action_result.data.\*.vulnerabilities | numeric | | |
action_result.summary.total_versions | numeric | | |
action_result.message | string | | |
summary.total_objects | numeric | | |
summary.total_objects_successful | numeric | | |

## action: 'list software devices'

Retrieve a list of devices that have a specific software installed

Type: **investigate** <br>
Read only: **True**

Based on the link (<a href="https://learn.microsoft.com/en-us/defender-endpoint/api/get-machines-by-software" target="_blank">Get Devices With Software Installed API Documentation</a>).

#### Action Parameters

PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**id** | required | ID of the software | string | `defender atp software id` |

#### Action Output

DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string | | success failed |
action_result.parameter.id | string | `defender atp software id` | |
action_result.data.\*.id | string | `defender atp device id` | |
action_result.data.\*.computerDnsName | string | | |
action_result.data.\*.osPlatform | string | | |
action_result.data.\*.rbacGroupName | string | | |
action_result.data.\*.rbacGroupId | string | | |
action_result.summary.total_devices | numeric | | |
action_result.message | string | | |
summary.total_objects | numeric | | |
summary.total_objects_successful | numeric | | |

## action: 'list software vulnerabilities'

Retrieve vulnerabilities associated with a specific software

Type: **investigate** <br>
Read only: **True**

Based on the link (<a href="https://learn.microsoft.com/en-us/defender-endpoint/api/get-vuln-by-software" target="_blank">Get Vulnerabilities By Software API Documentation</a>).

#### Action Parameters

PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**id** | required | ID of the software | string | `defender atp software id` |

#### Action Output

DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string | | success failed |
action_result.parameter.id | string | `defender atp software id` | |
action_result.data.\*.id | string | `defender atp vulnerability id` | |
action_result.data.\*.name | string | | |
action_result.data.\*.description | string | | |
action_result.data.\*.severity | string | | |
action_result.data.\*.cvssV3 | numeric | | |
action_result.data.\*.exposedMachines | numeric | | |
action_result.data.\*.publishedOn | string | | |
action_result.data.\*.updatedOn | string | | |
action_result.data.\*.firstDetected | string | | |
action_result.data.\*.publicExploit | boolean | | |
action_result.data.\*.exploitVerified | boolean | | |
action_result.data.\*.exploitInKit | boolean | | |
action_result.summary.total_vulnerabilities | numeric | | |
action_result.message | string | | |
summary.total_objects | numeric | | |
summary.total_objects_successful | numeric | | |

## action: 'list device vulnerabilities'

Retrieve vulnerabilities affecting devices or software in organization

Type: **investigate** <br>
Read only: **True**

Based on the link (<a href="https://learn.microsoft.com/en-us/defender-endpoint/api/get-all-vulnerabilities-by-machines" target="_blank">Get Machines by Vulnerability API Documentation</a>).

#### Action Parameters

PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**device_id** | optional | ID of the device | string | `defender atp device id` |
**software_id** | optional | ID of the software | string | `defender atp software id` |
**cve_id** | optional | CVE ID | string | `cve id` |
**product_name** | optional | Name of the product | string | |
**product_version** | optional | Version of the product | string | |
**severity** | optional | Severity of the vulnerability | string | |
**product_vendor** | optional | Vendor of the product | string | |
**limit** | optional | Maximum number of results to return | numeric | |
**offset** | optional | Number of results to skip | numeric | |

#### Action Output

DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string | | success failed |
action_result.parameter.device_id | string | `defender atp device id` | |
action_result.parameter.software_id | string | `defender atp software id` | |
action_result.parameter.cve_id | string | `cve id` | |
action_result.parameter.product_name | string | | |
action_result.parameter.product_version | string | | |
action_result.parameter.severity | string | | |
action_result.parameter.product_vendor | string | | |
action_result.parameter.limit | numeric | | |
action_result.parameter.offset | numeric | | |
action_result.data.\*.id | string | `defender atp software id` | |
action_result.data.\*.cveId | string | `cve id` | |
action_result.data.\*.machineId | string | `defender atp device id` | |
action_result.data.\*.productName | string | | |
action_result.data.\*.productVendor | string | | |
action_result.data.\*.productVersion | string | | |
action_result.data.\*.severity | string | | |
action_result.summary.total_vulnerabilities | numeric | | |
action_result.message | string | | |
summary.total_objects | numeric | | |
summary.total_objects_successful | numeric | | |

## action: 'list vulnerabilities'

Retrieve a list of vulnerabilities based on filters

Type: **investigate** <br>
Read only: **True**

Based on the link (<a href="https://learn.microsoft.com/en-us/defender-endpoint/api/get-all-vulnerabilities" target="_blank">Get Vulnerabilities API Documentation</a>).

#### Action Parameters

PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**id** | optional | ID of the vulnerability | string | `cve id` |
**name_equal** | optional | Exact name of the vulnerability | string | |
**name_contains** | optional | Name contains this string | string | |
**description_contains** | optional | Description contains this string | string | |
**published_on** | optional | Date when the vulnerability was published | string | |
**cvss** | optional | CVSS score | numeric | |
**severity** | optional | Severity of the vulnerability | string | |
**updated_on** | optional | Date when the vulnerability was last updated | string | |
**limit** | optional | Maximum number of results to return | numeric | |
**offset** | optional | Number of results to skip | numeric | |

#### Action Output

DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string | | success failed |
action_result.parameter.id | string | `cve id` | |
action_result.parameter.name_equal | string | | |
action_result.parameter.name_contains | string | | |
action_result.parameter.description_contains | string | | |
action_result.parameter.published_on | string | | |
action_result.parameter.cvss | numeric | | |
action_result.parameter.severity | string | | |
action_result.parameter.updated_on | string | | |
action_result.parameter.limit | numeric | | |
action_result.parameter.offset | numeric | | |
action_result.data.\*.id | string | `cve id` | |
action_result.data.\*.name | string | | |
action_result.data.\*.description | string | | |
action_result.data.\*.severity | string | | |
action_result.data.\*.cvssV3 | numeric | | |
action_result.data.\*.cvssVector | string | | |
action_result.data.\*.exposedMachines | numeric | | |
action_result.data.\*.publishedOn | string | | |
action_result.data.\*.updatedOn | string | | |
action_result.data.\*.firstDetected | string | | |
action_result.data.\*.publicExploit | boolean | | |
action_result.data.\*.exploitVerified | boolean | | |
action_result.data.\*.exploitInKit | boolean | | |
action_result.data.\*.cveSupportability | string | | |
action_result.data.\*.epss | numeric | | |
action_result.summary.total_vulnerabilities | numeric | | |
action_result.message | string | | |
summary.total_objects | numeric | | |
summary.total_objects_successful | numeric | | |

## action: 'get alert'

Retrieve specific Alert by its ID

Type: **investigate** <br>
Read only: **True**

Based on the link (<a href="https://docs.microsoft.com/en-us/microsoft-365/security/defender-endpoint/get-alert-info-by-id" target="_blank">Get Alert Information by ID API Documentation</a>), user can get alerts last updated according to your configured retention period.; rate limitations for this action are 100 calls per minute and 1500 calls per hour.

#### Action Parameters

PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**alert_id** | required | ID of the alert | string | `defender atp alert id` |

#### Action Output

DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string | | success failed |
action_result.parameter.alert_id | string | `defender atp alert id` | |
action_result.data.\*.@odata.context | string | `url` | https://api.securitycenter.windows.com/api/$metadata#Alerts/$entity |
action_result.data.\*.aadTenantId | string | | |
action_result.data.\*.alertCreationTime | string | | |
action_result.data.\*.assignedTo | string | | |
action_result.data.\*.category | string | | |
action_result.data.\*.classification | string | | |
action_result.data.\*.comments.\*.comment | string | | Test |
action_result.data.\*.comments.\*.createdBy | string | | Automation |
action_result.data.\*.comments.\*.createdTime | string | | 2022-04-08T18:03:45.6064942Z |
action_result.data.\*.computerDnsName | string | | |
action_result.data.\*.description | string | | |
action_result.data.\*.detectionSource | string | | |
action_result.data.\*.detectorId | string | | |
action_result.data.\*.determination | string | | |
action_result.data.\*.evidence.\*.aadUserId | string | | |
action_result.data.\*.evidence.\*.accountName | string | | |
action_result.data.\*.evidence.\*.detectionStatus | string | | |
action_result.data.\*.evidence.\*.domainName | string | `domain` | |
action_result.data.\*.evidence.\*.entityType | string | | |
action_result.data.\*.evidence.\*.evidenceCreationTime | string | | |
action_result.data.\*.evidence.\*.fileName | string | `file name` | |
action_result.data.\*.evidence.\*.filePath | string | `file path` | |
action_result.data.\*.evidence.\*.ipAddress | string | `ip` | |
action_result.data.\*.evidence.\*.parentProcessCreationTime | string | | |
action_result.data.\*.evidence.\*.parentProcessFileName | string | | |
action_result.data.\*.evidence.\*.parentProcessFilePath | string | | |
action_result.data.\*.evidence.\*.parentProcessId | string | `pid` | |
action_result.data.\*.evidence.\*.processCommandLine | string | | |
action_result.data.\*.evidence.\*.processCreationTime | string | | |
action_result.data.\*.evidence.\*.processId | string | `pid` | |
action_result.data.\*.evidence.\*.registryHive | string | | |
action_result.data.\*.evidence.\*.registryKey | string | | |
action_result.data.\*.evidence.\*.registryValue | string | | |
action_result.data.\*.evidence.\*.registryValueName | string | | |
action_result.data.\*.evidence.\*.registryValueType | string | | |
action_result.data.\*.evidence.\*.sha1 | string | `sha1` | |
action_result.data.\*.evidence.\*.sha256 | string | `sha256` | |
action_result.data.\*.evidence.\*.url | string | | |
action_result.data.\*.evidence.\*.userPrincipalName | string | | |
action_result.data.\*.evidence.\*.userSid | string | | |
action_result.data.\*.firstEventTime | string | | |
action_result.data.\*.id | string | `defender atp alert id` | |
action_result.data.\*.incidentId | numeric | | |
action_result.data.\*.investigationId | numeric | | |
action_result.data.\*.investigationState | string | | |
action_result.data.\*.lastEventTime | string | | |
action_result.data.\*.lastUpdateTime | string | | |
action_result.data.\*.loggedOnUsers.\*.accountName | string | | TestUser |
action_result.data.\*.loggedOnUsers.\*.domainName | string | | WINATPC2 |
action_result.data.\*.machineId | string | `defender atp device id` | |
action_result.data.\*.rbacGroupName | string | | |
action_result.data.\*.relatedUser | string | | |
action_result.data.\*.relatedUser.domainName | string | | WINATPC1 |
action_result.data.\*.relatedUser.userName | string | | TestUser |
action_result.data.\*.resolvedTime | string | | |
action_result.data.\*.severity | string | | |
action_result.data.\*.status | string | | |
action_result.data.\*.threatFamilyName | string | | |
action_result.data.\*.threatName | string | | |
action_result.data.\*.title | string | | |
action_result.summary.action_taken | string | | Retrieved Alert |
action_result.message | string | | Action taken: Retrieved Alert |
summary.total_objects | numeric | | 1 |
summary.total_objects_successful | numeric | | 1 |

## action: 'get alert user'

Retrieve user for specific Alert from its ID

Type: **investigate** <br>
Read only: **True**

#### Action Parameters

PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**alert_id** | required | ID of alert | string | `defender atp alert id` |

#### Action Output

DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string | | success failed |
action_result.parameter.alert_id | string | `defender atp alert id` | |
action_result.data.\*.id | string | `defender atp user id` | |
action_result.data.\*.accountName | string | | |
action_result.data.\*.accountDomain | string | | |
action_result.data.\*.accountSid | string | | |
action_result.data.\*.firstSeen | string | | |
action_result.data.\*.lastSeen | string | | |
action_result.data.\*.mostPrevalentMachineId | string | | |
action_result.data.\*.leastPrevalentMachineId | string | | |
action_result.data.\*.logonTypes | string | | |
action_result.data.\*.logOnMachinesCount | numeric | | |
action_result.data.\*.isDomainAdmin | boolean | | |
action_result.data.\*.isOnlyNetworkUser | boolean | | |
action_result.message | string | | |
summary.action_taken | string | | Retrieved Assigned User for Alert |
summary.total_objects | numeric | | 1 |
summary.total_objects_successful | numeric | | 1 |

## action: 'get alert files'

Retrieve files for specific Alert from its ID

Type: **investigate** <br>
Read only: **True**

#### Action Parameters

PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**alert_id** | required | ID of the alert | string | `defender atp alert id` |
**limit** | optional | Maximum number of files to return | numeric | |
**offset** | optional | Offset for pagination | numeric | |

#### Action Output

DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string | | success failed |
action_result.parameter.alert_id | string | `defender atp alert id` | |
action_result.parameter.limit | numeric | | |
action_result.parameter.offset | numeric | | |
action_result.data.\*.determinationType | string | | |
action_result.data.\*.determinationValue | string | | |
action_result.data.\*.fileProductName | string | | |
action_result.data.\*.filePublisher | string | | |
action_result.data.\*.fileType | string | | |
action_result.data.\*.isPeFile | boolean | | |
action_result.data.\*.isValidCertificate | boolean | | |
action_result.data.\*.size | numeric | | |
action_result.data.\*.issuer | string | | |
action_result.data.\*.globalFirstObserved | string | | |
action_result.data.\*.globalPrevalence | numeric | | |
action_result.data.\*.globalLastObserved | string | | |
action_result.data.\*.md5 | string | `md5` | 44adb27786eb24e5bbfd06b69e84d252 |
action_result.data.\*.sha1 | string | `sha1` | 954e0fd64a1242d0fa860b220198118268e35018 |
action_result.data.\*.sha256 | string | `sha256` | 1a563e59bfcdc9e7b4d8ac81c6b6579e2d215952f6dd98e0ab1ab026ac616896 |
action_result.data.\*.signer | string | | |
action_result.data.\*.signerHash | string | | |
action_result.message | string | | |
summary.action_taken | string | | Retrieved Files for Alert |
summary.total_results | numeric | | 1 |
summary.total_objects | numeric | | 1 |
summary.total_objects_successful | numeric | | 1 |

## action: 'get alert ips'

Retrieve IP addresses for a specific Alert from its ID

Type: **investigate** <br>
Read only: **True**

#### Action Parameters

PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**alert_id** | required | ID of the alert | string | `defender atp alert id` |
**limit** | optional | Maximum number of IP addresses to return | numeric | |
**offset** | optional | Offset for pagination | numeric | |

#### Action Output

DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string | | success failed |
action_result.parameter.alert_id | string | `defender atp alert id` | |
action_result.parameter.limit | numeric | | |
action_result.parameter.offset | numeric | | |
action_result.data.\*.id | string | `ip` | |
action_result.message | string | | |
summary.action_taken | string | | Retrieved IPs for Alert |
summary.total_results | numeric | | 5 |
summary.total_objects | numeric | | 1 |
summary.total_objects_successful | numeric | | 1 |

## action: 'get alert domains'

Retrieve domains for a specific Alert from its ID

Type: **investigate** <br>
Read only: **True**

#### Action Parameters

PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**alert_id** | required | ID of the alert | string | `defender atp alert id` |
**limit** | optional | Maximum number of domains to return | numeric | |
**offset** | optional | Offset for pagination | numeric | |

#### Action Output

DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string | | success failed |
action_result.parameter.alert_id | string | `defender atp alert id` | |
action_result.parameter.limit | numeric | | |
action_result.parameter.offset | numeric | | |
action_result.data.\*.host | string | `domain` | |
action_result.message | string | | |
summary.action_taken | string | | Retrieved Domains for Alert |
summary.total_results | numeric | | 5 |
summary.total_objects | numeric | | 1 |
summary.total_objects_successful | numeric | | 1 |

## action: 'create alert'

Create a new alert in Defender for Endpoint

Type: **generic** <br>
Read only: **False**

#### Action Parameters

PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**report_id** | required | Report ID of associated event | string | |
**event_time** | required | UTC event time of associated event (Use this format: %Y-%m-%dT%H:%M:%SZ in UTC timezone) | string | |
**device_id** | required | Device ID of associated event | string | `defender atp device id` |
**severity** | required | Severity level of alert | string | |
**title** | required | Alert title | string | |
**description** | required | Alert description | string | |
**recommended_action** | required | Recommended action for alert | string | |
**category** | required | Category of alert | string | |

#### Action Output

DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string | | success failed |
action_result.parameter.report_id | string | | |
action_result.parameter.event_time | string | | |
action_result.parameter.device_id | string | `defender atp device id` | |
action_result.parameter.severity | string | | |
action_result.parameter.title | string | | |
action_result.parameter.description | string | | |
action_result.parameter.recommended_action | string | | |
action_result.parameter.category | string | | |
action_result.data.\*.aadTenantId | string | | |
action_result.data.\*.alertCreationTime | string | | |
action_result.data.\*.assignedTo | string | | |
action_result.data.\*.category | string | | |
action_result.data.\*.classification | string | | |
action_result.data.\*.comments.\*.comment | string | | |
action_result.data.\*.comments.\*.createdBy | string | | |
action_result.data.\*.comments.\*.createdTime | string | | |
action_result.data.\*.computerDnsName | string | | |
action_result.data.\*.description | string | | |
action_result.data.\*.detectionSource | string | | |
action_result.data.\*.detectorId | string | | |
action_result.data.\*.determination | string | | |
action_result.data.\*.evidence.\*.aadUserId | string | | |
action_result.data.\*.evidence.\*.accountName | string | | |
action_result.data.\*.evidence.\*.detectionStatus | string | | |
action_result.data.\*.evidence.\*.domainName | string | `domain` | |
action_result.data.\*.evidence.\*.entityType | string | | |
action_result.data.\*.evidence.\*.evidenceCreationTime | string | | |
action_result.data.\*.evidence.\*.fileName | string | `file name` | |
action_result.data.\*.evidence.\*.filePath | string | `file path` | |
action_result.data.\*.evidence.\*.ipAddress | string | `ip` | |
action_result.data.\*.evidence.\*.parentProcessCreationTime | string | | |
action_result.data.\*.evidence.\*.parentProcessFileName | string | | |
action_result.data.\*.evidence.\*.parentProcessFilePath | string | | |
action_result.data.\*.evidence.\*.parentProcessId | string | `pid` | |
action_result.data.\*.evidence.\*.processCommandLine | string | | |
action_result.data.\*.evidence.\*.processCreationTime | string | | |
action_result.data.\*.evidence.\*.processId | string | `pid` | |
action_result.data.\*.evidence.\*.registryHive | string | | |
action_result.data.\*.evidence.\*.registryKey | string | | |
action_result.data.\*.evidence.\*.registryValue | string | | |
action_result.data.\*.evidence.\*.registryValueName | string | | |
action_result.data.\*.evidence.\*.registryValueType | string | | |
action_result.data.\*.evidence.\*.sha1 | string | `sha1` | |
action_result.data.\*.evidence.\*.sha256 | string | `sha256` | |
action_result.data.\*.evidence.\*.url | string | | |
action_result.data.\*.evidence.\*.userPrincipalName | string | | |
action_result.data.\*.evidence.\*.userSid | string | | |
action_result.data.\*.firstEventTime | string | | |
action_result.data.\*.id | string | `defender atp alert id` | |
action_result.data.\*.incidentId | numeric | | |
action_result.data.\*.investigationId | numeric | | |
action_result.data.\*.investigationState | string | | |
action_result.data.\*.lastEventTime | string | | |
action_result.data.\*.lastUpdateTime | string | | |
action_result.data.\*.loggedOnUsers.\*.accountName | string | | |
action_result.data.\*.loggedOnUsers.\*.domainName | string | | |
action_result.data.\*.machineId | string | `defender atp device id` | |
action_result.data.\*.rbacGroupName | string | | |
action_result.data.\*.relatedUser | string | | |
action_result.data.\*.relatedUser.domainName | string | | |
action_result.data.\*.relatedUser.userName | string | | |
action_result.data.\*.resolvedTime | string | | |
action_result.data.\*.severity | string | | |
action_result.data.\*.status | string | | |
action_result.data.\*.threatFamilyName | string | | |
action_result.data.\*.threatName | string | | |
action_result.data.\*.title | string | | |
action_result.message | string | | |
summary.action_taken | string | | Created Alert |
summary.total_objects | numeric | | 1 |
summary.total_objects_successful | numeric | | 1 |

## action: 'update alert'

Update properties of existing Alert

Type: **investigate** <br>
Read only: **False**

Based on the link (<a href="https://docs.microsoft.com/en-us/microsoft-365/security/defender-endpoint/update-alert" target="_blank">Get Alert Information by ID API Documentation</a>), user can update alerts that available in the API. See List Alerts for more information. Also, previously supported alert determination values ('Apt' and 'SecurityPersonnel') have been deprecated and no longer available via the API; rate limitations for this action are 100 calls per minute and 1500 calls per hour.

#### Action Parameters

PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**alert_id** | required | ID of the alert | string | `defender atp alert id` |
**status** | optional | Specifies the current status of the alert | string | |
**assigned_to** | optional | Owner of the alert | string | `email` |
**classification** | optional | Specifies the specification of the alert | string | |
**determination** | optional | Specifies the determination of the alert | string | |
**comment** | optional | Comment to be added to the alert | string | |

#### Action Output

DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string | | success failed |
action_result.parameter.alert_id | string | `defender atp alert id` | |
action_result.parameter.assigned_to | string | `email` | |
action_result.parameter.classification | string | | |
action_result.parameter.comment | string | | |
action_result.parameter.determination | string | | |
action_result.parameter.status | string | | |
action_result.data.\*.@odata.context | string | `url` | |
action_result.data.\*.aadTenantId | string | | |
action_result.data.\*.alertCreationTime | string | | |
action_result.data.\*.assignedTo | string | `email` | |
action_result.data.\*.category | string | | |
action_result.data.\*.classification | string | | |
action_result.data.\*.comments.\*.comment | string | | |
action_result.data.\*.comments.\*.createdBy | string | | |
action_result.data.\*.comments.\*.createdTime | string | | |
action_result.data.\*.computerDnsName | string | | |
action_result.data.\*.description | string | | |
action_result.data.\*.detectionSource | string | | |
action_result.data.\*.detectorId | string | | |
action_result.data.\*.determination | string | | |
action_result.data.\*.evidence.\*.aadUserId | string | | |
action_result.data.\*.evidence.\*.accountName | string | | |
action_result.data.\*.evidence.\*.detectionStatus | string | | |
action_result.data.\*.evidence.\*.domainName | string | `domain` | |
action_result.data.\*.evidence.\*.entityType | string | | |
action_result.data.\*.evidence.\*.evidenceCreationTime | string | | |
action_result.data.\*.evidence.\*.fileName | string | `file name` | |
action_result.data.\*.evidence.\*.filePath | string | `file path` | |
action_result.data.\*.evidence.\*.ipAddress | string | | |
action_result.data.\*.evidence.\*.parentProcessCreationTime | string | | |
action_result.data.\*.evidence.\*.parentProcessFileName | string | | |
action_result.data.\*.evidence.\*.parentProcessFilePath | string | | |
action_result.data.\*.evidence.\*.parentProcessId | string | `pid` | |
action_result.data.\*.evidence.\*.processCommandLine | string | | |
action_result.data.\*.evidence.\*.processCreationTime | string | | |
action_result.data.\*.evidence.\*.processId | string | `pid` | |
action_result.data.\*.evidence.\*.registryHive | string | | |
action_result.data.\*.evidence.\*.registryKey | string | | |
action_result.data.\*.evidence.\*.registryValue | string | | |
action_result.data.\*.evidence.\*.registryValueType | string | | |
action_result.data.\*.evidence.\*.sha1 | string | `sha1` | |
action_result.data.\*.evidence.\*.sha256 | string | `sha256` | |
action_result.data.\*.evidence.\*.url | string | `url` | |
action_result.data.\*.evidence.\*.userPrincipalName | string | | |
action_result.data.\*.evidence.\*.userSid | string | | |
action_result.data.\*.firstEventTime | string | | |
action_result.data.\*.id | string | `defender atp alert id` | |
action_result.data.\*.incidentId | numeric | | |
action_result.data.\*.investigationId | numeric | | |
action_result.data.\*.investigationState | string | | |
action_result.data.\*.lastEventTime | string | | |
action_result.data.\*.lastUpdateTime | string | | |
action_result.data.\*.loggedOnUsers.\*.accountName | string | | Test |
action_result.data.\*.loggedOnUsers.\*.domainName | string | | WINATPC2 |
action_result.data.\*.machineId | string | `defender atp device id` | |
action_result.data.\*.rbacGroupName | string | | |
action_result.data.\*.relatedUser | string | | |
action_result.data.\*.relatedUser.domainName | string | `domain` | |
action_result.data.\*.relatedUser.userName | string | `user name` | |
action_result.data.\*.resolvedTime | string | | |
action_result.data.\*.severity | string | | |
action_result.data.\*.status | string | | |
action_result.data.\*.threatFamilyName | string | | |
action_result.data.\*.threatName | string | | |
action_result.data.\*.title | string | | |
action_result.summary.action_taken | string | | Updated Alert |
action_result.message | string | | Action Taken: Updated Alert |
summary.total_objects | numeric | | 1 |
summary.total_objects_successful | numeric | | 1 |

## action: 'domain prevalence'

Return statistics for the specified domain

Type: **investigate** <br>
Read only: **True**

Based on the link (<a href="https://docs.microsoft.com/en-us/microsoft-365/security/defender-endpoint/get-domain-statistics?view=o365-worldwide" target="_blank">Get domain statistics API Documentation</a>), rate limitations for this action are 100 calls per minute and 1500 calls per hour. The maximum value for look_back_hours is 720 hours (30 days).

#### Action Parameters

PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**domain** | required | Domain to get the statistics | string | `domain` |
**look_back_hours** | optional | Define the hours you search back to get the statistics (Default: 720 hours (30 days)) | numeric | |

#### Action Output

DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string | | success failed |
action_result.parameter.domain | string | `domain` | abc.com |
action_result.parameter.look_back_hours | numeric | | 720 |
action_result.data.\*.@odata.context | string | `url` | https://api.securitycenter.windows.com/api/$metadata#microsoft.windowsDefenderATP.api.InOrgDomainStats |
action_result.data.\*.host | string | `domain` | abc.com |
action_result.data.\*.orgFirstSeen | string | | |
action_result.data.\*.orgLastSeen | string | | |
action_result.data.\*.orgPrevalence | string | | 0 |
action_result.data.\*.organizationPrevalence | numeric | | 0 |
action_result.summary.organization_prevalence | numeric | | 0 |
action_result.message | string | | Organization prevalence: 0 |
summary.total_objects | numeric | | 7 |
summary.total_objects_successful | numeric | | 4 |

## action: 'ip prevalence'

Return statistics for the specified IP

Type: **investigate** <br>
Read only: **True**

Based on the link (<a href="https://docs.microsoft.com/en-us/microsoft-365/security/defender-endpoint/get-ip-statistics?view=o365-worldwide" target="_blank">Get IP statistics API Documentation</a>), rate limitations for this action are 100 calls per minute and 1500 calls per hour. The maximum value for look_back_hours is 720 hours (30 days).

#### Action Parameters

PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**ip** | required | IP to get the statistics | string | `ip` `ipv6` |
**look_back_hours** | optional | Define the hours you search back to get the statistics (Default: 720 hours (30 days)) | numeric | |

#### Action Output

DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string | | success failed |
action_result.parameter.ip | string | `ip` `ipv6` | 172.217.9.206 2001:0db8:0000:0000:0000:ff00:0042:8329 |
action_result.parameter.look_back_hours | numeric | | 720 |
action_result.data.\*.@odata.context | string | `url` | https://api.securitycenter.windows.com/api/$metadata#microsoft.windowsDefenderATP.api.InOrgIPStats |
action_result.data.\*.ipAddress | string | `ip` `ipv6` | 172.217.9.206 2001:0db8:0000:0000:0000:ff00:0042:8329 |
action_result.data.\*.orgFirstSeen | string | | 2021-08-02T10:18:39.9233319Z |
action_result.data.\*.orgLastSeen | string | | 2021-08-02T10:18:39.9233319Z |
action_result.data.\*.orgPrevalence | string | | 1 |
action_result.data.\*.organizationPrevalence | numeric | | 1 |
action_result.summary.organization_prevalence | numeric | | 1 |
action_result.message | string | | Organization prevalence: 1 |
summary.total_objects | numeric | | 1 |
summary.total_objects_successful | numeric | | 1 |

## action: 'file prevalence'

Return statistics for the specified file

Type: **investigate** <br>
Read only: **True**

Based on the link (<a href="https://docs.microsoft.com/en-us/microsoft-365/security/defender-endpoint/get-file-statistics?view=o365-worldwide" target="_blank">Get File statistics API Documentation</a>), rate limitations for this action are 100 calls per minute and 1500 calls per hour. The maximum value for look_back_hours is 720 hours (30 days).

#### Action Parameters

PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**file_hash** | required | File hash to get the statistics (SHA1 or SHA256) | string | `sha1` `sha256` |
**look_back_hours** | optional | Define the hours you search back to get the statistics (Default: 720 hours (30 days)) | numeric | |

#### Action Output

DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string | | success failed |
action_result.parameter.file_hash | string | `sha1` `sha256` | 954e0fd64a1242d0fa860b220198118268e35018 |
action_result.parameter.look_back_hours | string | | 720 |
action_result.data.\*.@odata.context | string | `url` | https://api.securitycenter.windows.com/api/$metadata#microsoft.windowsDefenderATP.api.InOrgFileStats |
action_result.data.\*.globalFirstObserved | string | | 2021-07-11T08:50:15.2316886Z |
action_result.data.\*.globalLastObserved | string | | 2021-08-20T10:15:33.4741238Z |
action_result.data.\*.globalPrevalence | string | | 64356 |
action_result.data.\*.globallyPrevalence | numeric | | 64356 |
action_result.data.\*.orgFirstSeen | string | | |
action_result.data.\*.orgLastSeen | string | | |
action_result.data.\*.orgPrevalence | string | | 0 |
action_result.data.\*.organizationPrevalence | numeric | | 0 |
action_result.data.\*.sha1 | string | `sha1` | 954e0fd64a1242d0fa860b220198118268e35018 |
action_result.data.\*.topFileNames | string | `file name` | mssense.exe |
action_result.summary.organization_prevalence | numeric | | 0 |
action_result.message | string | | Organization prevalence: 0 |
summary.total_objects | numeric | | 1 |
summary.total_objects_successful | numeric | | 1 |

## action: 'get file info'

Retrieve a File information by identifier SHA1, or SHA256

Type: **investigate** <br>
Read only: **True**

Based on the link (<a href="https://docs.microsoft.com/en-us/microsoft-365/security/defender-endpoint/get-file-information?view=o365-worldwide" target="_blank">Get File Information API Documentation</a>), rate limitations for this action are 100 calls per minute and 1500 calls per hour. The valid file identifiers are SHA1, SHA256.

#### Action Parameters

PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**file_hash** | required | Identifier of the file | string | `sha1` `sha256` |

#### Action Output

DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string | | success failed |
action_result.parameter.file_hash | string | `sha1` `sha256` | 954e0fd64a1242d0fa860b220198118268e35018 1a563e59bfcdc9e7b4d8ac81c6b6579e2d215952f6dd98e0ab1ab026ac616896 |
action_result.data.\*.@odata.context | string | `url` | https://api.securitycenter.windows.com/api/$metadata#Files/$entity |
action_result.data.\*.determinationType | string | | Unknown |
action_result.data.\*.determinationValue | string | | |
action_result.data.\*.fileProductName | string | | Windows Operating System |
action_result.data.\*.filePublisher | string | | |
action_result.data.\*.fileType | string | | |
action_result.data.\*.globalFirstObserved | string | | 2021-07-11T08:50:15.2316886Z |
action_result.data.\*.globalLastObserved | string | | 2021-08-19T10:33:39.6552836Z |
action_result.data.\*.globalPrevalence | numeric | | 64134 |
action_result.data.\*.isPeFile | boolean | | True |
action_result.data.\*.isValidCertificate | boolean | | True |
action_result.data.\*.issuer | string | | Test Windows Production PCA 2011 |
action_result.data.\*.md5 | string | `md5` | 44adb27786eb24e5bbfd06b69e84d252 |
action_result.data.\*.sha1 | string | `sha1` | 954e0fd64a1242d0fa860b220198118268e35018 |
action_result.data.\*.sha256 | string | `sha256` | 1a563e59bfcdc9e7b4d8ac81c6b6579e2d215952f6dd98e0ab1ab026ac616896 |
action_result.data.\*.signer | string | | Windows Publisher |
action_result.data.\*.signerHash | string | | 4f95a05d113f1f31b481e92f8f0d2b9889545004 |
action_result.data.\*.size | numeric | | 5395384 |
action_result.summary.global_prevalence | numeric | | 64355 |
action_result.message | string | | Successfully retrieved file information |
summary.total_objects | numeric | | 1 |
summary.total_objects_successful | numeric | | 1 |

## action: 'get file devices'

Retrieve a collection of devices related to a given file hash (SHA1)

Type: **investigate** <br>
Read only: **True**

Based on the link (<a href="https://docs.microsoft.com/en-us/microsoft-365/security/defender-endpoint/get-file-related-machines?view=o365-worldwide" target="_blank">Get File Related Machines API Documentation</a>), rate limitations for this action are 100 calls per minute and 1500 calls per hour. The valid file identifier is SHA1.<br>The action retrieves data of the last 30 days.

#### Action Parameters

PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**file_hash** | required | Identifier of the file | string | `sha1` |

#### Action Output

DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string | | success failed |
action_result.parameter.file_hash | string | `sha1` | 954e0fd64a1242d0fa860b220198118268e35018 |
action_result.data.\*.aadDeviceId | string | | |
action_result.data.\*.agentVersion | string | | 10.7740.19041.1110 |
action_result.data.\*.computerDnsName | string | | testmachine4 |
action_result.data.\*.defenderAvStatus | string | `domain` | Updated |
action_result.data.\*.deviceValue | string | | Normal |
action_result.data.\*.exposureLevel | string | | Medium |
action_result.data.\*.firstSeen | string | | 2021-08-02T06:12:16.3736341Z |
action_result.data.\*.healthStatus | string | | Inactive |
action_result.data.\*.id | string | `defender atp device id` | 803c416946e8738b7711903a28362adeae6e1aea |
action_result.data.\*.ipAddresses.\*.ipAddress | string | `ip` | 10.1.1.4 |
action_result.data.\*.ipAddresses.\*.macAddress | string | | 000D3A7B423C |
action_result.data.\*.ipAddresses.\*.operationalStatus | string | | Up |
action_result.data.\*.ipAddresses.\*.type | string | | Ethernet |
action_result.data.\*.isAadJoined | boolean | | False True |
action_result.data.\*.lastExternalIpAddress | string | `ip` | 137.116.83.101 |
action_result.data.\*.lastIpAddress | string | `ip` | 10.1.1.4 |
action_result.data.\*.lastSeen | string | | 2021-08-04T13:40:25.2473895Z |
action_result.data.\*.managedBy | string | | |
action_result.data.\*.managedByStatus | string | | |
action_result.data.\*.onboardingStatus | string | | Onboarded |
action_result.data.\*.osArchitecture | string | | 64-bit |
action_result.data.\*.osBuild | numeric | | 19042 |
action_result.data.\*.osPlatform | string | | Windows10 |
action_result.data.\*.osProcessor | string | | x64 |
action_result.data.\*.osVersion | string | | |
action_result.data.\*.rbacGroupId | numeric | | 0 |
action_result.data.\*.rbacGroupName | string | | |
action_result.data.\*.riskScore | string | | Medium |
action_result.data.\*.version | string | | 20H2 |
action_result.data.\*.vmMetadata | string | | |
action_result.data.\*.vmMetadata.cloudProvider | string | | Azure |
action_result.data.\*.vmMetadata.resourceId | string | | /subscriptions/1b922e46-8595-4749-997a-1205e714cd91/resourceGroups/evaluation_3e5d447ba5d6470b9636a8709cd5b26a_4/providers/Microsoft.Compute/virtualMachines/TestMachine4 |
action_result.data.\*.vmMetadata.subscriptionId | string | | 1b922e46-8595-4749-997a-1205e714cd91 |
action_result.data.\*.vmMetadata.vmId | string | | 238443dc-56ce-487f-aeb6-261a2a00a38c |
action_result.summary.total_devices | numeric | | 1 |
action_result.message | string | | Total devices: 1 |
summary.total_objects | numeric | | 1 |
summary.total_objects_successful | numeric | | 1 |

## action: 'get user devices'

Retrieve a collection of devices related to a given user ID

Type: **investigate** <br>
Read only: **True**

Based on the link (<a href="https://docs.microsoft.com/en-us/microsoft-365/security/defender-endpoint/get-user-related-machines?view=o365-worldwide" target="_blank">Get User Related Machines API Documentation</a>), rate limitations for this action are 100 calls per minute and 1500 calls per hour. The ID is not the full UPN, but only the user name. (for example, to retrieve machines for user1@contoso.com use user1 for user_id parameter).<br>The action retrieves data of the last 30 days.

#### Action Parameters

PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**user_id** | required | ID of the user | string | `user name` |

#### Action Output

DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string | | success failed |
action_result.parameter.user_id | string | `user name` | Administrator1 |
action_result.data.\*.aadDeviceId | string | | |
action_result.data.\*.agentVersion | string | | 10.7740.19041.1110 |
action_result.data.\*.computerDnsName | string | `domain` | testmachine4 |
action_result.data.\*.defenderAvStatus | string | | Updated |
action_result.data.\*.deviceValue | string | | Normal |
action_result.data.\*.exposureLevel | string | | Medium |
action_result.data.\*.firstSeen | string | | 2021-08-02T06:12:16.3736341Z |
action_result.data.\*.healthStatus | string | | Inactive |
action_result.data.\*.id | string | `defender atp device id` | 803c416946e8738b7711903a28362adeae6e1aea |
action_result.data.\*.ipAddresses.\*.ipAddress | string | `ip` | 10.1.1.4 |
action_result.data.\*.ipAddresses.\*.macAddress | string | | 000D3A7B423C |
action_result.data.\*.ipAddresses.\*.operationalStatus | string | | Up |
action_result.data.\*.ipAddresses.\*.type | string | | Ethernet |
action_result.data.\*.isAadJoined | boolean | | False |
action_result.data.\*.lastExternalIpAddress | string | `ip` | 137.116.83.101 |
action_result.data.\*.lastIpAddress | string | `ip` | 10.1.1.4 |
action_result.data.\*.lastSeen | string | | 2021-08-04T13:40:25.2473895Z |
action_result.data.\*.managedBy | string | | |
action_result.data.\*.managedByStatus | string | | |
action_result.data.\*.onboardingStatus | string | | Onboarded |
action_result.data.\*.osArchitecture | string | | 64-bit |
action_result.data.\*.osBuild | numeric | | 19042 |
action_result.data.\*.osPlatform | string | | Windows10 |
action_result.data.\*.osProcessor | string | | x64 |
action_result.data.\*.osVersion | string | | |
action_result.data.\*.rbacGroupId | numeric | | 0 |
action_result.data.\*.rbacGroupName | string | | |
action_result.data.\*.riskScore | string | | Medium |
action_result.data.\*.version | string | | 20H2 |
action_result.data.\*.vmMetadata | string | | |
action_result.data.\*.vmMetadata.cloudProvider | string | | Azure |
action_result.data.\*.vmMetadata.resourceId | string | | /subscriptions/1b922e46-8595-4749-997a-1205e714cd91/resourceGroups/evaluation_3e5d447ba5d6470b9636a8709cd5b26a_4/providers/Microsoft.Compute/virtualMachines/TestMachine4 |
action_result.data.\*.vmMetadata.subscriptionId | string | | 1b922e46-8595-4749-997a-1205e714cd91 |
action_result.data.\*.vmMetadata.vmId | string | | 238443dc-56ce-487f-aeb6-261a2a00a38c |
action_result.summary.total_devices | numeric | | 1 |
action_result.message | string | | Total devices: 1 |
summary.total_objects | numeric | | 1 |
summary.total_objects_successful | numeric | | 1 |

## action: 'get installed software'

Retrieve a collection of installed software related to a given device ID

Type: **investigate** <br>
Read only: **True**

#### Action Parameters

PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**device_id** | required | ID of the device | string | `defender atp device id` |

#### Action Output

DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string | | success failed |
action_result.parameter.device_id | string | `defender atp device id` | 7af22c8a3f92ec0c9c49b80aee3379bf9bfa0768 |
action_result.data.\*.activeAlert | boolean | | False |
action_result.data.\*.category | string | | |
action_result.data.\*.exposedMachines | numeric | | 0 |
action_result.data.\*.id | string | | test-\_-.net_framework |
action_result.data.\*.impactScore | numeric | | 0 |
action_result.data.\*.installedMachines | numeric | | 5 |
action_result.data.\*.isNormalized | boolean | | True False |
action_result.data.\*.name | string | | .net_framework |
action_result.data.\*.publicExploit | boolean | | False |
action_result.data.\*.vendor | string | | Test Vendor |
action_result.data.\*.weaknesses | numeric | | 0 |
action_result.summary.total_software | numeric | | 9 |
action_result.message | string | | Total software: 9 |
summary.total_objects | numeric | | 1 |
summary.total_objects_successful | numeric | | 1 |

## action: 'restrict app execution'

Restrict execution of all applications on the device except a predefined set

Type: **contain** <br>
Read only: **False**

Based on the link (<a href="https://docs.microsoft.com/en-us/microsoft-365/security/defender-endpoint/restrict-code-execution?view=o365-worldwide" target="_blank">Restrict app execution API Documentation</a>), rate limitations for this API are 100 calls per minute and 1500 calls per hour.<br>This action can take a while to complete execution. The action retries at an interval of 5 seconds within a specified <b>timeout</b> to check if event execution is complete. If not, the action would return the latest status of the event along with the event ID.<br>The <b>get status</b> action can be used to fetch the latest status of the event with the event ID.<br>The maximum timeout period for a status check is 1 minute.

#### Action Parameters

PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**device_id** | required | ID of the device | string | `defender atp device id` |
**comment** | required | Comment | string | |
**timeout** | optional | Timeout in seconds (Default: 30) | numeric | |

#### Action Output

DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string | | success failed |
action_result.parameter.comment | string | | Restrict code execution due to alert 1234 |
action_result.parameter.device_id | string | `defender atp device id` | 7af22c8a3f92ec0c9c49b80aee3379bf9bfa0768 |
action_result.parameter.timeout | numeric | | 30 |
action_result.data.\*.@odata.context | string | `url` | https://api.securitycenter.windows.com/api/$metadata#MachineActions/$entity |
action_result.data.\*.cancellationComment | string | | |
action_result.data.\*.cancellationDateTimeUtc | string | | |
action_result.data.\*.cancellationRequestor | string | | |
action_result.data.\*.computerDnsName | string | | win10atp2 |
action_result.data.\*.creationDateTimeUtc | string | | 2019-05-03T08:50:05.8076226Z |
action_result.data.\*.error | string | | |
action_result.data.\*.errorHResult | numeric | | 0 |
action_result.data.\*.externalId | string | | |
action_result.data.\*.id | string | `defender atp event id` | 6925706d-3a7e-4596-b2d7-321fca9cd965 |
action_result.data.\*.lastUpdateDateTimeUtc | string | | 2019-05-03T08:50:05.8076226Z |
action_result.data.\*.machineId | string | `defender atp device id` | 349838747f77ec74e43ab7ca70773a41f7bfb6f2 |
action_result.data.\*.relatedFileInfo | string | | |
action_result.data.\*.requestSource | string | | PublicApi |
action_result.data.\*.requestor | string | | 65265db5-a7ca-4199-a425-f37ad1dd6d31 |
action_result.data.\*.requestorComment | string | | Restrict code execution due to alert 1234 |
action_result.data.\*.scope | string | | |
action_result.data.\*.status | string | | Succeeded |
action_result.data.\*.title | string | | |
action_result.data.\*.troubleshootInfo | string | | |
action_result.data.\*.type | string | | RestrictCodeExecution |
action_result.summary.event_id | string | `defender atp event id` | 6925706d-3a7e-4596-b2d7-321fca9cd965 |
action_result.summary.restrict_app_execution_status | string | | Succeeded |
action_result.summary.restriction_status | string | | Pending |
action_result.message | string | | Event id: cd2ab57e-5b52-43b0-99d8-c370fc620a54, Restriction status: Succeeded |
summary.total_objects | numeric | | 1 |
summary.total_objects_successful | numeric | | 1 |

## action: 'list indicators'

Retrieve a collection of all active Indicators

Type: **investigate** <br>
Read only: **True**

Based on the link (<a href="https://docs.microsoft.com/en-us/microsoft-365/security/defender-endpoint/get-ti-indicators-collection?view=o365-worldwide" target="_blank">List Indicators API Documentation</a>), rate limitations for this action are 100 calls per minute and 1500 calls per hour. If the user does not specify the limit value, it will fetch 100 indicators by default. The maximum value for the limit parameter is 10000.

#### Action Parameters

PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**filter** | optional | Additional OData V4 filters to apply | string | |
**limit** | optional | Maximum number of indicators to return (Maximum: 10,000) | numeric | |

#### Action Output

DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string | | success failed |
action_result.parameter.filter | string | | severity+eq+'Informational' |
action_result.parameter.limit | numeric | | 3 |
action_result.data.\*.action | string | | Alert Warn Block Audit BlockAndRemediate AlertAndBlock Allowed |
action_result.data.\*.additionalInfo | string | | |
action_result.data.\*.application | string | | |
action_result.data.\*.bypassDurationHours | string | | |
action_result.data.\*.category | numeric | | 1 |
action_result.data.\*.certificateInfo | string | | |
action_result.data.\*.certificateInfo.issuer | string | | E=test@DS1234.testing.net, CN=localhost, OU=QA, O=System, L=ABC, S=UT, C=US |
action_result.data.\*.certificateInfo.serial | string | | 123CE453421A81E2DB9A6A08C3440DBD06 |
action_result.data.\*.certificateInfo.sha256 | string | | 1234edd57a56d859cd9b18c3b20308917ea2fa5b2013f00d5c98d5a8a9be1234 |
action_result.data.\*.certificateInfo.subject | string | | E=test@DS1234.testing.net, CN=localhost, OU=QA, O=System, L=ABC, S=UT, C=US |
action_result.data.\*.createdBy | string | | test@testdomain.onmicrosoft.com |
action_result.data.\*.createdByDisplayName | string | | testuser@domain.onmicrosoft.com |
action_result.data.\*.createdBySource | string | | Portal |
action_result.data.\*.creationTimeDateTimeUtc | string | | 2021-08-25T12:30:51.7279453Z |
action_result.data.\*.description | string | | Test-ATP |
action_result.data.\*.educateUrl | string | | |
action_result.data.\*.expirationTime | string | | 2021-08-26T00:00:00Z |
action_result.data.\*.externalId | string | | |
action_result.data.\*.generateAlert | boolean | | False True |
action_result.data.\*.historicalDetection | boolean | | False True |
action_result.data.\*.id | string | `defender atp indicator id` | 13 |
action_result.data.\*.indicatorType | string | | FileSha1 FileMd5 CertificateThumbprint FileSha256 IpAddress DomainName Url |
action_result.data.\*.indicatorValue | string | `defender atp indicator value` `sha1` `sha256` `md5` `domain` `ip` `ipv6` `url` | 63b79504702c9c977e7165ad75d2e6989b2c5962 |
action_result.data.\*.lastUpdateTime | string | | 2021-08-25T12:30:51.7457726Z |
action_result.data.\*.lastUpdatedBy | string | | |
action_result.data.\*.lookBackPeriod | string | | |
action_result.data.\*.notificationBody | string | | |
action_result.data.\*.notificationId | string | | |
action_result.data.\*.recommendedActions | string | | |
action_result.data.\*.severity | string | | Informational |
action_result.data.\*.title | string | | Test |
action_result.data.\*.version | string | | |
action_result.summary.total_indicators | numeric | | 1 |
action_result.message | string | | Total indicators: 1 |
summary.total_objects | numeric | | 1 |
summary.total_objects_successful | numeric | | 1 |

## action: 'collect investigation package'

Collect an investigation package from a device by its device ID

Type: **generic** <br>
Read only: **False**

Based on the link (<a href="https://learn.microsoft.com/en-us/defender-endpoint/api/collect-investigation-package" target="_blank">Collect Investigation Package API Documentation</a>).

#### Action Parameters

PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**device_id** | required | ID of the device | string | `defender atp device id` |
**comment** | required | Comment to include in the investigation package | string | |

#### Action Output

DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string | | success failed |
action_result.parameter.device_id | string | `defender atp device id` | |
action_result.parameter.comment | string | | |
action_result.data.\*.id | string | `defender atp action id` | |
action_result.data.\*.type | string | | |
action_result.data.\*.scope | string | | |
action_result.data.\*.requestor | string | | |
action_result.data.\*.requestorComment | string | | |
action_result.data.\*.status | string | | |
action_result.data.\*.machineId | string | | |
action_result.data.\*.computerDnsName | string | | |
action_result.data.\*.creationDateTimeUtc | string | | |
action_result.data.\*.lastUpdateDateTimeUtc | string | | |
action_result.summary.action_taken | string | | Collected Investigation Package |
action_result.message | string | | |
summary.total_objects | numeric | | |
summary.total_objects_successful | numeric | | |

## action: 'get investigation uri'

Retrieve a URI for downloading an investigation package by its action ID

Type: **investigate** <br>
Read only: **True**

Based on the link (<a href="https://learn.microsoft.com/en-us/defender-endpoint/api/get-package-sas-uri" target="_blank">Get Package SAS URI API Documentation</a>).

#### Action Parameters

PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**action_id** | required | ID of the investigation action | string | `defender atp action id` |

#### Action Output

DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string | | success failed |
action_result.parameter.action_id | string | `defender atp action id` | |
action_result.data.\*.value | string | | |
action_result.summary.action_taken | string | | Retrieved Investigation URI |
action_result.message | string | | |
summary.total_objects | numeric | | |
summary.total_objects_successful | numeric | | |

## action: 'get device details'

Retrieve details for multiple devices by their device IDs

Type: **investigate** <br>
Read only: **True**

Based on the link (<a href="https://learn.microsoft.com/en-us/defender-endpoint/api/get-machine-by-id" target="_blank">Get Machine by ID API Documentation</a>).

#### Action Parameters

PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**device_ids** | required | Comma-separated list of device IDs | string | |

#### Action Output

DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string | | success failed |
action_result.parameter.device_ids | string | | |
action_result.data.\*.id | string | `defender atp device id` | |
action_result.data.\*.computerDnsName | string | | |
action_result.data.\*.firstSeen | string | | |
action_result.data.\*.lastSeen | string | | |
action_result.data.\*.osPlatform | string | | |
action_result.data.\*.version | string | | |
action_result.data.\*.osProcessor | string | | |
action_result.data.\*.lastIpAddress | string | | |
action_result.data.\*.lastExternalIpAddress | string | | |
action_result.data.\*.osBuild | numeric | | |
action_result.data.\*.healthStatus | string | | |
action_result.data.\*.rbacGroupId | numeric | | |
action_result.data.\*.rbacGroupName | string | | |
action_result.data.\*.riskScore | string | | |
action_result.data.\*.exposureLevel | string | | |
action_result.data.\*.isAadJoined | boolean | | |
action_result.data.\*.aadDeviceId | string | | |
action_result.message | string | | |
action_result.summary.action_taken | string | | Retrieved Device Details |
action_result.total_results | numeric | | |
summary.total_objects | numeric | | |
summary.total_objects_successful | numeric | | |

## action: 'get affected devices'

Retrieve a list of devices affected by a vulnerability using CVE IDs

Type: **investigate** <br>
Read only: **True**

Based on the link (<a href="https://learn.microsoft.com/en-us/defender-endpoint/api/get-machines-by-vulnerability" target="_blank">Get Machines by Vulnerability API Documentation</a>).

#### Action Parameters

PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**cve_id** | required | CVE ID of the vulnerability | string | `cve id` |

#### Action Output

DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string | | success failed |
action_result.parameter.cve_id | string | `cve id` | |
action_result.data.\*.id | string | `defender atp device id` | |
action_result.data.\*.computerDnsName | string | | |
action_result.data.\*.osPlatform | string | | |
action_result.data.\*.rbacGroupName | string | | |
action_result.summary.action_taken | string | | Retrieved Affected Devices |
action_result.summary.total_results | numeric | | |
action_result.message | string | | |
summary.total_objects | numeric | | |
summary.total_objects_successful | numeric | | |

## action: 'get indicator'

Retrieve an Indicator entity by its ID

Type: **investigate** <br>
Read only: **True**

#### Action Parameters

PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**indicator_id** | required | The ID of the indicator to retrieve | string | `defender atp indicator id` |

#### Action Output

DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string | | success failed |
action_result.parameter.indicator_id | string | `defender atp indicator id` | |
action_result.data.\*.action | string | | |
action_result.data.\*.additionalInfo | string | | |
action_result.data.\*.application | string | | |
action_result.data.\*.bypassDurationHours | string | | |
action_result.data.\*.category | numeric | | |
action_result.data.\*.certificateInfo | string | | |
action_result.data.\*.certificateInfo.issuer | string | | |
action_result.data.\*.certificateInfo.serial | string | | |
action_result.data.\*.certificateInfo.sha256 | string | | |
action_result.data.\*.certificateInfo.subject | string | | |
action_result.data.\*.createdBy | string | | |
action_result.data.\*.createdByDisplayName | string | | |
action_result.data.\*.createdBySource | string | | |
action_result.data.\*.creationTimeDateTimeUtc | string | | |
action_result.data.\*.description | string | | |
action_result.data.\*.educateUrl | string | | |
action_result.data.\*.expirationTime | string | | |
action_result.data.\*.externalId | string | | |
action_result.data.\*.generateAlert | boolean | | |
action_result.data.\*.historicalDetection | boolean | | |
action_result.data.\*.id | string | `defender atp indicator id` | |
action_result.data.\*.indicatorType | string | | |
action_result.data.\*.indicatorValue | string | `defender atp indicator value` `sha1` `sha256` `md5` `domain` `ip` `ipv6` `url` | |
action_result.data.\*.lastUpdateTime | string | | |
action_result.data.\*.lastUpdatedBy | string | | |
action_result.data.\*.lookBackPeriod | string | | |
action_result.data.\*.notificationBody | string | | |
action_result.data.\*.notificationId | string | | |
action_result.data.\*.recommendedActions | string | | |
action_result.data.\*.severity | string | | |
action_result.data.\*.title | string | | |
action_result.data.\*.version | string | | |
action_result.message | string | | |
summary.action_taken | string | | Retrieved Indicator |
summary.total_objects | numeric | | 1 |
summary.total_objects_successful | numeric | | 1 |

## action: 'submit indicator'

Submit or Update new Indicator entity

Type: **generic** <br>
Read only: **False**

Based on the link (<a href="https://docs.microsoft.com/en-us/microsoft-365/security/defender-endpoint/post-ti-indicator?view=o365-worldwide" target="_blank">Submit or Update Indicator API Documentation</a>), rate limitations for this action are 100 calls per minute and 1500 calls per hour. There is a limit of 15,000 active indicators per tenant.<br><b>Notes:</b><ul><li>For the possible values of given action parameters, refer to the documentation link provided above.<li>CIDR notation for IPs is not supported.</li></ul>

#### Action Parameters

PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**title** | required | Indicator alert title | string | |
**description** | required | Description of the indicator | string | |
**indicator_type** | required | Type of the indicator | string | |
**indicator_value** | required | Identity of the Indicator entity | string | `defender atp indicator value` `sha1` `sha256` `md5` `ip` `ipv6` `url` `domain` |
**action** | required | The action that will be taken if the indicator will be discovered in the organization | string | |
**application** | optional | The application associated with the indicator | string | |
**expiration_time** | optional | The expiration time of the indicator (Use this format: %Y-%m-%dT%H:%M:%SZ in UTC timezone) | string | |
**severity** | optional | The severity of the indicator | string | |
**recommended_actions** | optional | TI indicator alert recommended actions | string | |
**rbac_group_names** | optional | RBAC group names the indicator would be applied to (JSON formatted list) | string | |
**generate_alert** | optional | Whether or not this indicator should generate an alert | boolean | |

#### Action Output

DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string | | success failed |
action_result.parameter.action | string | | Alert Warn Block Audit BlockAndRemediate AlertAndBlock Allowed |
action_result.parameter.generate_alert | boolean | | True False |
action_result.parameter.application | string | | Test App |
action_result.parameter.description | string | | Test 1 |
action_result.parameter.expiration_time | string | | 2021-09-07T00:00:00Z |
action_result.parameter.indicator_type | string | | FileSha1 FileMd5 CertificateThumbprint FileSha256 IpAddress DomainName Url |
action_result.parameter.indicator_value | string | `defender atp indicator value` `sha1` `sha256` `md5` `ip` `ipv6` `url` `domain` | domain.com |
action_result.parameter.rbac_group_names | string | | ["Group1", "Group2"] |
action_result.parameter.recommended_actions | string | | Test Actions |
action_result.parameter.severity | string | | Low |
action_result.parameter.title | string | | Test 1 |
action_result.data.\*.@odata.context | string | `url` | https://api.securitycenter.windows.com/api/$metadata#Indicators/$entity |
action_result.data.\*.action | string | | Alert Warn Block Audit BlockAndRemediate AlertAndBlock Allowed |
action_result.data.\*.additionalInfo | string | | |
action_result.data.\*.application | string | | |
action_result.data.\*.bypassDurationHours | string | | |
action_result.data.\*.category | numeric | | 1 |
action_result.data.\*.certificateInfo | string | | |
action_result.data.\*.createdBy | string | | 65265db5-a7ca-4199-a425-f37ad1dd6d31 |
action_result.data.\*.createdByDisplayName | string | | WindowsDefenderATPSiemConnector |
action_result.data.\*.createdBySource | string | | PublicApi |
action_result.data.\*.creationTimeDateTimeUtc | string | | 2021-08-27T12:50:54.882519Z |
action_result.data.\*.description | string | | Test 1 |
action_result.data.\*.educateUrl | string | | |
action_result.data.\*.expirationTime | string | | 2021-09-07T00:00:00Z |
action_result.data.\*.externalId | string | | |
action_result.data.\*.generateAlert | boolean | | False True |
action_result.data.\*.historicalDetection | boolean | | False True |
action_result.data.\*.id | string | `defender atp indicator id` | 17 |
action_result.data.\*.indicatorType | string | | FileSha1 FileMd5 CertificateThumbprint FileSha256 IpAddress DomainName Url |
action_result.data.\*.indicatorValue | string | `defender atp indicator value` `ip` `ipv6` `sha1` `sha256` `md5` `domain` `url` | test.com |
action_result.data.\*.lastUpdateTime | string | | 2021-08-27T12:55:42.0621261Z |
action_result.data.\*.lastUpdatedBy | string | | 65265db5-a7ca-4199-a425-f37ad1dd6d31 |
action_result.data.\*.lookBackPeriod | string | | |
action_result.data.\*.notificationBody | string | | |
action_result.data.\*.notificationId | string | | |
action_result.data.\*.recommendedActions | string | | Test Actions |
action_result.data.\*.severity | string | | Low |
action_result.data.\*.title | string | | Test 1 |
action_result.data.\*.version | string | | |
action_result.summary.indicator_id | string | `defender atp indicator id` | 17 |
action_result.message | string | | Indicator id: 17 |
summary.total_objects | numeric | | 1 |
summary.total_objects_successful | numeric | | 1 |

## action: 'update indicator'

Update an existing Indicator entity

Type: **generic** <br>
Read only: **False**

#### Action Parameters

PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**indicator_value** | required | The identity value of the indicator to update | string | `defender atp indicator value` `sha1` `sha256` `md5` `ip` `ipv6` `url` `domain` |
**indicator_type** | required | The type of indicator | string | |
**action** | required | Action taken if the indicator is discovered | string | |
**severity** | optional | The severity of the malicious behavior identified by the indicator | string | |
**indicator_description** | required | Description of the indicator | string | |
**indicator_title** | required | Indicator alert title | string | |
**expiration_time** | optional | The expiration time of the indicator (Use this format: %Y-%m-%dT%H:%M:%SZ in UTC timezone) | string | |
**indicator_application** | optional | The application associated with the indicator | string | |
**recommended_actions** | optional | TI indicator alert recommended actions | string | |
**rbac_group_names** | optional | JSON formatted list of RBAC group names | string | |

#### Action Output

DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string | | success failed |
action_result.parameter.indicator_value | string | `defender atp indicator value` `sha1` `sha256` `md5` `ip` `ipv6` `url` `domain` | domain.com |
action_result.parameter.indicator_type | string | | |
action_result.parameter.action | string | | |
action_result.parameter.severity | string | | |
action_result.parameter.indicator_description | string | | |
action_result.parameter.indicator_title | string | | |
action_result.parameter.expiration_time | string | | |
action_result.parameter.indicator_application | string | | |
action_result.parameter.recommended_actions | string | | |
action_result.parameter.rbac_group_names | string | | |
action_result.parameter.expiration_time | string | | |
action_result.data.\*.id | string | `defender atp indicator id` | |
action_result.data.\*.indicator | string | | |
action_result.data.\*.isFailed | boolean | | |
action_result.data.\*.failureReason | string | | |
action_result.message | string | | |
summary.action_taken | string | | Updated Indicator |
summary.total_objects | numeric | | 1 |
summary.total_objects_successful | numeric | | 1 |

## action: 'update indicator batch'

Update or create a batch of Indicator entities

Type: **generic** <br>
Read only: **False**

This action updates or creates a batch of indicators from a json object. Based on (<a href="https://learn.microsoft.com/en-us/defender-endpoint/api/import-ti-indicators" target="_blank">Batch Update Indicator API Documentation</a>). New indicators will be created if they do not exist.

#### Action Parameters

PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**indicator_batch** | required | A JSON object with a list of indicators to update or create. Each indicator should include properties like indicatorValue, indicatorType, action, title, etc. | string | |

#### Action Output

DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string | | success failed |
action_result.parameter.indicator_batch | string | | |
action_result.data.\*.id | string | `defender atp indicator id` | |
action_result.data.\*.indicator | string | | |
action_result.data.\*.isFailed | boolean | | |
action_result.data.\*.failureReason | string | | |
action_result.message | string | | |
summary.action_taken | string | | Updated batch of indicators |
summary.total_results | numeric | | 5 |
summary.total_objects | numeric | | 1 |
summary.total_objects_successful | numeric | | 1 |

## action: 'get file alerts'

Retrieve alerts related to a specific file hash

Type: **investigate** <br>
Read only: **True**

Retrieve alerts related to a specific file hash, such as a SHA1 or SHA256 hash.

#### Action Parameters

PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**file_hash** | required | The file hash (e.g., SHA1) used to retrieve related alerts | string | `sha1` `sha256` `file_hash` |

#### Action Output

DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string | | success failed |
action_result.parameter.file_hash | string | `sha1` `sha256` `file_hash` | |
action_result.data.\*.aadTenantId | string | | |
action_result.data.\*.alertCreationTime | string | | |
action_result.data.\*.assignedTo | string | | |
action_result.data.\*.category | string | | |
action_result.data.\*.classification | string | | |
action_result.data.\*.comments.\*.comment | string | | |
action_result.data.\*.comments.\*.createdBy | string | | |
action_result.data.\*.comments.\*.createdTime | string | | |
action_result.data.\*.computerDnsName | string | | |
action_result.data.\*.description | string | | |
action_result.data.\*.detectionSource | string | | |
action_result.data.\*.detectorId | string | | |
action_result.data.\*.determination | string | | |
action_result.data.\*.evidence.\*.aadUserId | string | | |
action_result.data.\*.evidence.\*.accountName | string | | |
action_result.data.\*.evidence.\*.detectionStatus | string | | |
action_result.data.\*.evidence.\*.domainName | string | `domain` | |
action_result.data.\*.evidence.\*.entityType | string | | |
action_result.data.\*.evidence.\*.evidenceCreationTime | string | | |
action_result.data.\*.evidence.\*.fileName | string | `file name` | |
action_result.data.\*.evidence.\*.filePath | string | `file path` | |
action_result.data.\*.evidence.\*.ipAddress | string | `ip` | |
action_result.data.\*.evidence.\*.parentProcessCreationTime | string | | |
action_result.data.\*.evidence.\*.parentProcessFileName | string | | |
action_result.data.\*.evidence.\*.parentProcessFilePath | string | | |
action_result.data.\*.evidence.\*.parentProcessId | string | `pid` | |
action_result.data.\*.evidence.\*.processCommandLine | string | | |
action_result.data.\*.evidence.\*.processCreationTime | string | | |
action_result.data.\*.evidence.\*.processId | string | `pid` | |
action_result.data.\*.evidence.\*.registryHive | string | | |
action_result.data.\*.evidence.\*.registryKey | string | | |
action_result.data.\*.evidence.\*.registryValue | string | | |
action_result.data.\*.evidence.\*.registryValueName | string | | |
action_result.data.\*.evidence.\*.registryValueType | string | | |
action_result.data.\*.evidence.\*.sha1 | string | `sha1` | |
action_result.data.\*.evidence.\*.sha256 | string | `sha256` | |
action_result.data.\*.evidence.\*.url | string | | |
action_result.data.\*.evidence.\*.userPrincipalName | string | | |
action_result.data.\*.evidence.\*.userSid | string | | |
action_result.data.\*.firstEventTime | string | | |
action_result.data.\*.id | string | `defender atp alert id` | |
action_result.data.\*.incidentId | numeric | | |
action_result.data.\*.investigationId | numeric | | |
action_result.data.\*.investigationState | string | | |
action_result.data.\*.lastEventTime | string | | |
action_result.data.\*.lastUpdateTime | string | | |
action_result.data.\*.loggedOnUsers.\*.accountName | string | | |
action_result.data.\*.loggedOnUsers.\*.domainName | string | | |
action_result.data.\*.machineId | string | `defender atp device id` | |
action_result.data.\*.rbacGroupName | string | | |
action_result.data.\*.relatedUser | string | | |
action_result.data.\*.relatedUser.domainName | string | | |
action_result.data.\*.relatedUser.userName | string | | |
action_result.data.\*.resolvedTime | string | | |
action_result.data.\*.severity | string | | |
action_result.data.\*.status | string | | |
action_result.data.\*.threatFamilyName | string | | |
action_result.data.\*.threatName | string | | |
action_result.data.\*.title | string | | |
action_result.message | string | | |
summary.action_taken | string | | Retrieved Alerts for File |
summary.total_results | numeric | | 5 |
summary.total_objects | numeric | | 1 |
summary.total_objects_successful | numeric | | 1 |

## action: 'get device alerts'

Retrieve all alerts related to a specific device

Type: **investigate** <br>
Read only: **True**

#### Action Parameters

PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**device_id** | required | The device ID of the device to retrieve related alerts | string | `defender atp device id` |

#### Action Output

DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string | | success failed |
action_result.parameter.device_id | string | `defender atp device id` | |
action_result.data.\*.id | string | `defender atp alert id` | |
action_result.data.\*.aadTenantId | string | | |
action_result.data.\*.alertCreationTime | string | | |
action_result.data.\*.assignedTo | string | | |
action_result.data.\*.category | string | | |
action_result.data.\*.classification | string | | |
action_result.data.\*.comments.\*.comment | string | | |
action_result.data.\*.comments.\*.createdBy | string | | |
action_result.data.\*.comments.\*.createdTime | string | | |
action_result.data.\*.computerDnsName | string | | |
action_result.data.\*.description | string | | |
action_result.data.\*.detectionSource | string | | |
action_result.data.\*.detectorId | string | | |
action_result.data.\*.determination | string | | |
action_result.data.\*.evidence.\*.aadUserId | string | | |
action_result.data.\*.evidence.\*.accountName | string | | |
action_result.data.\*.evidence.\*.detectionStatus | string | | |
action_result.data.\*.evidence.\*.domainName | string | `domain` | |
action_result.data.\*.evidence.\*.entityType | string | | |
action_result.data.\*.evidence.\*.evidenceCreationTime | string | | |
action_result.data.\*.evidence.\*.fileName | string | `file name` | |
action_result.data.\*.evidence.\*.filePath | string | `file path` | |
action_result.data.\*.evidence.\*.ipAddress | string | `ip` | |
action_result.data.\*.evidence.\*.parentProcessCreationTime | string | | |
action_result.data.\*.evidence.\*.parentProcessFileName | string | | |
action_result.data.\*.evidence.\*.parentProcessFilePath | string | | |
action_result.data.\*.evidence.\*.parentProcessId | string | `pid` | |
action_result.data.\*.evidence.\*.processCommandLine | string | | |
action_result.data.\*.evidence.\*.processCreationTime | string | | |
action_result.data.\*.evidence.\*.processId | string | `pid` | |
action_result.data.\*.evidence.\*.registryHive | string | | |
action_result.data.\*.evidence.\*.registryKey | string | | |
action_result.data.\*.evidence.\*.registryValue | string | | |
action_result.data.\*.evidence.\*.registryValueName | string | | |
action_result.data.\*.evidence.\*.registryValueType | string | | |
action_result.data.\*.evidence.\*.sha1 | string | `sha1` | |
action_result.data.\*.evidence.\*.sha256 | string | `sha256` | |
action_result.data.\*.evidence.\*.url | string | | |
action_result.data.\*.evidence.\*.userPrincipalName | string | | |
action_result.data.\*.evidence.\*.userSid | string | | |
action_result.data.\*.firstEventTime | string | | |
action_result.data.\*.incidentId | numeric | | |
action_result.data.\*.investigationId | numeric | | |
action_result.data.\*.investigationState | string | | |
action_result.data.\*.lastEventTime | string | | |
action_result.data.\*.lastUpdateTime | string | | |
action_result.data.\*.loggedOnUsers.\*.accountName | string | | |
action_result.data.\*.loggedOnUsers.\*.domainName | string | | |
action_result.data.\*.machineId | string | `defender atp device id` | |
action_result.data.\*.rbacGroupName | string | | |
action_result.data.\*.relatedUser | string | | |
action_result.data.\*.relatedUser.domainName | string | | |
action_result.data.\*.relatedUser.userName | string | | |
action_result.data.\*.resolvedTime | string | | |
action_result.data.\*.severity | string | | |
action_result.data.\*.status | string | | |
action_result.data.\*.threatFamilyName | string | | |
action_result.data.\*.threatName | string | | |
action_result.data.\*.title | string | | |
action_result.message | string | | |
summary.action_taken | string | | Retrieved Alerts for Device |
summary.total_results | numeric | | 10 |
summary.total_objects | numeric | | 1 |
summary.total_objects_successful | numeric | | 1 |

## action: 'get user alerts'

Retrieve alerts related to a specific user

Type: **investigate** <br>
Read only: **True**

#### Action Parameters

PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**user** | required | The user to retrieve alerts for | string | |

#### Action Output

DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string | | success failed |
action_result.parameter.user | string | | |
action_result.data.\*.aadTenantId | string | | |
action_result.data.\*.alertCreationTime | string | | |
action_result.data.\*.assignedTo | string | | |
action_result.data.\*.category | string | | |
action_result.data.\*.classification | string | | |
action_result.data.\*.comments.\*.comment | string | | |
action_result.data.\*.comments.\*.createdBy | string | | |
action_result.data.\*.comments.\*.createdTime | string | | |
action_result.data.\*.computerDnsName | string | | |
action_result.data.\*.description | string | | |
action_result.data.\*.detectionSource | string | | |
action_result.data.\*.detectorId | string | | |
action_result.data.\*.determination | string | | |
action_result.data.\*.evidence.\*.aadUserId | string | | |
action_result.data.\*.evidence.\*.accountName | string | | |
action_result.data.\*.evidence.\*.detectionStatus | string | | |
action_result.data.\*.evidence.\*.domainName | string | `domain` | |
action_result.data.\*.evidence.\*.entityType | string | | |
action_result.data.\*.evidence.\*.evidenceCreationTime | string | | |
action_result.data.\*.evidence.\*.fileName | string | `file name` | |
action_result.data.\*.evidence.\*.filePath | string | `file path` | |
action_result.data.\*.evidence.\*.ipAddress | string | `ip` | |
action_result.data.\*.evidence.\*.parentProcessCreationTime | string | | |
action_result.data.\*.evidence.\*.parentProcessFileName | string | | |
action_result.data.\*.evidence.\*.parentProcessFilePath | string | | |
action_result.data.\*.evidence.\*.parentProcessId | string | `pid` | |
action_result.data.\*.evidence.\*.processCommandLine | string | | |
action_result.data.\*.evidence.\*.processCreationTime | string | | |
action_result.data.\*.evidence.\*.processId | string | `pid` | |
action_result.data.\*.evidence.\*.registryHive | string | | |
action_result.data.\*.evidence.\*.registryKey | string | | |
action_result.data.\*.evidence.\*.registryValue | string | | |
action_result.data.\*.evidence.\*.registryValueName | string | | |
action_result.data.\*.evidence.\*.registryValueType | string | | |
action_result.data.\*.evidence.\*.sha1 | string | `sha1` | |
action_result.data.\*.evidence.\*.sha256 | string | `sha256` | |
action_result.data.\*.evidence.\*.url | string | | |
action_result.data.\*.evidence.\*.userPrincipalName | string | | |
action_result.data.\*.evidence.\*.userSid | string | | |
action_result.data.\*.firstEventTime | string | | |
action_result.data.\*.id | string | `defender atp alert id` | |
action_result.data.\*.incidentId | numeric | | |
action_result.data.\*.investigationId | numeric | | |
action_result.data.\*.investigationState | string | | |
action_result.data.\*.lastEventTime | string | | |
action_result.data.\*.lastUpdateTime | string | | |
action_result.data.\*.loggedOnUsers.\*.accountName | string | | |
action_result.data.\*.loggedOnUsers.\*.domainName | string | | |
action_result.data.\*.machineId | string | `defender atp device id` | |
action_result.data.\*.rbacGroupName | string | | |
action_result.data.\*.relatedUser | string | | |
action_result.data.\*.relatedUser.domainName | string | | |
action_result.data.\*.relatedUser.userName | string | | |
action_result.data.\*.resolvedTime | string | | |
action_result.data.\*.severity | string | | |
action_result.data.\*.status | string | | |
action_result.data.\*.threatFamilyName | string | | |
action_result.data.\*.threatName | string | | |
action_result.data.\*.title | string | | |
action_result.message | string | | |
summary.action_taken | string | | Retrieved Alerts for User |
summary.total_results | numeric | | 5 |
summary.total_objects | numeric | | 1 |
summary.total_objects_successful | numeric | | 1 |

## action: 'get domain alerts'

Retrieve alerts related to a specific domain address

Type: **investigate** <br>
Read only: **True**

#### Action Parameters

PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**domain** | required | The domain address to retrieve alerts for | string | `domain` |

#### Action Output

DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string | | success failed |
action_result.parameter.domain | string | `domain` | |
action_result.data.\*.aadTenantId | string | | |
action_result.data.\*.alertCreationTime | string | | |
action_result.data.\*.assignedTo | string | | |
action_result.data.\*.category | string | | |
action_result.data.\*.classification | string | | |
action_result.data.\*.comments.\*.comment | string | | |
action_result.data.\*.comments.\*.createdBy | string | | |
action_result.data.\*.comments.\*.createdTime | string | | |
action_result.data.\*.computerDnsName | string | | |
action_result.data.\*.description | string | | |
action_result.data.\*.detectionSource | string | | |
action_result.data.\*.detectorId | string | | |
action_result.data.\*.determination | string | | |
action_result.data.\*.evidence.\*.aadUserId | string | | |
action_result.data.\*.evidence.\*.accountName | string | | |
action_result.data.\*.evidence.\*.detectionStatus | string | | |
action_result.data.\*.evidence.\*.domainName | string | `domain` | |
action_result.data.\*.evidence.\*.entityType | string | | |
action_result.data.\*.evidence.\*.evidenceCreationTime | string | | |
action_result.data.\*.evidence.\*.fileName | string | `file name` | |
action_result.data.\*.evidence.\*.filePath | string | `file path` | |
action_result.data.\*.evidence.\*.ipAddress | string | `ip` | |
action_result.data.\*.evidence.\*.parentProcessCreationTime | string | | |
action_result.data.\*.evidence.\*.parentProcessFileName | string | | |
action_result.data.\*.evidence.\*.parentProcessFilePath | string | | |
action_result.data.\*.evidence.\*.parentProcessId | string | `pid` | |
action_result.data.\*.evidence.\*.processCommandLine | string | | |
action_result.data.\*.evidence.\*.processCreationTime | string | | |
action_result.data.\*.evidence.\*.processId | string | `pid` | |
action_result.data.\*.evidence.\*.registryHive | string | | |
action_result.data.\*.evidence.\*.registryKey | string | | |
action_result.data.\*.evidence.\*.registryValue | string | | |
action_result.data.\*.evidence.\*.registryValueName | string | | |
action_result.data.\*.evidence.\*.registryValueType | string | | |
action_result.data.\*.evidence.\*.sha1 | string | `sha1` | |
action_result.data.\*.evidence.\*.sha256 | string | `sha256` | |
action_result.data.\*.evidence.\*.url | string | | |
action_result.data.\*.evidence.\*.userPrincipalName | string | | |
action_result.data.\*.evidence.\*.userSid | string | | |
action_result.data.\*.firstEventTime | string | | |
action_result.data.\*.id | string | `defender atp alert id` | |
action_result.data.\*.incidentId | numeric | | |
action_result.data.\*.investigationId | numeric | | |
action_result.data.\*.investigationState | string | | |
action_result.data.\*.lastEventTime | string | | |
action_result.data.\*.lastUpdateTime | string | | |
action_result.data.\*.loggedOnUsers.\*.accountName | string | | |
action_result.data.\*.loggedOnUsers.\*.domainName | string | | |
action_result.data.\*.machineId | string | `defender atp device id` | |
action_result.data.\*.rbacGroupName | string | | |
action_result.data.\*.relatedUser | string | | |
action_result.data.\*.relatedUser.domainName | string | | |
action_result.data.\*.relatedUser.userName | string | | |
action_result.data.\*.resolvedTime | string | | |
action_result.data.\*.severity | string | | |
action_result.data.\*.status | string | | |
action_result.data.\*.threatFamilyName | string | | |
action_result.data.\*.threatName | string | | |
action_result.data.\*.title | string | | |
action_result.message | string | | |
summary.action_taken | string | | Retrieved Alerts for Domain |
summary.total_results | numeric | | 5 |
summary.total_objects | numeric | | 1 |
summary.total_objects_successful | numeric | | 1 |

## action: 'delete indicator'

Delete an Indicator entity by ID

Type: **generic** <br>
Read only: **False**

Based on the link (<a href="https://docs.microsoft.com/en-us/microsoft-365/security/defender-endpoint/delete-ti-indicator-by-id?view=o365-worldwide" target="_blank">Delete Indicator API Documentation</a>), rate limitations for this action are 100 calls per minute and 1500 calls per hour.

#### Action Parameters

PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**indicator_id** | required | Indicator ID to delete | string | `defender atp indicator id` |

#### Action Output

DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string | | success failed |
action_result.parameter.indicator_id | string | `defender atp indicator id` | 16 |
action_result.data | string | | |
action_result.summary | string | | |
action_result.message | string | | Successfully deleted indicator entity |
summary.total_objects | numeric | | 1 |
summary.total_objects_successful | numeric | | 1 |

## action: 'run query'

An advanced search query

Type: **investigate** <br>
Read only: **True**

Based on the link (<a href="https://docs.microsoft.com/en-us/microsoft-365/security/defender-endpoint/run-advanced-query-api?view=o365-worldwide" target="_blank">Advanced Hunting API Documentation</a>), <li>rate limitations for this action are 45 calls per minute and 1500 calls per hour.</li><li>You can only run a query on data from the last 30 days.</li><li>The execution time is 10 minutes for every hour and 3 hours of running time a day. The maximal execution time of a single request is 10 minutes.</li><li>The maximum query result size of a single request cannot exceed 124 MB. If exceeded, HTTP 400 Bad Request with the message "Query execution has exceeded the allowed result size. Optimize your query by limiting the amount of results and try again" will appear.</li><li>The 429 response indicates that you have reached your quota limit, either in terms of requests or CPU usage. To figure out what limit has been reached, read the response body.</li>

#### Action Parameters

PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**query** | required | Query to fetch results | string | |

#### Action Output

DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string | | success failed |
action_result.parameter.query | string | | DeviceProcessEvents |where InitiatingProcessFileName =~ 'powershell.exe' |where ProcessCommandLine contains 'appdata' |project Timestamp, FileName, InitiatingProcessFileName, DeviceId |limit 2 |
action_result.data.\*.ActionType | string | | RegistryKeyDeleted |
action_result.data.\*.AntivirusEnabled | string | | BAD |
action_result.data.\*.AntivirusReporting | string | | N/A |
action_result.data.\*.AntivirusSignatureVersion | string | | N/A |
action_result.data.\*.AppGuardContainerId | string | | |
action_result.data.\*.BehaviorMonitoring | string | | GOOD |
action_result.data.\*.CloudProtection | string | | BAD |
action_result.data.\*.DeviceId | string | `defender atp device id` | 803c416946e8738b7711903a28362adeae6e1aea |
action_result.data.\*.DeviceName | string | | testserver9 |
action_result.data.\*.DomainName | string | `domain` | TestServer9 |
action_result.data.\*.DurationAtLeast | string | | 00.12:00:36 |
action_result.data.\*.FileName | string | `file name` | csc.exe |
action_result.data.\*.ImpairedCommunications | string | | BAD |
action_result.data.\*.InitiatingProcessAccountDomain | string | | nt authority |
action_result.data.\*.InitiatingProcessAccountName | string | | system |
action_result.data.\*.InitiatingProcessAccountObjectId | string | | |
action_result.data.\*.InitiatingProcessAccountSid | string | | S-1-5-18 |
action_result.data.\*.InitiatingProcessAccountUpn | string | | |
action_result.data.\*.InitiatingProcessCommandLine | string | | svchost.exe -k netsvcs -p -s wlidsvc |
action_result.data.\*.InitiatingProcessCreationTime | string | | 2022-09-13T12:18:40.7867576Z |
action_result.data.\*.InitiatingProcessFileName | string | `file name` | powershell.exe |
action_result.data.\*.InitiatingProcessFileSize | numeric | | 59952 |
action_result.data.\*.InitiatingProcessFolderPath | string | | c:\\windows\\system32\\test.exe |
action_result.data.\*.InitiatingProcessId | numeric | | 7656 |
action_result.data.\*.InitiatingProcessIntegrityLevel | string | | System |
action_result.data.\*.InitiatingProcessMD5 | string | | cd10cb894be1234fca0bf0e2b0c27c16 |
action_result.data.\*.InitiatingProcessParentCreationTime | string | | 2022-07-15T08:34:44.3266266Z |
action_result.data.\*.InitiatingProcessParentFileName | string | | services.exe |
action_result.data.\*.InitiatingProcessParentId | numeric | | 756 |
action_result.data.\*.InitiatingProcessSHA1 | string | | 1f912d4bec338ef10b7c9f12346286f8acc4eb97 |
action_result.data.\*.InitiatingProcessSHA256 | string | | f3feb95e7bcfb0766a694d93fca29eda7e2ca977c2395b4be75242814eb6d881 |
action_result.data.\*.InitiatingProcessTokenElevation | string | | TokenElevationTypeDefault |
action_result.data.\*.InitiatingProcessVersionInfoCompanyName | string | | Microsoft Corporation |
action_result.data.\*.InitiatingProcessVersionInfoFileDescription | string | | Host Process for Windows Services |
action_result.data.\*.InitiatingProcessVersionInfoInternalFileName | string | | svchost.exe |
action_result.data.\*.InitiatingProcessVersionInfoOriginalFileName | string | | svchost.exe |
action_result.data.\*.InitiatingProcessVersionInfoProductName | string | | Microsoft® Windows® Operating System |
action_result.data.\*.InitiatingProcessVersionInfoProductVersion | string | | 10.0.19041.1566 |
action_result.data.\*.LastTimestamp | string | | 2021-09-15T22:53:50.2952649Z |
action_result.data.\*.PUAProtection | string | | N/A |
action_result.data.\*.PreviousRegistryKey | string | | |
action_result.data.\*.PreviousRegistryValueData | string | | |
action_result.data.\*.PreviousRegistryValueName | string | | |
action_result.data.\*.RealtimeProtection | string | | N/A |
action_result.data.\*.RegistryKey | string | | |
action_result.data.\*.RegistryValueData | string | | |
action_result.data.\*.RegistryValueName | string | | |
action_result.data.\*.RegistryValueType | string | | |
action_result.data.\*.ReportId | numeric | | 641555 |
action_result.data.\*.SensorDataCollection | string | | BAD |
action_result.data.\*.SensorEnabled | string | | BAD |
action_result.data.\*.TamperProtection | string | | N/A |
action_result.data.\*.Timestamp | string | | 2021-09-15T10:53:13.5858707Z |
action_result.data.\*.UserName | string | `user name` | administrator1 |
action_result.summary.total_results | numeric | | 7 |
action_result.message | string | | Total results: 7 |
summary.total_objects | numeric | | 1 |
summary.total_objects_successful | numeric | | 1 |

## action: 'get domain devices'

Retrieve a collection of devices that have communicated to or from a given domain address

Type: **investigate** <br>
Read only: **True**

Based on the link (<a href="https://docs.microsoft.com/en-us/microsoft-365/security/defender-endpoint/get-domain-related-machines?view=o365-worldwide" target="_blank">Get domain related machines API Documentation</a>), rate limitations for this action are 100 calls per minute and 1500 calls per hour. You can query on devices last updated according to your configured retention period.<br>The action retrieves data of the last 30 days.

#### Action Parameters

PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**domain** | required | Domain to get the devices | string | `domain` |

#### Action Output

DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string | | success failed |
action_result.parameter.domain | string | `domain` | test.com |
action_result.data.\*.aadDeviceId | string | | |
action_result.data.\*.agentVersion | string | | 10.7740.19041.1110 |
action_result.data.\*.computerDnsName | string | | testmachine4 |
action_result.data.\*.defenderAvStatus | string | | Updated |
action_result.data.\*.deviceValue | string | | Normal |
action_result.data.\*.exposureLevel | string | | Medium |
action_result.data.\*.firstSeen | string | | 2021-08-02T06:12:16.3736341Z |
action_result.data.\*.healthStatus | string | | Inactive |
action_result.data.\*.id | string | `defender atp device id` | 803c416946e8738b7711903a28362adeae6e1aea |
action_result.data.\*.ipAddresses.\*.ipAddress | string | `ip` | 10.1.1.4 |
action_result.data.\*.ipAddresses.\*.macAddress | string | | 000X3X7X423X |
action_result.data.\*.ipAddresses.\*.operationalStatus | string | | Up |
action_result.data.\*.ipAddresses.\*.type | string | | Ethernet |
action_result.data.\*.isAadJoined | boolean | | False True |
action_result.data.\*.lastExternalIpAddress | string | `ip` | 137.116.83.101 |
action_result.data.\*.lastIpAddress | string | `ip` | 10.1.1.4 |
action_result.data.\*.lastSeen | string | | 2021-08-04T13:40:25.2473895Z |
action_result.data.\*.managedBy | string | | Unknown |
action_result.data.\*.managedByStatus | string | | Unknown |
action_result.data.\*.onboardingStatus | string | | Onboarded |
action_result.data.\*.osArchitecture | string | | 64-bit |
action_result.data.\*.osBuild | numeric | | 19042 |
action_result.data.\*.osPlatform | string | | Windows10 |
action_result.data.\*.osProcessor | string | | x64 |
action_result.data.\*.osVersion | string | | |
action_result.data.\*.rbacGroupId | numeric | | 0 |
action_result.data.\*.rbacGroupName | string | | |
action_result.data.\*.riskScore | string | | Medium |
action_result.data.\*.version | string | | 20H2 |
action_result.data.\*.vmMetadata | string | | |
action_result.data.\*.vmMetadata.cloudProvider | string | | TestCloudProvider |
action_result.data.\*.vmMetadata.resourceId | string | | /subscriptions/1b922e46-8595-4749-997a-1205e714cd91/resourceGroups/evaluation_3e5d447ba5d6470b9636a8709cd5b26a_4/providers/Test.Compute/virtualMachines/TestMachine4 |
action_result.data.\*.vmMetadata.subscriptionId | string | | 1b922e46-8595-4749-997a-1205e714cd91 |
action_result.data.\*.vmMetadata.vmId | string | | 238443dc-56ce-487f-aeb6-261a2a00a38c |
action_result.summary.total_devices | numeric | | 1 |
action_result.message | string | | Total devices: 1 |
summary.total_objects | numeric | | 1 |
summary.total_objects_successful | numeric | | 1 |

## action: 'update device tag'

Add or remove a tag from a given device (Maximum: 200 characters)

Type: **generic** <br>
Read only: **False**

#### Action Parameters

PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**device_id** | required | ID of the device | string | `defender atp device id` |
**operation** | required | Determines whether the provided tag is added or removed | string | |
**tag** | required | Value of the tag to add or remove from the machine | string | |

#### Action Output

DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string | | success failed |
action_result.parameter.device_id | string | `defender atp device id` | 7af22c8a3f92ec0c9c49b80aee3379bf9bfa0768 |
action_result.parameter.operation | string | | Add |
action_result.parameter.tag | string | | test-tag |
action_result.data.\*.@odata.context | string | | https://api.securitycenter.windows.com/api/$metadata#Machines/$entity |
action_result.data.\*.@odata.context | string | | https://api.securitycenter.windows.com/api/$metadata#Machines/$entity |
action_result.data.\*.aadDeviceId | string | | |
action_result.data.\*.agentVersion | string | | 10.5850.17763.404 |
action_result.data.\*.computerDnsName | string | `domain` | desktop-ph2a1ro |
action_result.data.\*.defenderAvStatus | string | | NotSupported |
action_result.data.\*.defenderAvStatus | string | | NotSupported |
action_result.data.\*.deviceValue | string | | Normal |
action_result.data.\*.deviceValue | string | | Normal |
action_result.data.\*.exposureLevel | string | | Medium |
action_result.data.\*.firstSeen | string | | 2019-04-16T00:27:12.2677222Z |
action_result.data.\*.groupName | string | | |
action_result.data.\*.healthStatus | string | | Active |
action_result.data.\*.id | string | `defender atp device id` | ae2e5bda4bb22ec9c321680079d03e5e4cdff400 |
action_result.data.\*.ipAddresses.\*.ipAddress | string | | 10.0.2.15 |
action_result.data.\*.ipAddresses.\*.ipAddress | string | | 10.0.2.15 |
action_result.data.\*.ipAddresses.\*.macAddress | string | | 002248242A86 |
action_result.data.\*.ipAddresses.\*.macAddress | string | | 001238242A86 |
action_result.data.\*.ipAddresses.\*.operationalStatus | string | | Up |
action_result.data.\*.ipAddresses.\*.operationalStatus | string | | Up |
action_result.data.\*.ipAddresses.\*.type | string | | Ethernet |
action_result.data.\*.ipAddresses.\*.type | string | | Ethernet |
action_result.data.\*.isAadJoined | boolean | | True False |
action_result.data.\*.lastExternalIpAddress | string | `ip` | 204.107.141.240 |
action_result.data.\*.lastIpAddress | string | `ip` | 10.1.66.140 |
action_result.data.\*.lastSeen | string | | 2019-05-03T05:23:45.9643247Z |
action_result.data.\*.machineTags | string | | Test Tag -21 |
action_result.data.\*.managedBy | string | | Unknown |
action_result.data.\*.managedBy | string | | |
action_result.data.\*.managedByStatus | string | | Unknown |
action_result.data.\*.managedByStatus | string | | Unknown |
action_result.data.\*.onboardingStatus | string | | Onboarded |
action_result.data.\*.onboardingStatus | string | | Onboarded |
action_result.data.\*.osArchitecture | string | | 64-bit |
action_result.data.\*.osArchitecture | string | | 64-bit |
action_result.data.\*.osBuild | numeric | | 17763 |
action_result.data.\*.osPlatform | string | | Windows10 |
action_result.data.\*.osProcessor | string | | x64 |
action_result.data.\*.osVersion | string | | |
action_result.data.\*.rbacGroupId | numeric | | 0 |
action_result.data.\*.rbacGroupName | string | | GROUP1 |
action_result.data.\*.riskScore | string | | None |
action_result.data.\*.systemProductName | string | | |
action_result.data.\*.version | string | | 1809 |
action_result.data.\*.vmMetadata | string | | |
action_result.data.\*.vmMetadata | string | | |
action_result.summary.operation | string | | Add |
action_result.summary.operation | string | | Add |
action_result.summary.tag | string | | test-new-ac |
action_result.summary.tag | string | | test-tag |
action_result.message | string | | Total devices: 1 |
summary.total_objects | numeric | | 1 |
summary.total_objects_successful | numeric | | 1 |

## action: 'get discovered vulnerabilities'

Retrieve a collection of discovered vulnerabilities related to a given device ID

Type: **investigate** <br>
Read only: **True**

Based on the link (<a href="https://docs.microsoft.com/en-us/microsoft-365/security/defender-endpoint/get-discovered-vulnerabilities?view=o365-worldwide" target="_blank">Get discovered vulnerabilities API Documentation</a>), rate limitations for this API are 50 calls per minute and 1500 calls per hour.

#### Action Parameters

PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**device_id** | required | ID of the device | string | `defender atp device id` |

#### Action Output

DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string | | success failed |
action_result.parameter.device_id | string | `defender atp device id` | 7af22c8a3f92ec0c9c49b80aee3379bf9bfa0768 |
action_result.data.\*.@odata.type | string | | |
action_result.data.\*.@odata.type | string | | #microsoft.windowsDefenderATP.api.PublicVulnerabilityDto |
action_result.data.\*.cvssV3 | numeric | | 8.8 |
action_result.data.\*.description | string | | Windows User Profile Service Elevation of Privilege Vulnerability |
action_result.data.\*.exploitInKit | numeric | | False |
action_result.data.\*.exploitTypes | string | | Local |
action_result.data.\*.exploitUris | string | `url` | https://msrc.microsoft.com/update-guide/vulnerability/CVE-2021-36934 |
action_result.data.\*.exploitVerified | numeric | | False |
action_result.data.\*.exposedMachines | numeric | | 1 |
action_result.data.\*.id | string | | CVE-2021-30600 |
action_result.data.\*.name | string | | CVE-2021-30600 |
action_result.data.\*.publicExploit | numeric | | False |
action_result.data.\*.publishedOn | string | | 2021-08-16T00:00:00Z |
action_result.data.\*.severity | string | | High |
action_result.data.\*.updatedOn | string | | 2021-08-23T00:00:00Z |
action_result.summary.total_vulnerabilities | numeric | | 7 |
action_result.message | string | | Total vulnerabilities: 7 |
summary.total_objects | numeric | | 1 |
summary.total_objects_successful | numeric | | 1 |

## action: 'remove app restriction'

Enable execution of any application on the device

Type: **contain** <br>
Read only: **False**

Based on the link (<a href="https://docs.microsoft.com/en-us/microsoft-365/security/defender-endpoint/unrestrict-code-execution?view=o365-worldwide" target="_blank">Remove app restriction API Documentation</a>), rate limitations for this API are 100 calls per minute and 1500 calls per hour.<br>This action can take a while to complete execution. The action retries at an interval of 5 seconds within a specified <b>timeout</b> to check if event execution is complete. If not, the action would return the latest status of the event along with the event ID.<br>The <b>get status</b> action can be used to fetch the latest status of the event with the event ID.<br>The maximum timeout period for a status check is 1 minute.

#### Action Parameters

PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**device_id** | required | ID of the device | string | `defender atp device id` |
**comment** | required | Comment | string | |
**timeout** | optional | Timeout in seconds (Default: 30) | numeric | |

#### Action Output

DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string | | success failed |
action_result.parameter.comment | string | | Unrestrict code execution since machine was cleaned and validated |
action_result.parameter.device_id | string | `defender atp device id` | 7af22c8a3f92ec0c9c49b80aee3379bf9bfa0768 |
action_result.parameter.timeout | numeric | | 30 |
action_result.data.\*.@odata.context | string | `url` | https://api.securitycenter.windows.com/api/$metadata#MachineActions/$entity |
action_result.data.\*.cancellationComment | string | | |
action_result.data.\*.cancellationDateTimeUtc | string | | |
action_result.data.\*.cancellationRequestor | string | | |
action_result.data.\*.computerDnsName | string | | win10atp2 |
action_result.data.\*.creationDateTimeUtc | string | | 2019-05-03T08:50:05.8076226Z |
action_result.data.\*.error | string | | |
action_result.data.\*.errorHResult | numeric | | 0 |
action_result.data.\*.externalId | string | | |
action_result.data.\*.id | string | `defender atp event id` | 6925706d-3a7e-4596-b2d7-321fca9cd965 |
action_result.data.\*.lastUpdateDateTimeUtc | string | | 2019-05-03T08:50:05.8076226Z |
action_result.data.\*.machineId | string | `defender atp device id` | 349838747f77ec74e43ab7ca70773a41f7bfb6f2 |
action_result.data.\*.relatedFileInfo | string | | |
action_result.data.\*.requestSource | string | | PublicApi |
action_result.data.\*.requestor | string | | 65265db5-a7ca-4199-a425-f37ad1dd6d31 |
action_result.data.\*.requestorComment | string | | Unrestrict code execution since machine was cleaned and validated |
action_result.data.\*.scope | string | | |
action_result.data.\*.status | string | | Succeeded |
action_result.data.\*.title | string | | |
action_result.data.\*.troubleshootInfo | string | | |
action_result.data.\*.type | string | | UnrestrictCodeExecution |
action_result.summary.event_id | string | `defender atp event id` | 6925706d-3a7e-4596-b2d7-321fca9cd965 |
action_result.summary.remove_app_restriction_status | string | | Pending |
action_result.summary.restriction_status | string | | Pending |
action_result.message | string | | Event id: cd2ab57e-5b52-43b0-99d8-c370fc620a54, Restriction status: Succeeded |
summary.total_objects | numeric | | 1 |
summary.total_objects_successful | numeric | | 1 |

## action: 'get exposure score'

Retrieve the organizational exposure score

Type: **investigate** <br>
Read only: **True**

#### Action Parameters

No parameters are required for this action

#### Action Output

DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string | | success failed |
action_result.data.\*.@odata.context | string | `url` | https://api.securitycenter.windows.com/api/$metadata#ExposureScore/$entity |
action_result.data.\*.rbacGroupId | string | | |
action_result.data.\*.rbacGroupName | string | | |
action_result.data.\*.score | numeric | | 46.23333333333333 |
action_result.data.\*.time | string | | 2021-08-31T10:41:12.6341624Z |
action_result.summary.exposure_score | numeric | | 46.23333333333333 |
action_result.message | string | | Exposure score: 46.23333333333333 |
summary.total_objects | numeric | | 1 |
summary.total_objects_successful | numeric | | 1 |

## action: 'get secure score'

Retrieve your Microsoft Secure Score for devices

Type: **investigate** <br>
Read only: **True**

Based on the link (<a href="https://docs.microsoft.com/en-us/microsoft-365/security/defender-endpoint/get-device-secure-score?view=o365-worldwide" target="_blank">Get device secure score API Documentation</a>), a higher Microsoft Secure Score for devices means your endpoints are more resilient from cybersecurity threat attacks.

#### Action Parameters

No parameters are required for this action

#### Action Output

DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string | | success failed |
action_result.data.\*.@odata.context | string | `url` | https://api.securitycenter.windows.com/api/$metadata#ConfigurationScore/$entity |
action_result.data.\*.rbacGroupId | string | | |
action_result.data.\*.rbacGroupName | string | | |
action_result.data.\*.score | numeric | | 350 |
action_result.data.\*.time | string | | 2021-08-31T10:55:48.6805335Z |
action_result.summary.secure_score | numeric | | 350 |
action_result.message | string | | Secure score: 350.0 |
summary.total_objects | numeric | | 1 |
summary.total_objects_successful | numeric | | 1 |

## action: 'get file'

Download a file from a device using live response

Type: **generic** <br>
Read only: **False**

Based on the link (<a href="https://docs.microsoft.com/en-us/microsoft-365/security/defender-endpoint/run-live-response?view=o365-worldwide" target="_blank">Run live response commands on a device API Documentation</a>), the user can collect file from a device in the vault, rate limitations for this API are 10 calls per minute.<br>The action tries to get the file using file_path along with the device_id. This action can take a while to complete the execution. The action retries at an interval of 5 seconds within a specified timeout to check if event execution is completed. If not, the action would return the latest status of the event along with the event ID. The get status action can be used to fetch the latest status of the event with the event ID. If the status is 'Succeeded', the event ID can be used in the same action to get the file. If all the parameters are given, the action gives higher priority to the event ID parameter.<br><br><b>Notes:</b><ul><li>Live response actions cannot be queued up and can only be executed one at a time.</li><li>If the machine that you are trying to run this action is in an RBAC device group that does not have an automated remediation level assigned to it, you'll need to at least enable the minimum Remediation Level for a given Device Group.</li></ul>

#### Action Parameters

PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**event_id** | optional | ID of the event | string | `defender atp event id` |
**device_id** | optional | ID of the device | string | `defender atp device id` |
**file_path** | optional | Path of the file to download from device | string | `file path` |
**comment** | optional | Comment | string | |
**timeout** | optional | Timeout in seconds (Default: 300) | numeric | |

#### Action Output

DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string | | success failed |
action_result.parameter.comment | string | | Testing get file live response |
action_result.parameter.device_id | string | `defender atp device id` | 7af22c8a3f92ec0c9c49b80aee3379bf9bfa0768 |
action_result.parameter.event_id | string | `defender atp event id` | f4ddc97a-6f4e-471c-9be5-45e0d6d64ab8 |
action_result.parameter.file_path | string | `file path` | C:\\Users\\administrator1\\Desktop\\Test\\one.txt |
action_result.parameter.timeout | numeric | | 300 |
action_result.data.\*.@odata.context | string | `url` | https://api.securitycenter.windows.com/api/$metadata#MachineActions/$entity |
action_result.data.\*.cancellationComment | string | | |
action_result.data.\*.cancellationDateTimeUtc | string | | |
action_result.data.\*.cancellationRequestor | string | | |
action_result.data.\*.commands.\*.command.params.\*.key | string | | Path |
action_result.data.\*.commands.\*.command.params.\*.value | string | `file path` | C:\\Users\\administrator1\\Desktop\\test\\one.txt |
action_result.data.\*.commands.\*.command.type | string | | GetFile |
action_result.data.\*.commands.\*.commandStatus | string | | Completed |
action_result.data.\*.commands.\*.endTime | string | | 2021-09-01T09:20:33.353Z |
action_result.data.\*.commands.\*.index | numeric | | 0 |
action_result.data.\*.commands.\*.startTime | string | | |
action_result.data.\*.computerDnsName | string | | testmachine7 |
action_result.data.\*.creationDateTimeUtc | string | | 2021-09-01T09:17:58.4219929Z |
action_result.data.\*.errorHResult | numeric | | 0 |
action_result.data.\*.externalId | string | | |
action_result.data.\*.id | string | `defender atp event id` | 81238f5f-f525-4b33-85e1-4460c5465ea4 |
action_result.data.\*.lastUpdateDateTimeUtc | string | | 2021-09-01T09:21:19.11422Z |
action_result.data.\*.machineId | string | `defender atp device id` | 51e978e9c3cd646dde81162f0517f13b8697cfcb |
action_result.data.\*.relatedFileInfo | string | | |
action_result.data.\*.requestSource | string | | PublicApi |
action_result.data.\*.requestor | string | | 65265db5-a7ca-4199-a425-f37ad1dd6d31 |
action_result.data.\*.requestorComment | string | | test |
action_result.data.\*.scope | string | | |
action_result.data.\*.status | string | | Succeeded |
action_result.data.\*.title | string | | |
action_result.data.\*.troubleshootInfo | string | | |
action_result.data.\*.type | string | | LiveResponse |
action_result.summary.event_id | string | `defender atp event id` | 6925706d-3a7e-4596-b2d7-321fca9cd965 |
action_result.summary.event_id_status | string | | Succeeded |
action_result.summary.file_status | string | | Succeeded |
action_result.summary.live_response_result | string | | |
action_result.summary.vault_id | string | `vault id` | 7553f175dbbfa2f0830bebe8c367fe68fd40a9a4 |
action_result.message | string | | Successfully added file to vault. vault_id: 7553f175dbbfa2f0830bebe8c367fe68fd40a9a4 |
summary.total_objects | numeric | | 1 |
summary.total_objects_successful | numeric | | 1 |

## action: 'put file'

Put a file from the library to a device using live response

Type: **generic** <br>
Read only: **False**

Based on the link (<a href="https://docs.microsoft.com/en-us/microsoft-365/security/defender-endpoint/run-live-response?view=o365-worldwide" target="_blank">Run live response commands on a device API Documentation</a>), the user can put a file from the library to the device, rate limitations for this API are 10 calls per minute.<br>This action can take a while to complete execution. The action retries at an interval of 5 seconds within a specified <b>timeout</b> to check if event execution is complete. If not, the action would return the latest status of the event along with the event ID.<br>The <b>get status</b> action can be used to fetch the latest status of the event with the event ID.<br><b>Notes:</b><ul><li>Live response actions cannot be queued up and can only be executed one at a time.</li><li>If the machine that you are trying to run this action is in an RBAC device group that does not have an automated remediation level assigned to it, you'll need to at least enable the minimum Remediation Level for a given Device Group.</li></ul>

#### Action Parameters

PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**device_id** | required | ID of the device | string | `defender atp device id` |
**file_name** | required | Name of the file | string | `file name` |
**comment** | required | Comment | string | |
**timeout** | optional | Timeout in seconds (Default: 300) | numeric | |

#### Action Output

DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string | | success failed |
action_result.parameter.comment | string | | Testing put file live response |
action_result.parameter.device_id | string | `defender atp device id` | 7af22c8a3f92ec0c9c49b80aee3379bf9bfa0768 |
action_result.parameter.file_name | string | `file name` | one.txt |
action_result.parameter.timeout | numeric | | 300 |
action_result.data.\*.@odata.context | string | `url` | https://api.securitycenter.windows.com/api/$metadata#MachineActions/$entity |
action_result.data.\*.cancellationComment | string | | |
action_result.data.\*.cancellationDateTimeUtc | string | | |
action_result.data.\*.cancellationRequestor | string | | |
action_result.data.\*.commands.\*.command.params.\*.key | string | | FileName |
action_result.data.\*.commands.\*.command.params.\*.value | string | `file name` | one.txt |
action_result.data.\*.commands.\*.command.type | string | | PutFile |
action_result.data.\*.commands.\*.commandStatus | string | | Completed |
action_result.data.\*.commands.\*.endTime | string | | 2021-09-01T06:43:33.717Z |
action_result.data.\*.commands.\*.index | numeric | | 0 |
action_result.data.\*.commands.\*.startTime | string | | 2021-09-01T06:43:32.42Z |
action_result.data.\*.computerDnsName | string | | testmachine7 |
action_result.data.\*.creationDateTimeUtc | string | | 2021-09-01T06:40:58.9203082Z |
action_result.data.\*.errorHResult | numeric | | 0 |
action_result.data.\*.externalId | string | | |
action_result.data.\*.id | string | `defender atp event id` | 30f736e4-1538-46ca-b21f-8f315b096077 |
action_result.data.\*.lastUpdateDateTimeUtc | string | | 2021-09-01T06:44:17.161248Z |
action_result.data.\*.machineId | string | `defender atp device id` | 51e978e9c3cd646dde81162f0517f13b8697cfcb |
action_result.data.\*.relatedFileInfo | string | | |
action_result.data.\*.requestSource | string | | PublicApi |
action_result.data.\*.requestor | string | | 65265db5-a7ca-4199-a425-f37ad1dd6d31 |
action_result.data.\*.requestorComment | string | | putfile |
action_result.data.\*.scope | string | | |
action_result.data.\*.status | string | | Succeeded |
action_result.data.\*.title | string | | |
action_result.data.\*.troubleshootInfo | string | | |
action_result.data.\*.type | string | | LiveResponse |
action_result.summary.event_id | string | `defender atp event id` | 6925706d-3a7e-4596-b2d7-321fca9cd965 |
action_result.summary.put_file_status | string | | Succeeded |
action_result.message | string | | Event id: 30f736e4-1538-46ca-b21f-8f315b096077, Put file status: Succeeded |
summary.total_objects | numeric | | 1 |
summary.total_objects_successful | numeric | | 1 |

## action: 'cancel live response'

Cancel a live response action

Type: **generic** <br>
Read only: **False**

Based on the link (<a href="https://learn.microsoft.com/en-us/defender-endpoint/api/cancel-machine-action" target="_blank">Cancel Machine Action API Documentation</a>).

#### Action Parameters

PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**action_id** | required | ID of the live response action to cancel | string | `defender atp action id` |
**comment** | required | Comment explaining the reason for cancellation | string | |

#### Action Output

DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string | | success failed |
action_result.parameter.action_id | string | `defender atp action id` | |
action_result.parameter.comment | string | | |
action_result.data.\*.id | string | `defender atp action id` | |
action_result.data.\*.type | string | | |
action_result.data.\*.scope | string | | |
action_result.data.\*.requestor | string | | |
action_result.data.\*.requestorComment | string | | |
action_result.data.\*.status | string | | |
action_result.data.\*.machineId | string | | |
action_result.data.\*.computerDnsName | string | | |
action_result.data.\*.creationDateTimeUtc | string | | |
action_result.data.\*.lastUpdateDateTimeUtc | string | | |
action_result.summary.action_taken | string | | Canceled Live Response Action |
action_result.message | string | | |
summary.total_objects | numeric | | 1 |
summary.total_objects_successful | numeric | | 1 |

## action: 'run script'

Run a script from the library on a device using live response

Type: **generic** <br>
Read only: **False**

Based on the link (<a href="https://docs.microsoft.com/en-us/microsoft-365/security/defender-endpoint/run-live-response?view=o365-worldwide" target="_blank">Run live response commands on a device API Documentation</a>), the user can run a script from the library on a device. The script_args parameter is passed to your script, rate limitations for this API are 10 calls per minute.<br>The action tries to execute the script using script_name along with the device_id. This action can take a while to complete the execution. The action retries at an interval of 5 seconds within a specified timeout to check if event execution is completed. If not, the action would return the latest status of the event along with the event ID. The get status action can be used to fetch the latest status of the event with the event ID. If the status is 'Succeded', the event ID can be used in the same action to get the script output. If all the parameters are given, the action gives higher priority to the event ID parameter.<br><br><b>Notes:</b><ul><li>The maximum timeout period for the script execution is 10 minutes.</li><li>Live response actions cannot be queued up and can only be executed one at a time.</li><li>If the machine that you are trying to run this action is in an RBAC device group that does not have an automated remediation level assigned to it, you'll need to at least enable the minimum Remediation Level for a given Device Group.</li></ul>

#### Action Parameters

PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**event_id** | optional | ID of the event | string | `defender atp event id` |
**device_id** | optional | ID of the device | string | `defender atp device id` |
**script_name** | optional | Name of the script file to execute on the device | string | `file name` |
**script_args** | optional | Arguments of the script file | string | |
**comment** | optional | Comment | string | |
**timeout** | optional | Timeout in seconds (Default: 300) | numeric | |

#### Action Output

DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string | | success failed |
action_result.parameter.comment | string | | Testing live response for run script |
action_result.parameter.device_id | string | `defender atp device id` | 7af22c8a3f92ec0c9c49b80aee3379bf9bfa0768 |
action_result.parameter.event_id | string | `defender atp event id` | f4ddc97a-6f4e-471c-9be5-45e0d6d64ab8 |
action_result.parameter.script_args | string | | OfficeClickToRun |
action_result.parameter.script_name | string | `file name` | minidump.ps1 |
action_result.parameter.timeout | numeric | | 300 |
action_result.data.\*.exit_code | numeric | | 0 |
action_result.data.\*.script_errors | string | | |
action_result.data.\*.script_name | string | | script4.ps1 |
action_result.data.\*.script_output | string | | Transcript started, output file is C:\\ProgramData\\Microsoft\\Windows Defender Advanced Threat Protection\\Temp\\PSScriptOutputs\\PSScript_Transcript\_{66D7B239-34C7-43EF-BB6D-2F6D4C03086E}.txt x is smaller than y |
action_result.summary.event_id | string | `defender atp event id` | 6925706d-3a7e-4596-b2d7-321fca9cd965 |
action_result.summary.event_id_status | string | | |
action_result.summary.live_response_result | string | | |
action_result.summary.script_status | string | | Succeeded |
action_result.message | string | | Successfully executed script |
summary.total_objects | numeric | | 1 |
summary.total_objects_successful | numeric | | 1 |

## action: 'get missing kbs'

Retrieve missing KBs (security updates) by given device ID

Type: **investigate** <br>
Read only: **True**

Based on the link (<a href="https://docs.microsoft.com/en-us/microsoft-365/security/defender-endpoint/get-missing-kbs-machine?view=o365-worldwide" target="_blank">Get missing KBs API Documentation</a>), the user can retrieve a collection of missing security updated related to a given device ID.

#### Action Parameters

PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**device_id** | required | ID of the device | string | `defender atp device id` |

#### Action Output

DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string | | success failed |
action_result.parameter.device_id | string | `defender atp device id` | 7af22c8a3f92ec0c9c49b80aee3379bf9bfa0768 |
action_result.data.\*.cveAddressed | numeric | | 26 |
action_result.data.\*.id | string | | 5005033 |
action_result.data.\*.machineMissedOn | numeric | | 1 |
action_result.data.\*.name | string | | August 2021 Security Updates |
action_result.data.\*.osBuild | numeric | | 19042 |
action_result.data.\*.productsNames | string | | windows_10 |
action_result.data.\*.url | string | `url` | https://catalog.update.microsoft.com/v7/site/Search.aspx?q=KB5005033 |
action_result.summary.total_kbs | numeric | | 1 |
action_result.message | string | | Total KBs: 1 |
summary.total_objects | numeric | | 1 |
summary.total_objects_successful | numeric | | 1 |

______________________________________________________________________

Auto-generated Splunk SOAR Connector documentation.

Copyright 2026 Splunk Inc.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing,
software distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and limitations under the License.
