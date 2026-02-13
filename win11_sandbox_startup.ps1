
############################################################ STARTUP ############################################################

param(
    [switch]$debugSaveFiles,
    [switch]$noInstall,
    [switch]$noDownload,
    [switch]$removeMsStoreAsSource = $false
)

# CHECK THAT WE'RE RUNNING IN THE WINDOWS SANDBOX - THIS SCRIPT IS INTENDED TO BE RUN FROM WITHIN THE WINDOWS SANDBOX
# WE'LL DO A RUDAMENTARY CHECK FOR IF THE CURRENT USER IS NAMED 'WDAGUtilityAccount'
if ($env:USERNAME -ne "WDAGUtilityAccount") {
    Write-Host "`n`n[ERROR] This script is intended to be run from WITHIN the Windows Sandbox.`nIt appears you are running this from outside the sandbox.`n" -ForegroundColor Red
    Write-Host "`nPress Enter to exit.`n`n" -ForegroundColor Yellow
    Read-Host
    exit
}

# CHECK FOR ADMINISTRATOR PRIVILEGES - REQUIRED FOR INSTALLATION STEPS
if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Host "`n`n[ERROR] This script requires Administrator privileges.`nPlease re-run the script as Administrator.`n" -ForegroundColor Red
    Write-Host "`nPress Enter to exit.`n`n" -ForegroundColor Yellow
    Read-Host
    exit
}


############################################################ GENERAL TWEAKS ############################################################

Write-Host "`n`n============================================================" -ForegroundColor Blue
Write-Host "Applying General Tweaks" -ForegroundColor Blue
Write-Host "============================================================" -ForegroundColor Blue

# FIX FOR SLOW MSI PACKAGE INSTALL - SEE: https://github.com/microsoft/Windows-Sandbox/issues/68#issuecomment-2754867968
Write-Host "`nApplying MSI package install performance fix..." -ForegroundColor Cyan
reg add "HKLM\SYSTEM\CurrentControlSet\Control\CI\Policy" /v "VerifiedAndReputablePolicyState" /t REG_DWORD /d 0 /f | Out-Null
CiTool.exe --refresh --json | Out-Null  # REFRESHES POLICY - USE JSON OUTPUT PARAM OR ELSE IT WILL PROMPT FOR CONFIRMATION, EVEN WITH OUT-NULL
Write-Host "  -> MSI performance fix applied." -ForegroundColor Green

# CHANGE EXECUTION POLICY FOR POWERSHELL TO ALLOW RUNNING SCRIPTS
Write-Host "`nSetting PowerShell execution policy..." -ForegroundColor Cyan
try { 
    Set-ExecutionPolicy -ExecutionPolicy Unrestricted -Scope LocalMachine -ErrorAction Stop | Out-Null
    Write-Host "  -> Execution policy set to Unrestricted." -ForegroundColor Green
} catch {
    Write-Host "  -> [WARNING] Could not set execution policy. $($_.Exception.Message)" -ForegroundColor Yellow
}

# DETECT SYSTEM ARCHITECTURE ONCE FOR THE ENTIRE SCRIPT
$systemArch = switch ($env:PROCESSOR_ARCHITECTURE) {
    "AMD64"   { "x64" }
    "ARM64"   { "arm64" }
    "x86"     { "x86" }
    "*ARM*"   { "arm" }
    default   { "x64" }
}
Write-Host "`nDetected system architecture: $systemArch" -ForegroundColor Green

# SET PROGRESS PREFERENCE FOR FASTER DOWNLOADS THROUGHOUT THE SCRIPT
$originalProgressPreference = $ProgressPreference
$ProgressPreference = 'SilentlyContinue'

Write-Host "`nGeneral tweaks applied successfully!" -ForegroundColor Blue


############################################################ DARK DESIGN ############################################################

Write-Host "`n`n============================================================" -ForegroundColor Blue
Write-Host "Configuring Dark Theme" -ForegroundColor Blue
Write-Host "============================================================" -ForegroundColor Blue

Write-Host "`nApplying dark theme settings..." -ForegroundColor Cyan

Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Themes\Personalize" -Name "AppsUseLightTheme" -Value 0
Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Themes\Personalize" -Name "SystemUsesLightTheme" -Value 0

# SET DARKMODE WALLPAPER
$wallpaperPath = "C:\Windows\Web\Wallpaper\Windows\img19.jpg"
$code = @'
using System.Runtime.InteropServices;
public class Wallpaper {
    [DllImport("user32.dll", CharSet=CharSet.Auto)]
    public static extern int SystemParametersInfo(int uAction, int uParam, string lpvParam, int fuWinIni);
}
'@

Add-Type $code
$SPI_SETDESKWALLPAPER = 0x0014
$UPDATE_INI_FILE = 0x01
$SEND_CHANGE = 0x02

[Wallpaper]::SystemParametersInfo($SPI_SETDESKWALLPAPER, 0, $wallpaperPath, ($UPDATE_INI_FILE -bor $SEND_CHANGE))

Write-Host "  -> Dark theme applied successfully!" -ForegroundColor Green

Write-Host "`nDark theme configuration completed successfully!" -ForegroundColor Blue


############################################################ EXPLORER ############################################################

Write-Host "`n`n============================================================" -ForegroundColor Blue
Write-Host "Configuring Windows Explorer" -ForegroundColor Blue
Write-Host "============================================================" -ForegroundColor Blue

Write-Host "`nConfiguring Explorer settings..." -ForegroundColor Cyan

# SHOW HIDDEN FILES AND FILE EXTENSIONS
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "HideFileExt" /t REG_DWORD /d 0 /f | Out-Null
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "Hidden" /t REG_DWORD /d 1 /f | Out-Null
Write-Host "  -> Enabled hidden files and file extensions visibility." -ForegroundColor Green

######################### ADD 'Open PowerShell/CMD Here' TO CONTEXT MENU #########################
Write-Host "`nAdding 'Open PowerShell/CMD Here' context menu options..." -ForegroundColor Cyan

$powershellPath = "C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"
$cmdPath = "C:\Windows\System32\cmd.exe"

if (!(Test-Path $powershellPath)) { $powershellPath = $null; Write-Host "  -> PowerShell executable not found. Can't add context menu option 'Open PowerShell Here'." -ForegroundColor Yellow }
if ($null -ne $powershellPath) {
    reg add "HKEY_CLASSES_ROOT\Directory\Background\shell\MyPowerShell" /ve /d "Open PowerShell Here" /f | Out-Null
    reg add "HKEY_CLASSES_ROOT\Directory\Background\shell\MyPowerShell" /v "Icon" /t REG_SZ /d "$powershellPath,0" /f | Out-Null
    reg add "HKEY_CLASSES_ROOT\Directory\Background\shell\MyPowerShell\command" /ve /d "powershell.exe -noexit -command Set-Location -literalPath '%V'" /f | Out-Null
    Write-Host "  -> Added 'Open PowerShell Here' context menu option." -ForegroundColor Green
}

if (!(Test-Path $cmdPath)) { $cmdPath = $null; Write-Host "  -> CMD executable not found. Can't add context menu option 'Open CMD Here'." -ForegroundColor Yellow }
if ($null -ne $cmdPath) {
    reg add "HKEY_CLASSES_ROOT\Directory\Background\shell\Mycmd" /ve /d "Open CMD Here" /f | Out-Null
    reg add "HKEY_CLASSES_ROOT\Directory\Background\shell\Mycmd" /v "Icon" /t REG_SZ /d "$cmdPath,0" /f | Out-Null
    reg add "HKEY_CLASSES_ROOT\Directory\Background\shell\Mycmd\command" /ve /d "cmd.exe /s /k cd /d `"\`"%V`"\`"" /f | Out-Null
    Write-Host "  -> Added 'Open CMD Here' context menu option." -ForegroundColor Green
}

######################### ADD FILE TYPES FOR CREATING NEW FILES TO CONTEXT MENU #########################
Write-Host "`nAdding 'New File' context menu options..." -ForegroundColor Cyan
reg add "HKEY_CLASSES_ROOT\txtfile" /ve /d "Text Document" /f | Out-Null
reg add "HKEY_CLASSES_ROOT\.txt\ShellNew" /f | Out-Null
reg --% add "HKEY_CLASSES_ROOT\.txt\ShellNew" /v "NullFile" /t REG_SZ /d "" /f
reg add "HKEY_CLASSES_ROOT\.txt\ShellNew" /v "ItemName" /t REG_SZ /d "New Text Document" /f | Out-Null
Write-Host "  -> Added 'New Text Document' to context menu." -ForegroundColor Green

reg add "HKEY_CLASSES_ROOT\.ps1" /ve /d "ps1file" /f | Out-Null
reg add "HKEY_CLASSES_ROOT\ps1file" /ve /d "PowerShell Script" /f | Out-Null
reg add "HKEY_CLASSES_ROOT\ps1file\DefaultIcon" /ve /d "%SystemRoot%\System32\imageres.dll,-5372" /f | Out-Null
reg add "HKEY_CLASSES_ROOT\.ps1\ShellNew" /ve /d "ps1file" /f | Out-Null
reg add "HKEY_CLASSES_ROOT\.ps1\ShellNew" /f | Out-Null
reg --% add "HKEY_CLASSES_ROOT\.ps1\ShellNew" /v "NullFile" /t REG_SZ /d "" /f
reg add "HKEY_CLASSES_ROOT\.ps1\ShellNew" /v "ItemName" /t REG_SZ /d "script" /f | Out-Null
Write-Host "  -> Added 'New PowerShell Script' to context menu." -ForegroundColor Green

Write-Host "`nExplorer configuration completed successfully!" -ForegroundColor Blue


############################################################ INSTALL MSStore ############################################################

Write-Host "`n`n============================================================" -ForegroundColor Blue
Write-Host "Starting Microsoft Store Installation" -ForegroundColor Blue
Write-Host "============================================================" -ForegroundColor Blue

######################### Configuration #########################
$flightRing = "Retail"         # APPARENTLY ACCEPTS 'Retail', 'Internal', AND 'External'
$flightingBranchName = ""      # EMPTY ('') FOR NORMAL RELEASE - OTHERWISE APPARENT POSSIBLE VALUES: Dev, Beta, ReleasePreview, MSIT, CanaryChannel, external
$currentBranch = "ge_release"  # 'rs_prerelease' FOR INSIDER, 'ni_release' FOR NORMAL RELEASE ON WINDOWS BUILD BELOW 26100, 'ge_release' FOR NORMAL RELEASE EQUAL OR ABOVE 26100

######################### Define Working Directory #########################
# GET THE PATH TO THE USER'S PERSONAL DOWNLOADS FOLDER IN A RELIABLE WAY
$userDownloadsFolder = (New-Object -ComObject Shell.Application).Namespace('shell:Downloads').Self.Path
# Define the subfolder name for all our files
$subfolderName = "MSStore Install"
# CATEGORY ID FOR THE MICROSOFT STORE APP PACKAGE
$storeCategoryId = "64293252-5926-453c-9494-2d4021f1c78d" 
# COMBINE THEM TO CREATE THE FULL WORKING DIRECTORY PATH
$workingDir = Join-Path -Path $userDownloadsFolder -ChildPath $subfolderName
$LogDirectory = Join-Path -Path $workingDir -ChildPath "Logs"

# CREATE THE DIRECTORY IF IT DOESN'T EXIST
if (-not (Test-Path -Path $workingDir)) {
    New-Item -Path $workingDir -ItemType Directory -Force | Out-Null
}

if ($debugSaveFiles) {
    # CREATE A SUBDIRECTORY FOR LOGS IF IT DOESN'T EXIST
    if (-not (Test-Path -Path $LogDirectory)) { New-Item -Path $LogDirectory -ItemType Directory -Force | Out-Null }
    Write-Host "All files (logs, downloads) will be saved to: '$LogDirectory'" -ForegroundColor Yellow
}

######################### XML Templates #########################

# [1] 'GetCookie' REQUEST BODY
# SEE: https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-wusp/36a5d99a-a3ca-439d-bcc5-7325ff6b91e2
$cookieXmlTemplate = @"
<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope" xmlns:a="http://www.w3.org/2005/08/addressing">
    <s:Header>
        <a:Action s:mustUnderstand="1">http://www.microsoft.com/SoftwareDistribution/Server/ClientWebService/GetCookie</a:Action>
        <a:MessageID>urn:uuid:$(New-Guid)</a:MessageID>
        <a:To s:mustUnderstand="1">https://fe3.delivery.mp.microsoft.com/ClientWebService/client.asmx</a:To>
        <o:Security s:mustUnderstand="1" xmlns:o="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd">
            <wuws:WindowsUpdateTicketsToken wsu:id="ClientMSA" xmlns:wsu="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd" xmlns:wuws="http://schemas.microsoft.com/msus/2014/10/WindowsUpdateAuthorization">
                <TicketType Name="MSA" Version="1.0" Policy="MBI_SSL"><user></user></TicketType>
            </wuws:WindowsUpdateTicketsToken>
        </o:Security>
    </s:Header>
    <s:Body><GetCookie xmlns="http://www.microsoft.com/SoftwareDistribution/Server/ClientWebService" /></s:Body>
</s:Envelope>
"@

# [2] 'SyncUpdates' REQUEST BODY - BASED ON INTERCEPTED XML REQUEST USING MICROSOFT STORE
# SEE: https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-wusp/6b654980-ae63-4b0d-9fae-2abb516af894
$fileListXmlTemplate = @"
<s:Envelope xmlns:a="http://www.w3.org/2005/08/addressing" xmlns:s="http://www.w3.org/2003/05/soap-envelope">
    <s:Header>
        <a:Action s:mustUnderstand="1">http://www.microsoft.com/SoftwareDistribution/Server/ClientWebService/SyncUpdates</a:Action>
        <a:MessageID>urn:uuid:$(New-Guid)</a:MessageID>
        <a:To s:mustUnderstand="1">https://fe3cr.delivery.mp.microsoft.com/ClientWebService/client.asmx</a:To>
        <o:Security s:mustUnderstand="1" xmlns:o="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd">
            <Timestamp xmlns="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd">
                <Created>$((Get-Date).ToUniversalTime().ToString("yyyy-MM-dd'T'HH:mm:ss.fff'Z'"))</Created>
                <Expires>$((Get-Date).AddMinutes(5).ToUniversalTime().ToString("yyyy-MM-dd'T'HH:mm:ss.fff'Z'"))</Expires>
            </Timestamp>
            <wuws:WindowsUpdateTicketsToken wsu:id="ClientMSA" xmlns:wsu="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd" xmlns:wuws="http://schemas.microsoft.com/msus/2014/10/WindowsUpdateAuthorization">
                <TicketType Name="MSA" Version="1.0" Policy="MBI_SSL">
                    <user/>
                </TicketType>
            </wuws:WindowsUpdateTicketsToken>
        </o:Security>
    </s:Header>
    <s:Body>
        <SyncUpdates xmlns="http://www.microsoft.com/SoftwareDistribution/Server/ClientWebService">
            <cookie>
                <Expiration>$((Get-Date).AddYears(10).ToUniversalTime().ToString('u').Replace(' ','T'))</Expiration>
                <EncryptedData>{0}</EncryptedData>
            </cookie>
            <parameters>
                <ExpressQuery>false</ExpressQuery>
                <InstalledNonLeafUpdateIDs>
                    <int>1</int><int>2</int><int>3</int><int>11</int><int>19</int><int>2359974</int><int>5169044</int>
                    <int>8788830</int><int>23110993</int><int>23110994</int><int>54341900</int><int>59830006</int><int>59830007</int>
                    <int>59830008</int><int>60484010</int><int>62450018</int><int>62450019</int><int>62450020</int><int>98959022</int>
                    <int>98959023</int><int>98959024</int><int>98959025</int><int>98959026</int><int>104433538</int><int>129905029</int>
                    <int>130040031</int><int>132387090</int><int>132393049</int><int>133399034</int><int>138537048</int><int>140377312</int>
                    <int>143747671</int><int>158941041</int><int>158941042</int><int>158941043</int><int>158941044</int><int>159123858</int>
                    <int>159130928</int><int>164836897</int><int>164847386</int><int>164848327</int><int>164852241</int><int>164852246</int>
                    <int>164852253</int>
                </InstalledNonLeafUpdateIDs>
                <SkipSoftwareSync>false</SkipSoftwareSync>
                <NeedTwoGroupOutOfScopeUpdates>false</NeedTwoGroupOutOfScopeUpdates>
                <FilterAppCategoryIds>
                    <CategoryIdentifier>
                        <Id>{1}</Id>
                    </CategoryIdentifier>
                </FilterAppCategoryIds>
                <TreatAppCategoryIdsAsInstalled>true</TreatAppCategoryIdsAsInstalled>
                <AlsoPerformRegularSync>false</AlsoPerformRegularSync>
                <ComputerSpec/>
                <ExtendedUpdateInfoParameters>
                    <XmlUpdateFragmentTypes>
                        <XmlUpdateFragmentType>Extended</XmlUpdateFragmentType>
                    </XmlUpdateFragmentTypes>
                    <Locales>
                        <string>en-US</string>
                        <string>en</string>
                    </Locales>
                </ExtendedUpdateInfoParameters>
                <ClientPreferredLanguages>
                    <string>en-US</string>
                </ClientPreferredLanguages>
                <ProductsParameters>
                    <SyncCurrentVersionOnly>false</SyncCurrentVersionOnly>
                    <DeviceAttributes>E:BranchReadinessLevel=CB&amp;CurrentBranch={2}&amp;OEMModel=Virtual%20Machine&amp;FlightRing={3}&amp;AttrDataVer=321&amp;InstallLanguage=en-US&amp;OSUILocale=en-US&amp;InstallationType=Client&amp;FlightingBranchName={4}&amp;OSSkuId=48&amp;App=WU_STORE&amp;ProcessorManufacturer=GenuineIntel&amp;OEMName_Uncleaned=Microsoft%20Corporation&amp;AppVer=1407.2503.28012.0&amp;OSArchitecture=AMD64&amp;IsFlightingEnabled=1&amp;TelemetryLevel=1&amp;DefaultUserRegion=39070&amp;WuClientVer=1310.2503.26012.0&amp;OSVersion=10.0.26100.3915&amp;DeviceFamily=Windows.Desktop</DeviceAttributes>
                    <CallerAttributes>Interactive=1;IsSeeker=1;</CallerAttributes>
                    <Products/>
                </ProductsParameters>
            </parameters>
        </SyncUpdates>
    </s:Body>
</s:Envelope>
"@

# [3] 'GetExtendedUpdateInfo2' - AFTER GETTING THE LIST OF MATCHED FILES (APP VERSION AND DEPENDENCIES), THIS LETS US GET THE ACTUAL DOWNLOAD URLs
# SEE: https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-wusp/2f66a682-164f-47ec-968e-e43c0a85dc21
$fileUrlXmlTemplate = @"
<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope" xmlns:a="http://www.w3.org/2005/08/addressing">
    <s:Header>
        <a:Action s:mustUnderstand="1">http://www.microsoft.com/SoftwareDistribution/Server/ClientWebService/GetExtendedUpdateInfo2</a:Action>
        <a:MessageID>urn:uuid:$(New-Guid)</a:MessageID>
        <a:To s:mustUnderstand="1">https://fe3cr.delivery.mp.microsoft.com/ClientWebService/client.asmx/secured</a:To>
        <o:Security s:mustUnderstand="1" xmlns:o="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd">
            <u:Timestamp u:Id="_0" xmlns:u="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd">
                <u:Created>$((Get-Date).ToUniversalTime().ToString("yyyy-MM-dd'T'HH:mm:ss.fff'Z'"))</u:Created>
                <u:Expires>$((Get-Date).AddMinutes(5).ToUniversalTime().ToString("yyyy-MM-dd'T'HH:mm:ss.fff'Z'"))</u:Expires>
            </u:Timestamp>
            <wuws:WindowsUpdateTicketsToken wsu:id="ClientMSA" xmlns:wsu="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd" xmlns:wuws="http://schemas.microsoft.com/msus/2014/10/WindowsUpdateAuthorization">
                <TicketType Name="MSA" Version="1.0" Policy="MBI_SSL"><user>{0}</user></TicketType>
            </wuws:WindowsUpdateTicketsToken>
        </o:Security>
    </s:Header>
    <s:Body>
        <GetExtendedUpdateInfo2 xmlns="http://www.microsoft.com/SoftwareDistribution/Server/ClientWebService">
            <updateIDs><UpdateIdentity><UpdateID>{1}</UpdateID><RevisionNumber>{2}</RevisionNumber></UpdateIdentity></updateIDs>
            <infoTypes><XmlUpdateFragmentType>FileUrl</XmlUpdateFragmentType></infoTypes>
            <DeviceAttributes>E:BranchReadinessLevel=CB&amp;CurrentBranch={3}&amp;OEMModel=Virtual%20Machine&amp;FlightRing={4}&amp;AttrDataVer=321&amp;InstallLanguage=en-US&amp;OSUILocale=en-US&amp;InstallationType=Client&amp;FlightingBranchName={5}&amp;OSSkuId=48&amp;App=WU_STORE&amp;ProcessorManufacturer=GenuineIntel&amp;OEMName_Uncleaned=Microsoft%20Corporation&amp;AppVer=1407.2503.28012.0&amp;OSArchitecture=AMD64&amp;IsFlightingEnabled=1&amp;TelemetryLevel=1&amp;DefaultUserRegion=39070&amp;WuClientVer=1310.2503.26012.0&amp;OSVersion=10.0.26100.3915&amp;DeviceFamily=Windows.Desktop</DeviceAttributes>
        </GetExtendedUpdateInfo2>
    </s:Body>
</s:Envelope>
"@

######################### SCRIPT EXECUTION #########################
$headers = @{ "Content-Type" = "application/soap+xml; charset=utf-8" }
$baseUri = "https://fe3.delivery.mp.microsoft.com/ClientWebService/client.asmx"

try {
    # [1] GET COOKIE
    Write-Host "`n[1] Getting authentication cookie..." -ForegroundColor Magenta
    $cookieRequestPayload = $cookieXmlTemplate
    if ($debugSaveFiles) { $cookieRequestPayload | Set-Content -Path (Join-Path $LogDirectory "01_Step1_Request.xml") }
    
    $cookieResponse = Invoke-WebRequest -Uri $baseUri -Method Post -Body $cookieRequestPayload -Headers $headers -UseBasicParsing
    if ($debugSaveFiles) { $cookieResponse.Content | Set-Content -Path (Join-Path $LogDirectory "01_Step1_Response.xml"); Write-Host "  -> Saved request and response logs for [1]." -ForegroundColor Gray }

    $cookieResponseXml = [xml]$cookieResponse.Content
    $encryptedCookieData = $cookieResponseXml.Envelope.Body.GetCookieResponse.GetCookieResult.EncryptedData
    Write-Host "  -> Success. Cookie received." -ForegroundColor Green

    # [2] GET FILE LIST
    Write-Host "`n[2] Getting file list..." -ForegroundColor Magenta
    $fileListRequestPayload = $fileListXmlTemplate -f $encryptedCookieData, $storeCategoryId, $currentBranch, $flightRing, $flightingBranchName
    if ($debugSaveFiles) { [System.IO.File]::WriteAllText((Join-Path $LogDirectory "02_Step2_Request_AUTOMATED.xml"), $fileListRequestPayload, [System.Text.UTF8Encoding]::new($false)) }

    $fileListResponse = Invoke-WebRequest -Uri $baseUri -Method Post -Body $fileListRequestPayload -Headers $headers -UseBasicParsing
    if ($debugSaveFiles) { $fileListResponse.Content | Set-Content -Path (Join-Path $LogDirectory "02_Step2_Response_SUCCESS.xml") }

    # THE RESPONSE CONTAINS XML FRAGMENTS THAT ARE HTML-ENCODED - WE MUST DECODE THIS BEFORE TREATING IT AS XML
    Add-Type -AssemblyName System.Web
    $decodedContent = [System.Web.HttpUtility]::HtmlDecode($fileListResponse.Content)
    $fileListResponseXml = [xml]$decodedContent
    Write-Host "  -> Successfully received and decoded [2] response." -ForegroundColor Green
    
    $fileIdentityMap = @{}
    
    # GET THE TWO MAIN LISTS OF UPDATES FROM THE NOW CORRECTLY-DECODED RESPONSE
    $newUpdates = $fileListResponseXml.Envelope.Body.SyncUpdatesResponse.SyncUpdatesResult.NewUpdates.UpdateInfo
    $allExtendedUpdates = $fileListResponseXml.Envelope.Body.SyncUpdatesResponse.SyncUpdatesResult.ExtendedUpdateInfo.Updates.Update

    Write-Host "`n--- Correlating Update Information ---" -ForegroundColor Cyan

    # FILTER THE 'NewUpdates' LIST TO ONLY INCLUDE ITEMS THAT ARE ACTUAL DOWNLOADABLE FILES
    # THESE ARE IDENTIFIED BY THE PRESENCE OF THE '<SecuredFragment>' TAG INSIDE THEIR INNER XML
    $downloadableUpdates = $newUpdates | Where-Object { $_.Xml.Properties.SecuredFragment }

    Write-Host "  -> Found $($downloadableUpdates.Count) potentially downloadable packages." -ForegroundColor Gray

    # NOW, PROCESS EACH DOWNLOADABLE UPDATE
    foreach ($update in $downloadableUpdates) {
        $lookupId = $update.ID
        
        # FIND THE MATCHING ENTRY IN THE 'ExtendedUpdateInfo' LIST USING THE SAME NUMERIC ID
        $extendedInfo = $allExtendedUpdates | Where-Object { $_.ID -eq $lookupId } | Select-Object -First 1
        
        if (-not $extendedInfo) {
            Write-Host "     [WARNING] Could not find matching ExtendedInfo for downloadable update ID $lookupId. Skipping." -ForegroundColor Yellow
            continue
        }
        
        # FROM THE EXTENDED INFO, GET THE ACTUAL PACKAGE FILE AND IGNORE THE METADATA '.cab' FILES
        $fileNode = $extendedInfo.Xml.Files.File | Where-Object { $_.FileName -and $_.FileName -notlike "Abm_*" } | Select-Object -First 1

        if (-not $fileNode) {
            Write-Host "     [WARNING] Found matching ExtendedInfo for ID $lookupId, but it contains no valid file node. Skipping." -ForegroundColor Yellow
            continue
        }

        # ADDITIONAL PARSING
        $fileName = $fileNode.FileName
        $updateGuid = $update.Xml.UpdateIdentity.UpdateID
        $revNum = $update.Xml.UpdateIdentity.RevisionNumber
        $fullIdentifier = $fileNode.GetAttribute("InstallerSpecificIdentifier")

        # DEFINE THE REGEX BASED ON THE OFFICIAL PACKAGE IDENTITY STRUCTURE
        # <Name>_<Version>_<Architecture>_<ResourceId>_<PublisherId>
        $regex = "^(?<Name>.+?)_(?<Version>\d+\.\d+\.\d+\.\d+)_(?<Architecture>[a-zA-Z0-9]+)_(?<ResourceId>.*?)_(?<PublisherId>[a-hjkmnp-tv-z0-9]{13})$"
        
        $packageInfo = [PSCustomObject]@{
            FullName       = $fullIdentifier
            FileName       = $fileName
            UpdateID       = $updateGuid
            RevisionNumber = $revNum
        }

        if ($fullIdentifier -match $regex) {
            # IF THE REGEX MATCHES, POPULATE THE OBJECT WITH THE NAMED CAPTURE GROUPS
            $packageInfo | Add-Member -MemberType NoteProperty -Name "PackageName" -Value $matches.Name
            $packageInfo | Add-Member -MemberType NoteProperty -Name "Version" -Value $matches.Version
            $packageInfo | Add-Member -MemberType NoteProperty -Name "Architecture" -Value $matches.Architecture
            $packageInfo | Add-Member -MemberType NoteProperty -Name "ResourceId" -Value $matches.ResourceId
            $packageInfo | Add-Member -MemberType NoteProperty -Name "PublisherId" -Value $matches.PublisherId
        } else {
            # FALLBACK FOR ANY IDENTIFIERS THAT DON'T MATCH THE PATTERN
            $packageInfo | Add-Member -MemberType NoteProperty -Name "PackageName" -Value "Unknown (Parsing Failed)"
            $packageInfo | Add-Member -MemberType NoteProperty -Name "Architecture" -Value "unknown"
        }

        $fileIdentityMap[$fullIdentifier] = $packageInfo

        Write-Host "  -> Correlated: '$($packageInfo.PackageName)' ($($packageInfo.Architecture))" -ForegroundColor Gray
    }

    Write-Host "--- Correlation Complete ---" -ForegroundColor Cyan
    Write-Host "  -> Found and prepared $($fileIdentityMap.Count) downloadable files." -ForegroundColor Green


    ######################### [3] FILTER, GET URLS, AND DOWNLOAD #########################
    try {
        Write-Host "`n[3] Filtering packages for your system architecture ('$systemArch')..." -ForegroundColor Magenta

        ######################### FILTER THE PACKAGES #########################

        # [1] ISOLATE THE 'Microsoft.WindowsStore' PACKAGES AND FIND THE LATEST VERSION
        $latestStorePackage = $fileIdentityMap.Values |
            Where-Object { $_.PackageName -eq 'Microsoft.WindowsStore' } |
            Sort-Object { [version]$_.Version } -Descending |
            Select-Object -First 1

        # [2] GET ALL OTHER DEPENDENCIES THAT MATCH THE SYSTEM ARCHITECTURE (OR ARE NEUTRAL)
        $filteredDependencies = $fileIdentityMap.Values |
            Where-Object {
                ($_.PackageName -ne 'Microsoft.WindowsStore') -and
                ( ($_.Architecture -eq $systemArch) -or ($_.Architecture -eq 'neutral') )
            }

        # [3] COMBINE THE LISTS FOR THE FINAL DOWNLOAD QUEUE
        $packagesToDownload = @()
        if ($latestStorePackage) {
            $packagesToDownload += $latestStorePackage
            Write-Host "  -> Found latest Store package: $($latestStorePackage.FullName)" -ForegroundColor Green
        } else {
            Write-Host "  -> [WARNING] Could not find any Microsoft.WindowsStore package." -ForegroundColor Yellow
        }

        $packagesToDownload += $filteredDependencies
        Write-Host "  -> Found $($filteredDependencies.Count) dependencies for '$systemArch' architecture." -ForegroundColor Gray
        Write-Host "  -> Total files to download: $($packagesToDownload.Count)" -ForegroundColor Green
        Write-Host ""


        ######################### LOOP THROUGH THE FILTERED LIST, GET URLS, AND DOWNLOAD #########################
        Write-Host "[4] Fetching URLs and downloading files..." -ForegroundColor Magenta

        foreach ($package in $packagesToDownload) {
            Write-Host "  -> Processing: $($package.FullName)" -ForegroundColor Gray

            # GET THE DOWNLOAD URL FOR THIS SPECIFIC PACKAGE
            $fileUrlRequestPayload = $fileUrlXmlTemplate -f $encryptedCookieData, $package.UpdateID, $package.RevisionNumber, $currentBranch, $flightRing, $flightingBranchName
            $fileUrlResponse = Invoke-WebRequest -Uri "$baseUri/secured" -Method Post -Body $fileUrlRequestPayload -Headers $headers -UseBasicParsing
            $fileUrlResponseXml = [xml]$fileUrlResponse.Content

            $fileLocations = $fileUrlResponseXml.Envelope.Body.GetExtendedUpdateInfo2Response.GetExtendedUpdateInfo2Result.FileLocations.FileLocation
            $baseFileName = [System.IO.Path]::GetFileNameWithoutExtension($package.FileName)
            $downloadUrl = ($fileLocations | Where-Object { $_.Url -like "*$baseFileName*" }).Url

            if (-not $downloadUrl) {
                Write-Host "     [WARNING] Could not retrieve download URL. Skipping." -ForegroundColor Yellow
                continue
            }
            if ($noDownload) {
                Write-Host "     Skipping download (noDownload switch set)." -ForegroundColor Yellow
                continue
            }

            # DOWNLOAD THE FILE - CONSTRUCT A MORE DESCRIPTIVE FILENAME USING THE PACKAGE'S FULL NAME AND ITS ORIGINAL EXTENSION
            $fileExtension = [System.IO.Path]::GetExtension($package.FileName)
            $newFileName = "$($package.FullName)$($fileExtension)"
            $filePath = Join-Path $workingDir $newFileName

            try {
                Invoke-WebRequest -Uri $downloadUrl -OutFile $filePath -UseBasicParsing
                Write-Host "     Download complete." -ForegroundColor Green
            } catch {
                Write-Host "     [ERROR] Failed to download. $($_.Exception.Message)" -ForegroundColor Red
            }
        }

        Write-Host "`nFinished downloading packages to: $workingDir" -ForegroundColor Green

    } catch {
        Write-Host "[ERROR] An error occurred during the filtering or downloading phase:" -ForegroundColor Red
        Write-Host "  $($_.Exception.Message)" -ForegroundColor Red
    }

    if ($noDownload) {
        Write-Host "`nSkipping remaining steps (noDownload switch set)." -ForegroundColor Yellow
        return
    }
    if ($noInstall) {
        Write-Host "`nSkipping installation step (noInstall switch set)." -ForegroundColor Yellow
        return
    }
    
    ######################### [5] INSTALL DOWNLOADED PACKAGES #########################
    Write-Host "`n[5] Installing packages..." -ForegroundColor Magenta

    # [1] DEFINE THE INSTALLATION ORDER FOR DEPENDENCIES BASED ON THEIR BASE NAMES - THE ORDER HERE IS CRITICAL FOR DEPENDENCIES
    $dependencyInstallOrder = @(
        'Microsoft.VCLibs',
        'Microsoft.NET.Native.Framework',
        'Microsoft.NET.Native.Runtime',
        'Microsoft.UI.Xaml'
    )

    # [2] GET ALL DOWNLOADED PACKAGE FILES AND SEPARATE THE MAIN APP FROM DEPENDENCIES
    try {
        $allDownloadedFiles = Get-ChildItem -Path $workingDir -File | Where-Object { $_.Extension -in '.appx', '.msix', '.appxbundle', '.msixbundle' }
        $storePackageFile = $allDownloadedFiles | Where-Object { $_.Name -like 'Microsoft.WindowsStore*' } | Select-Object -First 1
        $dependencyFiles = $allDownloadedFiles | Where-Object { $_.Name -notlike 'Microsoft.WindowsStore*' }

        if (-not $dependencyFiles -and -not $storePackageFile) {
            Write-Host "  -> No package files found in '$workingDir' to install." -ForegroundColor Yellow
            return
        }

        # [3] INSTALL DEPENDENCIES IN THE CORRECT, PREDEFINED ORDER
        Write-Host "  -> Installing dependencies..." -ForegroundColor Cyan
        foreach ($baseName in $dependencyInstallOrder) {
            # FIND ALL PACKAGES THAT START WITH THE CURRENT BASE NAME (e.g. 'Microsoft.VCLibs*')
            # SORTING BY NAME ENSURES A CONSISTENT ORDER IF MULTIPLE VERSIONS EXIST
            $packagesInGroup = $dependencyFiles | Where-Object { $_.Name -like "$baseName*" } | Sort-Object Name
            foreach ($package in $packagesInGroup) {
                Write-Host "     Installing $($package.Name)" -ForegroundColor Gray
                try {
                    Add-AppxPackage -Path $package.FullName
                    Write-Host "     Success." -ForegroundColor Green
                } catch {
                    Write-Host "     [ERROR] Failed to install. $($_.Exception.Message)" -ForegroundColor Red
                }
            }
        }

        # [4] INSTALL THE MAIN MICROSOFT STORE PACKAGE LAST
        if ($storePackageFile) {
            Write-Host "  -> Installing the main application..." -ForegroundColor Cyan
            Write-Host "     Installing $($storePackageFile.Name)" -ForegroundColor Gray
            try {
                Add-AppxPackage -Path $storePackageFile.FullName
                Write-Host "     Success: Microsoft Store has been installed/updated." -ForegroundColor Green
            } catch {
                Write-Host "     [ERROR] Failed to install. $($_.Exception.Message)" -ForegroundColor Red
            }
        } else {
            Write-Host "  -> Microsoft Store package was not found in the download folder." -ForegroundColor Yellow
        }

        Write-Host "`nInstallation process finished." -ForegroundColor Green

    } catch {
        Write-Host "[ERROR] A critical error occurred during the installation phase: $($_.Exception.Message)" -ForegroundColor Red
    }
    
    ######################### SET REGION TO US SO THE STORE WILL WORK - DEFAULT 'World' REGION DOES NOT WORK #########################
    Write-Host "`n  -> Configuring registry settings for Microsoft Store..." -ForegroundColor Cyan
    try {
        # DEFINE THE PATH TO THE REGISTRY KEY
        $geoKeyPath = "HKCU:\Control Panel\International\Geo"
        # CHECK IF THE 'Geo' KEY EXISTS - IF NOT, CREATE IT
        # THE '-Force' SWITCH ENSURES THAT PARENT KEYS ('International') ARE ALSO CREATED IF THEY ARE MISSING
        if (-not (Test-Path $geoKeyPath)) {
            New-Item -Path $geoKeyPath -Force | Out-Null
        }
        # SET THE 'Nation' VALUE
        Set-ItemProperty -Path $geoKeyPath -Name "Nation" -Value "244"
        # SET THE 'Name' VALUE
        Set-ItemProperty -Path $geoKeyPath -Name "Name" -Value "US"
        Write-Host "     Registry configuration complete." -ForegroundColor Green
    }
    catch {
        Write-Host "     [ERROR] Failed to configure registry settings. $($_.Exception.Message)" -ForegroundColor Red
    }

    Write-Host "`nMicrosoft Store installation completed successfully!" -ForegroundColor Blue

} catch {
    Write-Host "`n[ERROR] An error occurred during Microsoft Store installation:" -ForegroundColor Red
    if ($_.Exception.Response) {
        $statusCode = $_.Exception.Response.StatusCode.value__
        $statusDescription = $_.Exception.Response.StatusDescription
        Write-Host "  Status Code: $statusCode" -ForegroundColor Yellow
        Write-Host "  Status Description: $statusDescription" -ForegroundColor Yellow
        
        if ($debugSaveFiles) {
            $errorLogPath = Join-Path $LogDirectory "ERROR_Response.txt"
            try {
                $stream = $_.Exception.Response.GetResponseStream()
                $reader = New-Object System.IO.StreamReader($stream)
                $reader.ReadToEnd() | Set-Content -Path $errorLogPath
                Write-Host "  Server Response saved to '$errorLogPath'" -ForegroundColor Gray
            } catch { 
                "Could not read error response body." | Set-Content -Path $errorLogPath 
            }
        }
    } else {
        Write-Host "  $($_.Exception.Message)" -ForegroundColor Red
    }
}


############################################################ INSTALL WinGet ############################################################

Write-Host "`n`n============================================================" -ForegroundColor Blue
Write-Host "Starting WinGet Installation" -ForegroundColor Blue
Write-Host "============================================================" -ForegroundColor Blue

# DEFINE SHARED DOWNLOAD PATH
$downloadPath = (New-Object -ComObject Shell.Application).Namespace('shell:Downloads').Self.Path

function Get-LatestRelease {
    param(
        [string]$repoOwner = 'microsoft',
        [string]$repoName = 'winget-cli'
    )
    try {
        $releasesUrl = "https://api.github.com/repos/$repoOwner/$repoName/releases"
        $releases = Invoke-RestMethod -Uri $releasesUrl -UseBasicParsing
    } catch {
        Write-Host "[ERROR] Failed to fetch releases from GitHub API: $($_.Exception.Message)" -ForegroundColor Red
        return $null
    }
	if (-not $releases) { 
        Write-Host "[ERROR] No releases found for $repoOwner/$repoName." -ForegroundColor Red
        return $null
    }
    # PICK THE TOP ENTRY ONCE SORTED BY 'published_at' DESCENDING
    $latestRelease = $releases | Sort-Object -Property published_at -Descending | Select-Object -First 1
    return $latestRelease
}

function Get-AssetUrl {
    param(
        [Parameter(Mandatory=$true)]
        $release,
        [Parameter(Mandatory=$true)]
        [string]$assetName
    )
    if ($release.assets -and $release.assets.Count -gt 0) {
        $asset = $release.assets | Where-Object { $_.name -eq $assetName }
        if ($asset) { return $asset.browser_download_url }
    }
    return $null
}

function Install-WingetDependencies {
    param([string]$depsFolder)

    # LOOK FOR 'DesktopAppInstaller_Dependencies.json' TO DETERMINE EXPLICIT INSTALL ORDER
    $jsonFile = Join-Path $depsFolder "DesktopAppInstaller_Dependencies.json"
    if (Test-Path $jsonFile) {
        Write-Host "  -> Installing dependencies based on DesktopAppInstaller_Dependencies.json" -ForegroundColor Cyan
        $jsonContent = Get-Content $jsonFile -Raw | ConvertFrom-Json
        $dependencies = $jsonContent.Dependencies

        foreach ($dep in $dependencies) {
            # FOR EXAMPLE: 'Microsoft.VCLibs.140.00.UWPDesktop' + '14.0.33728.0'
            $matchingFiles = Get-ChildItem -Path $depsFolder -Filter *.appx -Recurse |
                Where-Object { $_.Name -like "*$($dep.Name)*" -and $_.Name -like "*$($dep.Version)*" }
            foreach ($file in $matchingFiles) {
                Write-Host "     Installing dependency: $($file.Name)" -ForegroundColor Gray
                Add-AppxPackage -Path $file.FullName
            }
        }
    }
    else {
        # IF THE JSON DOESN'T EXIST, INSTALL ALL .APPX IN THE FOLDER
        Write-Host "  -> No DesktopAppInstaller_Dependencies.json found, installing all .appx in $depsFolder" -ForegroundColor Yellow
        foreach ($appxFile in Get-ChildItem $depsFolder -Filter *.appx -Recurse) {
            Write-Host "     Installing: $($appxFile.Name)" -ForegroundColor Gray
            Add-AppxPackage -Path $appxFile.FullName
        }
    }
}

# PREVENTS PROGRESS BAR FROM SHOWING (OFTEN SPEEDS DOWNLOADS)
# (Already set globally at the beginning of the script)

$latestRelease = Get-LatestRelease
if (-not $latestRelease) { 
    Write-Host "[ERROR] Could not retrieve the latest release. Skipping WinGet installation." -ForegroundColor Red
    return
}

$latestTag = $latestRelease.tag_name
Write-Host "`nLatest winget version tag is: $latestTag" -ForegroundColor Green

# DOWNLOAD THE MSIX BUNDLE
Write-Host "`nDownloading WinGet package..." -ForegroundColor Cyan
$msixName = "Microsoft.DesktopAppInstaller_8wekyb3d8bbwe.msixbundle"
$msixUrl = Get-AssetUrl -release $latestRelease -assetName $msixName
if (-not $msixUrl) { 
    Write-Host "[ERROR] Could not find $msixName in the latest release assets." -ForegroundColor Red
    return
}

$msixPath = Join-Path $downloadPath $msixName
Invoke-WebRequest -Uri $msixUrl -OutFile $msixPath
Write-Host "  -> Downloaded $msixName successfully." -ForegroundColor Green

# USE THE GLOBALLY DETECTED ARCHITECTURE
Write-Host "`nUsing detected architecture: $systemArch" -ForegroundColor Gray

# DOWNLOAD THE DEPENDENCIES ZIP
Write-Host "`nDownloading WinGet dependencies..." -ForegroundColor Cyan
$depsZipName = "DesktopAppInstaller_Dependencies.zip"
$depsZipUrl  = Get-AssetUrl -release $latestRelease -assetName $depsZipName
$topDepsFolder = Join-Path $downloadPath "Dependencies"
$depsFolder    = Join-Path $topDepsFolder $systemArch

if ($depsZipUrl) {
    $depsZipPath = Join-Path $downloadPath $depsZipName
    Invoke-WebRequest -Uri $depsZipUrl -OutFile $depsZipPath
    # REMOVE EXISTING DEPENDENCIES FOLDER AND EXPAND THE ZIP
    if (Test-Path $topDepsFolder) { Remove-Item -Path $topDepsFolder -Recurse -Force }
    Expand-Archive -LiteralPath $depsZipPath -DestinationPath $topDepsFolder -Force
    Write-Host "  -> Downloaded dependencies successfully." -ForegroundColor Green
} 
else { 
    Write-Host "  -> No $depsZipName found in $latestTag, skipping dependency download." -ForegroundColor Yellow
}

# IF DEPENDENCIES EXIST FOR THIS ARCHITECTURE, INSTALL THEM
Write-Host "`nInstalling WinGet dependencies..." -ForegroundColor Cyan
if (Test-Path $depsFolder) {
    Install-WingetDependencies -depsFolder $depsFolder
} else {
    Write-Host "  -> No architecture-specific dependencies found at $depsFolder" -ForegroundColor Yellow
}

# INSTALL THE WINGET MSIX BUNDLE
Write-Host "`nInstalling WinGet..." -ForegroundColor Cyan
Add-AppxPackage -Path $msixPath
Write-Host "  -> WinGet installed successfully." -ForegroundColor Green

# REMOVE MSSTORE SOURCE IF SET TO DO SO
Write-Host "`nConfiguring WinGet sources..." -ForegroundColor Cyan
if ($removeMsStoreAsSource) {
    try {
        winget source remove -n msstore --ignore-warnings
        Write-Host "  -> Removed 'msstore' source from winget." -ForegroundColor Green
    } catch {
        Write-Host "  -> [WARNING] An error occurred while trying to remove msstore source: $($_.Exception.Message)" -ForegroundColor Yellow
    }
} else {
    # AUTOMATICALLY ACCEPT SOURCE AGREEMENTS TO AVOID PROMPTS - MOSTLY APPLIES TO MSSTORE
    winget list --accept-source-agreements | Out-Null
    Write-Host "  -> Accepted source agreements." -ForegroundColor Green
}

Write-Host "`nWinGet installation completed successfully!" -ForegroundColor Blue


############################################################ FINALIZATION ############################################################

# RESTORE PROGRESS PREFERENCE
$ProgressPreference = $originalProgressPreference

Write-Host "`n`n============================================================" -ForegroundColor Blue
Write-Host "Finalizing Setup" -ForegroundColor Blue
Write-Host "============================================================" -ForegroundColor Blue

# RESTART EXPLORER SO CHANGES TAKE EFFECT
Write-Host "`nRestarting Explorer to apply changes..." -ForegroundColor Cyan
try {
    Stop-Process -Name explorer -Force -ErrorAction Stop
    Start-Sleep -Milliseconds 500
    Start-Process explorer
    Write-Host "  -> Explorer restarted successfully." -ForegroundColor Green
} catch {
    Write-Host "  -> [WARNING] Could not restart Explorer. $($_.Exception.Message)" -ForegroundColor Yellow
}

Write-Host "`n`n============================================================" -ForegroundColor Blue
Write-Host "Setup Complete!" -ForegroundColor Blue
Write-Host "============================================================`n`n" -ForegroundColor Blue
