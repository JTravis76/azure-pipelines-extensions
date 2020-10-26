[CmdletBinding()]
param()

Trace-VstsEnteringInvocation $MyInvocation

$env:CURRENT_TASK_ROOTDIR = Split-Path -Parent $MyInvocation.MyCommand.Path

Import-Module $env:CURRENT_TASK_ROOTDIR\ps_modules\VstsTaskSdk

# Get inputs for the task
$machinesList = Get-VstsInput -Name machinesList -Require
$adminUserName = ""
$adminPassword = ""

$winRmAuthentication = Get-VstsInput -Name WinRMAuthentication
if ($winRmAuthentication -eq "Standard")
{
    $adminUserName = Get-VstsInput -Name AdminUserName -Require
    $adminPassword = Get-VstsInput -Name AdminPassword -Require
}
else
{
    $thycoticServer = Get-VstsInput -Name ThycoticServer -Require
    $thycoticRule = Get-VstsInput -Name ThycoticRule -Require
    $thycoticKey = Get-VstsInput -Name ThycoticKey -Require
    $thycoticSecretId = Get-VstsInput -Name ThycoticSecretId -Require

    # First set the Secret Server environment
    # Then, fetch secret and apply to admin username and password
    # Note: WINRM seems to like user name is this format; user@domain
    try {
        tss remove -c
        $v = tss init -u "$thycoticServer" -r "$thycoticRule" -k "$thycoticKey"
        if ($v[0] -eq "400 - Bad Request")
        {
            throw "Failed to init Thycotic SDK. Could check if Rule and Key are not flipped."
            exit 1
        }
        
        $secret = tss secret -s $thycoticSecretId
        if ($secret[0] -eq "400 - Bad Request")
        {
            throw "Access Denied to secret id: $thycoticSecretId"
            exit 1
        }

        $domain = ""
        $username = ""

        $thycotic = $secret | ConvertFrom-Json
        foreach ($i in $thycotic.items)
        {
            if ($i.fieldName -eq "Domain")
            {
                $domain = $i.itemValue
            }
            if ($i.fieldName -eq "Username")
            {
                $username = $i.itemValue
            }
            if ($i.fieldName -eq "Password")
            {
                $adminPassword = $i.itemValue
            }
        }
        if ($username -eq "" -or $domain -eq "")
        {
            throw "Invalid username and/or domain."
            exit 1
        }
        $adminUserName = ($username + "@" + $domain)  
    }
    catch [System.Exception] {
        Write-Host ("##vso[task.LogIssue type=error;]Error within Thycotic Secret Server. Please check your settings.")
        Write-Host $_
        exit 1
    }
}
$winrmProtocol = Get-VstsInput -Name WinRMProtocol -Require
$testCertificate = Get-VstsInput -Name TestCertificate -AsBool
$webDeployPackage = Get-VstsInput -Name WebDeployPackage -Require
$webDeployParamFile = Get-VstsInput -Name WebDeployParamFile
$overRideParams = Get-VstsInput -Name OverRideParams
$websiteName = Get-VstsInput -Name WebsiteName -Require
$removeAdditionalFiles = Get-VstsInput -Name RemoveAdditionalFiles -AsBool
$excludeFilesFromAppData = Get-VstsInput -Name ExcludeFilesFromAppData -AsBool
$takeAppOffline = Get-VstsInput -Name TakeAppOffline -AsBool
$additionalArguments = Get-VstsInput -Name AdditionalArguments
$deployInParallel = Get-VstsInput -Name DeployInParallel -AsBool

try
{
    if ([Console]::InputEncoding -is [Text.UTF8Encoding] -and [Console]::InputEncoding.GetPreamble().Length -ne 0) 
    { 
	    Write-Verbose "Resetting input encoding."
	    [Console]::InputEncoding = New-Object Text.UTF8Encoding $false 
    }

    . $env:CURRENT_TASK_ROOTDIR\TelemetryHelper\TelemetryHelper.ps1
    . $env:CURRENT_TASK_ROOTDIR\DeployIISWebApp.ps1

    (Main -machinesList $machinesList -adminUserName $adminUserName -adminPassword $adminPassword -winrmProtocol $winrmProtocol -testCertificate $testCertificate -webDeployPackage "$webDeployPackage" -webDeployParamFile "$webDeployParamFile" -overRideParams "$overRideParams" -websiteName "$websiteName" -removeAdditionalFiles $removeAdditionalFiles -excludeFilesFromAppData $excludeFilesFromAppData -takeAppOffline $takeAppOffline -additionalArguments $additionalArguments -deployInParallel $deployInParallel)
}
catch
{
    Write-Verbose $_.Exception.ToString() -Verbose
    throw
}
finally
{
    Trace-VstsLeavingInvocation $MyInvocation
}