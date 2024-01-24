<#
    .Example
        .\Set-ServiceonDC.ps1 -ServiceDisplayName "Print Spooler" -StartupType 'Automatic' -Enabled -Verbose
        VERBOSE: Starting 'Print Spooler' service on dc 'vm-dc-neu'
        VERBOSE: Changing  startup type for 'Print Spooler' service on dc 'vm-dc-neu' to 'Automatic'

    .Example
        .\Set-ServiceonDC.ps1 -ServiceDisplayName "Print Spooler" -StartupType 'Disabled' -Verbose
        VERBOSE: Stopping 'Print Spooler' service on dc 'vm-dc-neu'
        VERBOSE: Changing  startup type for 'Print Spooler' service on dc 'vm-dc-neu' to 'disabled'
    .Notes
    Author: Robert PRzybylski
    www.azureblog.pl
    www.entrablog.com
    version 01.24
#>

[CmdletBinding()]
param(
    [parameter(Mandatory = $true)][string] $ServiceDisplayName,
    [parameter(Mandatory = $true)][string] $StartupType,
    [parameter(Mandatory = $false)][switch] $Enabled
)

$DCList = Get-ADGroupMember -Identity 'Domain Controllers'


$DCList | ForEach-Object {
    $ComputerName = $_.Name
    if ($Enabled -eq $true){
        Write-Host  "Starting '$ServiceDisplayName' service on dc '$ComputerName'" -ForegroundColor Green
        Write-Verbose 'Get-Service -ComputerName $ComputerName -DisplayName $ServiceDisplayName | start-service'
        Get-Service -ComputerName $ComputerName -DisplayName $ServiceDisplayName | start-service
    } else {
        Write-Host "Stopping '$ServiceDisplayName' service on dc '$ComputerName'" -ForegroundColor Green
        Write-Verbose 'Get-Service -ComputerName $ComputerName -DisplayName $ServiceDisplayName| stop-service'
        Get-Service -ComputerName $ComputerName -DisplayName $ServiceDisplayName| stop-service
    }
    Write-Host "Changing  startup type for '$ServiceDisplayName' service on dc '$ComputerName' to '$StartupType'" -ForegroundColor Green
    Write-Verbose 'Get-Service -ComputerName $ComputerName -DisplayName $ServiceDisplayName | Set-service -StartupType $StartupType'
    Get-Service -ComputerName $ComputerName -DisplayName $ServiceDisplayName | Set-service -StartupType $StartupType
}  
