<#
    .Example
    .\New-GMSA.ps1 -Name 'svc_MDIReadOnly' -ComputerGroupToInclude 'Domain Controllers' -Verbose
    VERBOSE: Creating new GMSA 'svc_MDIReadOnly' with PrincipalsAllowedToRetrieveManagedPassword from 'Domain Controllers' group
    .Notes
    Author: Robert PRzybylski
    www.azureblog.pl
    www.entrablog.com
    version 01.24
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory=$True)] [string] $Name,
    [Parameter(Mandatory=$True)] [string] $ComputerGroupToInclude
)

if ($name.Length  -gt 15){
    Throw "Name lenght is to long (more than 15 characters)."
}

$computerGroup = Get-ADGroupMember -Identity $ComputerGroupToInclude
Write-Host  "Creating new GMSA '$Name' with PrincipalsAllowedToRetrieveManagedPassword from '$ComputerGroupToInclude' group" -ForegroundColor Green
write-verbose 'New-ADServiceAccount -Name $Name -DNSHostName "$($name).$domain" -PrincipalsAllowedToRetrieveManagedPassword $computerGroup'
New-ADServiceAccount -Name $Name -DNSHostName "$($name).$domain" -PrincipalsAllowedToRetrieveManagedPassword $computerGroup
Test-ADServiceAccount -Identity $Name
Get-ADServiceAccount -Identity $Name -Properties MemberOf