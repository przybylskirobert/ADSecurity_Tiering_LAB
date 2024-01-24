<#
    .Example
    .\Set-BGAPermissions.ps1 -BGAccount "justincase" -Verbose
    PS C:\Tools> .\Set-BGAPermissions.ps1 -BGAccount "justincase" -Verbose
    VERBOSE: Configuring FullControll permissions over the 'Domain Admins' for 'justincase'
    The command completed successfully
    VERBOSE: Configuring FullControll permissions over the 'Enterprise Admins' for 'justincase'
    The command completed successfully
    VERBOSE: Configuring FullControll permissions over the 'Administrators' for 'justincase'
    The command completed successfully  
    .Notes
    Author: Robert PRzybylski
    www.azureblog.pl
    www.entrablog.com
    version 01.24
#>

[CmdletBinding()]
param(
        [parameter(Mandatory = $true)][string] $BGAccount
)

$groups = @("Domain Admins","Enterprise Admins","Administrators")
$user = '"' + (Get-ADDomain).netbiosname + "\$BGAccount" + ":GA" + '"'

foreach ($group in $groups){
    $groupDN = (Get-ADGroup -identity $group).DistinguishedName
    Write-Host "Configuring FullControll permissions over the '$group' for '$BGAccount'" -ForegroundColor Green
    Write-Verbose 'dsacls $groupDN /I:T  /g $user'
    dsacls $groupDN /I:T  /g $user
}
