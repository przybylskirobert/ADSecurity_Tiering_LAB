<#
    .Example
    $csv = Read-Host -Prompt "Please provide full path to Groups csv file"
    .\Create-Computer.ps1 -CSVfile $csv -Verbose
    .Notes
    Author: Robert PRzybylski
    www.azureblog.pl
    www.entrablog.com
    version 01.24
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory=$True)][string] $CSVfile
)
$DNSRoot = (Get-ADDomain).DNSRoot
$DSN = (Get-ADDomain).DistinguishedName
$computers = Import-Csv $CSVfile
foreach ($computer in $computers) {
    $name = $computer.name
    $samAccountName = $computer.samAccountName + "$"
    $parentOU = $computer.ParentOU + ',' + $DSN
    $groupMembership = $computer.GroupMembership
    $enabled = [bool]$computer.enabled
    $checkForComputer = [bool]( Get-ADComputer -Filter {SamAccountname -eq $samaccountname})
    If ($checkForComputer -eq $false) {
        Write-Host "Creating new computer '$samAccountName' under '$parentOU'" -ForegroundColor Green
        Write-Verbose 'New-ADCOmputer -Name $name -Path $ParentOU -SamAccountName $samAccountName -Enabled $enabled'
        New-ADCOmputer -Name $name -Path $ParentOU -SamAccountName $samAccountName -Enabled $enabled
        start-sleep -Seconds 5
        if ($groupMembership -ne "") {
            $groupMembership = ($computer.GroupMembership) -split ','
            foreach ($group in $groupMembership){
                Write-Host  "Adding Computer '$samAccountName' to Group '$group'" -ForegroundColor Green
                Write-Verbose 'Add-ADGroupMember -Identity $group -Members $samAccountName'
                Add-ADGroupMember -Identity $group -Members $samAccountName
            }
        }
        $error.Clear()
    } 
    Else {
        Write-Host "Computer '$samAccountName' already exists." -ForegroundColor Red
    }
}
