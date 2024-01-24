<#
    .Example
    .\New-PasswordPolicy.ps1 -Name 'TieredUsers' `
    -PasswordHistoryCount '24' `
    -MinPasswordAge '01' `
    -ComplexityEnabled $true `
    -ReversibleEncryptionEnabled $false `
    -LockoutThreshold "4" `
    -LockoutObservationWindow "01" `
    -IncludedSubjects @("Domain Admins", 'Tier1ServerMaintenance', 'tier1admins', 'Tier1PAWUsers', 'Tier2ServiceDeskOperators', 'tier2admins', 'Tier2WorkstationMaintenance') `
    -Precedence 60 `
    -MaxPasswordAge "180" `
    -MinPasswordLength "10" `
    -Verbose
    VERBOSE: Creating new PSO 'TieredUsersPSO'
    .Notes
    Author: Robert PRzybylski
    www.azureblog.pl
    www.entrablog.com
    version 01.24
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory=$True)] [string] $Name,
    [Parameter(Mandatory=$True)] [string] $PasswordHistoryCount,
    [Parameter(Mandatory=$True)] [string] $MinPasswordAge,
    [Parameter(Mandatory=$True)] [bool] $ComplexityEnabled,
    [Parameter(Mandatory=$True)] [bool] $ReversibleEncryptionEnabled,
    [Parameter(Mandatory=$True)] [string] $LockoutThreshold,
    [Parameter(Mandatory=$True)] [string] $LockoutObservationWindow,
    [Parameter(Mandatory=$True)] [string[]] $IncludedSubjects,
    [Parameter(Mandatory=$True)] [string] $Precedence,
    [Parameter(Mandatory=$True)] [string] $MaxPasswordAge,
    [Parameter(Mandatory=$True)] [string] $MinPasswordLength

)

$parsedMinPasswordAge = "0." + $MinPasswordAge + ":00:00"
$parsedLockoutObservationWindow = "0." + $LockoutObservationWindow + ":00:00"
$parsedMaxPasswordAge = $MaxPasswordAge + ".00:00:00"
$PSOName = $Name + "PSO"
$TemplatePSO = New-Object Microsoft.ActiveDirectory.Management.ADFineGrainedPasswordPolicy
$TemplatePSO.PasswordHistoryCount = $PasswordHistoryCount
$TemplatePSO.MinPasswordAge = [TimeSpan]::Parse("$parsedMinPasswordAge")
$TemplatePSO.ComplexityEnabled = $ComplexityEnabled
$TemplatePSO.ReversibleEncryptionEnabled = $ReversibleEncryptionEnabled
$TemplatePSO.LockoutDuration = "-10675199.02:48:05.4775808" 
$TemplatePSO.LockoutObservationWindow = [TimeSpan]::Parse("$parsedLockoutObservationWindow")
$TemplatePSO.LockoutThreshold = $LockoutThreshold
Write-Host  "Creating new PSO '$PSONAme' " -ForegroundColor Green
Write-Verbose 'New-ADFineGrainedPasswordPolicy -Instance $TemplatePSO -Name $PSONAme -Precedence $Precedence -Description "The $PSONAme Password Policy" -DisplayName "$PSONAme PSO" -MaxPasswordAge $parsedMaxPasswordAge -MinPasswordLength $MinPasswordLength'
New-ADFineGrainedPasswordPolicy -Instance $TemplatePSO -Name $PSONAme -Precedence $Precedence -Description "The $PSONAme Password Policy" -DisplayName "$PSONAme PSO" -MaxPasswordAge $parsedMaxPasswordAge -MinPasswordLength $MinPasswordLength
Write-Verbose 'Add-ADFineGrainedPasswordPolicySubject -Identity $PSONAme -Subjects $IncludedSubjects'
Add-ADFineGrainedPasswordPolicySubject -Identity $PSONAme -Subjects $IncludedSubjects
