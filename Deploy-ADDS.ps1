<#
    .Example
    .\Deploy-ADDS.ps1 -ScriptsLocation "C:\Tools\ADDSDEploymentAndHydration" -DomainFQDN 'contoso.com' -MasterPassword 'zaq12WSXcde3' -ADInstall -verbose

    .Example
    .\Deploy-ADDS.ps1 -ScriptsLocation "C:\Tools\ADDSDeploymentAndHydration\" -DomainFQDN 'contoso.com' -MasterPassword 'zaq12WSXcde3' -ADHydration -verbose

    .Example
    .\Deploy-ADDS.ps1 -ScriptsLocation "C:\Tools\ADDSDeploymentAndHydration\" -DomainFQDN 'contoso.com' -MasterPassword 'zaq12WSXcde3' -Remediation -verbose


    .Notes
    Author: Robert PRzybylski
    www.azureblog.pl
    www.entrablog.com
    version 01.24
#>


Param (
    [Parameter(Mandatory = $True)][string] $ScriptsLocation,
    [Parameter(Mandatory = $True)][string] $DomainFQDN,
    [Parameter(Mandatory = $True)][string] $MasterPassword,
    [switch] $ADInstall,
    [switch] $ADHydration,
    [switch] $Remediation
)

if ($ADInstall) {

    $transcriptPath = "$ScriptsLocation\ADInstall.log"
    Start-Transcript -Path $transcriptPath

    Write-Host "Starting Domain Installation"

    Set-TimeZone -Name "Central European Standard Time"
    Import-Module ServerManager
    Install-windowsfeature -name AD-Domain-Services -IncludeManagementTools
    Install-WindowsFeature -name GPMC

    #region IESC Disable
    $adminKey = "HKLM:\SOFTWARE\Microsoft\Active Setup\Installed Components\{A509B1A7-37EF-4b3f-8CFC-4F3A74704073}"
    Set-ItemProperty -Path $adminKey -Name IsInstalled -Value 0
    Stop-Process -Name Explorer
    #endregion

    #region AD DS installation
    $domainname = $DomainFQDN
    $NTDPath = "C:\Windows\ntds"
    $logPath = "C:\Windows\ntds"
    $sysvolPath = "C:\Windows\Sysvol"
    $domainmode = "WinThreshold"
    $forestmode = "WinThreshold"
    $password = ConvertTo-SecureString $MasterPassword -AsPlainText -force
    Install-ADDSForest -CreateDnsDelegation:$false -DatabasePath $NTDPath -DomainMode $domainmode -DomainName $domainname -ForestMode $forestmode -InstallDns:$true -LogPath $logPath -NoRebootOnCompletion:$false -SysvolPath $sysvolPath -Force:$true -SafeModeAdministratorPassword $password
    #endregion
    Stop-Transcript
}

if ($ADHydration) {

    $transcriptPath = "$ScriptsLocation\ADHydration.log"
    Start-Transcript -Path $transcriptPath

    Write-Host "Starting Domain Hydration"

    Import-Module ActiveDirectory
    $dNC = (Get-ADRootDSE).defaultNamingContext
    $dsnAME = (Get-ADDomain).DistinguishedName
    $dnsRoot = (Get-ADDomain).DNSRoot
    $domain = $env:USERDNSDOMAIN
    
    #region Policy Definitions
    $destination = "C:\Windows\Sysvol\sysvol\" + (Get-ADDomain).DNSRoot + "\policies\"
    New-Item -ItemType Directory -Path "$destination\PolicyDefinitions" -Force
    Copy-Item -Path C:\Windows\PolicyDefinitions -Destination $destination -Recurse -ErrorAction SilentlyContinue -Force
    #endregion


    #region OU Creation
    $domainOUSCsv = Import-Csv -Path "$ScriptsLocation\DomainOUs.csv"
    ."$ScriptsLocation\Scripts\Create-OU.ps1" -OUs $domainOUSCsv -Verbose    
    Set-GpInheritance -Target "OU=Devices,OU=Tier0,OU=Admin,$dnc" -IsBlocked Yes | Out-Null
    Set-GpInheritance -Target "OU=Devices,OU=Tier1,OU=Admin,$dnc" -IsBlocked Yes | Out-Null
    Set-GpInheritance -Target "OU=Devices,OU=Tier2,OU=Admin,$dnc" -IsBlocked Yes | Out-Null
    #endregion

    #region Groups creation 

    $csv = "$ScriptsLocation\AdminGroups.csv"
    .$ScriptsLocation\Scripts\Create-Group.ps1 -List $csv -Verbose
    $csv = "$ScriptsLocation\StandardGroups.csv"
    .$ScriptsLocation\Scripts\Create-Group.ps1 -List $csv -Verbose
    #endregion

    #region ACL on OU
    $List = @(
        $(New-Object PSObject -Property @{Group = "Tier2ServiceDeskOperators"; OUPrefix = "OU=User Accounts" }),
        $(New-Object PSObject -Property @{Group = "Tier1Admins"; OUPrefix = "OU=Accounts,ou=Tier1,ou=Admin" }),
        $(New-Object PSObject -Property @{Group = "Tier1Admins"; OUPrefix = "OU=Service Accounts,ou=Tier1,ou=Admin" }),
        $(New-Object PSObject -Property @{Group = "Tier2Admins"; OUPrefix = "OU=Accounts,ou=Tier2,ou=Admin" }),
        $(New-Object PSObject -Property @{Group = "Tier2Admins"; OUPrefix = "OU=Service Accounts,ou=Tier2,ou=Admin" })
    )
    .$ScriptsLocation\Scripts\Set-OUUserPermissions.ps1 -list $list -Verbose 

    $List = @(
        $(New-Object PSObject -Property @{Group = "Tier2ServiceDeskOperators"; OUPrefix = "OU=Workstations" }),
        $(New-Object PSObject -Property @{Group = "Tier1Admins"; OUPrefix = "OU=Devices,ou=Tier1,ou=Admin" }),
        $(New-Object PSObject -Property @{Group = "Tier2Admins"; OUPrefix = "OU=Devices,ou=Tier2,ou=Admin" })
    )
    .$ScriptsLocation\Scripts\Set-OUWorkstationPermissions.ps1 -list $list -Verbose

    $List = @(
        $(New-Object PSObject -Property @{Group = "Tier1Admins"; OUPrefix = "OU=Groups,ou=Tier1,ou=Admin" }),
        $(New-Object PSObject -Property @{Group = "Tier2Admins"; OUPrefix = "OU=Groups,ou=Tier2,ou=Admin" })
    )
    .$ScriptsLocation\Scripts\Set-OUGroupPermissions.ps1 -list $list -Verbose

    $List = @(
        $(New-Object PSObject -Property @{Group = "Tier2WorkstationMaintenance"; OUPrefix = "OU=Quarantine" }),
        $(New-Object PSObject -Property @{Group = "Tier2WorkstationMaintenance"; OUPrefix = "OU=Workstations" }),
        $(New-Object PSObject -Property @{Group = "Tier1ServerMaintenance"; OUPrefix = "OU=Tier 1 Servers" })
    )
    .$ScriptsLocation\Scripts\Set-OUComputerPermissions.ps1 -list $list -Verbose

    $List = @(
        $(New-Object PSObject -Property @{Group = "Tier0ReplicationMaintenance"; OUPrefix = "" })
    )
    .$ScriptsLocation\Scripts\Set-OUReplicationPermissions.ps1 -list $list -Verbose

    $List = @(
        $(New-Object PSObject -Property @{Group = "Tier1ServerMaintenance"; OUPrefix = "OU=Tier 1 Servers" })
    )
    .$ScriptsLocation\Scripts\Set-OUGPOPermissions.ps1 -list $list -Verbose
    #endregion

    #region Create Users 
    $csv = "$ScriptsLocation\Users.csv"
    .$ScriptsLocation\Scripts\Create-User.ps1 -CSVfile $csv -password zaq12WSXcde3 -Verbose
    .$ScriptsLocation\Scripts\Set-BGAPermissions.ps1 -BGAccount "justincase" -Verbose
    #endregion
    
    #Region Create Computers
    $csv = "$ScriptsLocation\Computers.csv"
    .$ScriptsLocation\Scripts\Create-Computer.ps1 -CSVfile $csv -Verbose

    #endregion

    #region Redir
    $usrDN = '"' + "OU=Enabled Users,OU=User Accounts," + $dNc + '"'
    redirusr $usrDN
    $cmpDN = '"' + "OU=Quarantine," + $dNc + '"'
    redircmp $cmpDN 
    #endregion

    #region Import GPOS
    $migTable = "gpo_backup_" + $((Get-ADDOmain).NetBIOSName) + ".migtable"
    $migTablePath = "$ScriptsLocation\Scripts\" + $migTable

    Copy-Item -Path $ScriptsLocation\Scripts\gpo_backup.migtable -Destination $migTablePath
        ((Get-Content -path $migTablePath  -Raw) -replace 'CHANGEME', $dnsRoot ) | Set-Content -Path $migTablePath 
    $backupPath = "$ScriptsLocation\Scripts\GPO Backup"
    $gPOMigrationTable = (Get-ChildItem -Path "$ScriptsLocation\Scripts" -Filter "$migTable").fullname
    .$ScriptsLocation\Scripts\Import-GPO.ps1 -BackupPath $backupPath -GPOMigrationTable $gPOMigrationTable -Verbose
    #endregion

    Write-Host "!!!!!!!!!!!!!!!! Please copy proxy.pac file to the IIS Server" -ForegroundColor Green

    #region GPO link
    $GpoLinks = @(
        $(New-Object PSObject -Property @{ Name = "Do Not Display Logon Information" ; OU = "OU=Devices,OU=Tier0,OU=Admin"; Order = 1 ; LinkEnabled = 'YES' }),
        $(New-Object PSObject -Property @{ Name = "Do Not Display Logon Information" ; OU = "OU=Devices,OU=Tier1,OU=Admin"; Order = 1 ; LinkEnabled = 'YES' }),
        $(New-Object PSObject -Property @{ Name = "Do Not Display Logon Information" ; OU = "OU=Devices,OU=Tier2,OU=Admin"; Order = 1 ; LinkEnabled = 'YES' }),
        $(New-Object PSObject -Property @{ Name = "Do Not Display Logon Information" ; OU = "OU=Tier 1 Servers"; Order = 1 ; LinkEnabled = 'YES' }),
        $(New-Object PSObject -Property @{ Name = "Do Not Display Logon Information" ; OU = "OU=Workstations"; Order = 1 ; LinkEnabled = 'YES' }),
        $(New-Object PSObject -Property @{ Name = "Restrict Quarantine Logon" ; OU = "OU=Quarantine"; Order = 1 ; LinkEnabled = 'YES' }),
        $(New-Object PSObject -Property @{ Name = "Tier0 Restrict Server Logon" ; OU = "OU=Devices,OU=Tier0,OU=Admin"; Order = 1 ; LinkEnabled = 'YES' }),
        $(New-Object PSObject -Property @{ Name = "Tier1 Restrict Server Logon" ; OU = "OU=Devices,OU=Tier1,OU=Admin"; Order = 1 ; LinkEnabled = 'YES' }),
        $(New-Object PSObject -Property @{ Name = "Tier1 Restrict Server Logon" ; OU = "OU=Tier 1 Servers"; Order = 1 ; LinkEnabled = 'YES' }),
        $(New-Object PSObject -Property @{ Name = "Tier2 Restrict Workstation Logon" ; OU = "OU=Devices,OU=Tier2,OU=Admin"; Order = 1 ; LinkEnabled = 'YES' }),
        $(New-Object PSObject -Property @{ Name = "Tier2 Restrict Workstation Logon" ; OU = "OU=Workstations"; Order = 1 ; LinkEnabled = 'YES' }),
        $(New-Object PSObject -Property @{ Name = "Tier0 PAW Configuration - Computer" ; OU = "OU=Devices,OU=Tier0,OU=Admin"; Order = 1 ; LinkEnabled = 'YES' }),
        $(New-Object PSObject -Property @{ Name = "Tier0 PAW Configuration - User" ; OU = "OU=Accounts,OU=Tier0,OU=Admin"; Order = 1 ; LinkEnabled = 'No' }),
        $(New-Object PSObject -Property @{ Name = "Tier0 PAW Configuration - User PAC" ; OU = "OU=Accounts,OU=Tier0,OU=Admin"; Order = 1 ; LinkEnabled = 'YES' }),
        $(New-Object PSObject -Property @{ Name = "Tier1 PAW Configuration - Computer" ; OU = "OU=Devices,OU=Tier1,OU=Admin"; Order = 1 ; LinkEnabled = 'YES' }),
        $(New-Object PSObject -Property @{ Name = "Tier1 PAW Configuration - User" ; OU = "OU=Accounts,OU=Tier1,OU=Admin"; Order = 1 ; LinkEnabled = 'NO' })
        $(New-Object PSObject -Property @{ Name = "Tier1 PAW Configuration - User PAC" ; OU = "OU=Accounts,OU=Tier1,OU=Admin"; Order = 1 ; LinkEnabled = 'YES' })
    )
    .$ScriptsLocation\Scripts\Link-GpoToOU.ps1 -GpoLinks $GpoLinks -Verbose
    #endregion

    #region Sites Setup
    Import-Module ActiveDirectory
    $name = 'HQ'
    Get-ADObject -SearchBase (Get-ADRootDSE).ConfigurationNamingContext -filter "objectclass -eq 'site'" | where-object { $_.Name -eq 'Default-First-Site-Name' } | Rename-ADObject -NewName $name
    $subnet = Read-Host "Please provide subnet details - 0.0.0.0/XX"
    New-ADReplicationSubnet -Name $subnet -Site (Get-ADReplicationSite -Identity $name).DistinguishedName
    #endRegion

    #region KDS Root Key
    add-kdsrootkey -effectivetime ((get-date).addhours(-10))
    #endregion

    #region DNS registration
    $networkConfig = Get-WmiObject Win32_NetworkAdapterConfiguration -filter "ipenabled = 'true'"
    $networkConfig.SetDnsDomain("$domain")
    $networkConfig.SetDynamicDNSRegistration($true, $true)
    ipconfig /registerdns 
    #endregion

    #gmsa for MDI
    .$ScriptsLocation\Scripts\New-GMSA.ps1 -Name 'svc_MDIReadOnly' -ComputerGroupToInclude 'Domain Controllers' -Verbose
    #endregion

    Stop-Transcript
}

if ($Remediation -eq $true) {

    $transcriptPath = "$ScriptsLocation\ADHydration.log"
    Start-Transcript -Path $transcriptPath
    
    Write-Host "Starting Remediation Steps"
    $dsnAME = (Get-ADDomain).DistinguishedName
    $netbios = (Get-ADDomain).Name
    $domain = $env:USERDNSDOMAIN
    $migTable = "gpo_backup_" + $((Get-ADDOmain).NetBIOSName) + ".migtable"
    $migTablePath = "$ScriptsLocation\Scripts\" + $migTable
    Copy-Item -Path $ScriptsLocation\Scripts\gpo_backup.migtable -Destination $migTablePath
    ((Get-Content -path $migTablePath  -Raw) -replace 'CHANGEME', $dnsRoot ) | Set-Content -Path $migTablePath 
    $backupPath = "$ScriptsLocation\Scripts\GPO Backup"
    $gPOMigrationTable = (Get-ChildItem -Path "$ScriptsLocation\Scripts" -Filter "$migTable").fullname

    Copy-Item C:\Windows\PolicyDefinitions -Recurse -Destination C:\Windows\Sysvol\domain\Policies\ -Force
    Update-LapsADSchema -Verbose

    Set-LapsADComputerSelfPermission -Identity "OU=Devices,OU=Tier0,OU=Admin,$dsname"
    Set-LapsADComputerSelfPermission -Identity "OU=Tier0 Servers,OU=Tier0,OU=Admin,$dsname"
    Set-LapsADComputerSelfPermission -Identity "OU=Devices,OU=Tier1,OU=Admin,$dsname"
    Set-LapsADComputerSelfPermission -Identity "OU=Tier 1 Servers,$dsname"
    Set-LapsADComputerSelfPermission -Identity "CN=Computers,$dsname"
    Set-LapsADComputerSelfPermission -Identity "OU=Quarantine,$dsname"

    Set-LapsADReadPasswordPermission -Identity "OU=Devices,OU=Tier0,OU=Admin,$dsname" -AllowedPrincipals "Domain Admins"
    Set-LapsADReadPasswordPermission -Identity "OU=Tier0 Servers,OU=Tier0,OU=Admin,$dsname" -AllowedPrincipals "Domain Admins"
    Set-LapsADReadPasswordPermission -Identity "OU=Devices,OU=Tier1,OU=Admin,$dsname" -AllowedPrincipals "Domain Admins", "$netbios\tier1admins"
    Set-LapsADReadPasswordPermission -Identity "OU=Tier 1 Servers,$dsname" -AllowedPrincipals "Domain Admins", "$netbios\tier1admins"
    Set-LapsADReadPasswordPermission -Identity "CN=Computers,$dsname" -AllowedPrincipals "Domain Admins", "$netbios\tier2admins"
    Set-LapsADReadPasswordPermission -Identity "OU=Quarantine,$dsname" -AllowedPrincipals "Domain Admins", "$netbios\tier2admins"

    Set-LapsADResetPasswordPermission -Identity "OU=Devices,OU=Tier0,OU=Admin,$dsname" -AllowedPrincipals "Domain Admins"
    Set-LapsADResetPasswordPermission -Identity "OU=Tier0 Servers,OU=Tier0,OU=Admin,$dsname" -AllowedPrincipals "Domain Admins"
    Set-LapsADResetPasswordPermission -Identity "OU=Devices,OU=Tier1,OU=Admin,$dsname" -AllowedPrincipals "Domain Admins", "$netbios\tier1admins"
    Set-LapsADResetPasswordPermission -Identity "OU=Tier 1 Servers,$dsname" -AllowedPrincipals "Domain Admins", "$netbios\tier1admins"
    Set-LapsADResetPasswordPermission -Identity "CN=Computers,$dsname" -AllowedPrincipals "Domain Admins", "$netbios\tier2admins"
    Set-LapsADResetPasswordPermission -Identity "OU=Quarantine,$dsname" -AllowedPrincipals "Domain Admins", "$netbios\tier2admins"

    $backupPath = "$ScriptsLocation\GPO"
    .$ScriptsLocation\Scripts\Import-GPO.ps1 -BackupPath $backupPath -Verbose
    cd $location

    $GpoLinks = @(
        $(New-Object PSObject -Property @{ Name = "WindowsLAPS_DSRM" ; OU = "OU=Domain Controllers"; Order = 1 ; LinkEnabled = 'YES' }),
        $(New-Object PSObject -Property @{ Name = "WindowsLAPS" ; OU = "OU=Devices,OU=Tier0,OU=Admin"; Order = 1 ; LinkEnabled = 'YES' }),
        $(New-Object PSObject -Property @{ Name = "WindowsLAPS" ; OU = "OU=Tier0 Servers,OU=Tier0,OU=Admin"; Order = 1 ; LinkEnabled = 'YES' }),
        $(New-Object PSObject -Property @{ Name = "WindowsLAPS" ; OU = "OU=Devices,OU=Tier1,OU=Admin"; Order = 1 ; LinkEnabled = 'YES' }),
        $(New-Object PSObject -Property @{ Name = "WindowsLAPS" ; OU = "OU=Tier 1 Servers"; Order = 1 ; LinkEnabled = 'YES' }),
        $(New-Object PSObject -Property @{ Name = "WindowsLAPS" ; OU = "OU=Quarantine"; Order = 1 ; LinkEnabled = 'YES' })
    )
    .$ScriptsLocation\Scripts\Link-GpoToOU.ps1 -GpoLinks $GpoLinks
    cd $location

    #endregion
    

    #password policies
    .$ScriptsLocation\Scripts\New-PasswordPolicy.ps1 -Name 'Tier0USers' -PasswordHistoryCount '24' -MinPasswordAge '01' -ComplexityEnabled $true `
        -ReversibleEncryptionEnabled $false -LockoutThreshold "4" -LockoutObservationWindow "01" `
        -IncludedSubjects @("Domain Admins") `
        -Precedence 50 -MaxPasswordAge "180" -MinPasswordLength "16" -Verbose

    .$ScriptsLocation\Scripts\New-PasswordPolicy.ps1 -Name 'Tier1USers' -PasswordHistoryCount '24' -MinPasswordAge '01' -ComplexityEnabled $true `
        -ReversibleEncryptionEnabled $false -LockoutThreshold "4" -LockoutObservationWindow "01" `
        -IncludedSubjects @('Tier1ServerMaintenance', 'tier1admins', 'Tier1PAWUsers') `
        -Precedence 60 -MaxPasswordAge "180" -MinPasswordLength "14" -Verbose

    .$ScriptsLocation\Scripts\New-PasswordPolicy.ps1 -Name 'Tier2USers' -PasswordHistoryCount '24' -MinPasswordAge '01' -ComplexityEnabled $true `
        -ReversibleEncryptionEnabled $false -LockoutThreshold "4" -LockoutObservationWindow "01" `
        -IncludedSubjects @('Tier2ServiceDeskOperators', 'tier2admins', 'Tier2WorkstationMaintenance') `
        -Precedence 70 -MaxPasswordAge "180" -MinPasswordLength "12" -Verbose

    .$ScriptsLocation\Scripts\New-PasswordPolicy.ps1 -Name 'ServiceAccounts' -PasswordHistoryCount '24' -MinPasswordAge '01' -ComplexityEnabled $true `
        -ReversibleEncryptionEnabled $false -LockoutThreshold "4" -LockoutObservationWindow "01" `
        -IncludedSubjects @("Tier0serviceaccounts", "Tier2serviceaccounts", "Tier1serviceaccounts") `
        -Precedence 80 -MaxPasswordAge "180" -MinPasswordLength "20" -Verbose
    #endregion

    #AD Resycle
    Enable-ADOptionalFeature 'Recycle Bin Feature' -Scope ForestOrConfigurationSet -Target $domain -Confirm:$false
    #endregion

    #region Import Audit Gpos
    $backupPath = "$ScriptsLocation\Scripts\Audit Settings"
    .$ScriptsLocation\Scripts\Import-GPO.ps1 -BackupPath $backupPath -GPOMigrationTable $gPOMigrationTable -Verbose
    $GpoLinks = @(
        $(New-Object PSObject -Property @{ Name = "Audit Key Events" ; OU = "OU=Domain Controllers"; Order = 1 ; LinkEnabled = 'YES' }),
        $(New-Object PSObject -Property @{ Name = "Audit Powershell" ; OU = "OU=Domain Controllers"; Order = 1 ; LinkEnabled = 'YES' })
    )
    .$ScriptsLocation\Scripts\Link-GpoToOU.ps1 -GpoLinks $GpoLinks -Verbose

    #endregion
    Stop-Transcript
}