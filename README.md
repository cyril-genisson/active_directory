# Active Directory & PowerShell
Installation et configuration d'un service d'annuaire d'entreprise dans un environnment Microsoft.

## Schéma organisationnel CREDIT-INDUSTRIEL.CORP

````mermaid
flowchart TD
    A[CREDIT-INDUSTRIEL.CORP] --> B(Personnel)
    A --> C(Client)
    B --> D(Banquiers)
    D --> E[Catégorie A]
    D --> F[Catégorie B]
    D --> G[Catégorie C]
    D --> H[Catégorie D]
    C --> I[Pro]
    C --> J[Perso]
    B --> K(IT)
    K --> L[Informaticiens / Prestataires]
    K --> M[Chefs de projet]
````

## Préparation du serveur
- OS: Windows Server 2022 Standard Core
- vCPU: 1 / 4 Cores
- RAM: 2048
- Réseau: 1Gb Ethernet

### Renommage du serveur
````powershell
Rename-Computer -NewName ad1 -FORCE
Restart-Computer
````

### Configuration réseau
````powershell
New-NetIPAddress -IPAddress "192.168.139.3" -PrefixLenght "24" `
-InterfaceIndex (Get-NetAdapter).ifIndex -DefaultGateway "192.168.139.2"
Set-DnsClientServerAddress -InterfaceIndex (Get-NetAdapter).ifIndex -ServerAddresses ("127.0.0.1","8.8.8.8")
Rename-NetAdapter -Name Ethernet0 -NewName CORP
````

### Installation des rôles
````powershell
$FeatureList = @("RSAT-AD-Tools", "AD-Domain-Services", "DNS", "DHCP")

Foreach($Feature in $FeatureList) {
    if ( ((Get-WindowsFeature-Name $Feature).InstallState) -eq "Available" ) {
        Write-Output "Feature $Feature will be installed Now!"
        Try {
            Add-WindowsFeature-Name $Feature -IncludeManagementTools -IncludeAllSubFeature
            Write-Output "$Feature: Installation is a success!"
        } catch {
            Write-Output "$Feature: Error during installation!"
        }
    }
}
````

### Création du domaine Active Directory

````powershell
$DomainNameDNS = "credit-industriel.corp"
$DomainNameNetbios = "CDT-INDUSTRIEL"

$ForestConfiguration = @{
'-DatabasePath'='c:\windows\NTDS';
'-LogPath'='c:\windows\NTDS';
'-SysvolPath'='c:\windows\SYSVOL';
'-ForestMode'='WinThreshold';
'-DomainMode'='WinThreshold';
'-InstallDns'=$true;
'-DomainName'=$DomainNameDNS;
'-DomainNetbiosName'=$DomainNameNetbios;
'-CreateDnsDelegation'=$false;
'-Force'=$true;
'-NoRebootOnCompletion'=$false }

Import-Module ADDSDeployment
Install-ADDSForest @ForestConfiguration
````

### Configuration du serveur DHCP

````powershell
netsh dhcp add securitygroups
Restart-Service dhcpserver

Add-dhcpServerInDC -DnsName ad1.credit-industriel.corp -IPAddress 192.168.139.3
Set-ItemProperty -Path registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\ServerManager\Roles\12 `
-Name ConfigurationState -Value 2

Set-DhcpServerv4DnsSetting -ComputerName "ad1.credit-industriel.corp" `
-DynamicUpdates "Always" -DeleteDNSRRonlyLeaseExpire $True

Add-dhcpServerv4Scope -name "Crédit-Industriel" `
-StartRange 192.168.139.100 -EndRange 192.168.139.200 `
-SubnetMask 255.255.255.0 `
-Description "Plage DHCP Crédit-Industriel" `
-State Active

Set-DhcpServerv4OptionValue -DnsDomain credit-industriel.corp `
-DnsServer 192.168.139.3 -Router 192.168.139.2

Set-DhcpServerv4OptionValue -WinServer 192.168.139.3
````

### Création des utilisateurs
````csv
first,last,group
Amélie,Lotte,Catégorie A
Athur,Neutron,Catégorie A
Bob,Voulet,Catégorie B
Bruno,Desange,Catégorie B
Céline,Stoner,Catégorie C
Cyril,Potet,Catégorie C
Dorian,Matias,Catégorie D
Bernard,Taperio,Catégorie D
Karim,Fed,Client
Césarine,Cordonnier,Client
````

````powershell
$CVSFile = "C:\users.csv"
$CSVData = Import-CSV -Path $CSVFILE -Delimiter "," -Encoding Default

Foreach($user in $CSVData){
    $FirstName = $user.first
    $LastName = $user.last
    $Login = $Firstname.Tolower() + "." + $LastName.Tolower()
    $Email = $Login@credit-industriel.corp
    $Passwd = "Abcd@1234"
    $Group = $user.group
    
    if (Get-ADUser -filter {SamAccountName -eq $Login}) {
        Writing-Warning "$Login: User existing in Active Directory"
    } else {
        New-ADUser -Name "$FirstName $LastName" `
                   -DisplayName "$FirstName $LastName" `
                   -GivenName $FirstName `
                   -Surname $LastName `
                   -SamAccountName $Login `
                   -USerPrincipalName $Email `
                   -EmailAddress $Email `
                   -AccountPassword(ConvertTo-SecureString $Passwd -AsPlainText -Force) `
                   -ChangePasswordAtLogon $True `
                   -Enable $True
        Writing-Output "$Login ($FirstName $LastName): user created"
    }
}
````

### Création des répertoires et des fichiers
````powershell
$Path = "C:\Credit-industriel"
$ListDir = ("Opérations", "Virements\Moins10k", "Virements\10kto100k", "Virements\over100k", "Comptes")
$ListDir | Foreach { New-Item -Path $Path -ItemType "directory" -Name $_ }

$Path = $Path + "\Comptes"
$ListFile = ("Karim_Fed", "Cesarine_Cordonnier")
$ListFile | Foreach { New-Item -Path -ItemType "file" -Name $_ }
````
### Gestion des droits
````powershell
Install-Module NTFSSecurity
$Path = "C:\Credit-industriel"
Add-NTFSAccess -Path $Path+"\Opérations" -Account "Catégorie 1","Catégorie 2","Catégorie 3", "Catégorie 4" -AccessRights Modify
Add-NTFSAccess -Path $Path+"\Virements\Moins10k" -Account "Catégorie 2","Catégorie 3", "Catégorie 4" -AccessRights Modify
Add-NTFSAccess -Path $Path+"\Virements\10kto100k" -Account "Catégorie 3", "Catégorie 4" -AccessRights Modify
Add-NTFSAccess -Path $Path+"\Virements\over100k" -Account "Catégorie 4" -AccessRights Modify
Add-NTFSAccess -Path $Path+"\Virements\Comptes\Karim_Fed" -Account "karim.fed@credit-industriel.corp" -AccessRights Read
Add-NTFSAccess -Path $Path+"\Virements\Comptes\Cesarine_Cordonnier" -Account "cesarine.cordonnier@credit-industriel.corp" -AccessRights Read

````

### Récupération des comptes inactifs
````powershell
$InactivesObjects = Search-ADaccount -AccountInactive -Timespan 180 | Where{ ($_.DistinguishedName -notmatch "CN=Users") -and ($_.Enabled -eq $true) } | foreach{
    if(($_.objectClass -eq "user") -and (Get-ADUser -Filter "Name -eq '$($_.Name)'" -Properties WhenCreated).WhenCreated -lt (Get-Date).AddDays(-7)){ $_ }
    if(($_.objectClass -eq "computer") -and (Get-ADComputer -Filter "Name -eq '$($_.Name)'" -Properties WhenCreated).WhenCreated -lt (Get-Date).AddDays(-7)){ $_ }
}
````

### Gérer les heures d'accès du personnel
````powershell
Get-ADUser -SearchBase "OU=Personnel,DC=credit-industriel,DC=corp" -Filter *| Set-LogonHours `
-TimeIn24Format @(6,7,8,9,10,11,12,13,14,15,16,17,18,19) -Monday -Tuesday -Wednesday -Thursday -Friday `
-NonSelectedDaysare NonWorkingDays
````