<#
.SYNOPSIS
    Richtet die AD-Test-Lab-Domäne fuer Kerberos-Ticket-Demos ein (lab.local).

.DESCRIPTION
    NUR fuer das isolierte Test-Lab. Legt Test-OU, Benutzer, ein Service-Konto
    mit SPN (Ziel fuer Silver Ticket / Kerberoasting) und einen Demo-Domaenenadmin an.
    Optional promotet -PromoteDC diesen Server zuvor zum Domaenencontroller.

.PARAMETER PromoteDC
    Installiert AD DS und promotet den Server zur neuen Gesamtstruktur lab.local.
    NUR auf einem frischen Server ausfuehren (Neustart folgt).

.EXAMPLE
    # 1) DC promoten (Server startet neu):
    .\Setup-LabDomain.ps1 -PromoteDC

    # 2) Nach Neustart: Benutzer/SPN anlegen:
    .\Setup-LabDomain.ps1

.NOTES
    Passwoerter sind Lab-Defaults - NICHT in Produktion verwenden.
#>
[CmdletBinding()]
param(
    [switch]$PromoteDC,
    [string]$DomainName    = "lab.local",
    [string]$NetbiosName   = "LAB",
    [string]$DsrmPassword  = "P@ssw0rd!Lab"
)

$ErrorActionPreference = "Stop"

if ($PromoteDC) {
    Write-Host "[*] Installiere AD DS und promote zu $DomainName ..." -ForegroundColor Cyan
    Install-WindowsFeature AD-Domain-Services -IncludeManagementTools
    Import-Module ADDSDeployment
    Install-ADDSForest `
        -DomainName $DomainName `
        -DomainNetbiosName $NetbiosName `
        -ForestMode "WinThreshold" -DomainMode "WinThreshold" `
        -InstallDns `
        -SafeModeAdministratorPassword (ConvertTo-SecureString $DsrmPassword -AsPlainText -Force) `
        -Force
    # Server startet automatisch neu. Skript danach OHNE -PromoteDC erneut ausfuehren.
    return
}

Import-Module ActiveDirectory
Write-Host "[*] Lege Test-OU und Konten an ..." -ForegroundColor Cyan

$ouName = "LabAccounts"
if (-not (Get-ADOrganizationalUnit -Filter "Name -eq '$ouName'" -ErrorAction SilentlyContinue)) {
    New-ADOrganizationalUnit -Name $ouName -Path (Get-ADDomain).DistinguishedName
}
$ouPath = "OU=$ouName," + (Get-ADDomain).DistinguishedName

function New-LabUser {
    param($Name, $Sam, $Password)
    if (Get-ADUser -Filter "SamAccountName -eq '$Sam'" -ErrorAction SilentlyContinue) {
        Write-Host "    - $Sam existiert bereits, ueberspringe" -ForegroundColor DarkYellow
        return
    }
    New-ADUser -Name $Name -SamAccountName $Sam -Path $ouPath `
        -AccountPassword (ConvertTo-SecureString $Password -AsPlainText -Force) `
        -Enabled $true -PasswordNeverExpires $true
    Write-Host "    + $Sam angelegt" -ForegroundColor Green
}

# Standardbenutzer (Ausgangspunkt fuer Kerberoasting als Low-Priv-User)
New-LabUser -Name "Max Mustermann" -Sam "max" -Password "User123!"

# Service-Konto MIT SPN -> Ziel fuer Silver Ticket + Kerberoasting
New-LabUser -Name "svc_sql" -Sam "svc_sql" -Password "Sql_Svc_2024!"
setspn -S "MSSQLSvc/dc1.lab.local:1433" svc_sql | Out-Null
Write-Host "    + SPN MSSQLSvc/dc1.lab.local:1433 -> svc_sql" -ForegroundColor Green

# Demo-Domaenenadmin (nur Lab) -> zum Beschaffen des krbtgt-Hash via DCSync
New-LabUser -Name "labadmin" -Sam "labadmin" -Password "Admin_Lab_2024!"
Add-ADGroupMember -Identity "Domain Admins" -Members labadmin -ErrorAction SilentlyContinue

Write-Host ""
Write-Host "[*] Domaenen-SID (fuer Golden/Silver Ticket):" -ForegroundColor Cyan
(Get-ADDomain).DomainSID.Value
Write-Host ""
Write-Host "[OK] Lab-Domaene vorbereitet. Weiter: docs/03-golden-ticket.md / docs/04-silver-ticket.md" -ForegroundColor Green
