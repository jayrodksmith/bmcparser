<#

#>

###############################################################################
# Function - Logging
###############################################################################
# Check if the folder exists
$Script:logfilelocation = "C:\temp\ninjarmm\logs"
$Script:logfile = "$Script:logfilelocation\bmclogging.log"
$Script:logdescription = "bmclogging"

if (-not (Test-Path -Path $Script:logfilelocation -PathType Container)) {
  # Create the folder and its parent folders if they don't exist
  New-Item -Path $Script:logfilelocation -ItemType Directory -Force | Out-Null
}
$Global:nl = [System.Environment]::NewLine
$Global:ErrorCount = 0
$global:Output = '' 
function Get-TimeStamp() {
return (Get-Date).ToString("dd-MM-yyyy HH:mm:ss")
}
function RMM-LogParse{
    $cutOffDate = (Get-Date).AddDays(-30)
    $lines = Get-Content -Path $Script:logfile
    $filteredLines = $lines | Where-Object {
    if ($_ -match '^(\d{2}-\d{2}-\d{4} \d{2}:\d{2}:\d{2})') {
        $lineDate = [DateTime]::ParseExact($matches[1], 'dd-MM-yyyy HH:mm:ss', $null)
        $lineDate -ge $cutOffDate
            } else {
                $true  # Include lines without a recognized date
            }
    }
    $filteredLines | Set-Content -Path $Script:logfile
}

function RMM-Initilize{
Add-content $Script:logfile -value "$(Get-Timestamp) -----------------------------$Script:logdescription"
}

function RMM-Msg{
param (
  $Message,
  [ValidateSet('Verbose','Debug','Silent')]
  [string]$messagetype = 'Silent'
)
$global:Output += "$(Get-Timestamp) - Msg   : $Message"+$Global:nl
Add-content $Script:logfile -value "$(Get-Timestamp) - Msg   : $message"
if($messagetype -eq 'Verbose'){Write-Output "$Message"}elseif($messagetype -eq 'Debug'){Write-Debug "$Message"}
}

#######
function RMM-Error{
  param (
  $Message,
  [ValidateSet('Verbose','Debug','Silent')]
  [string]$messagetype = 'Silent'
)
$Global:ErrorCount += 1
$global:Output += "$(Get-Timestamp) - Error : $Message"+$Global:nl
Add-content $Script:logfile -value "$(Get-Timestamp) - Error : $message"
if($messagetype -eq 'Verbose'){Write-Warning "$Message"}elseif($messagetype -eq 'Debug'){Write-Debug "$Message"}
}

#######
function RMM-Exit{  
param(
  [int]$ExitCode = 0
)
$Message = '----------'+$Global:nl+"$(Get-Timestamp) - Errors : $Global:ErrorCount"
$global:Output += "$(Get-Timestamp) $Message"
Add-content $Script:logfile -value "$(Get-Timestamp) - Exit  : $message Exit Code = $Exitcode"
Add-content $Script:logfile -value "$(Get-Timestamp) -----------------------------Log End"
Write-Output "Errors : $Global:ErrorCount"
RMM-LogParse
Exit $ExitCode
}
RMM-Initilize
###############################################################################
# Function - Logging End
###############################################################################

# RMM-Msg "Checking $amddriverdetails for driver details" 
# RMM-Error "Download URL not found." -messagetype Verbose
# RMM-Exit 0

Function Get-RandomPassword {
    #define parameters
    param (
        [int]$PasswordLength = 10
    )
    #ASCII Character set for Password
    $CharacterSet = @{
            Uppercase   = (97..122) | Get-Random -Count 10 | % {[char]$_}
            Lowercase   = (65..90)  | Get-Random -Count 10 | % {[char]$_}
            Numeric     = (48..57)  | Get-Random -Count 10 | % {[char]$_}
            SpecialChar = (33..47)+(58..64)+(91..96)+(123..126) | Get-Random -Count 10 | % {[char]$_}
    }
    #Frame Random Password from given character set
    $StringSet = $CharacterSet.Uppercase + $CharacterSet.Lowercase + $CharacterSet.Numeric + $CharacterSet.SpecialChar
    -join (Get-Random -Count $PasswordLength -InputObject $StringSet)
} 

#########################################################
# Functions End
#########################################################

#########################################################
# Common Variables Start
#########################################################
$ErrorActionPreference = 'SilentlyContinue'
$urlsyscfg = "https://advprimarystorage.blob.core.windows.net/ninjarmm-public/Software/SYSCFG/Syscfg_V16.0.9_AllOS.zip"
$urlipmi = "https://advprimarystorage.blob.core.windows.net/ninjarmm-public/Software/IPMI/ipmitool-v1.8.19.zip"

$workingfolder = "C:\temp\ninjarmm\bmclogging"
$zipipmi = "$workingfolder\ipmi.zip"
$zipsyscfg = "$workingfolder\syscfg.zip"
$exeipmi = "$workingfolder\ipmitool.exe"
$exesyscfg = "$workingfolder\Win_x64\syscfg.exe"
$syscfgdriver = "$workingfolder\Win_x64\Drivers\install.cmd"
$ninjabmcid = "bmcid"
$ninjabmcusername = "bmcusername"
$ninjabmcpassword = "bmcpassword"
$ninjabmcip = "bmcip"
$ninjabmchealth = "bmchealth"


#########################################################
# Common Variables End
#########################################################

#########################################################
# Main Script
#########################################################

## Download Files
if (!(Test-Path $workingfolder -PathType Container)) {
    New-Item -ItemType Directory -Force -Path $workingfolder
}
if (!(Test-Path $exeipmi)){
    Invoke-WebRequest -Uri $urlipmi -OutFile $zipipmi
    Expand-Archive -Path $zipipmi -DestinationPath $workingfolder -Force
}
if (!(Test-Path $exesyscfg)){
    Invoke-WebRequest -Uri $urlsyscfg -OutFile $zipsyscfg
    Expand-Archive -Path $zipsyscfg -DestinationPath $workingfolder -Force
}

# Cleanup
Remove-Item $zipipmi -Force
Remove-Item $zipsyscfg -Force

# Get current user id 4 from bmc
$bmcid = Ninja-Property-Get $ninjabmcid
if ($bmcid -eq "" -or $null -eq $bmcid){
    $bmcid = "4"
    Ninja-Property-Set $ninjabmcid $bmcid
    }else{
        $bmcid = $bmcid
}
$bmcinfo = [System.Collections.Generic.List[object]]::New()
$sysycfglan = & "$exesyscfg" /d LAN 1 | Out-String
$sysycfguser = & "$exesyscfg" /d user $bmcid 1 | Out-String
$sysycfgpower = & "$exesyscfg" /d power | Out-String

$sysycfgusername = (($sysycfguser -split "`n" | Select-String -Pattern "User Name:" ).Line.TrimStart())-replace '^.*: (.*)', '$1'
$sysycfguserstatus = (($sysycfguser -split "`n" | Select-String -Pattern "User Status:").Line.TrimStart())-replace '^.*: (.*)', '$1'
$sysycfguserprivilege = (($sysycfguser -split "`n" | Select-String -Pattern "Privilege Level Limit:").Line.TrimStart())-replace '^.*: (.*)', '$1'
$sysycfgusersol = (($sysycfguser -split "`n" | Select-String -Pattern "SOL Enable:").Line.TrimStart())-replace '^.*: (.*)', '$1'
$sysycfglanip = (($sysycfglan -split "`n" | Select-String -Pattern "BMC Host IP Address:").Line.TrimStart())-replace '^.*: (.*)', '$1'
$sysycfglandhcp = (($sysycfglan -split "`n" | Select-String -Pattern "IP Address Source:").Line.TrimStart())-replace '^.*: (.*)', '$1'
$sysycfgpowerpolicy = (($sysycfgpower-split "`n" | Select-String -Pattern "Power Restore Policy:").Line.TrimStart())-replace '^.*: (.*)', '$1'

# Create Password if required
$generatedpassword = Get-RandomPassword -PasswordLength 15

# Check Ninja, if blank assume not run before
$bmcusername = Ninja-Property-Get $ninjabmcusername
if ($bmcusername -eq "" -or $null -eq $bmcusername){
    $bmcusername = "advsuperuser"
    Ninja-Property-Set $ninjabmcusername $bmcusername
    }else{
        $bmcusername = $bmcusername
}
$bmcpassword = Ninja-Property-Get $ninjabmcpassword
if ($bmcpassword -eq "" -or $null -eq $bmcpassword){
    $bmcpassword = $generatedpassword
    Ninja-Property-Set $ninja$bmcpassword $bmcpassword
    }else{
        $bmcpassword = $bmcpassword
}

# Create User
if($sysycfgusername -ne $bmcusername){
    & "$exesyscfg" /u $bmcid $bmcusername $bmcpassword
}

# Create Object with Details from BMC
$bmcobject = [PSCustomObject]@{
    'BMCID' = $bmcid
    'BMCUserName' = $sysycfgusername
    'BMCStatus'= $sysycfguserstatus
    'BMCPrivilege' = $sysycfguserprivilege
    'BMCSOL' = $sysycfgusersol
    'BMCPassword' = $bmcpassword
    'BMCIP' = $sysycfglanip
    'BMCDHCP' = $sysycfglandhcp
    'BMCPSUPolicy' = $sysycfgpowerpolicy
}
# Store Details to NinjaRMM
# Enable User on channel 1 if disabled
if($bmcobject.BMCStatus -eq 'DISABLE'){
    & "$exesyscfg" /ue $bmcid enable 1
    $bmcobject.BMCStatus = 'ENABLE'
}
# Enable Admin on channel 1 if not
if($($bmcobject.BMCPrivilege) -ne 'ADMIN' -or $($bmcobject.BMCSOL) -eq 'DISABLE' ){
    & "$exesyscfg" /up $bmcid 1 ADMIN SOL
    $bmcobject.BMCPrivilege = 'ADMIN'
}

# ipmitool -I lanplus -H 192.168.1.56 -U Admin -P "Pal@ce1010" sdr list

$ipmicommand = @(
  "-I",
  "lanplus",
  "-H",
  $sysycfglanip,
  "-U",
  $bmcusername,
  "-P",
  $bmcpassword,
  "sdr list"
)

$ipmiraw = & "$exeipmi" @ipmicommand | Out-String
$ipmirawcompact = & "$exeipmi" `-I lanplus `-H $($bmcobject.BMCIP) `-U $($bmcobject.BMCUserName) `-P $($bmcobject.BMCPassword) sdr list compact | Out-String

# $ipmiraw = (($sysycfguser -split "`n" | Select-String -Pattern "User Name:" ).Line.TrimStart())-replace '^.*: (.*)', '$1'

## Save to file
$ipmiraw| New-Item -ItemType File -Name "$workingfolder\ipmi.log"

$ipmiobject = [PSCustomObject]@{
    'ipmitest' = $ipmitest
}

