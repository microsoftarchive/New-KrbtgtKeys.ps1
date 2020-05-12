<#----------------------------------------------------------------------------------------------------
Version 1.7

    Known issues/bugs:
        - Currently requires English language due to checking text output of rpcping.exe and repadmin.exe

Release Notes:

    v1.7:
        Author: Jared Poeppelman, Microsoft
        - Modified rpcping.exe call to use "-u 9 -a connect" parameters to accomodate tighter 
          RPC security settings as specified in DISA STIG ID: 5.124 Rule ID: SV-32395r1_rule 
          Vuln ID: V-14254 (thanks Adam Haynes)

    v1.6: 
        Author: Jared Poeppelman, Microsoft
        - Removed 'finally' block of Get-GPOReport error handling (not a bug, just not needed)
                
    v1.5: 
        Author: Jared Poeppelman, Microsoft
        - Renamed script to New-CtmADKrbtgtKeys.ps1
        - Added logic for GroupPolicy Powershell module dependency
        - Fixed bug of attempting PDC to PDC replication
        - Replaced function for password generation
        - Renamed functions to use appropriate Powershell verbs 
        - Added error handling around Get-GpoReport for looking up MaxTicketAge and MaxClockSkew

    v1.4: 
        Author: Jared Poeppelman, Microsoft
        - First version published on TechNet Script Gallery

    To do list:
        Revise Test-RpcToHost function to not use external command (rpcping.exe)
        - Add more error handling, if needed
        - Revise Start-CtmADSingleObjectReplication function to not use external command (repadmin.exe)
        - Add support for resetting RODC-specific krbtgt keys (maybe)
----------------------------------------------------------------------------------------------------#>

function Test-Command
    {
    Param([string]$Command)
    
    Try {Invoke-Expression $Command} 
    Catch [System.Exception] {If ($Error.FullyQualifiedErrorId -eq 'CommandNotFoundException') {Return $false}} 
    Return $true
    }

function Test-RpcToHost
    {
    Param([string]$Hostname)
    
    Try {$RpcPingResult = rpcping.exe -s $Hostname -u 9 -a connect} # Attempt to RPCPING the target host
    
    # Check for RPCPING.exe command and execution errors
    Catch [System.Exception] 
        {
        If ($Error.FullyQualifiedErrorId -eq 'CommandNotFoundException') {Write-Host -ForegroundColor Red "The 'RPCPING.exe' utility is not available. Install it and/or add its location to the path and retry... exiting."; Exit}
        Write-Host -ForegroundColor Red "An unknown error occurred when attempting to execute 'RPCPING.exe'... exiting."; Exit
        } 

    # Check output of RPCPING for success
    If ($RpcPingResult -like "*Completed*") {Return (New-Object -TypeName PSObject -Property @{'Success'=$true; 'Message'="$Hostname - RPC connectivity successful."})}
        
    # Check output of RPCPING for exceptions
    If ($RpcPingResult -like "*Exception 5*")    {Return (New-Object -TypeName PSObject -Property @{'Success'=$false; 'Message'="$Hostname - Access is denied. Ensure your credentials have the required rights on the target host."})}
    If ($RpcPingResult -like "*Exception 1722*") {Return (New-Object -TypeName PSObject -Property @{'Success'=$false; 'Message'="$Hostname - RPC server unavailable. Check firewall rules and name resolution for the target host."})}
    If ($RpcPingResult -like "*Exception*")      {Return (New-Object -TypeName PSObject -Property @{'Success'=$false; 'Message'="$Hostname - RPC to the target host failed for an unknown reason."})}
    }

function Start-CtmADSingleObjectReplication
    {
    Param([string]$TargetDC, [string]$SourceDC, [string]$ObjectDN)
       
    Try {$RepAdminResult = repadmin.exe /replsingleobj $TargetDC $SourceDC $ObjectDN} # Attempt REPADMIN 

    # Check for REPADMIN.exe command and execution errors
    Catch [System.Exception] 
        {
        If ($Error.FullyQualifiedErrorId -eq 'CommandNotFoundException') {Write-Host -ForegroundColor Red "The 'REPADMIN.exe' utility is not available. Install it and/or add its location to the path and retry... exiting."; Exit}
        Write-Host -ForegroundColor Red "An unknown error occurred when attempting to execute 'REPADMIN.exe'... exiting."; Exit
        }

    # Check output of REPADMIN for success
    If ($RepAdminResult -like "*Successfully replicated object*") {Return (New-Object -TypeName PSObject -Property @{'Success'=$true; 'Message'="$ObjectDN - Successfully replicated from $SourceDC to $TargetDC."})}
    
    # Check output of REPADMIN for exceptions
    If ($RepAdminResult -like "*Exception 5*")    {Return (New-Object -TypeName PSObject -Property @{'Success'=$false; 'Message'="$ObjectDN - $SourceDC access is denied. Ensure your credentials have the required rights on the target host."})}
    If ($RepAdminResult -like "*Exception 1722*") {Return (New-Object -TypeName PSObject -Property @{'Success'=$false; 'Message'="$ObjectDN - $SourceDC server unavailable. Check firewall rules and name resolution for the target host."})}
    If ($RepAdminResult -like "*Exception*")      {Return (New-Object -TypeName PSObject -Property @{'Success'=$false; 'Message'="$ObjectDN - Failed to replicate from $SourceDC to $TargetDC for an unknown reason."})}
    }

function Confirm-CtmADPasswordIsComplex
    {
    Param(
    [Parameter(Mandatory=$true,ValueFromPipeline=$true)]
    [string]
    $Pw
    )
        Process
        {
        $CriteriaMet = 0
        If ($Pw -cmatch '[A-Z]') {$CriteriaMet++}
        If ($Pw -cmatch '[a-z]') {$CriteriaMet++}
        If ($Pw -match '\d') {$CriteriaMet++}
        If ($Pw -match '[\^~!@#$%^&*_+=`|\\(){}\[\]:;"''<>,.?/]') {$CriteriaMet++}
        If ($CriteriaMet -lt 3) {Return $false}
        If ($Pw.Length -lt 6) {Return $false}
        Return $true
        }
    }

function New-CtmADComplexPassword 
    {
    Param(
        [Parameter(Mandatory=$false,ValueFromPipeline=$true)]
        [ValidateRange(6,127)]
        [Int]
        $PwLength=24
    )
    Process
        {
        $Iterations = 0
        Do 
            {
            If ($Iterations -ge 20) 
                {
                Write-Host "Password generation failed to meet complexity after $Iterations attempts, exiting."
                Return $null
                }
            $Iterations++
            $PWBytes = @()
            $RNG = New-Object System.Security.Cryptography.RNGCryptoServiceProvider
            Do 
                {
                [byte[]]$Byte = [byte]1
                $RNG.GetBytes($Byte)
                If ($Byte[0] -lt 33 -or $Byte[0] -gt 126) { continue }
                $PWBytes += $Byte[0]
                } 
            While 
                ($PWBytes.Count -lt $PwLength)

            $Pw = ([char[]]$PWBytes) -join ''
            } 
        Until 
            (Confirm-CtmADPasswordIsComplex $Pw)
        Return $Pw
        }      
    }

function New-CtmADKrbtgtAccountPassword
    {
    Param([string]$Server)

    Try {Set-ADAccountPassword -Identity (Get-ADUser krbtgt -Server $Server).DistinguishedName -Server $Server -Reset -NewPassword (ConvertTo-SecureString ((New-CtmADComplexPassword 32).ToString()) -AsPlainText -Force)}
    Catch 
        {
        If (($Error.FullyQualifiedErrorId -eq 'ActiveDirectoryCmdlet:System.UnauthorizedAccessException,Microsoft.ActiveDirectory.Management.Commands.SetADAccountPassword') -and ($Error.CategoryInfo -like "*PermissionDenied*"))
            {Return (New-Object -TypeName PSObject -Property @{'Success'=$false; 'Message'='Krbtgt key reset failed due to insufficient permissions.'})}
        Else {Return (New-Object -TypeName PSObject -Property @{'Success'=$false; 'Message'='Krbtgt key reset failed for an unknown reason.'})}
        }
    Return (New-Object -TypeName PSObject -Property @{'Success'=$true; 'Message'='Krbtgt key reset successfully.'})
    }

<#----------------------------------------------------------------------------------------------------
Initialize
----------------------------------------------------------------------------------------------------#>
#cls

Set-Location (Split-Path $MyInvocation.MyCommand.Path) # Set the path of the script as the working directory

$TimeStamp = Get-Date -Format o | foreach {$_ -replace ":", "."} # Timestamp for logfile

$LogFile = "New-CtmADKrbtgtKeys_$TimeStamp.log" # Logfile

$Status = New-Object -TypeName PSObject # Custom object for status information


<#----------------------------------------------------------------------------------------------------
Display menu options to user
----------------------------------------------------------------------------------------------------#>
$ScriptDescription = @'
This script can be used to perform a single reset of the krbtgt key that is shared by all 
writable domain controllers in the domain in which it is run.  

This script has 3 modes: 
'@
$Mode1Description = @'
  - Mode 1 is Informational Mode. This mode is safe to run at any time and makes no changes
    to the environment. It will analyze the environment and check for issues that may impact
    the successful execution of Mode 2 or Mode 3.
'@
$Mode2Description = @'
  - Mode 2 is Simulation Mode. This mode will perform all the analysis and checks included
    in Mode 1. It will also initiate a single object replication of the krbtgt object from 
    the PDC emulator DC to every writable domain controller that is reachable. This 
    replication is not to replicate changes (no changes will be made). Instead, this replication
    is performed so that the replication time for mode 3 can be estimated.
    of Mode 3.
'@
$Mode3Description = @'
  - Mode 3 is Reset Mode. This mode will perform all the analysis and checks included 
    in Mode 1. It will also perform a single reset of the krbtgt key on the PDC emulator DC.
    If the krbtgt reset is successful, it will automatically initiate a single object 
    replication of krbtgt from the PDC emulator DC to every writable domain controller that
    is reachable. Once the replication is complete, the total impact time will be displayed.
    During the impact duration of Mode 3 (estimated in Mode 2), the following impacts may 
    be observed:
'@
$Mode3Impact1 = @'
        - Kerberos PAC validation failures: Until the new krbtgt key is replicated to all 
          writable DCs in the domain, applications which attempt KDC PAC validation may 
          experience KDC PAC validation failures. This is possible when a client in one 
          site is accessing a Kerberos-authenticated application that is in a different site.
          If that application is not a trusted part of the operating system, it may attempt 
          to validate the PAC of the client''s Kerberos service ticket against the KDC (DC) in
          its site. If the DC in its site does not yet have the new krbtgt key, this KDC PAC 
          validation will fail. This will likely manifest itself to the client as 
          authentication errors for that application. Once all DCs have the new krbtgt key,
          some affected clients may recover gracefully and resume functioning normally. If not,
          rebooting the affected client(s) will resolve the issue. This issue may not occur if
          the replication of the new krbtgt key is timely and successful and no applications 
          attempt KDC PAC validation against an out of sync DC during that time.
'@
$Mode3Impact2 = @'
        - Kerberos TGS request failures: Until the new krbtgt key is replicated to all writable
          DCs in the domain, a client may experience Kerberos authentication failures. This is 
          when a client in one site has obtained a Kerberos user ticket (TGT) from a DC that has
          the new krbtgt, but then subsequently attempts to obtain a service ticket via a TGS
          request against a DC in a different site. If that DC does not also have the new krbtgt
          key, it will not be able to decrypt the client''s TGT, which will result in a TGS
          request failure. This will manifest itself to the client as authenticate errors.
          However, it should be noted that this impact is very unlikely, because it is very 
          unlikely that a client will attempt to obtain a service ticket from a different DC 
          than the one from which their TGT was obtained, especially during the relatively short
          impact duration of Mode 3.
'@
$ScriptRecommendation = @'
It is highly recommended that Mode 1 be run first, then Mode 2, and then Mode 3.
'@
$Menu = @'
In which mode do you wish to run the script?

     1 --- Informational Mode  (no changes made; no replication triggered)
     2 --- Simulation Mode (no changes made, but replication WILL BE triggered for estimation purposes)
     3 --- Reset Mode  (krbtgt WILL BE reset once, and replication WILL BE triggered)
     0 --- Exit
'@
$MenuPrompt = '(Enter 1-3, or 0 to exit)'

Write-Host ''
Write-Host $ScriptDescription
Write-Host -ForegroundColor Green  $Mode1Description
Write-Host -ForegroundColor Yellow $Mode2Description
Write-Host -ForegroundColor Red    $Mode3Description
Write-Host -ForegroundColor Cyan    $Mode3Impact1
Write-Host -ForegroundColor Cyan    $Mode3Impact2
Write-Host ''
Write-Host $ScriptRecommendation
Write-Host ''
Write-Host $Menu
Write-Host ''

$Status | Add-Member -MemberType NoteProperty -Name 'ScriptMode' -Value (Read-Host $MenuPrompt)

If (($Status.ScriptMode -lt 1) -or ($Status.ScriptMode -gt 3)) {Write-Host 'Invalid selection...exiting'; Exit} # Validate input

<#----------------------------------------------------------------------------------------------------
Perform pre-flight checks
----------------------------------------------------------------------------------------------------#>
Write-Host 'Checking for script pre-requisites...'
$Status | Add-Member -MemberType NoteProperty -Name 'PreFlightPassed' -Value $true
Write-Host ''

Write-Host '   Checking for ActiveDirectory Powershell module.....' -NoNewline
If (Get-Module -List ActiveDirectory) {Write-Host -ForegroundColor Green 'PASSED'} 
Else {$Status.PreFlightPassed = $false; Write-Host -ForegroundColor Red 'FAILED'}

Write-Host '   Checking for GroupPolicy Powershell module.....' -NoNewline
If (Get-Module -List GroupPolicy) {Write-Host -ForegroundColor Green 'PASSED'} 
Else {$Status.PreFlightPassed = $false; Write-Host -ForegroundColor Red 'FAILED'}

Write-Host '   Checking if RPCPING.exe is installed and in the path.....' -NoNewline
If (Test-Command rpcping.exe) {Write-Host -ForegroundColor Green 'PASSED'} 
Else {$Status.PreFlightPassed = $false; Write-Host -ForegroundColor Red 'FAILED'}

Write-Host '   Checking if REPADMIN.exe is installed and in the path.....' -NoNewline
If (Test-Command repadmin.exe) {Write-Host -ForegroundColor Green 'PASSED'} 
Else {$Status.PreFlightPassed = $false; Write-Host -ForegroundColor Red 'FAILED'}

Write-Host ''
If ($Status.PreFlightPassed -ne $true) {Write-Host -ForegroundColor Red "Pre-flight checks failed... exiting."; Exit}

<#----------------------------------------------------------------------------------------------------
Gather and analyze domain information
----------------------------------------------------------------------------------------------------#>
Write-Host 'Gathering and analyzing target domain information...'
Import-Module ActiveDirectory
Import-Module GroupPolicy

$TargetDomain = Get-AdDomain | Select Name,DNSRoot,NetBIOSName,DomainMode,PDCEmulator

Write-Host ''
Write-Host '   Domain NetBIOS name: ' -NoNewline; Write-Host -ForegroundColor Cyan $TargetDomain.NetBIOSName
Write-Host '   Domain DNS name: ' -NoNewline; Write-Host -ForegroundColor Cyan $TargetDomain.DNSRoot 
Write-Host '   PDC emulator: ' -NoNewline; Write-Host -ForegroundColor Cyan $TargetDomain.PDCEmulator
Write-Host '   DomainMode: ' -NoNewline; Write-Host -ForegroundColor Cyan $TargetDomain.DomainMode
Write-Host '   Checking domain functional mode is ''Windows2008Domain'' or higher.....' -NoNewline

$Status | Add-Member -MemberType NoteProperty -Name 'DomainModePassed' -Value (!(($TargetDomain.DomainMode -eq 'Windows2000Domain') -or ($TargetDomain.DomainMode -eq 'Windows2003InterimDomain') -or ($TargetDomain.DomainMode -eq 'Windows2003Domain')))
If ($Status.DomainModePassed) {Write-Host -ForegroundColor Green 'PASSED'} 
Else {Write-Host -ForegroundColor Red 'FAILED'}

Write-Host ''

<#----------------------------------------------------------------------------------------------------
Gather and analyze krbtgt information and Kerberos policy
----------------------------------------------------------------------------------------------------#>
Write-Host 'Gathering and analyzing krbtgt account information and domain Kerberos policy...'
Write-Host ''

$Krbtgt = Get-ADUser krbtgt -Properties PasswordLastSet -Server $TargetDomain.PDCEmulator

Try
    {
    [xml]$gpo = Get-GPOReport -Guid '{31B2F340-016D-11D2-945F-00C04FB984F9}' -ReportType Xml
    $MaxTgtLifetimeHrs = (($gpo.gpo.Computer.ExtensionData | Where-Object {$_.name -eq 'Security'}).Extension.ChildNodes | Where-Object {$_.Name -eq 'MaxTicketAge'}).SettingNumber
    $MaxClockSkewMins = (($gpo.gpo.Computer.ExtensionData | Where-Object {$_.name -eq 'Security'}).Extension.ChildNodes | Where-Object {$_.Name -eq 'MaxClockSkew'}).SettingNumber
    }
Catch
    {
    Write-Warning 'Could not lookup MaxTicketAge (default 10 hrs) and MaxClockSkew (default 5 mins) from "Default Domain Policy" GPO, so default values will be assumed.'
    $MaxTgtLifetimeHrs = 10
    $MaxClockSkewMins = 5
    }

$ExpirationTimeForNMinusOneTickets = (($Krbtgt.PasswordLastSet.AddHours($MaxTgtLifetimeHrs)).AddMinutes($MaxClockSkewMins)).AddMinutes($MaxClockSkewMins) # Doubling the clock skew to account for skew in both directions


Write-Host '   Krbtgt account: ' -NoNewline; Write-Host -ForegroundColor Cyan $Krbtgt.DistinguishedName
Write-Host '   Krbtgt account password last set on PDC emulator: ' -NoNewline; Write-Host -ForegroundColor Cyan $Krbtgt.PasswordLastSet
Write-Host '   Kerberos maximum lifetime for user ticket (TGT lifetime): ' -NoNewline; Write-Host -ForegroundColor Cyan $MaxTgtLifetimeHrs 'hours' 
Write-Host '   Kerberos maximum tolerance for computer clock synchronization: ' -NoNewline; Write-Host -ForegroundColor Cyan $MaxClockSkewMins 'minutes' 
Write-Host '   Checking if all tickets based on the previous (N-1) krbtgt key have expired.....' -NoNewline

$Status | Add-Member -MemberType NoteProperty -Name 'NMinusOneTicketExpirationPassed' -Value ($ExpirationTimeForNMinusOneTickets -lt [DateTime]::Now)
If ($Status.NMinusOneTicketExpirationPassed) {Write-Host -ForegroundColor Green 'PASSED'}
Else {Write-Host -ForegroundColor Red 'FAILED'}
Write-Host ''

<#----------------------------------------------------------------------------------------------------
Gather and analyze domain controller information
----------------------------------------------------------------------------------------------------#>
Write-Host 'Gathering and analyzing writable domain controller information...'
Write-Host ''

$RwDcs = @()

Try {$RwDcs = Get-ADDomainController -Filter {IsReadOnly -eq $false} -Server $TargetDomain.PDCEmulator | Select Name,Hostname,Domain,Site}
Catch {Throw $_}

Write-Host '   Checking RPC connectivity to domain controllers:' 
$Status | Add-Member -MemberType NoteProperty -Name 'RpcToDCsPassed' -Value $true

ForEach ($DC in $RwDcs)
    {
    Write-Host '      Checking RPC connectivity to'$DC.Hostname'.....' -NoNewline
    
    $DC | Add-Member -MemberType NoteProperty -Name 'IsPdcEmulator' -Value ($DC.Hostname -eq $TargetDomain.PDCEmulator)
    $DC | Add-Member -MemberType NoteProperty -Name 'IsReachableViaRpc' -Value ((Test-RpcToHost $DC.Hostname).Success)
    
    If (!$DC.IsReachableViaRpc) {$Status.RpcToDCsPassed = $false;  Write-Host -ForegroundColor Red 'FAILED'}
    Else {Write-Host -ForegroundColor Green 'PASSED'}
    }

If ($Status.RpcToDCsPassed) {Write-Host -ForegroundColor Green '   Check for RPC connectivity to writable domain controllers PASSED: All writable DCs were reachable.'}
Else {Write-Host -ForegroundColor Red '   Check for RPC connectivity to writable domain controllers FAILED. One or more writable DCs was unreachable.'}
Write-Host ''

<#----------------------------------------------------------------------------------------------------
MODES 2 AND 3 - Replicate krbtgt to all writable DCs that are reachable and generate an impact estimate
----------------------------------------------------------------------------------------------------#>
If ($Status.ScriptMode -gt 1 -and $Status.PreFlightPassed -and $Status.DomainModePassed -and $Status.RpcToDCsPassed)
    {    
    Write-Host 'Replicating krbtgt object to all writable domain controllers that are reachable...'
    
    If ($Status.ScriptMode -eq 2)
        {
        Write-Host -ForegroundColor Yellow '   The krbtgt object replication WILL BE triggered if you proceed. Are you sure you wish to proceed?'
        If (!((Read-Host  '   (Enter ''Y'' to proceed or any other key to exit)').ToUpper() -eq 'Y')) {Write-Host -ForegroundColor Yellow '   Replication of krbtgt was skipped at the user''s request...exiting'; Exit}
        }
    
    $ImpactStartTime = (Get-Date).ToUniversalTime()
    
    ########## THIS IS WHERE KRBTGT PASSWORD RESET OCCURS IN MODE 3 ##########

    # Replicate krbtgt to appropriate DCs
    $Status | Add-Member -MemberType NoteProperty -Name 'ReplicationCheckSucceeded' -Value $true
    ForEach ($DC in $RwDcs)
        {
        If (!$DC.IsPdcEmulator)
            {
            Write-Host '      Replication of krbtgt from'$TargetDomain.PDCEmulator'to'$DC.Hostname'...' -NoNewline
            If ($DC.IsReachableViaRpc)
                {
                $ReplAttemptStart = (Get-Date).ToUniversalTime()
                If ((Start-CtmADSingleObjectReplication $DC.Hostname $TargetDomain.PDCEmulator $Krbtgt.DistinguishedName).Success) {Write-Host -ForegroundColor Green 'SUCCEEDED' -NoNewline}
                Else {$Status.ReplicationCheckSucceeded = $false;  Write-Host -ForegroundColor Red 'FAILED' -NoNewline}
                $ReplElapsedTime = ((Get-Date).ToUniversalTime() - $ReplAttemptStart)
                Write-Host -ForegroundColor Cyan '  Time:'$ReplElapsedTime
                }
            Else {Write-Host -ForegroundColor Yellow 'SKIPPED'}
            }
        }
    $TotalImpactTime = (Get-Date).ToUniversalTime() - $ImpactStartTime
    Write-Host ''
    $Status | Add-Member -MemberType NoteProperty -Name 'ImpactDurationEstimate' -Value $TotalImpactTime

    If ($Status.ReplicationCheckSucceeded) {Write-Host -ForegroundColor Cyan 'The total duration of impact when running Mode 3 will be approximately:' $TotalImpactTime}
    Else {Write-Host -ForegroundColor Red 'Single object replication failed to one or more writable domain controllers. All failures should be remediated before attempting Mode 3.'}
    }

<#----------------------------------------------------------------------------------------------------
MODE 3 ONLY - Reset the krbtgt key and replicate to all writable DCs that are reachable
----------------------------------------------------------------------------------------------------#>
If ($Status.ScriptMode -eq 3 -and $Status.PreFlightPassed -and $Status.DomainModePassed -and $Status.RpcToDCsPassed -and $Status.ReplicationCheckSucceeded)
    {     
    Write-Host 'Resetting krbtgt key and replicating krbtgt object to all reachable domain controllers...'
    Write-Host ''

    Write-Host -ForegroundColor Red '   WARNING!!! The krbtgt key WILL BE reset AND krbtgt object replication WILL BE triggered if you proceed. Are you sure you wish to proceed?'
    Write-Host -ForegroundColor Red '   If you proceed, the impact duration of Mode 3 (described above) will begin and not end until all DCs obtained the new krbtgt key.'
    If (!((Read-Host  '   (Enter ''Y'' to proceed or any other key to exit)').ToUpper() -eq 'Y')) {Write-Host -ForegroundColor Yellow '   The krbtgt reset and replication was skipped at the user''s request...exiting'; Exit}
    Write-Host ''
    
    If (!$Status.NMinusOneTicketExpirationPassed)
        {
        Write-Host -ForegroundColor Red '   The last change of the krbtgt key for this domain occurred: ' -NoNewline; Write-Host -ForegroundColor Cyan $Krbtgt.PasswordLastSet 'according to'$TargetDomain.PDCEmulator
        Write-Host -ForegroundColor Red '   and the domain Kerberos policy is configured with a maximum user ticket (TGT) lifetime of '-NoNewline; Write-Host -ForegroundColor Cyan $MaxTgtLifetimeHrs 'hours'
        Write-Host -ForegroundColor Red '   and a maximum tolerance for computer clock synchronization of ' -NoNewline; Write-Host -ForegroundColor Cyan $MaxClockSkewMins 'minutes'
        Write-Host -ForegroundColor Red '   That means that if you reset the krbtgt key again before ' -NoNewline; Write-Host -ForegroundColor Cyan $ExpirationTimeForNMinusOneTickets 
        Write-Host -ForegroundColor Red '   A major impact is very likely.  Are you sure you wish to proceed?'
        If (!((Read-Host  '   (Enter ''Y'' to proceed or any other key to exit)').ToUpper() -eq 'Y')) {Write-Host -ForegroundColor Yellow '   The krbtgt reset and replication was skipped at the user''s request...exiting'; Exit}
        Write-Host ''
        }

    $ImpactStartTime = (Get-Date).ToUniversalTime() # Record start time
    
    # Reset krbtgt password 
    Write-Host -ForegroundColor Cyan '   Resetting krbtgt key.....' -NoNewline
    $Status | Add-Member -MemberType NoteProperty -Name 'ResetSucceeded' -Value (New-CtmADKrbtgtAccountPassword $TargetDomain.PDCEmulator).Success
    If ($Status.ResetSucceeded) {Write-Host -ForegroundColor Green 'SUCCEEDED'} 
    Else {Write-Host -ForegroundColor Red 'FAILED'; Write-Host -ForegroundColor Red '   Krbtgt reset failed. Check to ensure you have sufficient rights to reset the krbtgt account. Replication will be skipped'}
    Write-Host ''
    
    # Replicate krbtgt to appropriate DCs
    If ($Status.ResetSucceeded)
        {
        $Status | Add-Member -MemberType NoteProperty -Name 'PostResetReplicationSucceeded' -Value $true
        ForEach ($DC in $RwDcs)
            {
            If (!$DC.IsPdcEmulator)
                {
                Write-Host '      Replication of krbtgt from'$TargetDomain.PDCEmulator'to'$DC.Hostname'...' -NoNewline
                If ($DC.IsReachableViaRpc)
                    {
                    $ReplAttemptStart = (Get-Date).ToUniversalTime()
                    If ((Start-CtmADSingleObjectReplication $DC.Hostname $TargetDomain.PDCEmulator $Krbtgt.DistinguishedName).Success) {Write-Host -ForegroundColor Green 'SUCCEEDED' -NoNewline}
                    Else {$Status.PostResetReplicationSucceeded = $false;  Write-Host -ForegroundColor Red 'FAILED' -NoNewline}
                    $ReplElapsedTime = ((Get-Date).ToUniversalTime() - $ReplAttemptStart)
                    Write-Host -ForegroundColor Cyan '  Time:'$ReplElapsedTime
                    }
                Else {Write-Host -ForegroundColor Yellow 'SKIPPED'}
                }
            }
        $TotalImpactTime = (Get-Date).ToUniversalTime() - $ImpactStartTime
        $Status | Add-Member -MemberType NoteProperty -Name 'ImpactDuration' -Value $TotalImpactTime
        
        If ($Status.PostResetReplicationSucceeded) {Write-Host -ForegroundColor Cyan 'The total duration of impact when running mode 3 was:' $TotalImpactTime}
        Else {Write-Host -ForegroundColor Red 'Single object replication failed to one or more writable domain controllers.'}
        Write-Host ''

        # Validate krbtgt password last set is in sync with PDC emulator
        Write-Host '   Validating krbtgt password last set is in sync with PDC emulator...'
        $Status | Add-Member -MemberType NoteProperty -Name 'NewKrbtgtKeyReplValidationPassed' -Value $true
        $KrbtgtKeyLastSetOnPdc = (Get-ADUser krbtgt -Properties PasswordLastSet -Server $TargetDomain.PDCEmulator).PasswordLastSet
        Write-Host '      PDC emulator: Krbtgt account password last set on'$TargetDomain.PDCEmulator'.....' -NoNewline; Write-Host -ForegroundColor Cyan $KrbtgtKeyLastSetOnPdc
        ForEach ($DC in $RwDcs)
            {
            If (!$DC.IsPdcEmulator) 
                {
                Write-Host '      Checking krbtgt account password last set on '$DC.Hostname'.....' -NoNewline
                If (!$DC.IsReachableViaRpc) {Write-Host -ForegroundColor Yellow "SKIPPED"}
                Else 
                    {
                    $CouldConnect = $true
                    Try {$KrbtgtKeyLastSetOnThisDc = (Get-ADUser krbtgt -Properties PasswordLastSet -Server $DC.Hostname).PasswordLastSet}
                    Catch 
                        {If ($Error.FullyQualifiedErrorId -eq 'ActiveDirectoryServer:0,Microsoft.ActiveDirectory.Management.Commands.GetADUser') {$CouldConnect = $false}}
                    If ($CouldConnect)
                        {
                        If ($KrbtgtKeyLastSetOnThisDc -ne $KrbtgtKeyLastSetOnPdc) {Write-Host -ForegroundColor Red "FAILED" -NoNewline; $Status.NewKrbtgtKeyReplValidationPassed = $false}
                        Else {Write-Host -ForegroundColor Green "PASSED" -NoNewline}
                        Write-Host -ForegroundColor Cyan '  Last set:' $KrbtgtKeyLastSetOnThisDc
                    }
                    Else {Write-Host -ForegroundColor Yellow "SKIPPED (could not connect to server)"}
                    }
                }
            }
        }
    Write-Host ''
    If (!$Status.NewKrbtgtKeyReplValidationPassed) {Write-Host -ForegroundColor Red '   Check if krbtgt key on all writable domain controllers was in sync with PDC emulator FAILED. One or more reachable DCs was out of sync with the PDC emulator.'}
    Else {Write-Host -ForegroundColor Green '   Check if krbtgt key on all writable domain controllers was in sync with PDC emulator PASSED. All reachable DCs were in sync with the PDC emulator..'}
    Write-Host ''
    }

If ((!$Status.PreFlightPassed -or !$Status.DomainModePassed -or !$Status.RpcToDCsPassed) -or ($Status.ScriptMode -gt 1 -and !$Status.ReplicationCheckSucceeded))
    {Write-Host -ForegroundColor Red 'One or more items failed. Resolve failures and retry.'}

# Log status data
$Status | Out-File -FilePath $LogFile -Append
Write-Host "Logged to file: $LogFile"
