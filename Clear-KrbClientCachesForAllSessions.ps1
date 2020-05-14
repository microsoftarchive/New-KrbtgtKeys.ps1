#Requires -RunAsAdministrator
Get-WmiObject Win32_LogonSession | Where-Object {$_.AuthenticationPackage -ne 'NTLM'} | ForEach-Object {klist.exe purge -li ([Convert]::ToString($_.LogonId, 16))}
<#
    This script is helpful to remove all cached Kerberos tickets on a machine without a reboot.  Since 'klist purge' only works in the context of the user, it does not clear the 
    Kerberos client ticket cache for the system or service accounts.  (Restarting the OS will clear the cache, but sometimes that needs to be avoided).  This one-liner enumerates all sessions on the local system that could be using Kerberos and purges the caches of 
    each of them, whether they are other users logged in interactively (RDP), service accounts of running services, or services running as the system.  
    
    WMI exposes the session ids in hex (base-16), while klist.exe expects them as strings, hence the base-16 to string conversion.

    Author: Jared Poeppelman, Microsoft
#>