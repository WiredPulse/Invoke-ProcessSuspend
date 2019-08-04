# https://github.com/FuzzySecurity/PowerShell-Suite/blob/master/Detect-Debug.ps1


# todos:
# Easy
# create better error logics
# make better help messages

# Mid-level
# add input validation checks
# - is ID an int?---DONE

# HARD
# - re-introduce the -Duration option & use ScheduledJob instead of sleep



<#

.SYNOPSIS
    This script enables a person to suspend and resume processes by attaching and removing a debugger.

.PARAMETER id (Invoke-ProcessSuspend, Invoke-ResumeProcess, Invoke-TimedProcessSuspend)
    Specify process id to suspend or resume

.PARAMETER duration (Invoke-TimedProcessSuspend)
    Specify the amount mintues to wait between suspending and resuming a process

.EXAMPLE
    PS C:\> . C:\Invoke-ProcessSuspend.ps1
    PS C:\> Invoke-ProcessSuspend -id 1234

    Suspends a process (attaches debugger) with an ID of 1234

.EXAMPLE
    PS C:\> . C:\Invoke-ProcessSuspend.ps1
    PS C:\> Invoke-ResumeSuspend -id 1234  

    Resumes a process (removes debugger) with an ID of 1234

.EXAMPLE
    PS C:\> . C:\Invoke-ProcessSuspend.ps1
    PS C:\> Invoke-TimedProcessSuspend -id 1234 -duration 5

    Suspends a process (attaches debugger) with an ID of 1234 and then resumes the process (removes debugger) after 5 minutes

.LINKS
    https://github.com/FuzzySecurity/PowerShell-Suite/blob/master/Detect-Debug.ps1
    https://www.geoffchappell.com/studies/windows/win32/kernel32/api/index.htm
#>

Add-Type -TypeDefinition @"
            using System;
            using System.Diagnostics;
            using System.Security.Principal;
            using System.Runtime.InteropServices;

            public static class Kernel32
            {
                [DllImport("kernel32.dll")]
                public static extern bool CheckRemoteDebuggerPresent(
                    IntPtr hProcess,
                    out bool pbDebuggerPresent);

                [DllImport("kernel32.dll")]
                public static extern int DebugActiveProcess(int PID);

                [DllImport("kernel32.dll")]
                public static extern int DebugActiveProcessStop(int PID);
            }
"@

function Invoke-ProcessSuspend{

[CmdletBinding()]

    Param (
    [parameter(Mandatory=$true)]
        [ValidateRange(1, [int]::MaxValue)]
        [int] $id
    )

    $procName = (Get-Process -id $id -ErrorAction SilentlyContinue).name
    
    if($procName -eq $null){
        Write-Host -ForegroundColor Red "ERROR: There is no process with an ID of $id"
        break
    }

    Write-host -ForegroundColor Cyan "Attempting to suspend $procName (PID: $id)..."

    if ($id -le 0) {
        write-host -ForegroundColor Red "You didn't input a positive integer"
        break
    }
            
    $debug = whoami /priv | Where-Object{$_ -like "*SeDebugPrivilege*"}
         
    if($debug -ne $null){                
        $DebugPresent = [IntPtr]::Zero
        $out = [Kernel32]::CheckRemoteDebuggerPresent(((Get-Process -Id $id).Handle),[ref]$debugPresent)
        if ($debugPresent){
            write-host -ForegroundColor Red "There is already a debugger attached to this process"
            break
        }
        $suspend = [Kernel32]::DebugActiveProcess($id)

        if ($suspend -eq $false){
            write-host -ForegroundColor red "ERROR: Unable to suspend $procName (PID: $id)"
        } 
        else{
            " "; write-host -ForegroundColor Green "The $procName process (PID: $id) was successfully suspended!"
        }
    }
    else{
        write-host -ForegroundColor Red "ERROR: You do not have debugging privileges to pause any process"
        break
    }   
}
            

function Invoke-ResumeProcess {

[CmdletBinding()]

    Param (
    [parameter(Mandatory=$true)]
        [ValidateRange(1, [int]::MaxValue)]
        [int] $id
    )

    $procName = (Get-Process -Id $id).name

    if($procName -eq $null){
        Write-Host -ForegroundColor Red "ERROR: There is no process with an ID of $id"
        break
    }

    Write-Host -ForegroundColor "Attempting to resume $procName (PID: $id)..."
        
    $debug = whoami /priv | where-object{$_ -like "*SeDebugPrivilege*"}
         
    if($debug -ne $null){    
        $resume = [Kernel32]::DebugActiveProcessStop($id)
        if ($resume -eq $false){
            Write-host -ForegroundColor red "ERROR: Unable to resume $procName (PID: $id)"
        } 
        else{
            Write-Host -ForegroundColor Green "The $procName process (PID: $id) was successfully resumed!"
        }
    }
}


function Invoke-TimedSuspendProcess{

[CmdletBinding()]

    Param (
    [parameter(Mandatory=$true)]
        [ValidateRange(1, [int]::MaxValue)]
        [int] $id,
    [parameter(Mandatory=$true)]
        [int] $duration
    )

    Invoke-ProcessSuspend $id

    Start-Sleep -Seconds ($duration * 60)

    Invoke-ResumeProcess $id
}