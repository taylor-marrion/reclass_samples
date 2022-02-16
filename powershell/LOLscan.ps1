<#
.SYNOPSIS
  Simply run the script and provide input as prompted
.DESCRIPTION
  This script will prompt the user for a starting IP address. Next, the user can enter an ending IP address or a CIDR notation integer [1-32] to determine the end of the desired IP range.
  Each IP address in the range is pinged and if the ping is replied to, tested for WS-MAN being enabled and select ports of interest are scanned.
  Each port socket created is closed and discarded to prevent active listening ports.
  This version of the script has had all automated remote command execution removed. Previous versions included use of New-PSSession nad Invoke-Command to search for indicators of compromise (IOCs) on remote systems.
.INPUTS
  None
.OUTPUTS
  Scan results printed to terminal
.NOTES
  Title:          LOLscan.ps1
  github:         https://github.com/taylor-marrion/reclass_samples/blob/main/powershell/LOLscan.ps1
  Version:        2.0
  Author:         Marrion, Taylor
  Creation Date:  06/14/2021
  Purpose/Change: "Living Off the Land" - Perform network scan without installing third party software tools or modules
#>

function IP-toINT64 () {
    <#
    .Synopsis
        Convert IP address string to 64 bit integer
    .EXAMPLE
        $x = IP-toINT64 -ip "10.10.10.10"
    #>
  param ($ip) 
 
  $octets = $ip.split(".") 
  return [int64]([int64]$octets[0]*16777216 +[int64]$octets[1]*65536 +[int64]$octets[2]*256 +[int64]$octets[3]) 
} # end IP-toINT64

function INT64-toIP() {
    <#
    .Synopsis
        Convert 64 bit integer to IP address string
    .EXAMPLE
        $ip_addr = INT64-toIP -int 168430090
    #>
  param ([int64]$int) 

  return (([math]::truncate($int/16777216)).tostring()+"."+([math]::truncate(($int%16777216)/65536)).tostring()+"."+([math]::truncate(($int%65536)/256)).tostring()+"."+([math]::truncate($int%256)).tostring() )
} # end INT64-toIP

function Get-IPrange {
    <#
    .SYNOPSIS
        Get the IP addresses in a range
    .EXAMPLE 
        Get-IPrange -start 192.168.8.2 -end 192.168.8.20
    .EXAMPLE
        Get-IPrange -ip 192.168.8.2 -mask 255.255.255.0
    .EXAMPLE 
        Get-IPrange -ip 192.168.8.3 -cidr 24 
    #> 
 
    param (
        [string]$start,
        [string]$end,
        [string]$ip,
        [string]$mask,
        [int]$cidr
    ) 

    if ($ip) {$ipaddr = [Net.IPAddress]::Parse($ip)} 
    if ($cidr) {$maskaddr = [Net.IPAddress]::Parse((INT64-toIP -int ([convert]::ToInt64(("1"*$cidr+"0"*(32-$cidr)),2)))) } 
    if ($mask) {$maskaddr = [Net.IPAddress]::Parse($mask)} 
    if ($ip) {$networkaddr = new-object net.ipaddress ($maskaddr.address -band $ipaddr.address)} 
    if ($ip) {$broadcastaddr = new-object net.ipaddress (([system.net.ipaddress]::parse("255.255.255.255").address -bxor $maskaddr.address -bor $networkaddr.address))} 
 
    if ($ip) {
        $startaddr = IP-toINT64 -ip $networkaddr.ipaddresstostring
        $endaddr = IP-toINT64 -ip $broadcastaddr.ipaddresstostring 
    } else {
        $startaddr = IP-toINT64 -ip $start
        $endaddr = IP-toINT64 -ip $end 
    } 

    for ($i = $startaddr; $i -le $endaddr; $i++) 
    {
        INT64-toIP -int $i
    }
} # end Get-IPrange

function Scan-Network {
    <#
    .SYNOPSIS
        Scan network to find alive hosts and open ports of interest
    .EXAMPLE 
        Scan-Network -targets $array_of_addresses -ports $array_of_ports
    .EXAMPLE
        Scan-Network -targets @(10.10.10.1, 10.10.10.2)
    #> 

    param(
        [array]$targets,
        [array]$ports = (21,22,23,80,139,443,445,5985,5986,8000,8080)
    )

    if(!$targets) {
        Write-Host "Please provide an array of targets to scan!"
        Write-Host "Example usage: Scan-Network -targets $array_of_addresses -ports $array_of_ports"
        Write-Host "Example usage: Scan-Network -targets @(10.10.10.1, .., 10.10.10.123)"
        break
    }


    for ($i = 0; $i -lt $targets.Count; $i++) {
        $target = $targets[$i]
        Write-Progress -Activity "Scanning IP range" -Status $("Scanning " + $target) -PercentComplete $(($i/$targets.Count)*100)
        # if IP responds to ping
        if ($(Test-Connection -ComputerName $target -Count 1 -Quiet)) {
            Write-Host "$target is pingable."
            # test if WS-MAN is enabled
            if ($(Test-WSMan -ComputerName $target 2>$null)) {
                Write-Host "`t WS-MAn is enabled"
            } else {
                Write-Host "`t WS-MAn is disabled"
            }
            # port scan
            foreach ($port in $ports) {
                Write-Progress -Activity "Scanning IP range" -Status $("Scanning " + $target + ":" + $port) -PercentComplete $(($i/$targets.Count)*100)
                $socket = New-Object Net.Sockets.TcpClient # create new socket to connect
                $ErrorActionPreference = 'SilentlyContinue'
                $socket.Connect($target,$port) 2>$null
                $ErrorActionPreference = 'Continue'
                if ($socket.Connected) {
                    "`t Port $port is open."
                    $socket.Close() # close socket
                }
                $socket.Dispose() # dispose of socket
                $socket=$null
            }
        }
    }
} # end Scan-Network

# prompt user for IP address range info
$IP_start = Read-Host "Enter the starting IP address"
$IP_end = Read-Host "Enter the last IP address or CIDR #"

# determine IP range
if($IP_end -In 1..32){
    $targets = Get-IPrange -ip $IP_start -cidr $IP_end
    }
else{
    $targets = Get-IPrange -start $IP_start -end $IP_end
    }

Scan-Network -targets $targets
