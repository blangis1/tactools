<#Get script paths and load mysql commands#>
$scriptpath = $MyInvocation.MyCommand.Path
$dir = split-path $scriptpath
[void][system.reflection.Assembly]::LoadFrom("$dir" + "\MySql.Data.dll")


<#Defining all functions#>

<# CHECKING ENABLED SSL PROTOCOLS---------------------------------------------------------------------------------------------------------------------------------------------------------------------
    .DESCRIPTION
    Outputs the SSL protocols that the client is able to successfully use to connect to a server.
 
    .NOTES
 
    Copyright 2014 Chris Duck
    http://blog.whatsupduck.net
 
    Licensed under the Apache License, Version 2.0 (the "License");
    you may not use this file except in compliance with the License.
    You may obtain a copy of the License at
 
     http://www.apache.org/licenses/LICENSE-2.0
 
    Unless required by applicable law or agreed to in writing, software
    distributed under the License is distributed on an "AS IS" BASIS,
    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
    See the License for the specific language governing permissions and
    limitations under the License.
 
    .PARAMETER ComputerName
    The name of the remote computer to connect to.
 
    .PARAMETER Port
    The remote port to connect to. The default is 443.
 
    .EXAMPLE
    Test-SslProtocols -ComputerName "www.google.com"
   
    ComputerName       : www.google.com
    Port               : 443
    KeyLength          : 2048
    SignatureAlgorithm : rsa-sha1
    Ssl2               : False
    Ssl3               : True
    Tls                : True
    Tls11              : True
    Tls12              : True
 #>
 function Test-SslProtocols {
   param(
     [Parameter(Mandatory=$true,ValueFromPipelineByPropertyName=$true,ValueFromPipeline=$true)]
     $ComputerName,
     
     [Parameter(ValueFromPipelineByPropertyName=$true)]
     [int]$Port = 443
   )
   begin {
     $ProtocolNames = [System.Security.Authentication.SslProtocols] | gm -static -MemberType Property | ?{$_.Name -notin @("Default","None")} | %{$_.Name}
   }
   process {
     $ProtocolStatus = [Ordered]@{}
     $ProtocolStatus.Add("ComputerName", $ComputerName)
     $ProtocolStatus.Add("Port", $Port)
     $ProtocolStatus.Add("KeyLength", $null)
     $ProtocolStatus.Add("SignatureAlgorithm", $null)
     
     $ProtocolNames | %{
       $ProtocolName = $_
       $Socket = New-Object System.Net.Sockets.Socket([System.Net.Sockets.SocketType]::Stream, [System.Net.Sockets.ProtocolType]::Tcp)
       $Socket.Connect($ComputerName, $Port)
       try {
         $NetStream = New-Object System.Net.Sockets.NetworkStream($Socket, $true)
         $SslStream = New-Object System.Net.Security.SslStream($NetStream, $true)
         $SslStream.AuthenticateAsClient($ComputerName,  $null, $ProtocolName, $false )
         $RemoteCertificate = [System.Security.Cryptography.X509Certificates.X509Certificate2]$SslStream.RemoteCertificate
         $ProtocolStatus["KeyLength"] = $RemoteCertificate.PublicKey.Key.KeySize
         $ProtocolStatus["SignatureAlgorithm"] = $RemoteCertificate.SignatureAlgorithm.FriendlyName
         $ProtocolStatus["Certificate"] = $RemoteCertificate
         $ProtocolStatus.Add($ProtocolName, $true)
       } catch  {
         $ProtocolStatus.Add($ProtocolName, $false)
       } finally {
         $SslStream.Close()
       }
     }
     [PSCustomObject]$ProtocolStatus
   }
 }

 <# END OF SSL CHECK MODULES #>

function get-rtcscore {

  function rtcscore {

    $query = 'SELECT t3.hostname, t1.Switchid, T1.hgscore, t2.bcascore, COALESCE(t1.hgscore,0) + COALESCE(t2.bcascore,0) AS Total
      FROM
      (SELECT SwitchID, CallStackDepth * COUNT(*) AS hgscore FROM 
      huntandpagingfeatures JOIN huntgroupmembers ON huntgroupmembers.HuntGroupDN = huntandpagingfeatures.ListDN 
      WHERE IsHuntGroup = 1 GROUP BY SwitchID, ListDN ) AS t1

      LEFT JOIN

      (SELECT 
      SwitchID, COUNT(*) / 2 AS bcascore 
      FROM userprogbuttons 
      JOIN maes ON maes.MAE_DN=userprogbuttons.DialNumberDN 
      WHERE userprogbuttons.FunctionID = 30 GROUP BY SwitchID ) AS t2
      ON (t1.switchid = t2.switchid)


      LEFT JOIN
      (SELECT hostname,switchid FROM switches) AS t3
      ON (t1.switchid = t3.switchid)
    ;'
                              
    write-output "Here is your RTC Score"
    $Command = New-Object MySql.Data.MySqlClient.MySqlCommand($Query, $Connection)
    $DataAdapter = New-Object MySql.Data.MySqlClient.MySqlDataAdapter($Command)
    $DataSet = New-Object System.Data.DataSet
    $RecordCount = $dataAdapter.Fill($dataSet, "data")
    $DataSet.Tables[0]
    
  }



  $MySQLAdminUserName = 'root'
  $MySQLAdminPassword = 'shorewaredba'
  $MySQLDatabase = 'shoreware'
  $MySQLHost = 'localhost'
  $ConnectionString = "server=" + $MySQLHost + ";port=4308;uid=" + $MySQLAdminUserName + ";pwd=" + $MySQLAdminPassword + ";database="+$MySQLDatabase

  [void][System.Reflection.Assembly]::LoadWithPartialName("MySql.Data")
  $Connection = New-Object MySql.Data.MySqlClient.MySqlConnection
  $Connection.ConnectionString = $ConnectionString
  $Connection.Open()
  
  
  RTCscore | ft
  


  $Connection.Close()
  
  
  write-output ''
  write-output ''
  
 
 }

function Install-Prereqs {
  <# This function checks the windows version of the machine and then will install prerequisite Roles/features #>
  $choice = ""


  while ($choice -notmatch "[y|n]"){
    $choice = read-host "This script will install roles and features on your server. Do you want to continue? (Y/N)"
  }

  if ($choice -eq "y"){
    
    import-module servermanager

    $Version = [Environment]::OSVersion.Version.ToString(3)

    If ($version -like "*6.0.*" -Or $version -like "*6.1.*") {add-windowsfeature -includeallsubfeature "Application-Server", "Web-Server", "qWave", "SMTP-Server"}
    elseif ($version -like "*6.2.*" -Or $version -like "*6.3.*") {install-windowsfeature -includeallsubfeature "Application-Server", "Web-Server", "qWave", "SMTP-Server"}
    elseif ($version -like "*10*" ) {install-windowsfeature -includeallsubfeature "Web-Server","web-whc", "qWave", "SMTP-Server", "MSMQ", "net-framework-45-features", "fs-fileserver", "fs-resource-manager", "net-framework-45-aspnet", "net-wcf-services45", "internet-print-client", "powershell-v2", "net-framework-features", "lpr-port-monitor", "server-media-foundation", "rsat-smtp", "rsat-fsrm-mgmt", "was", "remote-assistance", "fs-smb1"}

    set-service "SMTPSVC" -startuptype Automatic
    set-service "ftpsvc" -startuptype Automatic
    set-service "qwave" -StartupType Automatic
  }
    
  else {write-output  "Done!"}
}

function get-prereqs {
  <# This function checks windows version and then will run a report on installed roles and features #>
  $Version = [Environment]::OSVersion.Version.ToString(3)
  import-module servermanager
  $Features = "qWave", "Application-server", "AS-NET-Framework", "AS-Web-Framework", "AS-ENT-Services", "AS-TCP-Port-Sharing", "AS-WAS-Support", "AS-Ent-Services", "AS-HTTP-Activation", "AS-MSMQ-Activation", "AS-TCP-Activation", "AS-Named-Pipes", "AS-Dist-Trasaction", "AS-Incoming-Trans", "AS-Outgoing-Trans", "AS-WS-Atomic", "Web-Server", "Web-Server", "Web-WebServer", "Web-Common-Http", "Web-Static-Content", "Web-Default-Doc", "Web-Dir-Browsing", "Web-Http-Errors", "Web-Http-Redirect", "Web-DAV-Publishing", "Web-App-Dev", "Web-Asp-Net", "Web-Net-Ext", "Web-ASP", "Web-CGI", "Web-ISAPI-Ext", "Web-ISAPI-Filter", "Web-Includes",  "Web-Health", "Web-Http-Logging", "Web-Log-Libraries", "Web-Request-Monitor", "Web-Http-Tracing", "Web-Custom-Logging", "Web-ODBC-Logging", "Web-Security", "Web-Basic-Auth", "Web-Windows-Auth", "Web-Digest-Auth", "Web-Client-Auth", "Web-Cert-Auth", "Web-Url-Auth", "Web-Filtering",  "Web-IP-Security", "Web-Performance", "Web-Stat-Compression", "Web-Dyn-Compression", "Web-Mgmt-Tools", "Web-Mgmt-Console", "Web-Scripting-Tools", "Web-Mgmt-Service", "Web-Mgmt-Compat", "Web-Metabase", "Web-WMI", "Web-Lgcy-Scripting", "Web-Lgcy-Mgmt-Console", "Web-Ftp-Server", "Web-Ftp-Service", "Web-Ftp-Ext", "Web-WHC", "SMTP-Server"
  $Features2016 ="Web-*","web-whc", "qWave", "SMTP-Server", "MSMQ*", "net-*", "fs-fileserver", "fs-resource-manager", "net-framework-45-aspnet", "net-wcf-services45", "internet-print-client", "powershell*", "net-framework-features", "lpr-port-monitor", "server-media-foundation", "rsat-smtp", "rsat-fsrm-mgmt", "was*", "remote-assistance", "fs-smb1", "wow64*"
  If ($version -like "*6.*") {get-windowsfeature -name $features}
  elseif ($version -like "*10*") {get-windowsfeature -name $Features2016 | where {$_.name -ne "Web-application-proxy"}}
}

function get-escalationpackage {
  <# This function will create an escalation package to escalate to a case to TAC or a case from Tier 2 to Tier 3 #>
  $profile = $env:userprofile
  $dirpath = $profile + '\documents'
  $path = $profile + '\documents\esctemplate'
  $msinfopath = $path + '\msinfo.nfo'
  $gppath = $path + '\gpresult.html'
  $esctemplate = $profile + '\documents\esctemplate\Esctemplate.txt'
  $uaccheck = (Get-ItemProperty HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System).EnableLUA
  $depcheck = Get-WmiObject -Class Win32_OperatingSystem -Property DataExecutionPrevention_SupportPolicy | fl dataexecutionprevention_supportpolicy
  $teleregpath = $path + '/shorelineteleworks.reg'
  $shorelinereg = $path + '/shorelinecommunications.reg'
  $shorelinephonereg = $path + '/shorelinePhones.reg'
  $wintelephony = $path + '/windows_telephony.reg'

  remove-item -path $path -recurse -force 
  start-sleep -s 3

  new-item -path $dirpath -name esctemplate -itemtype directory
  start-sleep -s 3
  Get-Date >> $esctemplate
  echo $env:COMPUTERNAME >> $esctemplate

  ipconfig | findstr [0-9].\. >> $esctemplate

  echo "Server configuration:" >> $esctemplate

  #Check if UAC is enabled
  If ($uaccheck -eq "1") {"UAC is enabled" >> $esctemplate}
  Else {"UAC is disabled" >> $esctemplate}

  #Check status of DEP
  If ($depcheck -eq "dataexecutionprevention_supportpolicy : 2") {"DEP is set to: Turn on DEP for Windows Programs and services only" >>$esctemplate}
  ELSE {"DEP is set to: Tun on DEP for all programs and services except those I select" >> $esctemplate}

  #Get OS version
  echo "Windows Version:" >>$esctemplate
  (Get-WmiObject Win32_OperatingSystem).Name >> $esctemplate
  (Get-WmiObject Win32_OperatingSystem).OSArchitecture >>$esctemplate

  #Show Firewall Status
  echo "Windows firewall status:" >> $esctemplate
  netsh advfirewall show currentprofile state >> $esctemplate

  #Show Shoretel service Status
  get-service -name Shore* | ft -autosize status,Displayname >> $esctemplate


  #Show Roles and Features 
  import-module servermanager
  $Features = "qWave", "Application-server", "AS-NET-Framework", "AS-Web-Framework", "AS-ENT-Services", "AS-TCP-Port-Sharing", "AS-WAS-Support", "AS-Ent-Services", "AS-HTTP-Activation", "AS-MSMQ-Activation", "AS-TCP-Activation", "AS-Named-Pipes", "AS-Dist-Trasaction", "AS-Incoming-Trans", "AS-Outgoing-Trans", "AS-WS-Atomic", "Web-Server", "Web-Server", "Web-WebServer", "Web-Common-Http", "Web-Static-Content", "Web-Default-Doc", "Web-Dir-Browsing", "Web-Http-Errors", "Web-Http-Redirect", "Web-DAV-Publishing", "Web-App-Dev", "Web-Asp-Net", "Web-Net-Ext", "Web-ASP", "Web-CGI", "Web-ISAPI-Ext", "Web-ISAPI-Filter", "Web-Includes",  "Web-Health", "Web-Http-Logging", "Web-Log-Libraries", "Web-Request-Monitor", "Web-Http-Tracing", "Web-Custom-Logging", "Web-ODBC-Logging", "Web-Security", "Web-Basic-Auth", "Web-Windows-Auth", "Web-Digest-Auth", "Web-Client-Auth", "Web-Cert-Auth", "Web-Url-Auth", "Web-Filtering",  "Web-IP-Security", "Web-Performance", "Web-Stat-Compression", "Web-Dyn-Compression", "Web-Mgmt-Tools", "Web-Mgmt-Console", "Web-Scripting-Tools", "Web-Mgmt-Service", "Web-Mgmt-Compat", "Web-Metabase", "Web-WMI", "Web-Lgcy-Scripting", "Web-Lgcy-Mgmt-Console", "Web-Ftp-Server", "Web-Ftp-Service", "Web-Ftp-Ext", "Web-WHC", "SMTP-Server"
  get-windowsfeature -name $features >> $esctemplate

  #Export Shoretel Registry keys.'=
  reg export "HKEY_LOCAL_MACHINE\SOFTWARE\Wow6432Node\Shoreline Teleworks" $teleregpath
  reg export "HKEY_LOCAL_MACHINE\SOFTWARE\Wow6432Node\Shoreline Communications" $shorelinereg
  reg export "HKEY_LOCAL_MACHINE\SOFTWARE\Wow6432Node\Shoretel Phones" $shorelinephonereg
  reg export "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Telephony" $wintelephony

  #Get last 10 windows updates installed
  echo "Last 10 Windows updates installed" >> $esctemplate
  (get-hotfix | sort installedon) | select -last 10 | sort installedon -Descending >> $esctemplate

  #RTC.BAT
  echo " " >> $esctemplate
  echo " " >> $esctemplate
  
  get-rtcscore >> $esctemplate


  #-----------------RTC.BAT-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------

  gpresult /h $gppath
  msinfo32 /nfo $msinfopath 
  slogwin

  echo " " >> $esctemplate
  echo " " >> $esctemplate
  echo "All logs are saved in" $path 
  echo "PLEASE GIVE SUFFICIENT TIME FOR MSINFO TO COMPLETE"
  start-sleep 10
  invoke-item $path
}


  

import-module WebAdministration

do {   
    
    Write-output  '===================Mitel TAC Powershell Toolkit 1.0 ==================='

  Write-output  "1: Provide certificate and private key to check - READ ONLY"
  Write-output  "2: Check server.crt and server.key from keystore - READ ONLY"
  Write-output  "3: Decrypt private key -"
  Write-output  "4: Check for 403 forbidden / Missing HW Root Certificate - WRITE"
  Write-output  "5: Compare Server.crt to Nginx.crt - READ ONLY"
  Write-output  "6: Check IIS bindings vs Keystore - READ ONLY"
  write-output  "7: Check server prerequisites - READ ONLY"
  write-output  "8: Install server prerequisites - WRITE"
  write-output  "9: Collect escalation package"
  write-output  "10: Report enabled SSL/TLS versions"
  write-output  "11: Get RTC Score"
  write-output  "12: Quit"


  $Choice = read-host -prompt "Please make a selection"


  switch ($choice)
  {
 

    "1"{
        $owncertpath = read-host -prompt 'Please enter the full path to your certificate public key (Example c:\certs\wildcard.crt)'
        $ownkeypath =  read-host -prompt 'Please enter the full path to your private key (Example c:\certs\key.key)'
        $owncertmod = openssl x509 -noout -modulus -in $owncertpath 
        $ownkeymod = openssl rsa -noout -modulus -in $ownkeypath
        $matchcheck = $owncertmod -eq $ownkeymod
      IF ($matchcheck -eq $True)
      {
        Write-host "Your certificate and private key match" -foregroundcolor Green
      }
      else
      {   
        Write-host "Your certificate and private key do not match" -foregroundcolor Red
      }
      Sleep 5
    }


    "2"
    {
      Echo "This script will compare the server.crt and server.key file from your keystore to ensure they match."
      Echo " "
      Echo " "
      $volume = Read-host -prompt "What volume is your Shoreline Data folder on, please include the :\ (ie C:\ or E:\)"
      $certpath = $volume + 'shoreline data\keystore\certs\server.crt'
      $privkeypath = $volume + 'shoreline data\keystore\private\server.key'
      $cert = openssl x509 -noout -modulus -in $certpath 
      $privkey = openssl rsa -noout -modulus -in $privkeypath 
      $matchcheck = $cert -eq $privkey
      IF ($matchcheck -eq $True)
      {
        Write-host "Your certificate and private key match" -foregroundcolor Green
      }
      else
      {   
        Write-host "Your certificate and private key do not match" -foregroundcolor Red
      }
  
      Sleep 5

    }

    "3"
    {
      Echo "This will output a decrypted copy of your private key"
      Echo " "
      $enckeypath = Read-host -prompt "Please enter the path to your encrypted private key"
      $deckeypath = Read-host -Prompt "Please enter the path to write your decrypted key, including the file name (example: c:\certs\key.key"
      openssl rsa -in $enckeypath -out $deckeypath

      Echo "Your private key should have been written to the path supplied"
      Sleep 5
    }

    "4"
    {
      Echo "Checking if Shoretel HW Root is Present"
      $HWroot = Get-ChildItem Cert:\LocalMachine\Root | Where-object{$_.Thumbprint -eq "‎191a1c5696f2bff780d0187f5735040e5caf2b0d"}
      If (!$hwroot) 
      {
       
        write-host "HW Root is not installed, CAS authentication will fail" -ForegroundColor Red
        $importroot = read-host -prompt "Would you like to reimport the HW root certificate to the trusted root store? Y/N"
        
        Switch ($importroot) 
        { 
          Y 
          {
            $volume = Read-host -prompt "What volume is your Shoreline Data folder on, please include the :\ (ie C:\ or E:\)"
            $hwrootpath = $volume + 'shoreline data\keystore\certs\shoretel_mfg_ca.crt'
            Set-Location -path Cert:\LocalMachine\Root
            Import-Certificate -filepath $HWrootpath
            ECHO ""
            Write-host "Shoretel HW Root has been imported."
            Sleep 5
         
          }
        
          N 
          {
            sleep 1
          }
        }
      }


      else
        {
        write-host "HW root is installed" -foregroundcolor Green
        Sleep 2
        $hwrootinstalled = "1"
        }

        echo ""
        echo ""
    
    
      Write-host "Checking IIS log file for 403 Forbidden"
      Sleep 2
      $inetpub = 'C:\inetpub\logs\LogFiles\W3SVC1'
      $IISlog = gci $inetpub | sort lastwritetime | select -last 1
      $IIS403 = select-string -path $IISlog -pattern \bcertauth.*2148204809
      IF (($IIS403 -ne $null) -and ($HWrootinstalled = "1"))
      {
        ""
        ""
        write-host "IIS log contains 403 errors on certauth subdirectory and HW root is installed. IF you did not just install the HW root certificate this is normally caused by improper intermediate certificates installed in the trusted root store. The script will now check for improperly installed intermediate certificates." -foregroundcolor red
        echo ""
        echo ""
        Sleep 8

        $intcertinroot = Get-Childitem cert:\LocalMachine\root -Recurse | Where-Object {$_.Issuer -ne $_.Subject}

        IF ($intcertinroot -ne $null)
        {
            write-host "Intermediate certificates have been detected in the Windows Trusted Root Store, this may cause CAS functionality to fail"
            $getcertlist = Read-Host -prompt "Would you like to export a list of certificates that are installed in the wrong store? Y/N"
            

      
          Switch ($getcertlist)
          {
         
            Y  {
              Get-Childitem cert:\LocalMachine\root -Recurse | Where-Object {$_.Issuer -ne $_.Subject} | Format-List * | Out-File "c:\certlist.txt"
              write-host "List of certificates has been exported to c:\certlist"
            }
            N
            {
              ""
              write-host "You have chosen not to export the list of certificates"
              ""
            }

          }
            
     
          $clientauth = Read-Host -prompt "Would you like to put in a registry key to work around this problem? The registry alters the way certificate chain validation is carried out. More information can be found here https://oneview.mitel.com/s/article/IP400-Series-Phones-Fail-to-Connect-to-CAS     Y/N"

          Switch ($clientauth)
          {
          
            Y {
              ""
              New-ItemProperty -Path HKLM:\System\CurrentControlSet\Control\SecurityProviders\SCHANNEL\ -Name ClientAuthTrustMode -Value 2 -propertytype "DWord"
              Write-host "Registry key has been imported, you should re-test CAS functionality"
            }
        
            N {
              ""
              Write-host "No action has been taken, if you continue to have CAS problems, please contact Mitel support, or run this script again and attempt the registry key workaround. Other common causes of CAS functionality failures are DNS related or the service IP address being incorrect in the registry."
              write-host "If opening a case with TAC, please reproduce the problem on a phone and upload phone logs to the case"
              ""
              sleep 8
            }
          }

        }

        else 
        {
          write-host "No improperly installed intermediate certificates were found"
        }

      }
        
      else
        {
        ""
        ""
        write-host "IIS logs do not contain 403 errors. CAS issues are not caused by missing HW root or certificate store issues." -foregroundcolor green
        write-host "Other common causes of CAS functionality failures are DNS related or the service IP address being incorrect in the registry."
        write-host "If opening a case with TAC, please reproduce the problem on a phone and upload phone logs to the case"
        echo ""
        
        Sleep 8
        }

      write-host "Checking Service IP address"
      Sleep 3
    
      $env:HostIP = ( `
        Get-NetIPConfiguration | `
        Where-Object { `
          $_.IPv4DefaultGateway -ne $null `
          -and `
          $_.NetAdapter.Status -ne "Disconnected" `
        } `
      ).IPv4Address.IPAddress

      $serviceip = (Get-ItemProperty -path 'HKLM:\software\wow6432node\Shoreline Teleworks'-name serviceipaddress).serviceipaddress


      If ($env:HostIP -eq $serviceip)
      {
        ""
        ""
        write-host "Service IP address is currently set to the IP address of the server. No action required." -foregroundcolor green
        sleep 4
      }

      else
      {
        write-host "Service IP address is set to" $serviceip "but we expected" $env:HostIP "These values should be the same. Please set the Service IP address to the IP address of the server and reboot."
        sleep 4    
      }


    }

    "5"
    {
      Echo " "
      Echo "This script will compare the server.crt and nginx.crt file from your keystore to ensure they match."
      Echo " "
      Echo " "
      $volume = Read-host -prompt "What volume is your Shoreline Data folder on, please include the :\ (ie C:\ or E:\)"
      $certpath1 = $volume + 'shoreline data\keystore\certs\server.crt'
      $servercert = openssl x509 -noout -fingerprint -in $certpath1 
      $volume2 = Read-host -prompt "What volume is your Shoreline Communications folder on, please include the :\ (ie C:\ or E:\)"
      $certpath2 = $volume2 + '\Program Files (x86)\Shoreline Communications\ShoreWare Director\nginx\conf\nginx.crt'
      $nginxcert = openssl x509 -noout -fingerprint -in $certpath2


      IF ($servercert -eq $nginxcert)
      {
        Write-host "Your certificates match" -foregroundcolor Green
      }
      else
      {   
        Write-host "Your certificates do not match" -foregroundcolor Red
      }
      Sleep 2
    }

    "6"
    {
      Echo ""
      Echo "Checking IIS binding vs Keystore"
      Echo ""
      Echo ""
    
      $iisbinding = Get-ChildItem -path IIS:\SslBindings | where-object {$_.port -eq 443}
      $iisthumbprint=$iisbinding.thumbprint
      $volume = Read-host -prompt "What volume is your Shoreline Data folder on, please include the :\ (ie C:\ or E:\)"
      $certpath1 = $volume + 'shoreline data\keystore\certs\server.crt'
      $servercert = openssl x509 -noout -fingerprint -in $certpath1 
    
        If ($iisthumbprint=$servercert)
      {
        write-host "IIS binding matches Keystore" -foregroundcolor Green
      }
        else
      {
        write-host "IIS binding does not match keystore" -ForegroundColor Red
      }       
      Sleep 2
    }

    "7"
     {
      get-prereqs
     }
      
    "8"
     {
      install-prereqs
     }
     
    "9"
    {
      get-escalationpackage
    } 
      
    "10"
    {
      $hostname = read-host -prompt "What is the FQDN of the server you would like to test. This FQDN should be what is set in director."
      Test-SslProtocols $hostname 

    }
    "11"
    {
      get-rtcscore
    }
  }
} While ($choice -ne 12)
