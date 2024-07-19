#ClickShare Toolbox - Gabriel Whatley
#Makes test API calls to various ClickShare base units, also checks required XMS server connections.
#Seems to work on PowerShell 5.1, works only with default integrator level API accounts and passwords.
$ver="1.8"
<#
--- Version History ---
v1.0 - Dec 2020 - Initial concepting. Merry Christmas!
v1.1 - Jan 2021 - Pause to prevent window from closing on exit.
v1.2 - Jan 2021 - Looping and product selection validation, XMS TCP connection test option.
v1.3 - Jan 2021 - Built-in instructions.
v1.4 - Jan 2021 - API Query error handling.
v1.5 - Feb 2021 - CX series setup external servers check.
v1.6 - March 2021 - WePresent base unit API call tests added (Shoutout to Steve :D).
v1.7 - March 2021 - Added PowerShell version check to ensure v5.1.
v1.8 - September 2021 - Added mass API update option to change base unit API keys en-masse from text file.
#>

#Instructions
function instructions {
write-host "`nThe purpose of this script is to verify the that the requirements for the XMS server to
communicate successfully have been met by the end user's network. Test options 1, 2,
3, 4 and 5 make API calls to the different models of base unit and return the serial number of
the base unit or other information if the call is successful. Option 6 tests the ability to connect to XMS
Cloud as well as the update servers for both the base unit firmware and XMS Edge OS.`n"
write-host -ForegroundColor White -BackgroundColor Red "In order for the tests in this script to provide any useful information
it must be run from a computer connected to the same subnet as the XMS Edge.`n"
write-host "Option 7 - check the ability of the computer to connect to the ports needed for CX series base 
units to register, check for firmware updates so they can complete the setup process.`n
For more information on the XMS Edge server, its networking and installation requirements:`n
User Guide for eXperience Management Suite - https://www.barco.com/en/support/docs/R5900020
XMS Edge knowledgebase - https://www.barco.com/en/clickshare/support/xms-virtual-edge/knowledge-base
XMS Virtual Edge Installation Requirements - https://www.barco.com/en/support/knowledge-base/KB9776`n"
write-host "Option 8 & 9 - These tools update base unit configuration as specified in a text file named 
'cxtarget.txt' or 'csetarget.txt' which is to be placed in the same folder as this script file.
The format of the file needs to be comma separated with the following format:

[Baseunit IP Address], [API Key to be changed], [New Value of API key]
ex: 10.1.34.167,v1.0/OnScreenText/MeetingRoomName,CSE-200Plus

A new line is to be used for each API key to be changed, API documentation is available
For CX: Inside the baseunit at https://[BaseUnit IP]:4003/api-docs
For the CS/CSE: https://www.barco.com/en/support/docs/R5900056`n"
pause
}

#Array of hostnames and ports used in XMS connectivity check.
$XMSServers = @{
	"xms.cloud.barco.com" = "443"
	"barcoprdwebsitefs.azureedge.net" = "443"
	"update-xms.cloud.barco.com" = "443"
	"sil-xms-prd01-iothub.azure-devices.net" = "443"
	"update.barco.com" = "80"
	"www.barco.com" = "80"
}

#Array of hostnames and ports used in CX connectivity check.
$CXServers = @{
	"update.cmp.barco.com" = "443"
	"assets.cloud.barco.com" = "443"
	"global.azure-devices-provisioning.net" = "443"
}

#Creates encoded auth header for HTTPS API connection. Adds type to ignore PowerShell certificate errors due to self-signed certificate on base unit.
function https-setup {
$userpass = "$username`:$password"
$bytes = [System.Text.Encoding]::UTF8.GetBytes($userpass)
$encodedlogin =[Convert]::ToBase64String($bytes)
$authheader = "basic " + $encodedlogin
$global:headers = New-Object "System.Collections.Generic.Dictionary[[String],[String]]"
$global:headers.Add("Authorization",$authheader)
}

#Ignores self-signed SSL certificates to prevrent warnings, errors, and invove-webrequest from doing its job.
function ignore-certs{
if ("TrustAllCertsPolicy" -as [type]) {return}
add-type @"
    using System.Net;
    using System.Security.Cryptography.X509Certificates;
    public class TrustAllCertsPolicy : ICertificatePolicy {
        public bool CheckValidationResult(
            ServicePoint srvPoint, X509Certificate certificate,
            WebRequest request, int certificateProblem) {
            return true;
        }
    }
"@
[System.Net.ServicePointManager]::CertificatePolicy = New-Object TrustAllCertsPolicy
[Net.ServicePointManager]::SecurityProtocol = "Tls, Tls11, Tls12"
}

#Creates digest auth headers for CSM/CSC/WePresent API connection.
function digest-setup {
	$secureString = ConvertTo-SecureString -String $password -AsPlainText -Force
	$global:digestCreds = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList $username, $secureString
}

#Builds API call URL based on selected product.
function api-call {
	$address = read-host -prompt "Enter Base Unit IP Address"
	$response = try {
		Invoke-WebRequest -Uri "$protocol`://$address`:$port/$apivers/$apikey" -Credential $digestCreds -Header $headers
	}
	catch [System.Net.WebException] {
		write-host -ForegroundColor White -BackgroundColor Red "An error was encountered:" $_.Exception.Message;
        break
	}
	write-host `n"$response"`n
	$response = $null
}

#Checks TCP connections for XMS using data in hashtable $XMSServers.
function xms-check {
	foreach ($h in $XMSServers.GetEnumerator()) {
		tnc $($h.Name) -p $($h.Value)
	}
}

#Checks TCP connections for CX series firmware update and setup using data in hashtable $CXServers.
function cx-check {
	foreach ($h in $CXServers.GetEnumerator()) {
		tnc $($h.Name) -p $($h.Value)
	}
}

function cx-mass-update {
        foreach($line in gc "cxtarget.txt") {
    $array = $line.Split(",")
    $response = try {
		Invoke-RestMethod "https://$($array[0])`:4003/$($array[1])" -Method Put -Body (@{value=$array[1]}|ConvertTo-Json) -ContentType 'application/json' -Header $headers
	}
	catch [System.Net.WebException] {
		write-host -ForegroundColor White -BackgroundColor Red "An error was encountered:" $_.Exception.Message;
        break
	}
    write-host "$($array[0]) - $($array[1]) - Value: $($array[2]) - $response"`n
	$response = $null
	$line = $null
    }
}

function cse-mass-update {
	foreach($line in gc "csetarget.txt") {
        $array = $line.Split(",")
        $response = try {
		    Invoke-RestMethod "https://$($array[0])`:4001/$($array[1])" -Method Put -Body (@{value=$array[1]}|ConvertTo-Json) -ContentType 'application/json' -Header $headers
	    }
	    catch [System.Net.WebException] {
		    write-host -ForegroundColor White -BackgroundColor Red "An error was encountered:" $_.Exception.Message;
            break
	    }
    write-host "$($array[0]) - $($array[1]) - Value: $($array[2]) - $response"`n
	$response = $null
	$line = $null
    }
}
#One time run
$Global:ProgressPreference = 'SilentlyContinue'
$PsVerMajor = $PSVersionTable.PSVersion.Major.ToString()
$PsVerMinor = $PSVersionTable.PSVersion.Minor.ToString()
$PsVer = "$PsVerMajor.$PsVerMinor"

#Main program loop
do {
	clear-host
	if ($PSVer -ne "5.1") {
		Write-Host -ForegroundColor White -BackgroundColor Red "Running on version of PowerShell other than v5.1 may cause unexpected or undesired operation."
		Write-Host -ForegroundColor White -BackgroundColor Red "Current PS version v$PsVer"
	}
	write-host "==========================="
	write-host "ClickShare/XMS Toolbox v$ver"
	write-host "==========================="
	write-host "Which product line are you working with?"`n

	write-host "--ClickShare API Test--"
	write-host "[1] CX series (CX-20, CX-30. CX-50)"
	write-host "[2] CS/CSE series (CS-100, CSE-200, CSE-200+, CSE-800)"
	write-host "[3] CSM/CSC series (CSM-1, CSC-1)"`n

	write-host "--WePresent API Test--"
	write-host "[4] WePresent 2100"
	write-host "[5] WePresent 1600W"`n

	write-host "--ClickShare External Servers Test--"
	write-host "[6] Check XMS Required Connections"
	write-host "[7] Check CX Setup Required Connections"`n

    write-host "-BaseUnit Mass Update Mode--"
	write-host "[8] CX series (CX-20, CX-30. CX-50)"
	write-host "[9] CS/CSE series (CS-100, CSE-200, CSE-200+, CSE-800)"`n


    write-host "[i] Instructions"
	$model = read-host -prompt "Enter Option"
	switch ($model) {
		1 {
			write-host -ForegroundColor Black -BackgroundColor Green `n" - CX Selected - "`n;
			$protocol ="https";
			$port ="4003";
			$apivers = "v2";
			$apikey = "configuration/system/device-identity";
			$username = 'admin';
			$password = 'admin';
			https-setup;
			ignore-certs;
			api-call;
			break
		}
		2 {
			write-host -ForegroundColor Black -BackgroundColor Green `n" - CS/CSE Selected - "`n;
			$protocol ="https";
			$port ="4001";
			$apivers = "v1.0";
			$apikey = "DeviceInfo/SerialNumber";
			$username = 'integrator';
			$password = 'integrator';
			https-setup;
			ignore-certs;
			api-call;
			break
		}
		3 {
			write-host -ForegroundColor Black -BackgroundColor Green `n" - CSM/CSC Selected - "`n;
			$protocol ="http";
			$port ="4000";
			$apivers = "v1.0";
			$apikey = "DeviceInfo/SerialNumber";
			$username = 'integrator';
			$password = 'integrator';
			digest-setup;
			api-call;
			break
		}
		4 {
			write-host -ForegroundColor Black -BackgroundColor Green `n" - WePresent 2100 Selected - "`n;
			$protocol ="https";
			$port ="4001";
			$apivers = "w1.0";
			$apikey = "DeviceInfo";
			$username = 'admin';
			$password = 'epevsc$9{xiq6/4>:zmIQ2t9[X74IRadmin';
			digest-setup;
			ignore-certs;
			api-call;
			break
		}
		5 {
			write-host -ForegroundColor Black -BackgroundColor Green `n" - WePresent 1600W Selected - "`n;
			write-host -ForegroundColor White -BackgroundColor Red "Firmware v2.5.3.11 or above required for this to work"`n;
			$protocol ="https";
			$port ="4001";
			$apivers = "w1.0";
			$apikey = "DeviceInfo";
			$username = 'admin';
			$password = '1?xz*c@tk^Bw7fA2s#=4zU~YH#wU*t';
			digest-setup;
			ignore-certs;
			api-call;
			break
		}
		6 {
			clear-host;
			write-host -ForegroundColor Black -BackgroundColor Green `n" - XMS Connection Test Selected - "`n;
			xms-check;
			break
		}
		7 {
			clear-host;
			write-host -ForegroundColor Black -BackgroundColor Green `n" - CX Connection Test Selected - "`n;
			cx-check;
			break
		}
        8 {
			clear-host;
			https-setup;
			ignore-certs;
			write-host -ForegroundColor Black -BackgroundColor Green `n" - CX Mass Update Mode - "`n;
			cx-mass-update;
			break
		}
        9 {
			clear-host;
			https-setup;
			ignore-certs;
			write-host -ForegroundColor Black -BackgroundColor Green `n" - CS/CSE Mass Update Mode - "`n;
			cse-mass-update;
			break
		}
        "i" {
			clear-host;
            instructions;
            $skip = 1;
            break
        }
		default {
			write-host -ForegroundColor black -BackgroundColor yellow `n"Input Incorrect";
			sleep 3;
            $skip = 1;
            break
        }
	}
	if ($skip -ne 1) {
		$loop = read-host -prompt "[Enter] to run again [q] to exit"
	}
	$skip = 0
} while($loop -ne "q")
exit