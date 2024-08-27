#requires -version 5

$ErrorActionPreference = "Stop"
Import-Module -Force -Scope Global IISAdministration

function Open-IISManager {
    Write-Debug "IIS Server Manager: reset and starting new scope"

    # Ensure we're starting with no pending writes for applicationHost.config,
    # which would interfere with our attempt to commit writes.
    Stop-IISCommitDelay -Commit $false -WarningAction SilentlyContinue

    Reset-IISServerManager -Confirm:$false
}

function Close-IISManager {
    Write-Debug "IIS Server Manager: committing changes"
    (Get-IISServerManager).CommitChanges()
}

function New-EdFiSelfSignedCertificate {
    $plainPassword = ( -join ((0x30..0x39) + ( 0x41..0x5A) + ( 0x61..0x7A) | Get-Random -Count 20 | ForEach-Object { 
        [char]$_ 
    }))

    $password = ConvertTo-SecureString $plainPassword -AsPlainText -Force

    $certFile = "$PSScriptRoot\Ed-Fi-ODS-SelfSignedCertificate.pfx"

    $certParams = @{
        CertStoreLocation = 'Cert:\LocalMachine\My'
        Subject           = $env:computername
        DnsName           = $env:computername
        KeyExportPolicy   = 'Exportable'
        KeyAlgorithm      = 'RSA'
        KeyLength         = 2048
        FriendlyName      = "Ed-Fi-ODS"
    }

    $cert = (Get-ChildItem $certParams.CertStoreLocation | Where-Object { 
        $_.subject -like "*$($certParams.Subject)*" -and $_.FriendlyName -like $($certParams.FriendlyName) 
    })

    if (!$cert) {
        Write-Host "Creating new self signed certificate: $($certParams.FriendlyName)"
        $rootcert = (Get-ChildItem cert:\LocalMachine\Root\ | Where-Object { 
            $_.subject -like "*$($certParams.Subject)*" -and $_.FriendlyName -like $($certParams.FriendlyName) 
        })

        if ($rootcert) {
            $rootcert | Remove-Item
        }
        try {
            # Some older version of windows and powershell, namely windows 8 and windows server 2012,
            # have a different definition of New-SelfSignedCertificate that doesn't include parameters
            # for Subject and FriendlyName. In this case, the installation should continue and the user
            # will setup the certificate manually.
            $cert = (New-SelfSignedCertificate @certParams)
        }
        catch {
            Write-Warning "Unable to create new self signed certificate: $($certParams.FriendlyName), an error has occured. " +
                          "Run the script in debug mode for more detail, or create the certificate manually"
            Write-Debug $_
        }
    } else {
        Write-Warning "Using self signed certificate: $($certParams.FriendlyName), that already exists"
    }


    $rootcert = (Get-ChildItem cert:\LocalMachine\Root\ | Where-Object { 
        $_.subject -like "*$($certParams.Subject)*" -and $_.FriendlyName -like $($certParams.FriendlyName) 
    })

    if ($cert -and !$rootcert) {
        $exportCertParams = @{
            Cert     = "cert:\LocalMachine\My\$($cert.Thumbprint)"
            FilePath = $certFile
            Password = $password
        }

        Write-Host "Importing $($certParams.FriendlyName) to Trust Root Certifcate store"
        Export-PfxCertificate @exportCertParams | Out-Null
        Import-PfxCertificate -CertStoreLocation 'Cert:\LocalMachine\Root' -FilePath $certFile -Password $password | Out-Null
    }

    Write-Host "Returning thumbprint $($cert.Thumbprint)"

    return $cert
}

function Get-SelfSignedCertificate {
    param (
        [string] $thumbprint
    )

    if ($thumbprint) {
        return Get-Item "Cert:\LocalMachine\My\$thumbprint"
    }

    return New-EdFiSelfSignedCertificate
}

function Get-WebsiteByName {
    param (
        [string] [Parameter(Mandatory=$true)] $WebsiteName
    )

    $manager = Get-IISServerManager

    return $manager.Sites[$WebsiteName]
}

function Get-WebApplicationByName {
    param (
        [string] [Parameter(Mandatory=$true)] $WebsiteName,
        [string] [Parameter(Mandatory=$true)] $WebApplicationName
    )

    $manager = Get-IISServerManager

    if ($manager.Sites[$WebsiteName]) {
        return $manager.Sites[$WebsiteName].Applications["/$WebApplicationName"]
    }

    throw "Error retrieving IIS Application $($WebApplicationName): Website $($WebsiteName) does not exist."
}

function New-IISApplicationPool {
    param (
        [string] [Parameter(Mandatory=$true)] $ApplicationPoolName,
        [string] $IdentityType = "ApplicationPoolIdentity"
    )

    $manager = Get-IISServerManager

    $appPool = $manager.ApplicationPools[$ApplicationPoolName]

    if (!$appPool) {
        $appPool = $manager.ApplicationPools.Add($ApplicationPoolName)
        $appPool.ManagedPipelineMode = "Integrated"
        $appPool.ManagedRuntimeVersion = "v4.0"
        $appPool.Enable32BitAppOnWin64 = $false
        $appPool.AutoStart = $true
        $appPool.StartMode = "AlwaysRunning"
        $appPool.ProcessModel.IdentityType = $IdentityType

        Write-Debug "IIS Server Manager: Added application pool $($ApplicationPoolName) using identity ""$($IdentityType)"""

        Write-Host "Created new IIS application pool: $($ApplicationPoolName)" -ForegroundColor Green
    }
    else {
        Write-Warning "Using application pool: $($ApplicationPoolName), that already exists"
    }

    return $appPool.Name
}

function New-IISWebsite {
    param (
        [string] [Parameter(Mandatory=$true)] $SiteName,
        [int] $Port = 443,
        [string] [Parameter(Mandatory=$true)] $WebsitePath,
        [string] $CertThumbprint
    )

    $website = Get-WebsiteByName $SiteName
    if ($website) {
        Write-Warning "Using IIS Website: $($SiteName), that already exists"
        Write-Warning "No changes to the website's physical path were made"

        return $false
    } else {
        # Check if Port is already in use
        $Websites = Get-IISSite
        foreach ($Site in $Websites)
        {
            if($Site.Name -ne $SiteName)
            {
                $webBinding = $Site.Bindings | Where-Object -FilterScript {$_.BindingInformation -like "*$Port*" -and $_.protocol -eq 'https'}
                if($webBinding)
                {
                    Write-Debug "Found binding $webBinding"
                    throw "Error creating the website: $SiteName. Port: $Port is already in use by site '$Site'."
                }
            }
        }
        
        # The following two IP:Port mappings are equivalent in IIS and PS terms
        #
        # The difference is due to the interpretation of colons in powershell,
        # and thus an exclamation point is used instead.
        $iisIpPortMapping = "*:$($Port):$($env:computername)"
        $powershellIpPortMapping = "0.0.0.0!$Port"

        $manager = Get-IISServerManager

        $selfSignedCert = Get-SelfSignedCertificate $CertThumbprint
        $certThumbprintBytes = Get-CertThumbprintBytes $selfSignedCert.Thumbprint
        $site = $manager.Sites.Add($SiteName, $iisIpPortMapping, $WebsitePath, $certThumbprintBytes, 'My')

        Write-Debug "IIS Server Manager: Added site $($SiteName) running with http on port $($Port)"
        Write-Debug "Website setup for the physical path: $($WebsitePath)"

        $site.Applications["/"].ApplicationPoolName = New-IISApplicationPool $SiteName
        $site.ServerAutoStart = $true;

        Write-Host "Created new IIS Website: $($SiteName), running on port $($Port)" -ForegroundColor Green

        return $true
    }
}

function New-IISWebApplication {
    param (
        [string] [Parameter(Mandatory=$true)] $WebsiteName,
        [string] [Parameter(Mandatory=$true)] $WebApplicationName,
        [string] [Parameter(Mandatory=$true)] $WebApplicationPath,
        [string] [Parameter(Mandatory=$true)] $AppPoolName
    )

    $webApplication = Get-WebApplicationByName $WebsiteName $WebApplicationName
    if ($webApplication) {
        Write-Warning "Using IIS web application: $($WebApplicationName), that already exists"

        if ($webApplication.VirtualDirectories[0].PhysicalPath -ine $WebApplicationPath) {
            $webApplication.VirtualDirectories[0].PhysicalPath = $WebApplicationPath
            Write-Host "Set $($WebApplicationName) web application to use the physical path: $($WebApplicationPath)" -ForegroundColor Green
        }

        if ($webApplication.ApplicationPoolName -ine $AppPoolName) {
            $webApplication.ApplicationPoolName = $AppPoolName
            Write-Host "Set $($WebApplicationName) web application to use application pool: $($AppPoolName)" -ForegroundColor Green
        }
    } else {

        $manager = Get-IISServerManager

        $site = $manager.Sites[$WebsiteName]

        $webApplication = $site.Applications.Add("/$WebApplicationName", $WebApplicationPath)

        Write-Debug "IIS Server Manager: Added application $($WebApplicationName)"
        Write-Debug "Application setup with physical path $($WebApplicationPath)"
        Write-Debug "Application setup under the website $($WebsiteName) and available at /$($WebApplicationName)"

        Write-Host "Created new IIS web application: $($WebApplicationName)" -ForegroundColor Green

        $webApplication.ApplicationPoolName = $AppPoolName
        Write-Host "Set $($WebApplicationName) web application to use application pool: $($AppPoolName)" -ForegroundColor Green
    }
}

function Uninstall-WebSite {
    [CmdletBinding()]
    param(
        [string]
        $WebSiteName = "Ed-Fi"
    )

    # Only remove the website if it isn't being used by another application
    $website = Get-WebsiteByName $WebSiteName
    $websiteApps = $website.Applications
    # Empty website still has application "/"
    if (1 -eq $websiteApps.Count -and $null -ne $website){
        Write-Debug "Removing website $WebSiteName"
        $websiteAppPoolName = $website.Applications["/"].ApplicationPoolName
        $websitePath = $website.Applications["/"].VirtualDirectories.PhysicalPath
        $serverMgr = Get-IISServerManager
        $serverMgr.Sites.Remove($webSite)

        $websiteAppPool = $serverMgr.ApplicationPools[$websiteAppPoolName]
        if ($null -ne $websiteAppPool){
            Write-Debug "Removing app pool $websiteAppPool"
            $serverMgr.ApplicationPools.Remove($websiteAppPool)
        }

        Remove-Item -Path $websitePath
    }
    else {
        Write-Warning "Unable to remove website '$($WebSiteName)' because is not empty."
    }
}

function Uninstall-WebApplication {
    [CmdletBinding()]
    param(
        [string] $WebSiteName,
        [string] $WebApplicationName,
        [string] $WebApplicationPath
    )

    $webApp = Get-WebApplicationByName $WebSiteName $WebApplicationName

    if ($null -eq $webapp) {
        Write-Warning "Web application '$WebApplicationName' does not exists."
        return;
    }

    $serverMgr = Get-IISServerManager
    $appPoolName = $webApp.Attributes['ApplicationPool'].Value
    if ($null -ne $webApp) {
        Write-Debug "Removing application $WebApplicationName"
        $serverMgr.Sites[$WebSiteName].Applications.Remove($webApp)
    }

    $childApps = (Get-IISAppPool -Name $appPoolName).WorkerProcesses
    if ($null -ne $childApps.length){
        Write-Debug "Removing app pool $appPoolName"
        $appPool = $serverMgr.ApplicationPools[$appPoolName]
        $serverMgr.ApplicationPools.Remove($appPool)
    }
    else {
        Write-Warning "Unable to remove app pool '$appPoolName' because it is still in use."
    }

    Get-ChildItem -Path $WebApplicationPath -Force -Recurse | Sort-Object -Property FullName -Descending | Remove-Item
    Remove-Item -Path $WebApplicationPath
}

function Get-PortNumber {
    param (
        [ValidateNotNullOrEmpty()]
        [String] $webSiteName
    )

    $website = Get-WebsiteByName $webSiteName
    if (!$website) {
        Write-Error "Website $webSiteName does not exist."
        Exit -1
    }

    $bindingInformation = $website.bindings[0].bindingInformation
   
    if ([String]::IsNullOrEmpty($bindingInformation)) {
        Write-Error "Information for website named $webSiteName not found. Please ensure $webSiteName is already running."
        Exit -1
    }
    $portNumber = $bindingInformation.Split(':')[1]
    return $portNumber
}

function Get-CertThumbprintBytes {
    param (
        [ValidateNotNullOrEmpty()]
        [String] $thumbprint
    )
    $bytes = for($i = 0; $i -lt $thumbprint.Length; $i += 2) {
        [convert]::ToByte($thumbprint.SubString($i, 2), 16)
    }

    return $bytes
}

$functions = @(
    "Uninstall-WebSite"
    "Uninstall-WebApplication"
    "New-IISWebApplication"
    "New-IISWebsite"
    "New-IISApplicationPool"
    "New-EdFiSelfSignedCertificate"
    "Close-IISManager"
    "Open-IISManager"
    "Get-PortNumber"
    "Get-WebsiteByName"
    "Get-WebApplicationByName"
)

Export-ModuleMember -Function $functions
