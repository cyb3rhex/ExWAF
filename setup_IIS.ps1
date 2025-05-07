# ExWAF Setup Script for IIS
# This script helps set up the Web Application Firewall for Exchange 2019
# It installs and configures URL Rewrite and Application Request Routing

param (
    [Parameter(Mandatory=$false)]
    [string]$WafIp = "127.0.0.1",
    
    [Parameter(Mandatory=$false)]
    [int]$WafPort = 8080,
    
    [Parameter(Mandatory=$false)]
    [string]$ExchangeServer = "localhost",
    
    [Parameter(Mandatory=$false)]
    [int]$ExchangePort = 443,
    
    [Parameter(Mandatory=$false)]
    [string[]]$CustomPaths = @("/owa")
)

# Ensure we're running with administrative privileges
$currentPrincipal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Error "This script must be run as an Administrator. Please restart PowerShell as Administrator."
    exit 1
}

Write-Host "ExWAF Setup Script" -ForegroundColor Green
Write-Host "=======================" -ForegroundColor Green
Write-Host ""

# Function to check if IIS is installed
function Check-IIS {
    $iisFeature = Get-WindowsFeature -Name Web-Server
    return $iisFeature.Installed
}

# Function to install IIS if not already installed
function Install-IIS {
    Write-Host "Installing IIS..." -ForegroundColor Yellow
    Install-WindowsFeature -Name Web-Server -IncludeManagementTools
    Write-Host "IIS installed successfully." -ForegroundColor Green
}

# Function to install URL Rewrite module
function Install-URLRewrite {
    Write-Host "Checking for URL Rewrite module..." -ForegroundColor Yellow
    
    $rewriteModule = Get-WebGlobalModule -Name "RewriteModule"
    if ($null -eq $rewriteModule) {
        Write-Host "URL Rewrite module not found. Installing..." -ForegroundColor Yellow
        
        $downloadUrl = "https://download.microsoft.com/download/1/2/8/128E2E22-C1B9-44A4-BE2A-5859ED1D4592/rewrite_amd64_en-US.msi"
        $installerPath = "$env:TEMP\rewrite_amd64_en-US.msi"
        
        try {
            Invoke-WebRequest -Uri $downloadUrl -OutFile $installerPath
            Start-Process -FilePath "msiexec.exe" -ArgumentList "/i `"$installerPath`" /quiet /norestart" -Wait
            Write-Host "URL Rewrite module installed successfully." -ForegroundColor Green
        }
        catch {
            Write-Error "Failed to install URL Rewrite module: $_"
            exit 1
        }
    }
    else {
        Write-Host "URL Rewrite module is already installed." -ForegroundColor Green
    }
}

# Function to install Application Request Routing (ARR)
function Install-ARR {
    Write-Host "Checking for Application Request Routing module..." -ForegroundColor Yellow
    
    $arrFeature = Get-WebGlobalModule -Name "ApplicationRequestRouting" -ErrorAction SilentlyContinue
    if ($null -eq $arrFeature) {
        Write-Host "Application Request Routing module not found. Installing..." -ForegroundColor Yellow
        
        $downloadUrl = "https://download.microsoft.com/download/E/9/8/E9849D6A-020E-47E4-9FD0-A023E99B54EB/requestRouter_amd64.msi"
        $installerPath = "$env:TEMP\requestRouter_amd64.msi"
        
        try {
            Invoke-WebRequest -Uri $downloadUrl -OutFile $installerPath
            Start-Process -FilePath "msiexec.exe" -ArgumentList "/i `"$installerPath`" /quiet /norestart" -Wait
            Write-Host "Application Request Routing module installed successfully." -ForegroundColor Green
        }
        catch {
            Write-Error "Failed to install Application Request Routing module: $_"
            exit 1
        }
    }
    else {
        Write-Host "Application Request Routing module is already installed." -ForegroundColor Green
    }
}

# Function to configure URL rewrite rule
function Configure-URLRewrite {
    param(
        [string[]]$Paths
    )
    
    Write-Host "Configuring URL Rewrite rules for ExWAF..." -ForegroundColor Yellow
    
    # Enable proxy functionality in ARR
    Set-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST' -filter "system.webServer/proxy" -name "enabled" -value "True"
    
    # Create rewrite rule for each path
    foreach ($path in $Paths) {
        $pathName = $path.TrimStart('/')
        
        # Check if the virtual directory exists
        if (!(Test-Path "IIS:\Sites\Default Web Site\$pathName")) {
            Write-Host "Creating virtual directory for $pathName..." -ForegroundColor Yellow
            New-WebVirtualDirectory -Site "Default Web Site" -Name $pathName -PhysicalPath "C:\inetpub\wwwroot\$pathName"
        }
        
        # Configure the rewrite rule
        $ruleName = "ExWAF_$pathName"
        
        # Check if rule already exists and remove it if it does
        $existingRule = Get-WebConfigurationProperty -pspath "MACHINE/WEBROOT/APPHOST/Default Web Site/$pathName" -filter "system.webServer/rewrite/rules/rule[@name='$ruleName']" -Name "."
        if ($existingRule.Count -gt 0) {
            Remove-WebConfigurationProperty -pspath "MACHINE/WEBROOT/APPHOST/Default Web Site/$pathName" -filter "system.webServer/rewrite/rules" -Name "." -AtElement @{name=$ruleName}
        }
        
        Add-WebConfigurationProperty -pspath "MACHINE/WEBROOT/APPHOST/Default Web Site/$pathName" -filter "system.webServer/rewrite/rules" -name "." -value @{name=$ruleName; patternSyntax='Wildcard'; stopProcessing='True'}
        Set-WebConfigurationProperty -pspath "MACHINE/WEBROOT/APPHOST/Default Web Site/$pathName" -filter "system.webServer/rewrite/rules/rule[@name='$ruleName']/match" -name "url" -value "*"
        Set-WebConfigurationProperty -pspath "MACHINE/WEBROOT/APPHOST/Default Web Site/$pathName" -filter "system.webServer/rewrite/rules/rule[@name='$ruleName']/action" -name "type" -value "Rewrite"
        Set-WebConfigurationProperty -pspath "MACHINE/WEBROOT/APPHOST/Default Web Site/$pathName" -filter "system.webServer/rewrite/rules/rule[@name='$ruleName']/action" -name "url" -value "http://${WafIp}:${WafPort}${path}/{R:0}"
        
        Write-Host "URL Rewrite rule configured for $path." -ForegroundColor Green
    }
    
    Write-Host "URL Rewrite rules configured successfully." -ForegroundColor Green
}

# Function to modify the Exchange WAF configuration
function Configure-WAF {
    param (
        [string]$ExchangeServer,
        [int]$ExchangePort
    )
    
    Write-Host "Configuring the ExWAF..." -ForegroundColor Yellow
    
    # Update the WAF configuration file
    $wafConfigPath = ".\ExWAF.py"
    
    if (Test-Path $wafConfigPath) {
        $wafConfig = Get-Content $wafConfigPath
        
        # Update the EXCHANGE_SERVER setting
        $newExchangeServer = "https://${ExchangeServer}:${ExchangePort}"
        $wafConfig = $wafConfig -replace 'EXCHANGE_SERVER = ".*"', "EXCHANGE_SERVER = `"$newExchangeServer`""
        
        # Save the updated configuration
        $wafConfig | Set-Content $wafConfigPath
        
        Write-Host "WAF configuration updated successfully." -ForegroundColor Green
    }
    else {
        Write-Warning "WAF configuration file not found at $wafConfigPath. Please update it manually."
    }
}

# Main script execution
if (-not (Check-IIS)) {
    Install-IIS
}

Install-URLRewrite
Install-ARR

# Configure URL Rewrite for each path provided
Configure-URLRewrite -Paths $CustomPaths

# Configure the WAF to point to the Exchange server
Configure-WAF -ExchangeServer $ExchangeServer -ExchangePort $ExchangePort

Write-Host ""
Write-Host "Setup completed successfully!" -ForegroundColor Green
Write-Host ""
Write-Host "Next steps:" -ForegroundColor Yellow
Write-Host "1. Start the ExWAF by running: start_ExWAF.bat" -ForegroundColor White
Write-Host "2. Start the dashboard by running: start_Dashboard.bat" -ForegroundColor White
Write-Host "3. Test the WAF by accessing your OWA through your normal URL" -ForegroundColor White
Write-Host ""
Write-Host "If you encounter any issues, check the exwaf.log file for details." -ForegroundColor White 