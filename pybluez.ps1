# Install Python 3.9 on Windows via PowerShell
# Run this script as Administrator

# Define Python 3.9 installer URL (64-bit)
$pythonInstallerUrl = "https://www.python.org/ftp/python/3.9.0/python-3.9.0-amd64.exe"
$installerPath = "$env:TEMP\python-3.9-installer.exe"

Write-Host "Downloading Python 3.9 installer..."
Invoke-WebRequest -Uri $pythonInstallerUrl -OutFile $installerPath

Write-Host "Running installer silently..."
Start-Process -FilePath $installerPath -ArgumentList "/quiet InstallAllUsers=1 PrependPath=1 Include_test=0" -Wait

Write-Host "Cleaning up installer..."
Remove-Item $installerPath -Force

Write-Host "Verifying installation..."
python --version