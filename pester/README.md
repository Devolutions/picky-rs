Docker is needed and your user need to be in docker group before running the script. 

Before start a case for the first time, you need to:
* Install Powershell Core 
`https://docs.microsoft.com/en-us/powershell/scripting/install/installing-powershell?view=powershell-6`
*  Start a non admin PowerShell session
*  Install pester: `Install-Module -Name Pester -Force`

Start Test with docker:

*  Start test by running: `./Picky.Tests.ps1` with parameters:
 `-UseMongo`  `-UseMemory` or `-UseFile` the default is mongodb,
 `-SavePickyCertificates` to save the certificates on backend.
 `-Silent` to hide all the Write-Host

Start Test in debug:
*  Run Pester `./Picky.Tests.ps1` `-Debug`, with the same parameters

Start All Test with Docker
*  Run Pester `./Picky.AllCase.ps1`
 
 Start All Test in Debug
*  Install Rust `https://www.rust-lang.org/tools/install`
*  Run Pester `./Picky.AllCase.ps1` `-Debug`
 


