Docker is needed and your user need to be in docker group before running the script. 

Start Test:SavePickyCertificates

*  Start a non admin PowerShell session
*  Install pester: `Install-Module -Name Pester -Force`
*  Start test by running: './Picky.Test' with parameter -UseMongo -UseMemory or -UseFile, the default is mongodb, use -SavePickyCertificates to save the certificates on backend. 

Start Test with debug:

*  Install pester: `Install-Module -Name Pester -Force`
*  1 Start Mongo manually: 'docker run -p 27017:27017 -d --name picky-mongo library/mongo:4.1-bionic'
*  2 Set the environement variable of the build if they are not set : PICKY_REALM=WaykDen;PICKY_API_KEY=secret;PICKY_SAVE_CERTIFICATE=true
*  3 Run Picky Server with Clion
*  4 Run Pester './PickyDebug.Test'
