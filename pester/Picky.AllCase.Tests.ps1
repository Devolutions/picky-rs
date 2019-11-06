Describe 'Start All cases test for picky'{
    Context 'Mongodb without save certificates on backend'{
        & ./Picky.Tests.ps1 -UseMongo -Silent
    }
    Context 'Mongodb with save certificates on backend'{
        & ./Picky.Tests.ps1 -UseMongo -SavePickyCertificates -Silent
    }
    Context 'Memory without save certificates on backend'{
        & ./Picky.Tests.ps1 -UseMemory -Silent
    }
    Context 'Memory with save certificates on backend'{
        & ./Picky.Tests.ps1 -UseMemory -SavePickyCertificates -Silent
    }
    Context 'File without save certificates on backend'{
        & ./Picky.Tests.ps1 -UseFile -Silent
    }
    Context 'File with save certificates on backend'{
        & ./Picky.Tests.ps1 -UseFile -SavePickyCertificates -Silent
    }
}