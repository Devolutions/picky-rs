param(
    [switch] $Debug
)
if ($Debug) {
    Describe 'Rust Tests' {
        Context 'debug mode' {
            & 'cargo' 'test' '--manifest-path' '../Cargo.toml'
        }
        Context 'release mode' {
            & 'cargo' 'test' '--manifest-path' '../Cargo.toml' '--release'
        }
    }

    Describe 'Start All cases test for picky'{
        Context 'Mongodb without save certificates on backend'{
            & ./Picky.Tests.ps1 -UseMongo -Silent -Debug
        }
        Context 'Mongodb with save certificates on backend'{
            & ./Picky.Tests.ps1 -UseMongo -SavePickyCertificates -Silent -Debug
        }
        Context 'Memory without save certificates on backend'{
            & ./Picky.Tests.ps1 -UseMemory -Silent -Debug
        }
        Context 'Memory with save certificates on backend'{
            & ./Picky.Tests.ps1 -UseMemory -SavePickyCertificates -Silent -Debug
        }
        Context 'File without save certificates on backend'{
            & ./Picky.Tests.ps1 -UseFile -Silent -Debug
        }
        Context 'File with save certificates on backend'{
            & ./Picky.Tests.ps1 -UseFile -SavePickyCertificates -Silent -Debug
        }
    }
} else {
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
}