param(
    [switch] $Verbose,
    [switch] $Debug
)
if ($Debug) {
    Describe 'rust tests' {
        Context 'debug mode' {
            & 'cargo' 'test' '--manifest-path' '../Cargo.toml'
        }
        Context 'release mode' {
            & 'cargo' 'test' '--manifest-path' '../Cargo.toml' '--release'
        }
    }

    Describe 'all tests for picky (debug)' {
        Context 'Mongodb without save certificates on backend'{
            & ./Picky.Tests.ps1 -UseMongo -Debug -Verbose:$Verbose
        }
        Context 'Mongodb with save certificates on backend'{
            & ./Picky.Tests.ps1 -UseMongo -SavePickyCertificates -Debug -Verbose:$Verbose
        }
        Context 'Memory without save certificates on backend'{
            & ./Picky.Tests.ps1 -UseMemory -Debug -Verbose:$Verbose
        }
        Context 'Memory with save certificates on backend'{
            & ./Picky.Tests.ps1 -UseMemory -SavePickyCertificates -Debug -Verbose:$Verbose
        }
        Context 'File without save certificates on backend'{
            & ./Picky.Tests.ps1 -UseFile -Debug -Verbose:$Verbose
        }
        Context 'File with save certificates on backend'{
            & ./Picky.Tests.ps1 -UseFile -SavePickyCertificates -Debug -Verbose:$Verbose
        }
    }
} else {
    Describe 'all tests for picky' {
        Context 'Mongodb without save certificates on backend'{
            & ./Picky.Tests.ps1 -UseMongo -Verbose:$Verbose
        }
        Context 'Mongodb with save certificates on backend'{
            & ./Picky.Tests.ps1 -UseMongo -SavePickyCertificates -Verbose:$Verbose
        }
        Context 'Memory without save certificates on backend'{
            & ./Picky.Tests.ps1 -UseMemory -Verbose:$Verbose
        }
        Context 'Memory with save certificates on backend'{
            & ./Picky.Tests.ps1 -UseMemory -SavePickyCertificates -Verbose:$Verbose
        }
        Context 'File without save certificates on backend'{
            & ./Picky.Tests.ps1 -UseFile -Verbose:$Verbose
        }
        Context 'File with save certificates on backend'{
            & ./Picky.Tests.ps1 -UseFile -SavePickyCertificates -Verbose:$Verbose
        }
    }
}