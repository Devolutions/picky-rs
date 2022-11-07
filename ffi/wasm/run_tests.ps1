#!/bin/env pwsh

$ErrorActionPreference = "Stop"

wasm-pack build --target nodejs --scope 'devolutions' --out-name picky

if ($LastExitCode -ne 0)
{
    throw "wasm-pack build failed"
}

try
{
    Push-Location ava_tests

    npm install
    npm test
    
    if ($LastExitCode -ne 0)
    {
        throw "ava tests failed"
    }
    
    Write-Host "Success!"
}
finally
{
    Pop-Location
}
