#!/bin/env pwsh

$ErrorActionPreference = "Stop"

wasm-pack build --target nodejs --scope 'devolutions' --out-name picky

if ($LastExitCode -ne 0)
{
    throw "wasm-pack build failed"
}

(Get-Content ./pkg/package.json) -Replace '@devolutions/picky-wasm', '@devolutions/picky' | Set-Content ./pkg/package.json

cd ava_tests
npm install
npm test

if ($LastExitCode -ne 0)
{
    throw "ava tests failed"
}

Write-Host "Success!"
