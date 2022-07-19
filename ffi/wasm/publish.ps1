#!/bin/env pwsh

$ErrorActionPreference = "Stop"

wasm-pack build --target web --scope devolutions --out-name picky --features wee_alloc

if ($LastExitCode -ne 0)
{
    throw "wasm-pack build failed"
}

(Get-Content ./pkg/package.json) -Replace '@devolutions/picky-wasm', '@devolutions/picky' | Set-Content ./pkg/package.json

wasm-pack publish

if ($LastExitCode -ne 0)
{
    throw "ava tests failed"
}

Write-Host "Success!"
