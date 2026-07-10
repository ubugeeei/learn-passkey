set dotenv-load := true
set shell := ["zsh", "-cu"]

default:
    @just --list

setup:
    swift package resolve

build:
    swift build

test:
    swift test --parallel

format:
    swift format --in-place --recursive Package.swift Sources Tests Apps 2>/dev/null || swift format --in-place --recursive Package.swift Sources Tests

lint:
    swift format lint --strict --recursive Package.swift Sources Tests Apps 2>/dev/null || swift format lint --strict --recursive Package.swift Sources Tests

server:
    swift run PasskeyServerCLI

clean:
    swift package clean
    rm -rf .derivedData
