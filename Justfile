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
    swift format --configuration .swift-format --in-place --recursive Package.swift Sources Tests Apps

lint:
    swift format lint --configuration .swift-format --strict --recursive Package.swift Sources Tests Apps

check: lint build test

server:
    swift run PasskeyServerCLI

clean:
    swift package clean
    rm -rf .derivedData
