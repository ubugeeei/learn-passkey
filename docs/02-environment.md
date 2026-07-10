# Build the Development Environment

## Goal

By the end of this chapter you can:

- explain which tools are controlled by Nix and which are controlled by Xcode;
- build and test the Swift packages through one repeatable command;
- identify the additional requirements for an iOS device build.

## Why Swift itself comes from Apple on macOS

The client uses AuthenticationServices, an iOS SDK, simulator/device support, and code signing. Those are supplied as a coherent set by Xcode. Replacing only the compiler with a Nixpkgs Swift build can accidentally mix compiler, SDK, and platform framework versions.

The environment therefore assigns ownership explicitly:

| Owner | Components |
| --- | --- |
| Xcode / Command Line Tools | Swift compiler, Foundation, CryptoKit platform support, AuthenticationServices, Apple SDKs, simulator, signing |
| Nix flake | `just`, `jq`, `curl`, OpenSSL CLI, SQLite CLI, surrounding versions and environment |
| SwiftPM | SwiftNIO, Swift Crypto, Swift Testing, and the package graph |

The flake uses `mkShellNoCC` and a small Swift shim. This matters: injecting Nix's C/C++ compiler into an Apple Swift build can mix libc++ and SDK headers. The shell resets `DEVELOPER_DIR` and `SDKROOT` to the selected Apple developer directory.

## Prerequisites

- macOS;
- Nix with flakes enabled;
- Xcode 26 or compatible Command Line Tools;
- full Xcode, an Apple Developer signing team, and an iOS device for the native chapter;
- an HTTPS domain you control for a real Associated Domains test.

Inspect the selected developer directory:

```sh
xcode-select -p
xcrun swift --version
xcodebuild -version
```

If `xcodebuild` reports that the selected directory is only a Command Line Tools instance, the server packages can still build, but the iOS application cannot. After installing Xcode, select it if necessary:

```sh
sudo xcode-select --switch /Applications/Xcode.app/Contents/Developer
```

## Enter the shell

```sh
nix develop
just setup
just test
```

With direnv:

```sh
direnv allow
```

The lock file is committed. Update it deliberately and retest everything:

```sh
nix flake update
nix develop --command just test
```

## Commands

```sh
just             # list tasks
just setup       # resolve SwiftPM dependencies
just build       # build libraries and the server executable
just test        # run all test suites in parallel
just format      # format package, sources, tests, and app Swift files
just lint        # check formatting without modifying files
just server      # run the local HTTP server
just clean       # remove Swift build artifacts
```

The selected Swift toolchain's bundled `swift format` is used so formatter syntax support tracks the compiler.

## Secrets and configuration

`.env` is ignored. Do not put runtime secrets into `flake.nix`: Nix store paths are not a secret store and may be readable by other local users or retained in caches.

The lab defaults do not require a secret. Production database credentials, encryption/session keys, and infrastructure tokens must come from a runtime secret manager.

Server environment variables:

| Variable | Default | Meaning |
| --- | --- | --- |
| `PASSKEY_RP_ID` | `passkeys.example.com` | credential scope, without scheme |
| `PASSKEY_RP_NAME` | `Passkey Lab` | user-visible relying-party name |
| `PASSKEY_ALLOWED_ORIGINS` | `https://passkeys.example.com` | comma-separated exact origins |
| `PASSKEY_APP_ID` | `TEAMID.com.example.PasskeyLab` | AASA webcredentials application ID |
| `PASSKEY_HOST` | `127.0.0.1` | HTTP listener host |
| `PASSKEY_PORT` | `8080` | HTTP listener port |

## Exercises

1. Compare `command -v swift`, `command -v clang`, and `xcrun --find swift` inside and outside `nix develop`.
2. Explain why the shell uses Apple Clang rather than Nix Clang for SwiftPM C targets.
3. Run `nix flake metadata` and locate the pinned Nixpkgs revision.
4. Confirm that `.env` is not tracked.

## Completion criteria

- `nix flake check` succeeds;
- `nix develop --command swift --version` reports the intended Apple Swift;
- `nix develop --command just test` passes;
- before the iOS chapter, `xcodebuild -version` reports full Xcode.
