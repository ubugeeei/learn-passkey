{
  description = "A reproducible learning environment for implementing Passkeys in Swift";

  inputs.nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";

  outputs = { nixpkgs, ... }:
    let
      systems = [ "aarch64-darwin" "x86_64-darwin" ];
      forAllSystems = function:
        nixpkgs.lib.genAttrs systems (system: function nixpkgs.legacyPackages.${system});
    in
    {
      devShells = forAllSystems (pkgs:
        let
          appleSwift = pkgs.writeShellScriptBin "swift" ''
            exec /usr/bin/swift "$@"
          '';
        in
        {
        default = pkgs.mkShellNoCC {
          packages = with pkgs; [
            appleSwift
            curl
            git
            jq
            just
            openssl
            pkg-config
            sqlite
          ];

          shellHook = ''
            # mkShell selects Nix's SDK by default. Swift must use the SDK that
            # belongs to the selected Xcode/Command Line Tools installation.
            unset DEVELOPER_DIR SDKROOT
            export DEVELOPER_DIR="$(/usr/bin/xcode-select -p)"
            export SDKROOT="$(/usr/bin/xcrun --sdk macosx --show-sdk-path)"
            export SWIFT_DETERMINISTIC_HASHING=1
            export PASSKEY_ENVIRONMENT=nix

            if ! /usr/bin/swift --version >/dev/null 2>&1; then
              echo "error: Install Xcode or the Xcode Command Line Tools before entering this shell." >&2
              exit 1
            fi

            swift_version="$(/usr/bin/swift --version 2>/dev/null | head -n 1)"
            echo "learn-passkey development shell"
            echo "  $swift_version"
            echo "  Run: just test"
          '';
        };
      });
    };
}
