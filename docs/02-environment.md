# 開発環境を作る

## この章のゴール

- Nix と Apple toolchain の責務を区別できる
- server package の build/test command を同じ入口から実行できる
- iOS 実機 build に必要な Xcode と signing の前提を確認できる

## なぜ Swift 自体を Nix に入れないのか

この教材の client は `AuthenticationServices` を使う iOS app です。Apple SDK、iOS Simulator、code signing は Xcode が提供します。macOS 上で Nixpkgs の Swift に置き換えると、使用する Apple SDK と Xcode の組み合わせが不明確になり、client と server で異なる toolchain を誤って検証しやすくなります。

そのため責務を次のように分けます。

| 管理元 | 管理するもの |
| --- | --- |
| Xcode / Command Line Tools | Swift compiler、Foundation、CryptoKit、AuthenticationServices、Apple SDK、simulator、signing |
| Nix flake | `just`、`jq`、`curl`、OpenSSL CLI、SQLite CLI、環境変数、補助 command の version |
| SwiftPM | SwiftNIO、Swift Crypto と package graph |

server を Linux に deploy する段階では、CI/container で Swift.org の公式 Linux toolchain version を固定します。Nixpkgs の Swift version が教材の最低 version に追随していると確認できるまでは、暗黙に古い compiler を選びません。

## 必要なもの

- macOS
- Nix with flakes
- Xcode 26 以降、または server のみなら対応する Command Line Tools
- iOS client を実機で動かす場合は Apple Developer signing team と HTTPS domain

現在選択されている developer directory を確認します。

```sh
xcode-select -p
xcrun swift --version
xcodebuild -version
```

`xcodebuild` が「CommandLineTools is a command line tools instance」と返す場合、server は build できますが iOS app は build できません。full Xcode をインストール後、必要なら次を実行します。

```sh
sudo xcode-select --switch /Applications/Xcode.app/Contents/Developer
```

## shell に入る

```sh
nix develop
just setup
just test
```

direnv を使う場合は一度だけ許可します。

```sh
direnv allow
```

flake lock は commit されます。更新は意図的に行い、更新後に全 test を実行します。

```sh
nix flake update
nix develop --command just test
```

## command 一覧

```sh
just          # 一覧
just build    # server と library を build
just test     # unit/integration tests
just format   # bundled swift-format で整形
just lint     # format 差分を作らず検査
just server   # local RP server
```

`swift format` は選択中の Swift toolchain に同梱された version を使います。compiler と formatter の Swift syntax support を揃えるためです。

## secret と local configuration

`.env` は commit しません。secret を Nix store や flake source に書くと world-readable な store path に残り得るためです。教材の local default は secret を必要としません。本番 credential、database DSN、session signing/encryption key は runtime secret store から注入します。

## 確認問題

1. Nix shell に入っても iOS SDK が Nix から提供されないのはなぜですか。
2. `swift --version` と `xcrun swift --version` が異なる場合、どちらを build に使うべきですか。
3. secret を `flake.nix` に直接書いてはいけないのはなぜですか。

## 完了条件

- `nix flake check` が成功する
- `nix develop --command swift --version` が選択中の Apple Swift を表示する
- `nix develop --command just test` が成功する
- client を進める場合、`xcodebuild -version` が full Xcode を表示する
