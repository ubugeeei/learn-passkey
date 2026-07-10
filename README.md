# Learn Passkey with Swift

Passkey を「API の呼び出し方」ではなく、WebAuthn の仕様、バイト列、暗号検証、状態管理、iOS の UX、運用上の防御まで、Swift で段階的に実装して理解するハンズオンです。

クライアントとサーバーをどちらも Swift で実装します。サーバーの HTTP 転送層に SwiftNIO、Linux での暗号実装互換性に Swift Crypto を使いますが、WebAuthn の検証ロジック、CBOR/COSE の解釈、challenge と credential の管理はこのリポジトリ内で実装します。

## 到達点

最後まで進むと、次を説明・実装・レビューできる状態を目指します。

- パスワード、公開鍵認証、WebAuthn、Passkey の関係を説明する
- registration と authentication の各バイト列を仕様と対応づける
- RP ID、origin、challenge、UP/UV、credential ID、user handle の役割を説明する
- `clientDataJSON`、attestation object、authenticator data、COSE key を自力で解析する
- ES256 assertion signature をサーバーで検証する
- challenge の一回性、期限、credential counter、session を安全に管理する
- AuthenticationServices を使う iOS クライアントを実装する
- Associated Domains と AASA を正しく構成する
- account recovery、credential 管理、監査、レート制限を含む本番設計を判断する

## 進め方

1. [学習ロードマップ](docs/00-roadmap.md)で全体像と完了条件を確認する
2. [最初のメンタルモデル](docs/01-mental-model.md)を読む
3. `nix develop` で同じ開発環境に入る
4. 各章でコードを読み、テストを壊し、直し、実際の iOS 端末で ceremony を通す
5. 最後に threat model と production checklist を使って自分の設計をレビューする

各章は「目的 → 仕様 → 実装 → 観察 → 演習 → 完了条件」の順で、前から通読できる構成にします。

## 重要な境界

この教材は、学習用の短い擬似実装ではなく、検証順序や失敗時の扱いまで実用水準に近づけます。一方で、次は意図的に境界の外に置き、production adapter の差し替え点として明示します。

- TLS 終端と DDoS 防御
- 永続 DB、KMS、secret rotation
- メールや本人確認を伴う account recovery
- FIDO Metadata Service を使う attestation trust policy
- 分散環境での challenge/session の共有

これらを省略したまま「本番対応」とは呼びません。最終章で必要な差し替えと受け入れ基準を定義します。

## 一次資料

- [Web Authentication Level 3](https://www.w3.org/TR/webauthn-3/)
- [Apple: Supporting passkeys](https://developer.apple.com/documentation/authenticationservices/supporting-passkeys)
- [Apple: Supporting associated domains](https://developer.apple.com/documentation/xcode/supporting-associated-domains)
- [RFC 8949: CBOR](https://www.rfc-editor.org/rfc/rfc8949.html)
- [RFC 9052: COSE Structures](https://www.rfc-editor.org/rfc/rfc9052.html)
- [RFC 9053: COSE Algorithms](https://www.rfc-editor.org/rfc/rfc9053.html)

仕様と OS API は更新されます。このリポジトリの説明より一次資料を優先してください。
