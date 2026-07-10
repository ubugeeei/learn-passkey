# 学習ロードマップ

## 学び方の原則

Passkey は一つの API ではありません。OS、authenticator、クライアント、Relying Party server、Web PKI、アカウント運用が協調する仕組みです。そのため、このハンズオンでは UI から始めず、観測可能なデータと trust boundary を一層ずつ積み上げます。

各ステップには次の完了条件があります。

- **Explain**: 自分の言葉で「なぜ必要か」を説明できる
- **Inspect**: 実際のバイト列や状態を観察できる
- **Implement**: ライブラリの検証関数に隠さず実装できる
- **Attack**: 何を省略するとどの攻撃が成立するか説明できる
- **Operate**: 失効、回復、監査、障害時の方針を決められる

## Phase 0: 土台

### Step 0 — 認証のメンタルモデル

公開鍵、署名、challenge-response、phishing resistance、RP ID と origin を学びます。

成果物:

- 登場主体と trust boundary の図
- registration/authentication のシーケンス
- 用語集

### Step 1 — 再現可能な Swift 環境

Nix、SwiftPM、テスト、formatter/linter の入口を揃えます。macOS では Swift toolchain と Apple SDK は Xcode/Command Line Tools を利用し、Nix は周辺ツールと環境変数を固定します。

確認:

```sh
nix develop
swift --version
swift test
```

## Phase 1: wire format を理解する

### Step 2 — Base64url と protocol model

JSON がバイト列を直接持てないため WebAuthn が使う unpadded Base64url を実装します。challenge、credential ID、user handle を「文字列」ではなく opaque bytes として扱います。

### Step 3 — CBOR を読む

attestation object と COSE key を読むため、必要範囲の CBOR decoder を実装します。length limit、nesting limit、duplicate key rejection もここで扱います。

### Step 4 — authenticator data と COSE key

`rpIdHash | flags | signCount | attestedCredentialData | extensions` の境界を byte cursor で読み、ES256/P-256 公開鍵を取り出します。

## Phase 2: Relying Party server

### Step 5 — registration options

user handle と challenge を CSPRNG で生成し、期限つき・一回限りの ceremony state に保存します。client へ渡す options と server にだけ残す期待値を分離します。

### Step 6 — registration verification

WebAuthn の検証順序に沿って、type、challenge、origin、RP ID hash、UP/UV、attested credential data、algorithm を検証します。教材の標準 policy は privacy を優先した `attestation: none`、discoverable credential、user verification required です。

### Step 7 — authentication verification

assertion の signed bytes を正確に組み立て、保存済み P-256 公開鍵で ES256 signature を検証します。credential と user handle の結びつき、backup flags、signature counter の扱いも実装します。

### Step 8 — HTTP API と session

SwiftNIO で薄い HTTP adapter を作ります。body/header limit、content type、error mapping、request ID、Bearer session、logout を追加し、WebAuthn domain logic と transport を分離します。

## Phase 3: Apple client

### Step 9 — iOS registration

`ASAuthorizationPlatformPublicKeyCredentialProvider` で registration request を作り、OS から受け取った credential ID、client data、attestation object を server へ返します。

### Step 10 — iOS authentication

assertion request、AutoFill-assisted request、cancellation/error handling を実装します。秘密鍵や生体情報がアプリ／サーバーへ渡らないことをデバッガで確認します。

### Step 11 — Associated Domains

`webcredentials:<domain>` entitlement と `/.well-known/apple-app-site-association` の双方向の関連づけを構成します。実機、HTTPS、有効な証明書、Apple CDN、development alternate mode の違いを確認します。

## Phase 4: 実用設計

### Step 12 — end-to-end と攻撃テスト

正常系だけでなく、challenge replay、wrong origin、wrong RP ID、missing UV、tampered signature、credential substitution、expired ceremony を fixture で再現します。

### Step 13 — credential lifecycle

credential の一覧、表示名変更、追加、失効、全 session revoke、再認証を設計します。「同じ account に複数 credential」を基本モデルにします。

### Step 14 — recovery と運用

passkey を全て失った場合の recovery は認証方式全体の強度を決めます。help desk、verified device、recovery code、本人確認を threat model と product policy に合わせて選びます。

### Step 15 — production review

永続化、トランザクション、分散 challenge store、key management、TLS、proxy trust、rate limit、observability、privacy、incident response を checklist で確認します。

## 推奨ペース

| 区間 | 目安 | 手を動かす比率 |
| --- | ---: | ---: |
| Phase 0 | 2–3 時間 | 40% |
| Phase 1 | 6–10 時間 | 80% |
| Phase 2 | 10–16 時間 | 85% |
| Phase 3 | 6–10 時間 | 80% |
| Phase 4 | 8–16 時間 | 70% |

速さより、「受信した 1 byte がどこから来て、何を信頼してよいか」を追跡できることを優先します。

## 最終課題

次の条件を満たす小さなサービスを、自分の RP ID と Bundle ID で構築します。

- iPhone 実機で passkey を登録し、ログインできる
- credential を二つ登録し、片方を失効できる
- replay と origin mismatch が server test で拒否される
- server 再起動後も credential と session policy が意図どおり動く
- recovery policy と脅威モデルを文章で説明できる
- production checklist の未達項目を「既知の制約」として列挙できる
