# 最初のメンタルモデル

## 1. 認証で証明したいこと

サーバーが最終的に知りたいのは「この request を送った主体を、どの account として扱ってよいか」です。パスワードでは、client と server が同じ秘密を知っていることを使います。Passkey では、authenticator だけが持つ秘密鍵に、server が一回限りの challenge を署名させます。

server が保存するのは公開鍵です。公開鍵から秘密鍵を復元できないため、credential database が漏れても、それだけで attacker が署名を作ることはできません。

## 2. 5 つの登場主体

| 主体 | この教材での実体 | 主な責務 |
| --- | --- | --- |
| User | iPhone を操作する人 | ceremony に同意し、端末上で user verification を行う |
| Authenticator | iCloud Keychain と端末の保護領域 | key pair、credential source、署名を管理する |
| Client platform | iOS / AuthenticationServices | RP と authenticator の仲介、origin/RP scope の強制 |
| Client application | SwiftUI app | server から options を取得し、OS API と結果を中継する |
| Relying Party | Swift server | challenge、公開鍵、account、policy を管理し検証する |

Face ID や Touch ID の biometric template は server に送られません。user verification は authenticator が秘密鍵の利用を許可した事実として、authenticator data の UV flag と署名で server へ伝わります。

## 3. 二つの ceremony

### Registration

1. server が account 用の opaque user handle と random challenge を用意する
2. client が options を iOS へ渡す
3. authenticator が RP ID に scoped な key pair を作る
4. client が public key を含む attestation response を server へ返す
5. server が challenge、origin、RP ID、flags、format、algorithm を検証する
6. server が credential ID と public key を account に紐づけて保存する

秘密鍵は 3 から外へ出ません。

### Authentication

1. server が新しい random challenge を用意する
2. client が challenge と RP ID を iOS へ渡す
3. authenticator が対象 credential を選び、user consent/verification 後に署名する
4. client が authenticator data、client data、signature を server へ返す
5. server が保存済み public key で署名と全ての binding を検証する
6. server が短命な application session を発行する

Passkey credential と application session は別物です。毎 API request で WebAuthn ceremony を行うのではなく、ログインまたは重要操作の再認証後に server session を使います。

## 4. phishing resistance の正体

「秘密を人が入力しない」だけでは不十分です。credential は RP ID に scope され、client data は origin を含み、authenticator data は RP ID の SHA-256 hash を含みます。server が両方を厳密に検証することで、見た目をコピーした別 origin が得た結果を正規サービスで再利用できなくなります。

次のどれかを省略すると binding が壊れます。

- challenge: 古い正常 response の replay を許す
- origin: 悪意ある client origin からの ceremony を許す
- RP ID hash: 別 RP scope の authenticator data を許す
- type: registration と authentication の文脈を混同する
- signature: response の改ざんと秘密鍵 possession を検出できない
- UP/UV: user presence / verification policy を満たしたか判断できない

## 5. identifier を混ぜない

| 値 | 誰が決めるか | 用途 | 秘密か |
| --- | --- | --- | --- |
| account ID | server | application account の主キー | いいえ |
| user handle (`user.id`) | server | authenticator が覚える RP 内の opaque ID | いいえ。ただし個人情報を直接入れない |
| credential ID | authenticator | 公開鍵 credential を特定する | いいえ |
| challenge | server | ceremony を一回限りにする nonce | 予測不能である必要がある |
| session token | server | 検証済み login state を参照する bearer secret | はい |

email address を user handle にしません。username が変わっても安定し、RP 外で意味を持たない random bytes を使います。

## 6. synced passkey と counter

Passkey は複数端末へ安全に同期されることがあります。authenticator data の BE (backup eligibility) と BS (backup state) はその性質を表します。従来の単一 authenticator を想定した signature counter が常に増えるとは限らず、synced passkey では 0 のままの実装もあります。

したがって counter だけを「clone なら必ず検出できる仕組み」と見なしません。counter rollback は risk signal として扱い、credential の backup state、device/session telemetry、再認証 policy と組み合わせます。

## 7. 次に観察するもの

以降では、次の signed message を自分で組み立てて検証します。

```text
authenticatorData || SHA-256(clientDataJSON)
```

`clientDataJSON` は challenge と origin を client context に bind し、`authenticatorData` は RP ID、flags、counter を authenticator context に bind します。署名はこの二つを一つの改ざん不能な証明にします。
