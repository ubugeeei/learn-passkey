# 用語集

- **Authenticator**: credential private key を保持し、user consent のもとで生成・署名を行う機能。
- **Ceremony**: client、authenticator、RP server が協調する registration または authentication の一連の処理。
- **Challenge**: replay を防ぐため server が生成する、一回限りで予測不能な値。
- **Client data**: ceremony type、challenge、origin などを含む JSON bytes。
- **COSE**: CBOR 上で暗号鍵や署名 algorithm を表現する標準。WebAuthn public key は COSE_Key として格納される。
- **Credential ID**: authenticator が credential source を識別する opaque bytes。
- **Discoverable credential**: server から allowCredentials を渡さなくても authenticator が RP ID から候補を発見できる credential。Passkey の基本形。
- **Origin**: scheme、host、port の組。RP ID より狭い client context を表す。
- **Passkey**: phishing-resistant な WebAuthn credential を、platform UX と credential lifecycle を含めて利用しやすくしたもの。
- **Relying Party (RP)**: WebAuthn を使って user を認証するサービス。
- **RP ID**: credential の scope。通常はサービスの registrable domain またはその domain suffix 条件を満たす host。
- **User handle**: RP が account に割り当て、discoverable credential に保存する opaque bytes。
- **User presence (UP)**: user が ceremony を開始・承認する操作を行ったこと。
- **User verification (UV)**: authenticator が PIN、biometric、端末 passcode などで user を検証したこと。
- **WebAuthn**: 公開鍵 credential を作成・利用する client API と RP/authenticator の検証モデルを定義する W3C 仕様。
