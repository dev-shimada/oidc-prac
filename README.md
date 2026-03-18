# oidc-prac

## ローカル OIDC プロバイダー + Conformance Suite のセットアップ

### 1. Conformance Suite の JAR ビルド

Maven を Docker で実行してビルドします（初回は依存関係のダウンロードで数分かかります）。
プロジェクトルートから実行してください。

```bash
MAVEN_CACHE=/tmp/conformance-maven-cache \
docker compose -f conformance-suite/builder-compose.yml -f builder-compose-local.yml up --exit-code-from builder
```

### 2. 起動

```bash
docker compose -f conformance-suite/docker-compose-dev-mac.yml -f conformance-suite-local-provider.yml up
```

起動するサービス：
- `httpd`: https://localhost.emobix.co.uk:8443 (Conformance Suite UI)
- `server`: Conformance Suite サーバー（Java）
- `mongodb`: MongoDB
- `authorization`: ローカル OIDC プロバイダー（http://localhost.emobix.co.uk:49151）

### 3. 証明書の信頼設定（初回のみ）

```bash
docker compose -f conformance-suite/docker-compose-dev-mac.yml exec httpd \
  cat /etc/ssl/certs/ssl-cert-snakeoil.pem > ~/Downloads/localhost-cert.pem
sudo security add-trusted-cert -d -k /Library/Keychains/System.keychain ~/Downloads/localhost-cert.pem
```

証明書の削除：
```bash
openssl x509 -fingerprint -sha256 -in ~/Downloads/localhost-cert.pem | grep "sha" | grep -o -E "[0-9A-Z:]{64}" | sed "s/://g"
sudo security delete-certificate -c localhost -Z "<SHA256_HASH>" /Library/Keychains/System.keychain
```

### 4. テストの実行

ブラウザで https://localhost.emobix.co.uk:8443 を開き、テストプランを作成します。

**テストプラン設定値：**
| 項目 | 値 |
|------|-----|
| Discovery URL | `http://localhost.emobix.co.uk:49151/.well-known/openid-configuration` |
| Client ID | `1234` |
| Client Secret | `secret` |

推奨テストプラン: `OpenID Connect Core: Basic Certification Profile Authorization server test`

---

## ネットワーク構成

```
ブラウザ (Mac)
  └─ https://localhost.emobix.co.uk:8443  ──► [httpd コンテナ] ──► [server コンテナ]
  └─ http://localhost.emobix.co.uk:49151  ──► [authorization コンテナ]
                                                     ↑
[server コンテナ] ─ extra_hosts (host-gateway) ─────┘
  back-channel calls (token, userinfo, jwks)
```

`localhost.emobix.co.uk` は公開 DNS で `127.0.0.1` に解決されます。
Conformance Suite 自体もこのドメインをデフォルトで使用しています。
